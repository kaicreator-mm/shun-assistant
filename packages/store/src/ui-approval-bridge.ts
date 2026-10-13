// Durable R2 UI approval bridge for a genuine ActionController ApprovalPort.
// Browser code never issues grants. The only approving actor is a live,
// explicit decision on the same exact task/plan that the controller requested.
// The SQLite row is in ShunStore's database, not an untrusted sidecar manifest.
import { randomUUID } from 'node:crypto';
import { ApprovalDecisionSchema, type ApprovalPort, ApprovalRequestSchema } from '@shun/contracts';
import type { ShunStore } from './shun-store.ts';

type ApprovalRequest = Parameters<ApprovalPort['requestApproval']>[0];
type ApprovalDecision = Awaited<ReturnType<ApprovalPort['requestApproval']>>;
type Status = 'PENDING' | 'APPROVED' | 'DECLINED' | 'EXPIRED';

interface ApprovalRow {
  approval_id: string;
  task_id: string;
  plan_hash: string;
  summary: string;
  evidence_refs: string;
  status: Status;
  created_at: string;
  expires_at: string;
}

export interface DurableApprovalView {
  approvalId: string;
  taskId: string;
  planHash: string;
  summary: string;
  evidenceRefs: string[];
  status: Status;
  createdAt: string;
  expiresAt: string;
}

export type ApprovalDecisionResult =
  | { ok: true; decision: ApprovalDecision }
  | { ok: false; code: 'NOT_FOUND' | 'NOT_LIVE' | 'ALREADY_DECIDED' | 'EXPIRED' | 'HASH_MISMATCH' };

export class ShunStoreUiApprovalBridge implements ApprovalPort {
  readonly #store: ShunStore;
  readonly #clock: () => string;
  readonly #ttlMs: number;
  readonly #pending = new Map<
    string,
    {
      resolve: (decision: ApprovalDecision) => void;
      timer: ReturnType<typeof setTimeout>;
      taskId: string;
      planHash: string;
    }
  >();

  constructor(store: ShunStore, options: { clock?: () => string; ttlMs?: number } = {}) {
    this.#store = store;
    this.#clock = options.clock ?? (() => new Date().toISOString());
    this.#ttlMs = options.ttlMs ?? 15 * 60_000;
    if (!Number.isSafeInteger(this.#ttlMs) || this.#ttlMs < 1 || this.#ttlMs > 15 * 60_000) {
      throw new Error('approval lifetime must be bounded to 15 minutes');
    }
    store.database.exec(
      'CREATE TABLE IF NOT EXISTS ui_approval_decisions (' +
        'approval_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, plan_hash TEXT NOT NULL, ' +
        'summary TEXT NOT NULL, evidence_refs TEXT NOT NULL, ' +
        "status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','DECLINED','EXPIRED')), " +
        'created_at TEXT NOT NULL, expires_at TEXT NOT NULL, ' +
        'UNIQUE(task_id, plan_hash))',
    );
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalDecision> {
    const parsed = ApprovalRequestSchema.parse(request);
    const createdAt = this.#clock();
    const now = Date.parse(createdAt);
    if (!Number.isFinite(now)) throw new Error('trusted approval clock is invalid');
    const approvalId = `ui-${randomUUID()}`;
    const expiresAt = new Date(now + this.#ttlMs).toISOString();
    // Unique task+plan and the SQLite transaction prohibit conflicting
    // concurrent approval requests, including from another process.
    this.#transaction(() => {
      this.#store.database
        .prepare(
          'INSERT INTO ui_approval_decisions ' +
            '(approval_id,task_id,plan_hash,summary,evidence_refs,status,created_at,expires_at) ' +
            "VALUES (?,?,?,?,?,'PENDING',?,?)",
        )
        .run(
          approvalId,
          parsed.taskId,
          parsed.planHash,
          parsed.summary,
          JSON.stringify(parsed.evidenceRefs),
          createdAt,
          expiresAt,
        );
    });
    return new Promise<ApprovalDecision>((resolve) => {
      const timer = setTimeout(() => {
        this.#expire(approvalId);
      }, this.#ttlMs);
      this.#pending.set(approvalId, {
        resolve,
        timer,
        taskId: parsed.taskId,
        planHash: parsed.planHash,
      });
    });
  }

  /** Only a live controller wait is actionable. A process-restart orphan is
   * not silently adopted or granted authority by a new UI session. */
  listPending(): DurableApprovalView[] {
    const rows = this.#store.database
      .prepare("SELECT * FROM ui_approval_decisions WHERE status = 'PENDING' ORDER BY created_at")
      .all() as unknown as ApprovalRow[];
    return rows.filter((row) => this.#pending.has(row.approval_id)).map((row) => this.#toView(row));
  }

  get(approvalId: string): DurableApprovalView | null {
    const row = this.#load(approvalId);
    return row ? this.#toView(row) : null;
  }

  decide(input: {
    approvalId: string;
    taskId: string;
    planHash: string;
    approved: boolean;
  }): ApprovalDecisionResult {
    const record = this.#load(input.approvalId);
    if (!record || record.task_id !== input.taskId) return { ok: false, code: 'NOT_FOUND' };
    if (record.plan_hash !== input.planHash) return { ok: false, code: 'HASH_MISMATCH' };
    if (record.status !== 'PENDING') return { ok: false, code: 'ALREADY_DECIDED' };
    // A restarted process cannot mint an approval for an action whose
    // in-flight controller authorization/plan identity disappeared.
    const waiter = this.#pending.get(input.approvalId);
    if (!waiter) return { ok: false, code: 'NOT_LIVE' };
    if (Date.parse(this.#clock()) >= Date.parse(record.expires_at)) {
      this.#expire(input.approvalId);
      return { ok: false, code: 'EXPIRED' };
    }
    const next: Status = input.approved ? 'APPROVED' : 'DECLINED';
    const changed = this.#transaction(() => {
      const result = this.#store.database
        .prepare(
          "UPDATE ui_approval_decisions SET status = ? WHERE approval_id = ? AND status = 'PENDING' " +
            'AND task_id = ? AND plan_hash = ?',
        )
        .run(next, input.approvalId, input.taskId, input.planHash);
      return Number(result.changes) === 1;
    });
    if (!changed) return { ok: false, code: 'ALREADY_DECIDED' };
    clearTimeout(waiter.timer);
    this.#pending.delete(input.approvalId);
    const decision = ApprovalDecisionSchema.parse({
      approvalId: input.approvalId,
      taskId: input.taskId,
      planHash: input.planHash,
      approved: input.approved,
      approvedBy: 'USER_APPROVAL',
    });
    waiter.resolve(decision);
    return { ok: true, decision };
  }

  /** Shutdown is fail-closed: every waiting controller receives denial.
   * The persisted row cannot become an authorization after restart. */
  abortPending(): void {
    for (const approvalId of [...this.#pending.keys()]) this.#expire(approvalId);
  }

  #expire(approvalId: string): void {
    const waiter = this.#pending.get(approvalId);
    if (!waiter) return;

    // Remove the live capability first. Even if durable storage is already
    // closed or faults during shutdown, this approval can no longer be used
    // to resume the controller. A surviving PENDING row is an orphan and any
    // future bridge instance will treat it as NOT_LIVE.
    clearTimeout(waiter.timer);
    this.#pending.delete(approvalId);
    try {
      this.#transaction(() => {
        this.#store.database
          .prepare(
            "UPDATE ui_approval_decisions SET status = 'EXPIRED' WHERE approval_id = ? AND status = 'PENDING'",
          )
          .run(approvalId);
      });
    } catch {
      // Fail closed on shutdown/storage faults: denial resolution must not
      // throw or leave the controller waiter suspended.
    }
    waiter.resolve(
      ApprovalDecisionSchema.parse({
        approvalId,
        taskId: waiter.taskId,
        planHash: waiter.planHash,
        approved: false,
        approvedBy: 'USER_APPROVAL',
      }),
    );
  }

  #load(approvalId: string): ApprovalRow | null {
    const result = this.#store.database
      .prepare('SELECT * FROM ui_approval_decisions WHERE approval_id = ?')
      .get(approvalId) as ApprovalRow | undefined;
    return result ?? null;
  }

  #toView(row: ApprovalRow): DurableApprovalView {
    return {
      approvalId: row.approval_id,
      taskId: row.task_id,
      planHash: row.plan_hash,
      summary: row.summary,
      evidenceRefs: JSON.parse(row.evidence_refs) as string[],
      status: row.status,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
    };
  }

  #transaction<T>(operation: () => T): T {
    this.#store.database.exec('BEGIN IMMEDIATE');
    try {
      const result = operation();
      this.#store.database.exec('COMMIT');
      return result;
    } catch (error) {
      try {
        this.#store.database.exec('ROLLBACK');
      } catch {
        // SQLite may already have rolled back.
      }
      throw error;
    }
  }
}
