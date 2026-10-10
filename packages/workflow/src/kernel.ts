// Bounded WorkflowKernelPort adapter (L2 §5.2/§5.3) — the T03 reference
// realization of "released DomainHarness durable Runtime semantics":
//
//   - durable workflow-instance mechanics in a SQLite runtime store
//     (orchestration ONLY — business authority lives in ShunStore, §5.4);
//   - serialized state transitions over the frozen L2 §5.1 flow;
//   - durable acceptance/disposition of workflow messages with idempotent
//     replay and content-identity conflicts;
//   - effect invocation/recovery mechanics over the idempotent
//     application-effect protocol (stable effectId → intent journal →
//     ShunStore apply → durable receipt);
//   - four-state action recovery with same-actionId resume and
//     reconcile-first for uncertain destructive actions (§9.4).
//
// The kernel owns mechanics only. Goal semantics, registries, trust, policy
// and business records stay outside (§5.3 MUST-NOT-own list).
import { createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync, type StatementSync } from 'node:sqlite';
import {
  canonicalJson,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
  type GoalContract,
  GoalContractSchema,
  type MessageDisposition,
  type RecoveryClassification,
  type RiskClass,
  type ShunStoreMutation,
  type StoreApplicationReceipt,
  type StorePort,
  type TaskState,
  TaskStateSchema,
  type TaskWorkflowState,
  type WorkflowKernelPort,
  type WorkflowMessage,
  WorkflowMessageSchema,
} from '@shun/contracts';
import { ShunStoreEffectConflictError } from '@shun/store';
import {
  KernelActionResolvedError,
  KernelActionUncertainError,
  KernelEffectConflictError,
  KernelEffectUncertainError,
  KernelHandlerFailedError,
  KernelInvalidReceiptError,
  KernelInvalidTransitionError,
  KernelMessageConflictError,
  KernelUnknownTaskError,
  KernelUnresolvedDestructiveActionError,
  WorkflowKernelError,
} from './errors.ts';
import type { WorkflowJournalEvent } from './journal.ts';
import { journaledMutation, WorkflowEffectJournal } from './journal.ts';
import type { ActionRecoveryView, DestructiveReconcileProbe, RecoveryReport } from './recovery.ts';

export type { WorkflowKernelPort };

/** Frozen L2 §5.1 flow. Not an autonomous loop; terminals never exit except NEEDS_INTERVENTION resume.
 *
 * NEEDS_INTERVENTION is reachable from every non-terminal state: the §9.4
 * recovery model may escalate at ANY phase (an uncertain effect discovered at
 * restart, an unresolved destructive action mid-EXECUTING, ...). The §5.1
 * arrows below remain the primary forward flow; the escalation edge is the
 * recovery mechanism, not a new phase. Terminals still never exit.
 */
const ESCALATION_TARGETS: TaskState[] = ['NEEDS_INTERVENTION'];

export const TASK_FLOW_TRANSITIONS: Record<TaskState, TaskState[]> = {
  RECEIVED: ['INTERPRETING', 'CANCELLED', ...ESCALATION_TARGETS],
  INTERPRETING: ['CLARIFICATION', 'RESOLVING', 'FAILED', 'CANCELLED', ...ESCALATION_TARGETS],
  CLARIFICATION: ['INTERPRETING', 'CANCELLED', ...ESCALATION_TARGETS],
  RESOLVING: ['PLANNED', 'FAILED', 'CANCELLED', ...ESCALATION_TARGETS],
  PLANNED: ['AWAITING_AUTHORIZATION', 'EXECUTING', 'FAILED', 'CANCELLED', ...ESCALATION_TARGETS],
  AWAITING_AUTHORIZATION: ['EXECUTING', 'FAILED', 'CANCELLED', ...ESCALATION_TARGETS],
  EXECUTING: [
    'VERIFYING',
    'LIFECYCLE_RECONCILIATION',
    'FAILED',
    'CANCELLED',
    ...ESCALATION_TARGETS,
  ],
  VERIFYING: [
    'LIFECYCLE_RECONCILIATION',
    'SUCCEEDED',
    'FAILED',
    'CANCELLED',
    ...ESCALATION_TARGETS,
  ],
  LIFECYCLE_RECONCILIATION: ['SUCCEEDED', 'FAILED', ...ESCALATION_TARGETS],
  NEEDS_INTERVENTION: ['EXECUTING', 'FAILED', 'CANCELLED'],
  SUCCEEDED: [],
  FAILED: [],
  CANCELLED: [],
};

const TERMINAL_STATES: ReadonlySet<TaskState> = new Set<TaskState>([
  'SUCCEEDED',
  'FAILED',
  'CANCELLED',
]);

const DESTRUCTIVE_RISK: ReadonlySet<RiskClass> = new Set<RiskClass>(['R2', 'R3']);

export type WorkflowMessageHandler = (message: WorkflowMessage) => Promise<void>;

export interface BeginActionSpec {
  actionId: string;
  planHash: string;
  riskClass: RiskClass;
  /** Declared verifiable expected state — required input for reconcile-first (L2 §9.4). */
  expectedState?: unknown;
}

export interface DurableWorkflowKernelOptions {
  /** Directory holding runtime.db and the effect journal (orchestration mechanics only). */
  dataDir: string;
  /** The ShunStore business-authority seam; all business mutations go through it idempotently. */
  store: StorePort;
}

interface InstanceRow {
  task_id: string;
  goal_json: string;
  state: string;
  revision: number;
}

interface MessageRow {
  task_id: string;
  message_id: string;
  kind: string;
  payload_json: string;
  payload_hash: string;
  disposition_json: string;
  processed_at: string | null;
}

export class DurableWorkflowKernel implements WorkflowKernelPort {
  /** Exposed for store-separation tests (runtime.db holds mechanics tables only). */
  readonly database: DatabaseSync;

  private readonly store: StorePort;
  private readonly journal: WorkflowEffectJournal;
  private readonly handlers = new Map<string, WorkflowMessageHandler>();
  private readonly subscribers = new Map<string, Set<(state: TaskWorkflowState) => void>>();
  private readonly locks = new Map<string, Promise<unknown>>();
  private readonly lockDepth = new Map<string, number>();
  private closed = false;

  private readonly statements: {
    insertInstance: StatementSync;
    findInstance: StatementSync;
    updateInstance: StatementSync;
    insertMessage: StatementSync;
    findMessage: StatementSync;
    markMessageProcessed: StatementSync;
    listPendingMessages: StatementSync;
  };

  constructor(options: DurableWorkflowKernelOptions) {
    mkdirSync(options.dataDir, { recursive: true });
    this.store = options.store;
    this.journal = new WorkflowEffectJournal({
      file: join(options.dataDir, 'effect-journal.jsonl'),
    });
    this.database = new DatabaseSync(join(options.dataDir, 'runtime.db'));
    this.database.exec('PRAGMA journal_mode = WAL');
    this.database.exec('PRAGMA synchronous = FULL');
    this.database.exec('PRAGMA busy_timeout = 5000');
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS instances (
        task_id    TEXT PRIMARY KEY,
        goal_json  TEXT NOT NULL,
        state      TEXT NOT NULL,
        revision   INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS messages (
        task_id          TEXT NOT NULL,
        message_id       TEXT NOT NULL,
        kind             TEXT NOT NULL,
        payload_json     TEXT NOT NULL,
        payload_hash     TEXT NOT NULL,
        disposition_json TEXT NOT NULL,
        received_at      TEXT NOT NULL,
        processed_at     TEXT,
        PRIMARY KEY (task_id, message_id)
      )
    `);

    this.statements = {
      insertInstance: this.database.prepare(
        'INSERT INTO instances (task_id, goal_json, state, revision, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)',
      ),
      findInstance: this.database.prepare(
        'SELECT task_id, goal_json, state, revision FROM instances WHERE task_id = ?',
      ),
      updateInstance: this.database.prepare(
        'UPDATE instances SET state = ?, revision = ?, updated_at = ? WHERE task_id = ?',
      ),
      insertMessage: this.database.prepare(
        'INSERT INTO messages (task_id, message_id, kind, payload_json, payload_hash, disposition_json, received_at, processed_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)',
      ),
      findMessage: this.database.prepare(
        'SELECT task_id, message_id, kind, payload_json, payload_hash, disposition_json, processed_at FROM messages WHERE task_id = ? AND message_id = ?',
      ),
      markMessageProcessed: this.database.prepare(
        'UPDATE messages SET processed_at = ? WHERE task_id = ? AND message_id = ?',
      ),
      listPendingMessages: this.database.prepare(
        'SELECT task_id, message_id, kind, payload_json, payload_hash, disposition_json, processed_at FROM messages WHERE task_id = ? AND processed_at IS NULL ORDER BY received_at ASC, rowid ASC',
      ),
    };
  }

  // ---- Port: open / query / subscribe / recover (L2 §5.2). ----

  async open(task: { taskId: string; goal: GoalContract }): Promise<string> {
    const goal = parseGoal(task.goal);
    return this.withLock(task.taskId, () => this.openLocked(task.taskId, goal));
  }

  async query(taskId: string): Promise<TaskWorkflowState> {
    this.assertOpen();
    return this.toState(this.requireInstance(taskId));
  }

  subscribe(taskId: string, callback: (state: TaskWorkflowState) => void): () => void {
    this.assertOpen();
    const current = this.toState(this.requireInstance(taskId));
    let set = this.subscribers.get(taskId);
    if (!set) {
      set = new Set();
      this.subscribers.set(taskId, set);
    }
    set.add(callback);
    callback(current);
    return () => {
      this.subscribers.get(taskId)?.delete(callback);
    };
  }

  async recover(taskId: string): Promise<TaskWorkflowState> {
    this.assertOpen();
    return this.withLock(taskId, async () => {
      const report = await this.reconcileLocked(taskId, {});
      return report.state;
    });
  }

  // ---- Port: send — durable acceptance/disposition of workflow messages. ----

  async send(message: WorkflowMessage): Promise<MessageDisposition> {
    const parsed = WorkflowMessageSchema.safeParse(message);
    if (!parsed.success) {
      throw new WorkflowKernelError('KERNEL_INVALID_MESSAGE', 'invalid workflow message', {
        cause: parsed.error,
      });
    }
    const valid = parsed.data;
    return this.withLock(valid.taskId, () => this.sendLocked(valid));
  }

  async pendingMessages(taskId: string): Promise<Array<{ messageId: string; kind: string }>> {
    this.assertOpen();
    this.requireInstance(taskId);
    return this.listPendingMessages(taskId).map((row) => ({
      messageId: row.message_id,
      kind: row.kind,
    }));
  }

  /** Re-dispatch durably-accepted messages whose handler did not complete. */
  async redeliverPending(taskId: string): Promise<{
    redeliveredMessageIds: string[];
    failedMessageIds: string[];
  }> {
    this.assertOpen();
    return this.withLock(taskId, async () => this.redeliverPendingLocked(taskId));
  }

  registerHandler(kind: string, handler: WorkflowMessageHandler): void {
    this.assertOpen();
    this.handlers.set(kind, handler);
  }

  // ---- Serialized state transitions (mechanics owned by the kernel, §5.3). ----

  async transition(taskId: string, to: TaskState, reason?: string): Promise<TaskWorkflowState> {
    this.assertOpen();
    return this.withLock(taskId, () => this.transitionLocked(taskId, to, reason));
  }

  // ---- Idempotent application-effect protocol (L2 §5.4). ----

  async applyStoreEffect(
    taskId: string,
    effectId: string,
    mutation: ShunStoreMutation,
  ): Promise<StoreApplicationReceipt> {
    this.assertOpen();
    return this.withLock(taskId, () => this.applyStoreEffectLocked(taskId, effectId, mutation));
  }

  // ---- Durable actionId registry and journaled dispatch (§9.4). ----

  async beginAction(taskId: string, spec: BeginActionSpec): Promise<void> {
    this.assertOpen();
    await this.withLock(taskId, () => this.beginActionLocked(taskId, spec));
  }

  async dispatchAction(
    taskId: string,
    actionId: string,
    exec: () => Promise<ExecutionReceipt>,
  ): Promise<ExecutionReceipt> {
    this.assertOpen();
    return this.withLock(taskId, () => this.dispatchActionLocked(taskId, actionId, exec));
  }

  async listActionRecoveries(taskId: string): Promise<ActionRecoveryView[]> {
    this.assertOpen();
    this.requireInstance(taskId);
    return this.deriveActionRecoveries(taskId);
  }

  // ---- Four-state reconciliation driver (L2 §9.4). ----

  async reconcile(
    taskId: string,
    options?: { destructiveProbe?: DestructiveReconcileProbe },
  ): Promise<RecoveryReport> {
    this.assertOpen();
    return this.withLock(taskId, () => this.reconcileLocked(taskId, options ?? {}));
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.journal.close();
    this.database.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    this.database.close();
  }

  // ---- internals — every *Locked function runs under the task lock. ----

  private async openLocked(taskId: string, goal: GoalContract): Promise<string> {
    const existing = this.findInstance(taskId);
    if (existing) {
      if (canonicalJson(JSON.parse(existing.goal_json) as GoalContract) !== canonicalJson(goal)) {
        throw new WorkflowKernelError(
          'KERNEL_CONFLICT',
          `task ${taskId} already exists with a different goal contract`,
        );
      }
      return taskId;
    }
    const now = new Date().toISOString();
    this.statements.insertInstance.run(taskId, canonicalJson(goal), 'RECEIVED', now, now);
    return taskId;
  }

  private async sendLocked(message: WorkflowMessage): Promise<MessageDisposition> {
    this.requireInstance(message.taskId);
    const payloadHash = sha256Identity(message.kind, message.payload);

    const existing = this.statements.findMessage.get(message.taskId, message.messageId) as
      | MessageRow
      | undefined;
    if (existing) {
      if (existing.kind !== message.kind || existing.payload_hash !== payloadHash) {
        throw new KernelMessageConflictError(message.messageId, message.taskId);
      }
      return JSON.parse(existing.disposition_json) as MessageDisposition;
    }

    const disposition: MessageDisposition = { accepted: true };
    this.statements.insertMessage.run(
      message.taskId,
      message.messageId,
      message.kind,
      canonicalJson(message.payload),
      payloadHash,
      JSON.stringify(disposition),
      new Date().toISOString(),
    );

    await this.deliverMessage(message);
    return disposition;
  }

  /**
   * Handler dispatch. Acceptance is durable and already recorded; a failing
   * handler leaves the message pending for redelivery — it does NOT revoke
   * the acceptance disposition. Handlers must route every business mutation
   * through applyStoreEffect (stable effectId) so redelivery stays idempotent.
   */
  private async deliverMessage(message: WorkflowMessage): Promise<void> {
    const handler = this.handlers.get(message.kind);
    if (!handler) {
      return;
    }
    try {
      await handler(message);
    } catch (error) {
      throw new KernelHandlerFailedError(message.messageId, { cause: error });
    }
    this.statements.markMessageProcessed.run(
      new Date().toISOString(),
      message.taskId,
      message.messageId,
    );
  }

  private async redeliverPendingLocked(taskId: string): Promise<{
    redeliveredMessageIds: string[];
    failedMessageIds: string[];
  }> {
    const redeliveredMessageIds: string[] = [];
    const failedMessageIds: string[] = [];
    for (const row of this.listPendingMessages(taskId)) {
      const message: WorkflowMessage = {
        messageId: row.message_id,
        taskId: row.task_id,
        kind: row.kind,
        payload: JSON.parse(row.payload_json) as unknown,
      };
      try {
        await this.deliverMessage(message);
        redeliveredMessageIds.push(row.message_id);
      } catch {
        failedMessageIds.push(row.message_id);
      }
    }
    return { redeliveredMessageIds, failedMessageIds };
  }

  private async transitionLocked(
    taskId: string,
    to: TaskState,
    reason?: string,
  ): Promise<TaskWorkflowState> {
    const instance = this.requireInstance(taskId);
    const target = TaskStateSchema.safeParse(to);
    if (!target.success) {
      throw new KernelInvalidTransitionError(taskId, instance.state, String(to));
    }
    const allowed = TASK_FLOW_TRANSITIONS[instance.state as TaskState] ?? [];
    if (!allowed.includes(target.data)) {
      throw new KernelInvalidTransitionError(taskId, instance.state, target.data);
    }
    const revision = instance.revision + 1;
    this.statements.updateInstance.run(target.data, revision, new Date().toISOString(), taskId);
    void reason;
    const next: TaskWorkflowState = { taskId, state: target.data, revision };
    this.notify(next);
    return next;
  }

  private async beginActionLocked(taskId: string, spec: BeginActionSpec): Promise<void> {
    this.requireInstance(taskId);
    if (spec.actionId.length < 1 || spec.planHash.length < 1) {
      throw new WorkflowKernelError(
        'KERNEL_INVALID_MESSAGE',
        'actionId/planHash must be non-empty',
      );
    }
    const recoveries = this.deriveActionRecoveries(taskId);
    const blocking = recoveries.find(
      (recovery) =>
        recovery.actionId !== spec.actionId &&
        !recovery.resolved &&
        DESTRUCTIVE_RISK.has(recovery.riskClass),
    );
    if (blocking) {
      throw new KernelUnresolvedDestructiveActionError(blocking.actionId);
    }

    const existing = recoveries.find((recovery) => recovery.actionId === spec.actionId);
    if (existing) {
      if (existing.resolved && existing.classification === 'COMPLETED_VERIFIED') {
        throw new KernelActionResolvedError(spec.actionId);
      }
      if (existing.planHash !== spec.planHash || existing.riskClass !== spec.riskClass) {
        throw new WorkflowKernelError(
          'KERNEL_CONFLICT',
          `action ${spec.actionId} identity mismatch: journal has planHash=${existing.planHash} riskClass=${existing.riskClass}`,
        );
      }
      // Same identity re-registration = same-actionId resume preparation (§9.4).
      return;
    }

    this.journal.append({
      kind: 'ACTION_INTENT',
      taskId,
      actionId: spec.actionId,
      payload: {
        planHash: spec.planHash,
        riskClass: spec.riskClass,
        expectedState: spec.expectedState,
      },
    });
  }

  private async applyStoreEffectLocked(
    taskId: string,
    effectId: string,
    mutation: ShunStoreMutation,
  ): Promise<StoreApplicationReceipt> {
    this.requireInstance(taskId);
    const intent = this.journal.events.find(
      (event) =>
        event.kind === 'EFFECT_INTENT' && event.taskId === taskId && event.effectId === effectId,
    );
    if (intent) {
      if (canonicalJson(journaledMutation(intent)) !== canonicalJson(mutation)) {
        throw new KernelEffectConflictError(
          effectId,
          new Error('presented mutation differs from the journaled intent'),
        );
      }
    } else {
      this.journal.append({
        kind: 'EFFECT_INTENT',
        taskId,
        effectId,
        payload: { mutation },
      });
    }

    let receipt: StoreApplicationReceipt;
    try {
      receipt = await this.store.apply(effectId, mutation);
    } catch (error) {
      // Nothing is assumed committed: the application outcome is uncertain
      // until the journal is reconciled against ShunStore truth (L2 §5.4).
      const conflict = error instanceof ShunStoreEffectConflictError;
      this.journal.append({
        kind: 'EFFECT_UNCERTAIN',
        taskId,
        effectId,
        payload: { error: describeError(error), conflict },
      });
      throw conflict
        ? new KernelEffectConflictError(effectId, { cause: error })
        : new KernelEffectUncertainError(effectId, { cause: error });
    }

    this.journal.append({
      kind: 'EFFECT_RECORDED',
      taskId,
      effectId,
      payload: { applied: receipt.applied, receiptRef: receipt.receiptRef },
    });
    return receipt;
  }

  private async dispatchActionLocked(
    taskId: string,
    actionId: string,
    exec: () => Promise<ExecutionReceipt>,
  ): Promise<ExecutionReceipt> {
    this.requireInstance(taskId);
    const recovery = this.deriveActionRecoveries(taskId).find((view) => view.actionId === actionId);
    if (!recovery) {
      throw new WorkflowKernelError(
        'KERNEL_UNKNOWN_ACTION',
        `action ${actionId} was never registered`,
      );
    }
    if (recovery.resolved && recovery.classification === 'COMPLETED_VERIFIED') {
      throw new KernelActionResolvedError(actionId);
    }

    // EXEC_START analog: from this journaled point the action may have executed.
    this.journal.append({ kind: 'ACTION_DISPATCHED', taskId, actionId, payload: {} });
    let receipt: ExecutionReceipt;
    try {
      const produced = await exec();
      const parsed = ExecutionReceiptSchema.safeParse(produced);
      if (!parsed.success) {
        throw new KernelInvalidReceiptError(actionId, { cause: parsed.error });
      }
      if (parsed.data.actionId !== actionId) {
        // Stable identity rule: a receipt for another actionId never closes this one.
        throw new KernelInvalidReceiptError(
          actionId,
          new Error(`receipt carries foreign actionId ${parsed.data.actionId}`),
        );
      }
      receipt = parsed.data;
    } catch (error) {
      this.journal.append({
        kind: 'ACTION_UNCERTAIN',
        taskId,
        actionId,
        payload: { error: describeError(error) },
      });
      throw new KernelActionUncertainError(actionId, { cause: error });
    }

    this.journal.append({
      kind: 'ACTION_RECEIPTED',
      taskId,
      actionId,
      payload: { receipt },
    });
    return receipt;
  }

  private async reconcileLocked(
    taskId: string,
    options: { destructiveProbe?: DestructiveReconcileProbe },
  ): Promise<RecoveryReport> {
    const instance = this.requireInstance(taskId);
    const resolvedEffectIds: string[] = [];
    const unresolvedEffectIds: string[] = [];
    const interventions: string[] = [];

    // 1. Store effects: reconcile from the journal by re-driving the SAME
    //    effectId through the idempotent protocol (L2 §5.4).
    const intentEffects = new Map<string, WorkflowJournalEvent>();
    const recordedEffects = new Set<string>();
    for (const event of this.journal.events) {
      if (event.taskId !== taskId || !event.effectId) {
        continue;
      }
      if (event.kind === 'EFFECT_INTENT') {
        intentEffects.set(event.effectId, event);
      } else if (event.kind === 'EFFECT_RECORDED') {
        recordedEffects.add(event.effectId);
      }
    }
    for (const [effectId, intent] of intentEffects) {
      if (recordedEffects.has(effectId)) {
        continue;
      }
      try {
        await this.applyStoreEffectLocked(taskId, effectId, journaledMutation(intent));
        resolvedEffectIds.push(effectId);
      } catch (error) {
        unresolvedEffectIds.push(effectId);
        interventions.push(
          error instanceof KernelEffectConflictError
            ? `effect ${effectId} identity conflict against ShunStore authority`
            : `effect ${effectId} remains uncertain: ${describeError(error)}`,
        );
      }
    }

    // 2. Actions: reconcile-first for anything MAY_HAVE_EXECUTED_UNCERTAIN —
    //    declared post-state verification before any retry (L2 §9.4).
    const probe = options.destructiveProbe;
    if (probe) {
      for (const recovery of this.deriveActionRecoveries(taskId)) {
        if (recovery.resolved || recovery.classification !== 'MAY_HAVE_EXECUTED_UNCERTAIN') {
          continue;
        }
        let verdict: Awaited<ReturnType<DestructiveReconcileProbe['verifyExpectedState']>>;
        try {
          verdict = await probe.verifyExpectedState({
            taskId,
            actionId: recovery.actionId,
            planHash: recovery.planHash,
            riskClass: recovery.riskClass,
            expectedState: recovery.expectedState,
          });
        } catch (error) {
          interventions.push(`action ${recovery.actionId} probe failed: ${describeError(error)}`);
          continue;
        }
        if (verdict.outcome === 'UNKNOWN') {
          continue;
        }
        this.journal.append({
          kind: 'ACTION_RECONCILED',
          taskId,
          actionId: recovery.actionId,
          payload: {
            classification:
              verdict.outcome === 'CONFIRMED_EXECUTED'
                ? 'COMPLETED_VERIFIED'
                : 'FAILED_BEFORE_EFFECT',
            evidence: verdict.evidence,
          },
        });
      }
    }

    const actionRecoveries = this.deriveActionRecoveries(taskId);
    const unresolvedActionIds = actionRecoveries
      .filter(
        (recovery) =>
          !recovery.resolved && recovery.classification === 'MAY_HAVE_EXECUTED_UNCERTAIN',
      )
      .map((recovery) => recovery.actionId);
    for (const recovery of actionRecoveries) {
      if (
        !recovery.resolved &&
        recovery.classification === 'MAY_HAVE_EXECUTED_UNCERTAIN' &&
        DESTRUCTIVE_RISK.has(recovery.riskClass)
      ) {
        interventions.push(
          `destructive action ${recovery.actionId} is MAY_HAVE_EXECUTED_UNCERTAIN; reconcile-first required, no blind retry`,
        );
      }
    }

    // 3. Redeliver durably-accepted messages whose handler did not complete.
    const delivery = await this.redeliverPendingLocked(taskId);

    // 4. Escalate when anything remains uncommitted — never treated as done.
    const mustEscalate =
      (unresolvedEffectIds.length > 0 ||
        unresolvedActionIds.some((id) => this.isDestructive(taskId, id))) &&
      !TERMINAL_STATES.has(instance.state as TaskState) &&
      instance.state !== 'NEEDS_INTERVENTION';
    let state = this.toState(this.requireInstance(taskId));
    if (mustEscalate) {
      state = await this.transitionLocked(taskId, 'NEEDS_INTERVENTION');
    }

    return {
      taskId,
      state,
      actionRecoveries,
      resolvedEffectIds,
      unresolvedEffectIds,
      unresolvedActionIds,
      interventionReason: interventions.length > 0 ? interventions.join('; ') : undefined,
      redeliveredMessageIds: delivery.redeliveredMessageIds,
      failedMessageIds: delivery.failedMessageIds,
    };
  }

  private deriveActionRecoveries(taskId: string): ActionRecoveryView[] {
    const byAction = new Map<string, WorkflowJournalEvent[]>();
    for (const event of this.journal.events) {
      if (event.taskId !== taskId || !event.actionId) {
        continue;
      }
      const list = byAction.get(event.actionId) ?? [];
      list.push(event);
      byAction.set(event.actionId, list);
    }

    const views: ActionRecoveryView[] = [];
    for (const [actionId, events] of byAction) {
      const intent = events.find((event) => event.kind === 'ACTION_INTENT');
      if (!intent) {
        continue;
      }
      const spec = intent.payload as {
        planHash: string;
        riskClass: RiskClass;
        expectedState?: unknown;
      };
      const base = {
        actionId,
        taskId,
        planHash: spec.planHash,
        riskClass: spec.riskClass,
        expectedState: spec.expectedState,
      };

      const receipted = [...events].reverse().find((event) => event.kind === 'ACTION_RECEIPTED');
      const reconciled = [...events].reverse().find((event) => event.kind === 'ACTION_RECONCILED');
      const dispatched = events.some((event) => event.kind === 'ACTION_DISPATCHED');

      if (receipted) {
        views.push({
          ...base,
          classification: 'COMPLETED_VERIFIED',
          resolved: true,
          canResume: false,
          receipt: (receipted.payload as { receipt: ExecutionReceipt }).receipt,
        });
        continue;
      }
      if (reconciled) {
        const classification = (reconciled.payload as { classification: RecoveryClassification })
          .classification;
        views.push({
          ...base,
          classification,
          resolved: true,
          canResume: classification === 'FAILED_BEFORE_EFFECT',
          receipt: null,
        });
        continue;
      }
      if (dispatched) {
        views.push({
          ...base,
          classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
          resolved: false,
          canResume: false,
          receipt: null,
        });
        continue;
      }
      // Intent journaled, dispatch never started: provably safe on the SAME actionId.
      views.push({
        ...base,
        classification: 'NOT_STARTED',
        resolved: true,
        canResume: true,
        receipt: null,
      });
    }
    return views;
  }

  // ---- helpers. ----

  private isDestructive(taskId: string, actionId: string): boolean {
    const recovery = this.deriveActionRecoveries(taskId).find((view) => view.actionId === actionId);
    return recovery ? DESTRUCTIVE_RISK.has(recovery.riskClass) : false;
  }

  /**
   * Per-task serialized execution. Re-entrant: a nested withLock call made
   * from inside the locked flow (e.g. a message handler calling
   * transition/applyStoreEffect) joins the current holder instead of
   * deadlocking on the queue.
   */
  private withLock<T>(taskId: string, fn: () => Promise<T> | T): Promise<T> {
    if ((this.lockDepth.get(taskId) ?? 0) > 0) {
      return Promise.resolve(fn());
    }
    const previous = this.locks.get(taskId) ?? Promise.resolve();
    const run = async (): Promise<T> => {
      this.lockDepth.set(taskId, (this.lockDepth.get(taskId) ?? 0) + 1);
      try {
        return await fn();
      } finally {
        const depth = (this.lockDepth.get(taskId) ?? 1) - 1;
        if (depth <= 0) {
          this.lockDepth.delete(taskId);
        } else {
          this.lockDepth.set(taskId, depth);
        }
      }
    };
    const next = previous.then(run, run);
    this.locks.set(
      taskId,
      next.catch(() => undefined),
    );
    return next;
  }

  private notify(state: TaskWorkflowState): void {
    for (const callback of this.subscribers.get(state.taskId) ?? []) {
      callback(state);
    }
  }

  private findInstance(taskId: string): InstanceRow | undefined {
    return this.statements.findInstance.get(taskId) as InstanceRow | undefined;
  }

  private requireInstance(taskId: string): InstanceRow {
    const row = this.findInstance(taskId);
    if (!row) {
      throw new KernelUnknownTaskError(taskId);
    }
    return row;
  }

  private toState(row: InstanceRow): TaskWorkflowState {
    return { taskId: row.task_id, state: TaskStateSchema.parse(row.state), revision: row.revision };
  }

  private listPendingMessages(taskId: string): MessageRow[] {
    return this.statements.listPendingMessages.all(taskId) as unknown as MessageRow[];
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new WorkflowKernelError('KERNEL_CLOSED', 'workflow kernel is closed');
    }
  }
}

function parseGoal(goal: GoalContract): GoalContract {
  const parsed = GoalContractSchema.safeParse(goal);
  if (!parsed.success) {
    throw new WorkflowKernelError('KERNEL_INVALID_MESSAGE', 'invalid goal contract', {
      cause: parsed.error,
    });
  }
  return parsed.data;
}

function sha256Identity(kind: string, payload: unknown): string {
  return createHash('sha256').update(canonicalJson({ kind, payload }), 'utf8').digest('hex');
}

function describeError(error: unknown): string {
  if (error instanceof Error) {
    return `${error.name}: ${error.message}`;
  }
  return String(error);
}
