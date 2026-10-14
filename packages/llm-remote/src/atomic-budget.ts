// T01 first bounded slice: trusted-host durable cloud call/price ledger.
// It NEVER calls HTTP, mints a consent grant, validates a physical user gesture,
// or refunds an ambiguous send. T08 must supply real private-broker authority.
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  type CloudConsentApproval,
  type CloudConsentCurrentness,
  canonicalJson,
  validateCloudConsent,
} from '@shun/contracts';

export type CloudLedgerRefusal =
  | 'CONSENT_REFUSED'
  | 'CONSENT_EXPIRED'
  | 'CONSENT_STALE'
  | 'DISCLOSURE_SCOPE_DRIFT'
  | 'PRICING_REVISION_STALE'
  | 'BUDGET_EXHAUSTED'
  | 'IDEMPOTENCY_REPLAY'
  | 'LEDGER_UNAVAILABLE';

export type LedgerResult =
  | { ok: true; attemptId: string; requestBytesSha256: string; reservedCostMicros: number }
  | { ok: false; code: CloudLedgerRefusal };

export type TrustedPricing = Readonly<{
  revision: string;
  inputMicrosPerToken: number;
  outputMicrosPerToken: number;
}>;

export type ReserveCloudAttempt = Readonly<{
  approval: unknown;
  currentness: CloudConsentCurrentness;
  now: string;
  /** Unique stable attempt identity, including after host crash. */
  attemptId: string;
  /** Exact outbound request body bytes, NOT an inferred/sanitized representation. */
  requestBytes: Uint8Array;
  /** Exact approved display/disclosure projection. */
  disclosureProjectionBytes: Uint8Array;
  outputTokenCeiling: number;
}>;

export type CloudAttemptStatus = 'RESERVED' | 'MAY_HAVE_SENT' | 'UNKNOWN_COST' | 'SETTLED';

type AttemptRow = {
  attempt_id: string;
  consent_id: string;
  request_sha256: string;
  status: CloudAttemptStatus;
  cost_micros: number;
};

const SHA64 = /^[a-f0-9]{64}$/;
function digest(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Constructor arguments MUST be wired by Shun's trusted backend, never copied
 * from an external API/UI/Planner/Recipe request. Schema presence is not proof
 * of an authenticated interactive broker; the injected verifier is that port.
 */
export class DurableCloudBudgetLedger {
  private readonly db: DatabaseSync;
  private readonly verifyBroker: (approval: CloudConsentApproval) => boolean;
  private readonly pricing: TrustedPricing;

  constructor(options: {
    file: string;
    verifyBroker: (approval: CloudConsentApproval) => boolean;
    pricing: TrustedPricing;
  }) {
    if (
      !options.file ||
      typeof options.verifyBroker !== 'function' ||
      !options.pricing.revision ||
      !Number.isSafeInteger(options.pricing.inputMicrosPerToken) ||
      !Number.isSafeInteger(options.pricing.outputMicrosPerToken) ||
      options.pricing.inputMicrosPerToken <= 0 ||
      options.pricing.outputMicrosPerToken <= 0
    )
      throw new Error('LEDGER_CONFIGURATION_REFUSED');
    this.pricing = Object.freeze({ ...options.pricing });
    this.verifyBroker = options.verifyBroker;
    this.db = new DatabaseSync(options.file);
    this.db.exec('PRAGMA journal_mode=WAL');
    this.db.exec('PRAGMA synchronous=FULL');
    this.db.exec('PRAGMA busy_timeout=5000');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS v02_cloud_attempts (
        attempt_id TEXT PRIMARY KEY,
        consent_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        scope_revision TEXT NOT NULL,
        scope_sha256 TEXT NOT NULL,
        pricing_revision TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        projection_sha256 TEXT NOT NULL,
        cost_micros INTEGER NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS v02_cloud_attempt_consent
        ON v02_cloud_attempts(consent_id);
    `);
  }

  /**
   * Fail closed before any network attempt. Reserve at most maxCalls slots and
   * worst-case cost in ONE SQLite transaction. Conservative estimation: UTF-8
   * request bytes bound input tokens, which cannot exceed byte count for a
   * byte-aligned tokenizer; excess bytes simply reject safe requests.
   */
  reserve(input: ReserveCloudAttempt): LedgerResult {
    let requested: ReturnType<typeof validateCloudConsent>;
    try {
      requested = validateCloudConsent({
        approval: input.approval,
        currentness: input.currentness,
        now: input.now,
        verifyBroker: this.verifyBroker,
      });
    } catch {
      return { ok: false, code: 'CONSENT_REFUSED' };
    }
    if (!requested.ok) return { ok: false, code: requested.code };
    const { scope, consentId } = requested.consent;
    const scopeSha256 = digest(Buffer.from(canonicalJson(scope), 'utf8'));
    if (input.currentness.kind !== 'CURRENT' || this.pricing.revision !== scope.pricingRevision)
      return { ok: false, code: 'PRICING_REVISION_STALE' };
    if (
      typeof input.attemptId !== 'string' ||
      input.attemptId.length < 1 ||
      input.attemptId.length > 256 ||
      !Number.isSafeInteger(input.outputTokenCeiling) ||
      input.outputTokenCeiling < 1 ||
      input.outputTokenCeiling > scope.maxOutputTokens ||
      !(input.requestBytes instanceof Uint8Array) ||
      !(input.disclosureProjectionBytes instanceof Uint8Array)
    )
      return { ok: false, code: 'BUDGET_EXHAUSTED' };
    let requestHash: string;
    let projectionHash: string;
    try {
      requestHash = digest(input.requestBytes);
      projectionHash = digest(input.disclosureProjectionBytes);
    } catch {
      return { ok: false, code: 'DISCLOSURE_SCOPE_DRIFT' };
    }
    if (!SHA64.test(projectionHash) || projectionHash !== scope.approvedProjectionSha256) {
      return { ok: false, code: 'DISCLOSURE_SCOPE_DRIFT' };
    }
    const conservativeInputTokens = input.requestBytes.byteLength;
    if (conservativeInputTokens < 1 || conservativeInputTokens > scope.maxInputTokens)
      return { ok: false, code: 'BUDGET_EXHAUSTED' };
    const maxCost =
      BigInt(conservativeInputTokens) * BigInt(this.pricing.inputMicrosPerToken) +
      BigInt(input.outputTokenCeiling) * BigInt(this.pricing.outputMicrosPerToken);
    if (maxCost > BigInt(scope.maxCostMicros) || maxCost > BigInt(Number.MAX_SAFE_INTEGER)) {
      return { ok: false, code: 'BUDGET_EXHAUSTED' };
    }
    try {
      this.db.exec('BEGIN IMMEDIATE');
      const prior = this.db
        .prepare('SELECT attempt_id FROM v02_cloud_attempts WHERE attempt_id = ?')
        .get(input.attemptId);
      if (prior) {
        this.db.exec('ROLLBACK');
        return { ok: false, code: 'IDEMPOTENCY_REPLAY' };
      }
      const tally = this.db
        .prepare(
          'SELECT COUNT(*) AS calls, COALESCE(SUM(cost_micros), 0) AS cost FROM v02_cloud_attempts WHERE consent_id = ?',
        )
        .get(consentId) as { calls: number; cost: number };
      if (
        tally.calls >= scope.maxCalls ||
        BigInt(tally.cost) + maxCost > BigInt(scope.maxCostMicros)
      ) {
        this.db.exec('ROLLBACK');
        return { ok: false, code: 'BUDGET_EXHAUSTED' };
      }
      // Scope identity is frozen for a consentId at first reservation.
      const priorScope = this.db
        .prepare(
          'SELECT task_id, scope_revision, scope_sha256, pricing_revision FROM v02_cloud_attempts WHERE consent_id = ? LIMIT 1',
        )
        .get(consentId) as
        | {
            task_id: string;
            scope_revision: string;
            scope_sha256: string;
            pricing_revision: string;
          }
        | undefined;
      if (
        priorScope &&
        (priorScope.task_id !== scope.taskId ||
          priorScope.scope_revision !== scope.scopeRevision ||
          priorScope.scope_sha256 !== scopeSha256 ||
          priorScope.pricing_revision !== scope.pricingRevision)
      ) {
        this.db.exec('ROLLBACK');
        return { ok: false, code: 'CONSENT_STALE' };
      }
      this.db
        .prepare(`
        INSERT INTO v02_cloud_attempts
        (attempt_id, consent_id, task_id, scope_revision, scope_sha256, pricing_revision,
         request_sha256, projection_sha256, cost_micros, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?)
      `)
        .run(
          input.attemptId,
          consentId,
          scope.taskId,
          scope.scopeRevision,
          scopeSha256,
          scope.pricingRevision,
          requestHash,
          projectionHash,
          Number(maxCost),
          input.now,
        );
      this.db.exec('COMMIT');
      return {
        ok: true,
        attemptId: input.attemptId,
        requestBytesSha256: requestHash,
        reservedCostMicros: Number(maxCost),
      };
    } catch {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        /* transaction may have ended */
      }
      return { ok: false, code: 'LEDGER_UNAVAILABLE' };
    }
  }

  /**
   * Final mandatory freshness and payload check at the exact send boundary.
   * The trusted broker/source of currentness is rechecked AFTER reservation,
   * so revocation/expiry between reservation and HTTP cannot authorize send.
   * Commit MAY_HAVE_SENT *before* the network operation begins.
   */
  markMayHaveSent(input: {
    attemptId: string;
    actualRequestBytes: Uint8Array;
    approval: unknown;
    currentness: CloudConsentCurrentness;
    now: string;
  }): boolean {
    if (!input.attemptId || !(input.actualRequestBytes instanceof Uint8Array)) return false;
    let verdict: ReturnType<typeof validateCloudConsent>;
    try {
      verdict = validateCloudConsent({
        approval: input.approval,
        currentness: input.currentness,
        now: input.now,
        verifyBroker: this.verifyBroker,
      });
    } catch {
      return false;
    }
    if (!verdict.ok || verdict.consent.scope.pricingRevision !== this.pricing.revision) {
      return false;
    }
    const { scope, consentId } = verdict.consent;
    const scopeHash = digest(Buffer.from(canonicalJson(scope), 'utf8'));
    try {
      this.db.exec('BEGIN IMMEDIATE');
      const row = this.db
        .prepare(
          `SELECT consent_id, task_id, scope_revision, scope_sha256,
          pricing_revision, request_sha256, status
          FROM v02_cloud_attempts WHERE attempt_id = ?`,
        )
        .get(input.attemptId) as
        | {
            consent_id: string;
            task_id: string;
            scope_revision: string;
            scope_sha256: string;
            pricing_revision: string;
            request_sha256: string;
            status: CloudAttemptStatus;
          }
        | undefined;
      if (
        row?.status !== 'RESERVED' ||
        row.consent_id !== consentId ||
        row.task_id !== scope.taskId ||
        row.scope_revision !== scope.scopeRevision ||
        row.scope_sha256 !== scopeHash ||
        row.pricing_revision !== scope.pricingRevision ||
        digest(input.actualRequestBytes) !== row.request_sha256
      ) {
        this.db.exec('ROLLBACK');
        return false;
      }
      this.db.prepare(
        "UPDATE v02_cloud_attempts SET status = 'MAY_HAVE_SENT' WHERE attempt_id = ?",
      ).run(input.attemptId);
      this.db.exec('COMMIT');
      return true;
    } catch {
      try { this.db.exec('ROLLBACK'); } catch { /* no active txn */ }
      return false;
    }
  }

  /** Nonterminal ambiguous send cannot refund or retry; record as UNKNOWN_COST. */
  markUnknownCost(attemptId: string): boolean {
    try {
      const result = this.db.prepare(
        "UPDATE v02_cloud_attempts SET status = 'UNKNOWN_COST' WHERE attempt_id = ? AND status = 'MAY_HAVE_SENT'",
      ).run(attemptId);
      return Number(result.changes) === 1;
    } catch {
      return false;
    }
  }

  inspect(attemptId: string): Readonly<AttemptRow> | null {
    try {
      const row = this.db.prepare(`
        SELECT attempt_id, consent_id, request_sha256, status, cost_micros
        FROM v02_cloud_attempts WHERE attempt_id = ?
      `).get(attemptId) as AttemptRow | undefined;
      return row ? Object.freeze({ ...row }) : null;
    } catch {
      return null;
    }
  }

  close(): void {
    this.db.close();
  }
}
