/**
 * R02-E (reference binding repair): the durable Host-issued submit-reference
 * ledger. The T09 gateway deliberately admits approval/currentness REFERENCE
 * strings only and never reads consent content; THIS ledger is the trusted
 * Host surface that actually mints, stores and authenticates those
 * references for ONE live Guided Case step.
 *
 * References are issued exclusively from trusted process-side composition
 * (never an HTTP route), bound durably to (caseId, stepId, validity window),
 * and every production submit must present the exact issued pair before the
 * Kernel facade is entered. This is not an approval object, consent issuer,
 * grant or second dispatcher: the T04 consent broker and the Kernel Permit
 * remain the only effect authorities — a verified reference proves only that
 * the trusted Host issued it for this live Case step, nothing more.
 */
import { randomBytes } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export type HostSubmitReferenceRefusalCode =
  | 'HOST_REFERENCES_NOT_ISSUED'
  | 'HOST_REFERENCES_CASE_MISMATCH'
  | 'HOST_REFERENCES_STEP_MISMATCH'
  | 'HOST_REFERENCES_REVOKED'
  | 'HOST_REFERENCES_EXPIRED';

export type HostSubmitReferenceIssueReceipt =
  | Readonly<{
      readonly status: 'ISSUED';
      readonly caseId: string;
      readonly stepId: string;
      readonly currentnessRef: string;
      readonly approvalRef: string;
      readonly validUntilUnixMs: number;
    }>
  | Readonly<{ readonly status: 'REFUSED'; readonly code: string }>;

export type HostSubmitReferenceVerdict =
  | Readonly<{ readonly status: 'VALID' }>
  | Readonly<{ readonly status: 'REFUSED'; readonly code: HostSubmitReferenceRefusalCode }>;

/** Same bounded grammar the T09 gateway enforces on submitted references. */
const REF = /^shun\.(currentness|approval)\.v1\/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/** Case identities follow the gateway's own bounded namespace (no ':'). */
const CASE_ID = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/;
/**
 * Step identities are opaque Host identities that may contain ':' (e.g.
 * "guided:<journeyId>:<templateId>:<revision>:<digest>") — bounded charset,
 * exact-match binding, never parsed for meaning.
 */
const STEP_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;

interface Row {
  readonly case_id: string;
  readonly step_id: string;
  readonly currentness_ref: string;
  readonly approval_ref: string;
  readonly valid_until_unix_ms: number;
  readonly state: string;
}

function mintRef(kind: 'currentness' | 'approval'): string {
  // 24 random bytes hex-encoded: unguessable, grammar-safe, bounded.
  return `shun.${kind}.v1/${randomBytes(24).toString('hex')}`;
}

export class SqliteHostSubmitReferenceLedger {
  readonly #db: DatabaseSync;
  readonly #clock: () => number;

  constructor(file: string, clock: () => number = Date.now) {
    if (typeof file !== 'string' || !isAbsolute(file) || file.endsWith(':memory:')) {
      throw new TypeError('SUBMIT_REFERENCE_LEDGER_DURABLE_FILE_REQUIRED');
    }
    if (typeof clock !== 'function') throw new TypeError('SUBMIT_REFERENCE_LEDGER_CLOCK_REQUIRED');
    this.#db = new DatabaseSync(file);
    this.#db.exec('PRAGMA journal_mode=WAL');
    this.#db.exec('PRAGMA synchronous=FULL');
    this.#db.exec('PRAGMA busy_timeout=5000');
    this.#db.exec(`CREATE TABLE IF NOT EXISTS host_submit_references (
      case_id TEXT NOT NULL,
      step_id TEXT NOT NULL,
      currentness_ref TEXT NOT NULL UNIQUE,
      approval_ref TEXT NOT NULL UNIQUE,
      issued_at_unix_ms INTEGER NOT NULL,
      valid_until_unix_ms INTEGER NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('CURRENT','REVOKED'))
    )`);
    this.#clock = clock;
  }

  /**
   * Mint (or idempotently restore) the one CURRENT reference pair for a live
   * Host-staged Case step. Trusted process-side calls only; never an HTTP
   * route. Re-issuing the same (caseId, stepId) returns the SAME durable
   * pair (restart-stable); staging a newer step of the same Case revokes the
   * superseded pair.
   */
  issue(input: {
    readonly caseId: string;
    readonly stepId: string;
    readonly validUntilUnixMs: number;
  }): HostSubmitReferenceIssueReceipt {
    const now = this.#clock();
    if (
      typeof input.caseId !== 'string' ||
      !CASE_ID.test(input.caseId) ||
      typeof input.stepId !== 'string' ||
      !STEP_ID.test(input.stepId) ||
      !Number.isSafeInteger(input.validUntilUnixMs) ||
      !Number.isSafeInteger(now) ||
      input.validUntilUnixMs <= now
    ) {
      return { status: 'REFUSED', code: 'HOST_SUBMIT_REFERENCE_INPUT_REFUSED' };
    }
    try {
      this.#db.exec('BEGIN IMMEDIATE');
      const existing = this.#currentFor(input.caseId);
      // Idempotent while the recorded pair is still live: a restart restores
      // the SAME references instead of orphaning the operator's copy.
      if (existing && existing.step_id === input.stepId && existing.valid_until_unix_ms > now) {
        this.#db.exec('COMMIT');
        return {
          status: 'ISSUED',
          caseId: existing.case_id,
          stepId: existing.step_id,
          currentnessRef: existing.currentness_ref,
          approvalRef: existing.approval_ref,
          validUntilUnixMs: existing.valid_until_unix_ms,
        };
      }
      if (existing) {
        // A newer Host step of the same Case — or an already-expired pair —
        // supersedes the recorded references.
        const changed = this.#db
          .prepare(
            `UPDATE host_submit_references SET state='REVOKED'
             WHERE case_id=? AND currentness_ref=? AND state='CURRENT'`,
          )
          .run(existing.case_id, existing.currentness_ref);
        if (changed.changes !== 1) throw new Error('SUPERSEDE_CONFLICT');
      }
      const record = {
        currentnessRef: mintRef('currentness'),
        approvalRef: mintRef('approval'),
      };
      this.#db
        .prepare(
          `INSERT INTO host_submit_references
           (case_id,step_id,currentness_ref,approval_ref,issued_at_unix_ms,valid_until_unix_ms,state)
           VALUES(?,?,?,?,?,?,'CURRENT')`,
        )
        .run(
          input.caseId,
          input.stepId,
          record.currentnessRef,
          record.approvalRef,
          now,
          input.validUntilUnixMs,
        );
      this.#db.exec('COMMIT');
      return {
        status: 'ISSUED',
        caseId: input.caseId,
        stepId: input.stepId,
        currentnessRef: record.currentnessRef,
        approvalRef: record.approvalRef,
        validUntilUnixMs: input.validUntilUnixMs,
      };
    } catch {
      this.#rollback();
      return { status: 'REFUSED', code: 'HOST_SUBMIT_REFERENCE_DURABILITY_UNKNOWN' };
    }
  }

  /**
   * Authenticate an exact submitted reference pair against the durable
   * Host-issued record for one live Case step. Valid-shaped but never
   * issued, pair-swapped, cross-Case, superseded-step, revoked or expired
   * references all refuse — callers must treat any refusal as "do not enter
   * the Kernel at all".
   */
  verify(input: {
    readonly caseId: string;
    readonly stepId: string;
    readonly currentnessRef: string;
    readonly approvalRef: string;
  }): HostSubmitReferenceVerdict {
    if (
      typeof input.currentnessRef !== 'string' ||
      !REF.test(input.currentnessRef) ||
      !input.currentnessRef.startsWith('shun.currentness.v1/') ||
      typeof input.approvalRef !== 'string' ||
      !REF.test(input.approvalRef) ||
      !input.approvalRef.startsWith('shun.approval.v1/') ||
      input.currentnessRef === input.approvalRef
    ) {
      return { status: 'REFUSED', code: 'HOST_REFERENCES_NOT_ISSUED' };
    }
    let row: Row | undefined;
    try {
      row = this.#db
        .prepare(
          `SELECT case_id,step_id,currentness_ref,approval_ref,valid_until_unix_ms,state
           FROM host_submit_references WHERE currentness_ref=? AND approval_ref=?`,
        )
        .get(input.currentnessRef, input.approvalRef) as Row | undefined;
    } catch {
      return { status: 'REFUSED', code: 'HOST_REFERENCES_NOT_ISSUED' };
    }
    // No single Host record carries this exact pair: forged, or two issued
    // references spliced together — both are unauthenticated either way.
    if (row === undefined) return { status: 'REFUSED', code: 'HOST_REFERENCES_NOT_ISSUED' };
    if (row.state !== 'CURRENT') return { status: 'REFUSED', code: 'HOST_REFERENCES_REVOKED' };
    if (row.case_id !== input.caseId) {
      return { status: 'REFUSED', code: 'HOST_REFERENCES_CASE_MISMATCH' };
    }
    if (row.step_id !== input.stepId) {
      return { status: 'REFUSED', code: 'HOST_REFERENCES_STEP_MISMATCH' };
    }
    if (row.valid_until_unix_ms <= this.#clock()) {
      return { status: 'REFUSED', code: 'HOST_REFERENCES_EXPIRED' };
    }
    return { status: 'VALID' };
  }

  close(): void {
    this.#db.close();
  }

  #currentFor(caseId: string): Row | null {
    return (
      (this.#db
        .prepare(
          `SELECT case_id,step_id,currentness_ref,approval_ref,valid_until_unix_ms,state
           FROM host_submit_references WHERE case_id=? AND state='CURRENT'`,
        )
        .get(caseId) as Row | undefined) ?? null
    );
  }

  #rollback(): void {
    try {
      this.#db.exec('ROLLBACK');
    } catch {
      /* retain unknown, no false receipt */
    }
  }
}
