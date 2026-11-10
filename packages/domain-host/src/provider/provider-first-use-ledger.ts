/**
 * R03C — durable Host-global Provider first-use request ledger
 * (OWNER_SHUN_V030_R03C_SOURCE_IMPLEMENTATION_APPROVE, #280 comment 6584396368).
 *
 * The ledger lives under the existing operator-owned Provider cache root and
 * is intentionally independent of Guided Case state: requests carry no Case,
 * task or caller identity at all — only Host-issued references and the exact
 * bounded preview the operator confirms.
 *
 * One-way state machine (never replayed, never auto-advanced):
 *
 *   PREPARED -> APPROVED -> RUNNING -> COMPLETED | REFUSED | UNKNOWN
 *       |           |          |
 *       +-> EXPIRED +->EXPIRED +-> UNKNOWN (process restart sweep)
 *
 * Uncertain/interrupted execution becomes UNKNOWN; a restart during RUNNING
 * is ambiguous by definition and is swept to UNKNOWN with no auto-retry.
 * Receipts and previews are closed-world JSON validated by one exact schema
 * on BOTH write and read: no free text, credentials, raw provider output,
 * output references, unrestricted paths or arbitrary nested objects are ever
 * stored or returned.
 */
import { randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const SAFE_REF = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION_TOKEN = /^\d{1,4}(?:\.\d{1,4}){0,3}(?:[-+][0-9A-Za-z][0-9A-Za-z._-]{0,31})?$/;
const MAX_PREVIEW_BYTES = 8_192;
const MAX_RECEIPT_BYTES = 16_384;
const REQUEST_TTL_MS = 5 * 60_000;

const PREVIEW_BASE_KEYS = [
  'providerId',
  'bindingId',
  'version',
  'artifactSha256',
  'publisherKeyId',
  'privilegeScope',
  'reason',
  'expectedChanges',
] as const;
const ELEVATED_ACTION_KEYS = ['program', 'args', 'sideEffectClass', 'requiredPrivilege'] as const;
const RECEIPT_KEYS = [
  'outcome',
  'code',
  'bindingId',
  'artifactSha256',
  'probeVersion',
  'probeVersionParsed',
  'canaryResult',
  'elevatedTerminal',
  'exitCode',
  'timedOut',
  'durationMs',
] as const;
const CANARY_RESULTS = ['MATCHED', 'NOT_MATCHED', 'UNCLEAR'] as const;
const ELEVATED_TERMINALS = [
  'SUCCEEDED',
  'REFUSED',
  'UAC_DECLINED',
  'CANCELLED',
  'FAILED',
  'TIMED_OUT',
  'UNCLEAR',
] as const;

export type ProviderFirstUseStatus =
  | 'PREPARED'
  | 'APPROVED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'REFUSED'
  | 'UNKNOWN'
  | 'EXPIRED';

export type ProviderPrivilegeScope = 'USER' | 'ELEVATED';

export interface ProviderFirstUsePreview {
  readonly providerId: string;
  readonly bindingId: string;
  readonly version: string;
  readonly artifactSha256: string;
  readonly publisherKeyId: string;
  readonly privilegeScope: ProviderPrivilegeScope;
  readonly reason: string;
  readonly expectedChanges: readonly string[];
  /** Present exactly when privilegeScope is ELEVATED (installer action preview). */
  readonly elevatedAction?: {
    readonly program: string;
    readonly args: readonly string[];
    readonly sideEffectClass: string;
    readonly requiredPrivilege: 'ELEVATED';
  };
}

/**
 * Closed-world durable receipt (exact key set, primitive values only).
 * Raw provider stdout/stderr, output references, absolute paths, free text
 * and arbitrary nested objects are structurally impossible: every present
 * field must pass its strict shape check, and `outcome` must match the
 * terminal status the receipt is written with (and is re-validated with on
 * every read).
 */
export type ProviderFirstUseReceipt = {
  readonly outcome: 'EXECUTED' | 'REFUSED' | 'UNKNOWN';
  /** Host-minted bounded refusal/completion code; never provider text. */
  readonly code: string;
  readonly bindingId?: string;
  readonly artifactSha256?: string;
  /** Strictly parsed provider version token; absent when unparsable. */
  readonly probeVersion?: string;
  readonly probeVersionParsed?: boolean;
  readonly canaryResult?: 'MATCHED' | 'NOT_MATCHED' | 'UNCLEAR';
  readonly elevatedTerminal?:
    | 'SUCCEEDED'
    | 'REFUSED'
    | 'UAC_DECLINED'
    | 'CANCELLED'
    | 'FAILED'
    | 'TIMED_OUT'
    | 'UNCLEAR';
  readonly exitCode?: number;
  readonly timedOut?: boolean;
  readonly durationMs?: number;
};

export interface ProviderFirstUseRequestRecord {
  readonly requestRef: string;
  readonly preview: ProviderFirstUsePreview;
  readonly status: ProviderFirstUseStatus;
  readonly createdAtUnixMs: number;
  readonly expiresAtUnixMs: number;
  readonly confirmedAtUnixMs?: number;
  readonly startedAtUnixMs?: number;
  readonly finishedAtUnixMs?: number;
  readonly receipt?: ProviderFirstUseReceipt;
}

export type LedgerTransition =
  | { readonly ok: true; readonly record: ProviderFirstUseRequestRecord }
  | { readonly ok: false; readonly code: string };

interface RequestRow {
  readonly request_ref: string;
  readonly preview_json: string;
  readonly status: ProviderFirstUseStatus;
  readonly created_at_unix_ms: number;
  readonly expires_at_unix_ms: number;
  readonly confirmed_at_unix_ms: number | null;
  readonly started_at_unix_ms: number | null;
  readonly finished_at_unix_ms: number | null;
  readonly receipt_json: string | null;
}

/** Bounded single-line text; never a path, secret-shaped value or control run. */
function isBoundedText(value: unknown, max = 240): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= max &&
    // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are exactly what this fail-closed filter rejects
    !/[\u0000-\u001f]/.test(value) &&
    !/(?:password|token|secret|credential|api[_-]?key)\s*=/i.test(value)
  );
}

function hasExactKeySet(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => key in value);
}

function optionalString(value: unknown, accept: (candidate: string) => boolean): boolean {
  return value === undefined || (typeof value === 'string' && accept(value));
}

function optionalBoolean(value: unknown): boolean {
  return value === undefined || typeof value === 'boolean';
}

function optionalEnum(value: unknown, allowed: readonly string[]): boolean {
  return value === undefined || (typeof value === 'string' && allowed.includes(value));
}

function optionalInteger(value: unknown, min: number, max: number): boolean {
  return (
    value === undefined ||
    (typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max)
  );
}

/**
 * Closed-world preview gate: exact key set on the preview itself AND on the
 * nested elevatedAction — caller-supplied extra properties are refused
 * instead of silently serialized into the durable preview.
 */
function validatePreview(value: ProviderFirstUsePreview): boolean {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    !hasExactKeySet(
      value as unknown as Record<string, unknown>,
      value.elevatedAction === undefined
        ? PREVIEW_BASE_KEYS
        : [...PREVIEW_BASE_KEYS, 'elevatedAction'],
    ) ||
    !SAFE_REF.test(value.providerId) ||
    !SAFE_REF.test(value.bindingId) ||
    !isBoundedText(value.version, 64) ||
    !SHA256.test(value.artifactSha256) ||
    !SAFE_REF.test(value.publisherKeyId) ||
    (value.privilegeScope !== 'USER' && value.privilegeScope !== 'ELEVATED') ||
    !isBoundedText(value.reason) ||
    !Array.isArray(value.expectedChanges) ||
    value.expectedChanges.length > 8 ||
    !value.expectedChanges.every((entry) => isBoundedText(entry, 160))
  ) {
    return false;
  }
  if (value.privilegeScope === 'ELEVATED') {
    const elevated = value.elevatedAction;
    if (
      !elevated ||
      !hasExactKeySet(elevated as unknown as Record<string, unknown>, ELEVATED_ACTION_KEYS) ||
      !isBoundedText(elevated.program, 512) ||
      !Array.isArray(elevated.args) ||
      elevated.args.length > 32 ||
      !elevated.args.every((entry) => isBoundedText(entry, 512)) ||
      !isBoundedText(elevated.sideEffectClass, 32) ||
      elevated.requiredPrivilege !== 'ELEVATED'
    ) {
      return false;
    }
    return true;
  }
  return value.elevatedAction === undefined;
}

/**
 * Closed-world receipt gate — the ONE schema shared by `finish` (write) and
 * `decodeRow` (read). Exact key set, primitive values only, strict per-field
 * shapes, and the receipt's `outcome` must agree with the terminal status it
 * is being validated against (COMPLETED↔EXECUTED, REFUSED↔REFUSED,
 * UNKNOWN↔UNKNOWN; non-terminal statuses validate shape only, which never
 * happens for persisted rows because receipts exist only on terminal rows).
 * Legacy/unknown/malformed shapes fail closed on both sides of the ledger.
 */
function validateReceipt(
  value: unknown,
  status: ProviderFirstUseStatus,
): value is ProviderFirstUseReceipt {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (!hasOnlyKnownReceiptKeys(record)) return false;
  if (
    record.outcome !== 'EXECUTED' &&
    record.outcome !== 'REFUSED' &&
    record.outcome !== 'UNKNOWN'
  ) {
    return false;
  }
  if (
    (status === 'COMPLETED' && record.outcome !== 'EXECUTED') ||
    (status === 'REFUSED' && record.outcome !== 'REFUSED') ||
    (status === 'UNKNOWN' && record.outcome !== 'UNKNOWN')
  ) {
    return false;
  }
  if (
    typeof record.code !== 'string' ||
    !SAFE_REF.test(record.code) ||
    isSecretShaped(record.code)
  ) {
    return false;
  }
  return (
    optionalString(record.bindingId, (candidate) => SAFE_REF.test(candidate)) &&
    optionalString(record.artifactSha256, (candidate) => SHA256.test(candidate)) &&
    optionalString(
      record.probeVersion,
      (candidate) => VERSION_TOKEN.test(candidate) && !isSecretShaped(candidate),
    ) &&
    optionalBoolean(record.probeVersionParsed) &&
    optionalEnum(record.canaryResult, CANARY_RESULTS) &&
    optionalEnum(record.elevatedTerminal, ELEVATED_TERMINALS) &&
    optionalInteger(record.exitCode, -2_147_483_648, 2_147_483_647) &&
    optionalBoolean(record.timedOut) &&
    optionalInteger(record.durationMs, 0, 2_147_483_647)
  );
}

/** Closed-world receipt keys: every present key must be a known receipt key. */
function hasOnlyKnownReceiptKeys(record: Record<string, unknown>): boolean {
  const keys = Object.keys(record);
  return keys.length > 0 && keys.every((key) => (RECEIPT_KEYS as readonly string[]).includes(key));
}

function isSecretShaped(value: string): boolean {
  return /(?:password|token|secret|credential|api[_-]?key)\s*=/i.test(value);
}

function decodeRow(row: RequestRow | undefined): ProviderFirstUseRequestRecord | undefined {
  if (!row || !SAFE_REF.test(row.request_ref)) return undefined;
  let preview: unknown;
  let receipt: unknown;
  try {
    preview = JSON.parse(row.preview_json) as unknown;
    if (row.receipt_json !== null) receipt = JSON.parse(row.receipt_json) as unknown;
  } catch {
    return undefined;
  }
  if (!validatePreview(preview as ProviderFirstUsePreview)) return undefined;
  // Read side of the closed receipt world: the SAME schema validated at
  // finish() must hold for the persisted JSON, matched against the row's
  // terminal status — malformed, legacy or out-of-schema receipts fail closed.
  if (row.receipt_json !== null && !validateReceipt(receipt, row.status)) return undefined;
  return Object.freeze({
    requestRef: row.request_ref,
    preview: Object.freeze(preview as ProviderFirstUsePreview),
    status: row.status,
    createdAtUnixMs: row.created_at_unix_ms,
    expiresAtUnixMs: row.expires_at_unix_ms,
    ...(row.confirmed_at_unix_ms !== null ? { confirmedAtUnixMs: row.confirmed_at_unix_ms } : {}),
    ...(row.started_at_unix_ms !== null ? { startedAtUnixMs: row.started_at_unix_ms } : {}),
    ...(row.finished_at_unix_ms !== null ? { finishedAtUnixMs: row.finished_at_unix_ms } : {}),
    ...(row.receipt_json !== null ? { receipt: receipt as ProviderFirstUseReceipt } : {}),
  });
}

/**
 * Durable, Case-independent, one-shot Provider first-use request ledger.
 * The file must be an absolute path on local disk (same rule as the other
 * trusted Host SQLite stores).
 */
export class ProviderFirstUseLedger {
  readonly #db: DatabaseSync;
  readonly #now: () => number;

  constructor(file: string, now: () => number = Date.now) {
    if (typeof file !== 'string' || !isAbsolute(file) || file.endsWith(':memory:')) {
      throw new TypeError('PROVIDER_FIRST_USE_DURABLE_FILE_REQUIRED');
    }
    mkdirSync(dirname(file), { recursive: true });
    this.#db = new DatabaseSync(file);
    this.#db.exec('PRAGMA journal_mode=WAL');
    this.#db.exec('PRAGMA synchronous=FULL');
    this.#db.exec('PRAGMA busy_timeout=5000');
    this.#db.exec(`CREATE TABLE IF NOT EXISTS provider_first_use_requests (
      request_ref TEXT PRIMARY KEY,
      preview_json TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN (
        'PREPARED','APPROVED','RUNNING','COMPLETED','REFUSED','UNKNOWN','EXPIRED'
      )),
      created_at_unix_ms INTEGER NOT NULL,
      expires_at_unix_ms INTEGER NOT NULL,
      confirmed_at_unix_ms INTEGER,
      started_at_unix_ms INTEGER,
      finished_at_unix_ms INTEGER,
      receipt_json TEXT
    )`);
    this.#db.exec(
      'CREATE INDEX IF NOT EXISTS provider_first_use_status_idx ON provider_first_use_requests(status,expires_at_unix_ms)',
    );
    this.#now = now;
    // Process-restart reconciliation: RUNNING is an ambiguous execution
    // boundary (never auto-replayed); unconfirmed PREPARED/APPROVED requests
    // are expired so a stale UI cannot replay them.
    const nowMs = this.#now();
    this.#db
      .prepare(
        `UPDATE provider_first_use_requests
         SET status='UNKNOWN',finished_at_unix_ms=?,receipt_json=?
         WHERE status='RUNNING'`,
      )
      .run(
        nowMs,
        JSON.stringify({ outcome: 'UNKNOWN', code: 'PROCESS_RESTARTED_WITH_UNCERTAIN_OUTCOME' }),
      );
    this.#db
      .prepare(
        `UPDATE provider_first_use_requests
         SET status='EXPIRED',finished_at_unix_ms=?
         WHERE status IN ('PREPARED','APPROVED')`,
      )
      .run(nowMs);
  }

  /** Host-issued bounded preview; at most one pending request at any time. */
  prepare(preview: ProviderFirstUsePreview): LedgerTransition {
    if (!validatePreview(preview)) return { ok: false, code: 'PROVIDER_PREVIEW_INVALID' };
    const previewJson = JSON.stringify(preview);
    if (Buffer.byteLength(previewJson, 'utf8') > MAX_PREVIEW_BYTES) {
      return { ok: false, code: 'PROVIDER_PREVIEW_TOO_LARGE' };
    }
    const now = this.#now();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const pending = this.#db
        .prepare(
          `SELECT request_ref FROM provider_first_use_requests
           WHERE status IN ('PREPARED','APPROVED','RUNNING') AND expires_at_unix_ms>?
           LIMIT 1`,
        )
        .get(now);
      if (pending !== undefined) {
        this.#db.exec('ROLLBACK');
        return { ok: false, code: 'PROVIDER_FIRST_USE_ALREADY_PENDING' };
      }
      const requestRef = `provider-request-${randomUUID()}`;
      const expiresAt = now + REQUEST_TTL_MS;
      this.#db
        .prepare(
          `INSERT INTO provider_first_use_requests(
             request_ref,preview_json,status,created_at_unix_ms,expires_at_unix_ms
           ) VALUES(?,?,'PREPARED',?,?)`,
        )
        .run(requestRef, previewJson, now, expiresAt);
      this.#db.exec('COMMIT');
      return {
        ok: true,
        record: {
          requestRef,
          preview: Object.freeze({ ...preview }),
          status: 'PREPARED',
          createdAtUnixMs: now,
          expiresAtUnixMs: expiresAt,
        },
      };
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  /** Explicit operator confirmation: PREPARED -> APPROVED, exactly once. */
  confirm(requestRef: string): LedgerTransition {
    if (!SAFE_REF.test(requestRef)) return { ok: false, code: 'PROVIDER_REQUEST_REF_INVALID' };
    const now = this.#now();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#read(requestRef);
      if (row === undefined || row.status !== 'PREPARED') {
        this.#db.exec('ROLLBACK');
        return { ok: false, code: 'PROVIDER_REQUEST_NOT_PREPARED' };
      }
      if (row.expires_at_unix_ms <= now) {
        this.#db
          .prepare(
            `UPDATE provider_first_use_requests
             SET status='EXPIRED',finished_at_unix_ms=? WHERE request_ref=? AND status='PREPARED'`,
          )
          .run(now, requestRef);
        this.#db.exec('COMMIT');
        return { ok: false, code: 'PROVIDER_REQUEST_EXPIRED' };
      }
      this.#db
        .prepare(
          'UPDATE provider_first_use_requests SET status=?,confirmed_at_unix_ms=? WHERE request_ref=?',
        )
        .run('APPROVED', now, requestRef);
      const record = decodeRow(this.#read(requestRef));
      this.#db.exec('COMMIT');
      return record !== undefined
        ? { ok: true, record }
        : { ok: false, code: 'PROVIDER_REQUEST_UNKNOWN' };
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  /** K-side consumption: APPROVED -> RUNNING exactly once (one-way). */
  begin(requestRef: string): LedgerTransition {
    if (!SAFE_REF.test(requestRef)) return { ok: false, code: 'PROVIDER_REQUEST_REF_INVALID' };
    const now = this.#now();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#read(requestRef);
      if (row === undefined || row.status !== 'APPROVED') {
        this.#db.exec('ROLLBACK');
        return { ok: false, code: 'PROVIDER_REQUEST_NOT_APPROVED' };
      }
      if (row.expires_at_unix_ms <= now) {
        this.#db
          .prepare(
            `UPDATE provider_first_use_requests
             SET status='EXPIRED',finished_at_unix_ms=? WHERE request_ref=? AND status='APPROVED'`,
          )
          .run(now, requestRef);
        this.#db.exec('COMMIT');
        return { ok: false, code: 'PROVIDER_REQUEST_EXPIRED' };
      }
      this.#db
        .prepare(
          'UPDATE provider_first_use_requests SET status=?,started_at_unix_ms=? WHERE request_ref=?',
        )
        .run('RUNNING', now, requestRef);
      const record = decodeRow(this.#read(requestRef));
      this.#db.exec('COMMIT');
      return record !== undefined
        ? { ok: true, record }
        : { ok: false, code: 'PROVIDER_REQUEST_UNKNOWN' };
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  /**
   * Terminal receipt write, only from RUNNING. COMPLETED/REFUSED are
   * definitive; UNKNOWN records an uncertain execution boundary. The receipt
   * must satisfy the closed receipt schema (with `outcome` matching this
   * status) — anything else is refused and the row stays RUNNING.
   */
  finish(
    requestRef: string,
    status: 'COMPLETED' | 'REFUSED' | 'UNKNOWN',
    receipt: unknown,
  ): boolean {
    if (!SAFE_REF.test(requestRef)) return false;
    if (!validateReceipt(receipt, status)) return false;
    let receiptJson: string;
    try {
      receiptJson = JSON.stringify(receipt);
    } catch {
      return false;
    }
    if (Buffer.byteLength(receiptJson, 'utf8') > MAX_RECEIPT_BYTES) return false;
    const result = this.#db
      .prepare(
        `UPDATE provider_first_use_requests
         SET status=?,finished_at_unix_ms=?,receipt_json=?
         WHERE request_ref=? AND status='RUNNING'`,
      )
      .run(status, this.#now(), receiptJson, requestRef);
    return result.changes === 1;
  }

  read(requestRef: string): ProviderFirstUseRequestRecord | undefined {
    if (!SAFE_REF.test(requestRef)) return undefined;
    return decodeRow(this.#read(requestRef));
  }

  close(): void {
    this.#db.close();
  }

  #read(requestRef: string): RequestRow | undefined {
    return this.#db
      .prepare('SELECT * FROM provider_first_use_requests WHERE request_ref=?')
      .get(requestRef) as RequestRow | undefined;
  }

  #rollback(): void {
    try {
      this.#db.exec('ROLLBACK');
    } catch {
      /* keep ambiguous outcomes fail-closed */
    }
  }
}
