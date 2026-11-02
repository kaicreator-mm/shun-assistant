import { randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const SAFE_REF = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const MAX_PREVIEW_BYTES = 8_192;
const MAX_RECEIPT_BYTES = 16_384;
const REQUEST_TTL_MS = 5 * 60_000;

export type ProviderFirstUseStatus =
  | 'PREPARED'
  | 'APPROVED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'REFUSED'
  | 'UNKNOWN'
  | 'EXPIRED';

export interface ProviderFirstUsePreview {
  readonly providerId: string;
  readonly bindingId: string;
  readonly version: string;
  readonly artifactSha256: string;
  readonly publisherKeyId: string;
  readonly privilegeScope: 'USER' | 'ELEVATED';
  readonly reason: string;
  readonly expectedChanges: readonly string[];
  readonly elevatedAction?: {
    readonly program: string;
    readonly args: readonly string[];
    readonly sideEffectClass: string;
    readonly requiredPrivilege: 'ELEVATED';
  };
}

export interface ProviderFirstUseRequestRecord {
  readonly requestRef: string;
  readonly preview: ProviderFirstUsePreview;
  readonly status: ProviderFirstUseStatus;
  readonly createdAtUnixMs: number;
  readonly expiresAtUnixMs: number;
  readonly confirmedAtUnixMs?: number;
  readonly startedAtUnixMs?: number;
  readonly finishedAtUnixMs?: number;
  readonly receipt?: unknown;
}

type Transition =
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

function isBoundedText(value: unknown, max = 240): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f]/.test(value);
}

function validatePreview(value: ProviderFirstUsePreview): boolean {
  if (
    !value ||
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
  ) return false;
  if (value.privilegeScope === 'ELEVATED') {
    const elevated = value.elevatedAction;
    if (
      !elevated ||
      !isBoundedText(elevated.program, 512) ||
      !Array.isArray(elevated.args) ||
      elevated.args.length > 32 ||
      !elevated.args.every((entry) => isBoundedText(entry, 512)) ||
      !isBoundedText(elevated.sideEffectClass, 32) ||
      elevated.requiredPrivilege !== 'ELEVATED'
    ) return false;
  } else if (value.elevatedAction !== undefined) {
    return false;
  }
  return true;
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
  return Object.freeze({
    requestRef: row.request_ref,
    preview: Object.freeze(preview as ProviderFirstUsePreview),
    status: row.status,
    createdAtUnixMs: row.created_at_unix_ms,
    expiresAtUnixMs: row.expires_at_unix_ms,
    ...(row.confirmed_at_unix_ms !== null ? { confirmedAtUnixMs: row.confirmed_at_unix_ms } : {}),
    ...(row.started_at_unix_ms !== null ? { startedAtUnixMs: row.started_at_unix_ms } : {}),
    ...(row.finished_at_unix_ms !== null ? { finishedAtUnixMs: row.finished_at_unix_ms } : {}),
    ...(row.receipt_json !== null ? { receipt } : {}),
  });
}

/**
 * Durable Host-global, one-shot Provider first-use request ledger.
 * It is intentionally independent of Guided Case state and stores only the
 * bounded preview plus terminal receipt metadata.
 */
export class ProviderFirstUseLedger {
  readonly #db: DatabaseSync;
  readonly #now: () => number;

  constructor(file: string, now: () => number = Date.now) {
    if (typeof file !== 'string' || !isAbsolute(file) || file.endsWith(':memory:')) {
      throw new TypeError('PROVIDER_FIRST_USE_DURABLE_FILE_REQUIRED');
    }
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
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
    this.#db.exec('CREATE INDEX IF NOT EXISTS provider_first_use_status_idx ON provider_first_use_requests(status,expires_at_unix_ms)');
    this.#now = now;
    // A process restart during RUNNING is ambiguous; PREPARED/APPROVED
    // confirmations are also expired so a stale UI cannot replay them.
    const nowMs = this.#now();
    this.#db.prepare(`UPDATE provider_first_use_requests
      SET status='UNKNOWN',finished_at_unix_ms=?,receipt_json=?
      WHERE status='RUNNING'`).run(
      nowMs,
      JSON.stringify({ code: 'PROCESS_RESTARTED_WITH_UNCERTAIN_OUTCOME' }),
    );
    this.#db.prepare(`UPDATE provider_first_use_requests
      SET status='EXPIRED',finished_at_unix_ms=?
      WHERE status IN ('PREPARED','APPROVED')`).run(nowMs);
  }

  prepare(preview: ProviderFirstUsePreview): Transition {
    if (!validatePreview(preview)) return { ok: false, code: 'PROVIDER_PREVIEW_INVALID' };
    const previewJson = JSON.stringify(preview);
    if (Buffer.byteLength(previewJson, 'utf8') > MAX_PREVIEW_BYTES) {
      return { ok: false, code: 'PROVIDER_PREVIEW_TOO_LARGE' };
    }
    const now = this.#now();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const pending = this.#db.prepare(`SELECT request_ref FROM provider_first_use_requests
        WHERE status IN ('PREPARED','APPROVED','RUNNING') AND expires_at_unix_ms>?
        LIMIT 1`).get(now);
      if (pending) {
        this.#db.exec('ROLLBACK');
        return { ok: false, code: 'PROVIDER_FIRST_USE_ALREADY_PENDING' };
      }
      const requestRef = `provider-request-${randomUUID()}`;
      const expiresAt = now + REQUEST_TTL_MS;
      this.#db.prepare(`INSERT INTO provider_first_use_requests(
        request_ref,preview_json,status,created_at_unix_ms,expires_at_unix_ms
      ) VALUES(?,?,'PREPARED',?,?)`).run(requestRef, previewJson, now, expiresAt);
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

  confirm(requestRef: string): Transition {
    if (!SAFE_REF.test(requestRef)) return { ok: false, code: 'PROVIDER_REQUEST_REF_INVALID' };
    const now = this.#now();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#read(requestRef);
      if (!row || row.status !== 'PREPARED') {
        this.#db.exec('ROLLBACK');
        return { ok: false, code: 'PROVIDER_REQUEST_NOT_PREPARED' };
      }
      if (row.expires_at_unix_ms <= now) {
        this.#db.prepare(`UPDATE provider_first_use_requests
          SET status='EXPIRED',finished_at_unix_ms=? WHERE request_ref=? AND status='PREPARED'`)
          .run(now, requestRef);
        this.#db.exec('COMMIT');
        return { ok: false, code: 'PROVIDER_REQUEST_EXPIRED' };
      }
      this.#db.prepare(`UPDATE provider_first_use_requests
        SET status='APPROVED',confirmed_at_unix_ms=?
        WHERE request_ref=? AND status='PREPARED'`).run(now, requestRef);
      const record = decodeRow(this.#read(requestRef));
      this.#db.exec('COMMIT');
      return record ? { ok: true, record } : { ok: false, code: 'PROVIDER_REQUEST_UNKNOWN' };
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  begin(requestRef: string): Transition {
    if (!SAFE_REF.test(requestRef)) return { ok: false, code: 'PROVIDER_REQUEST_REF_INVALID' };
    const now = this.#now();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#read(requestRef);
      if (!row || row.status !== 'APPROVED') {
        this.#db.exec('ROLLBACK');
        return { ok: false, code: 'PROVIDER_REQUEST_NOT_APPROVED' };
      }
      if (row.expires_at_unix_ms <= now) {
        this.#db.prepare(`UPDATE provider_first_use_requests
          SET status='EXPIRED',finished_at_unix_ms=? WHERE request_ref=? AND status='APPROVED'`)
          .run(now, requestRef);
        this.#db.exec('COMMIT');
        return { ok: false, code: 'PROVIDER_REQUEST_EXPIRED' };
      }
      this.#db.prepare(`UPDATE provider_first_use_requests
        SET status='RUNNING',started_at_unix_ms=?
        WHERE request_ref=? AND status='APPROVED'`).run(now, requestRef);
      const record = decodeRow(this.#read(requestRef));
      this.#db.exec('COMMIT');
      return record ? { ok: true, record } : { ok: false, code: 'PROVIDER_REQUEST_UNKNOWN' };
    } catch (error) {
      this.#rollback();
      throw error;
    }
  }

  finish(
    requestRef: string,
    status: 'COMPLETED' | 'REFUSED' | 'UNKNOWN',
    receipt: unknown,
  ): boolean {
    if (!SAFE_REF.test(requestRef)) return false;
    const receiptJson = JSON.stringify(receipt);
    if (typeof receiptJson !== 'string' || Buffer.byteLength(receiptJson, 'utf8') > MAX_RECEIPT_BYTES) {
      return false;
    }
    const result = this.#db.prepare(`UPDATE provider_first_use_requests
      SET status=?,finished_at_unix_ms=?,receipt_json=?
      WHERE request_ref=? AND status='RUNNING'`).run(
      status,
      this.#now(),
      receiptJson,
      requestRef,
    );
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
    return this.#db.prepare(
      'SELECT * FROM provider_first_use_requests WHERE request_ref=?',
    ).get(requestRef) as RequestRow | undefined;
  }

  #rollback(): void {
    try { this.#db.exec('ROLLBACK'); } catch { /* keep ambiguous outcomes fail-closed */ }
  }
}
