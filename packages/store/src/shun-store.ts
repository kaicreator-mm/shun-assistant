// Durable ShunStore — the business-authority store (L2 §5.4, §11.1).
//
// SQLite behind the frozen StorePort seam. Every workflow-triggered mutation
// goes through the idempotent application-effect protocol: the caller supplies
// a stable effectId; the first application persists the authoritative record
// AND the effect receipt in one transaction; any retry of the same effectId
// returns the recorded result instead of re-applying. The effectId is the
// idempotency key; presenting it with a different intended mutation is an
// identity conflict and fails closed.
//
// Store separation (L2 §5.4): this store holds Product/business authority
// records only. Orchestration mechanics live in the workflow runtime store
// (packages/workflow); there is no cross-database transaction requirement.
import { createHash } from 'node:crypto';
import { DatabaseSync, type StatementSync } from 'node:sqlite';
import {
  canonicalJson,
  type ShunStoreMutation,
  ShunStoreMutationSchema,
  type ShunStoreRecordKind,
  type StoreApplicationReceipt,
  type StorePort,
} from '@shun/contracts';
import {
  ShunStoreClosedError,
  ShunStoreEffectConflictError,
  ShunStoreInvalidMutationError,
  ShunStoreWriteFailedError,
} from './errors.ts';

export const SHUN_STORE_RECORD_KINDS: readonly ShunStoreRecordKind[] =
  ShunStoreMutationSchema.shape.recordKind.options;

export interface StoredRecord {
  recordKind: ShunStoreRecordKind;
  recordId: string;
  payload: Record<string, unknown>;
  revision: number;
  createdAt: string;
  updatedAt: string;
}

export interface ShunStoreOptions {
  /** SQLite database file path. */
  file: string;
}

interface EffectRow {
  effect_id: string;
  record_kind: string;
  record_id: string;
  request_hash: string;
  receipt_ref: string;
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function nowIso(): string {
  return new Date().toISOString();
}

export class ShunStore implements StorePort {
  /** Exposed for database-level fault injection in tests (triggers), nothing else. */
  readonly database: DatabaseSync;

  private readonly statements: {
    findEffect: StatementSync;
    upsertRecord: StatementSync;
    insertEffect: StatementSync;
    insertReceipt: StatementSync;
    findRecord: StatementSync;
    listRecords: StatementSync;
    findReceipt: StatementSync;
  };

  private closed = false;

  constructor(options: ShunStoreOptions) {
    this.database = new DatabaseSync(options.file);
    // synchronous=FULL + WAL: committed effects survive an abrupt process exit.
    this.database.exec('PRAGMA journal_mode = WAL');
    this.database.exec('PRAGMA synchronous = FULL');
    this.database.exec('PRAGMA busy_timeout = 5000');
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS records (
        record_kind  TEXT NOT NULL,
        record_id    TEXT NOT NULL,
        payload      TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        revision     INTEGER NOT NULL,
        created_at   TEXT NOT NULL,
        updated_at   TEXT NOT NULL,
        PRIMARY KEY (record_kind, record_id)
      )
    `);
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS effects (
        effect_id    TEXT PRIMARY KEY,
        record_kind  TEXT NOT NULL,
        record_id    TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        receipt_ref  TEXT NOT NULL,
        applied_at   TEXT NOT NULL
      )
    `);
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS effect_receipts (
        effect_id  TEXT PRIMARY KEY,
        receipt    TEXT NOT NULL,
        applied_at TEXT NOT NULL
      )
    `);

    this.statements = {
      findEffect: this.database.prepare(
        'SELECT effect_id, record_kind, record_id, request_hash, receipt_ref FROM effects WHERE effect_id = ?',
      ),
      upsertRecord: this.database.prepare(`
        INSERT INTO records (record_kind, record_id, payload, payload_hash, revision, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT (record_kind, record_id) DO UPDATE SET
          payload = excluded.payload,
          payload_hash = excluded.payload_hash,
          revision = records.revision + 1,
          updated_at = excluded.updated_at
      `),
      insertEffect: this.database.prepare(
        'INSERT INTO effects (effect_id, record_kind, record_id, request_hash, receipt_ref, applied_at) VALUES (?, ?, ?, ?, ?, ?)',
      ),
      insertReceipt: this.database.prepare(
        'INSERT INTO effect_receipts (effect_id, receipt, applied_at) VALUES (?, ?, ?)',
      ),
      findRecord: this.database.prepare(
        'SELECT record_kind, record_id, payload, revision, created_at, updated_at FROM records WHERE record_kind = ? AND record_id = ?',
      ),
      listRecords: this.database.prepare(
        'SELECT record_kind, record_id, payload, revision, created_at, updated_at FROM records WHERE record_kind = ? ORDER BY record_id ASC',
      ),
      findReceipt: this.database.prepare('SELECT receipt FROM effect_receipts WHERE effect_id = ?'),
    };
  }

  /** Idempotent application-effect protocol (L2 §5.4). Interface: StorePort.apply. */
  async apply(effectId: string, mutation: ShunStoreMutation): Promise<StoreApplicationReceipt> {
    if (this.closed) {
      throw new ShunStoreClosedError();
    }
    if (typeof effectId !== 'string' || effectId.length < 1) {
      throw new ShunStoreInvalidMutationError('effectId must be a non-empty string');
    }
    const parsed = ShunStoreMutationSchema.safeParse(mutation);
    if (!parsed.success) {
      throw new ShunStoreInvalidMutationError('invalid ShunStore mutation', {
        cause: parsed.error,
      });
    }

    const request = parsed.data;
    const payloadText = canonicalJson(request.payload);
    const requestHash = sha256(
      canonicalJson({
        recordKind: request.recordKind,
        recordId: request.recordId,
        payload: request.payload,
      }),
    );
    const receiptRef = `shunstore://effect/${effectId}`;
    const timestamp = nowIso();

    this.database.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.statements.findEffect.get(effectId) as EffectRow | undefined;
      if (existing) {
        const mismatches: string[] = [];
        if (existing.record_kind !== request.recordKind) mismatches.push('recordKind');
        if (existing.record_id !== request.recordId) mismatches.push('recordId');
        if (existing.request_hash !== requestHash) mismatches.push('payload');
        this.database.exec('ROLLBACK');
        if (mismatches.length > 0) {
          throw new ShunStoreEffectConflictError(effectId, mismatches);
        }
        return { effectId, applied: false, receiptRef: existing.receipt_ref };
      }

      this.statements.upsertRecord.run(
        request.recordKind,
        request.recordId,
        payloadText,
        sha256(payloadText),
        timestamp,
        timestamp,
      );
      this.statements.insertEffect.run(
        effectId,
        request.recordKind,
        request.recordId,
        requestHash,
        receiptRef,
        timestamp,
      );
      const receipt: StoreApplicationReceipt = { effectId, applied: true, receiptRef };
      this.statements.insertReceipt.run(effectId, canonicalJson(receipt), timestamp);
      this.database.exec('COMMIT');
      return receipt;
    } catch (error) {
      if (!(error instanceof ShunStoreEffectConflictError)) {
        this.rollbackQuietly();
      }
      if (error instanceof ShunStoreEffectConflictError || error instanceof ShunStoreClosedError) {
        throw error;
      }
      throw new ShunStoreWriteFailedError(`failed to apply effect ${effectId}`, { cause: error });
    }
  }

  /** Read model: business-authority record as persisted (reconciliation probes, upper layers). */
  async getRecord(recordKind: ShunStoreRecordKind, recordId: string): Promise<StoredRecord | null> {
    this.assertOpen();
    const row = this.statements.findRecord.get(recordKind, recordId) as RecordRow | undefined;
    return row ? this.toStoredRecord(row) : null;
  }

  async listRecords(recordKind: ShunStoreRecordKind): Promise<StoredRecord[]> {
    this.assertOpen();
    return (this.statements.listRecords.all(recordKind) as unknown as RecordRow[]).map((row) =>
      this.toStoredRecord(row),
    );
  }

  /**
   * Reconciliation probe (L2 §5.4/§9.4): did effectId durably apply, and what
   * was recorded? Unknown effectId → null (the effect provably never landed).
   */
  async getEffectReceipt(effectId: string): Promise<StoreApplicationReceipt | null> {
    this.assertOpen();
    const row = this.statements.findReceipt.get(effectId) as { receipt: string } | undefined;
    if (!row) {
      return null;
    }
    return JSON.parse(row.receipt) as StoreApplicationReceipt;
  }

  /**
   * Test-only hard-exit simulation: drops the handle without checkpoint/close
   * so the next connection observes the true post-crash durable state.
   */
  abandon(): void {
    this.closed = true;
    // node:sqlite keeps no explicit handle to abandon; a new DatabaseSync on
    // the same file sees only committed transactions regardless.
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.database.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    this.database.close();
  }

  private rollbackQuietly(): void {
    try {
      this.database.exec('ROLLBACK');
    } catch {
      // ROLLBACK when no transaction is active is fine (e.g. the ROLLBACK in
      // the replay path already ran).
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new ShunStoreClosedError();
    }
  }

  private toStoredRecord(row: RecordRow): StoredRecord {
    return {
      recordKind: row.record_kind as ShunStoreRecordKind,
      recordId: row.record_id,
      payload: JSON.parse(row.payload) as Record<string, unknown>,
      revision: row.revision,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}

interface RecordRow {
  record_kind: string;
  record_id: string;
  payload: string;
  revision: number;
  created_at: string;
  updated_at: string;
}
