// Durable authorization substrate inside the ShunStore SQLite database.
//
// Implements @shun/authorization's mandatory PolicyStateStore +
// GrantRecordStore semantics with cross-instance SQLite transactions. This is
// deliberately a separate adapter surface from frozen StorePort.apply(): CAS
// and one-shot nonce consumption cannot be represented safely as an
// unconditional idempotent business-record upsert.
import { DatabaseSync, type StatementSync } from 'node:sqlite';
import {
  AuthorityRecordSchema,
  PolicySnapshotRecordSchema,
  StoredGrantRecordSchema,
  type AuthorityRecord,
  type GrantRecordStore,
  type PolicySnapshotRecord,
  type PolicyStateStore,
  type StoredGrantRecord,
} from '@shun/authorization';
import { canonicalJson } from '@shun/contracts';

export interface DurableAuthorizationStoreOptions {
  /** Same SQLite file used by ShunStore. Multiple adapter instances may open it concurrently. */
  file: string;
}

interface PayloadRow {
  payload: string;
}

interface CountRow {
  count: number;
}

export class DurableAuthorizationStore implements PolicyStateStore, GrantRecordStore {
  readonly database: DatabaseSync;

  private readonly statements: {
    getAuthority: StatementSync;
    upsertAuthority: StatementSync;
    getPolicy: StatementSync;
    upsertPolicy: StatementSync;
    pruneNonces: StatementSync;
    getNonce: StatementSync;
    insertNonce: StatementSync;
    getGrant: StatementSync;
    insertGrant: StatementSync;
    countGrants: StatementSync;
  };

  private closed = false;

  constructor(options: DurableAuthorizationStoreOptions) {
    this.database = new DatabaseSync(options.file);
    this.database.exec('PRAGMA journal_mode = WAL');
    this.database.exec('PRAGMA synchronous = FULL');
    this.database.exec('PRAGMA busy_timeout = 5000');
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS authorization_authority_state (
        slot INTEGER PRIMARY KEY CHECK (slot = 1),
        payload TEXT NOT NULL,
        revision INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS authorization_policy_state (
        slot INTEGER PRIMARY KEY CHECK (slot = 1),
        payload TEXT NOT NULL,
        revision INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS authorization_grants (
        grant_id TEXT PRIMARY KEY,
        payload TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS authorization_issuance_nonces (
        nonce TEXT PRIMARY KEY,
        expires_at_ms INTEGER NOT NULL,
        consumed_at_ms INTEGER NOT NULL
      );
    `);

    this.statements = {
      getAuthority: this.database.prepare(
        'SELECT payload FROM authorization_authority_state WHERE slot = 1',
      ),
      upsertAuthority: this.database.prepare(`
        INSERT INTO authorization_authority_state (slot, payload, revision)
        VALUES (1, ?, 1)
        ON CONFLICT(slot) DO UPDATE SET
          payload = excluded.payload,
          revision = authorization_authority_state.revision + 1
      `),
      getPolicy: this.database.prepare(
        'SELECT payload FROM authorization_policy_state WHERE slot = 1',
      ),
      upsertPolicy: this.database.prepare(`
        INSERT INTO authorization_policy_state (slot, payload, revision)
        VALUES (1, ?, 1)
        ON CONFLICT(slot) DO UPDATE SET
          payload = excluded.payload,
          revision = authorization_policy_state.revision + 1
      `),
      pruneNonces: this.database.prepare(
        'DELETE FROM authorization_issuance_nonces WHERE expires_at_ms < ?',
      ),
      getNonce: this.database.prepare(
        'SELECT nonce FROM authorization_issuance_nonces WHERE nonce = ?',
      ),
      insertNonce: this.database.prepare(
        'INSERT INTO authorization_issuance_nonces (nonce, expires_at_ms, consumed_at_ms) VALUES (?, ?, ?)',
      ),
      getGrant: this.database.prepare(
        'SELECT payload FROM authorization_grants WHERE grant_id = ?',
      ),
      insertGrant: this.database.prepare(
        'INSERT INTO authorization_grants (grant_id, payload) VALUES (?, ?)',
      ),
      countGrants: this.database.prepare('SELECT COUNT(*) AS count FROM authorization_grants'),
    };
  }

  async loadAuthorityRecord(): Promise<unknown> {
    this.assertOpen();
    return this.readPayload(this.statements.getAuthority);
  }

  async loadCurrentPolicy(): Promise<unknown> {
    this.assertOpen();
    return this.readPayload(this.statements.getPolicy);
  }

  async saveAuthorityRecord(record: AuthorityRecord): Promise<void> {
    this.assertOpen();
    const parsed = AuthorityRecordSchema.parse(record);
    this.transaction(() => {
      this.statements.upsertAuthority.run(canonicalJson(parsed));
    });
  }

  async savePolicySnapshot(snapshot: PolicySnapshotRecord): Promise<void> {
    this.assertOpen();
    const parsed = PolicySnapshotRecordSchema.parse(snapshot);
    this.transaction(() => {
      this.statements.upsertPolicy.run(canonicalJson(parsed));
    });
  }

  async compareAndSaveAuthorityRecord(
    record: AuthorityRecord,
    expectedPrior: unknown,
  ): Promise<boolean> {
    this.assertOpen();
    const parsed = AuthorityRecordSchema.parse(record);
    return this.compareAndSave(
      this.statements.getAuthority,
      this.statements.upsertAuthority,
      parsed,
      expectedPrior,
    );
  }

  async compareAndSavePolicySnapshot(
    snapshot: PolicySnapshotRecord,
    expectedPrior: unknown,
  ): Promise<boolean> {
    this.assertOpen();
    const parsed = PolicySnapshotRecordSchema.parse(snapshot);
    return this.compareAndSave(
      this.statements.getPolicy,
      this.statements.upsertPolicy,
      parsed,
      expectedPrior,
    );
  }

  async consumeIssuanceNonce(
    nonce: string,
    expiresAtMs: number,
    nowMs: number,
  ): Promise<boolean> {
    this.assertOpen();
    if (
      nonce.length === 0 ||
      !Number.isSafeInteger(expiresAtMs) ||
      !Number.isSafeInteger(nowMs) ||
      expiresAtMs < nowMs
    ) {
      return false;
    }
    return this.transaction(() => {
      this.statements.pruneNonces.run(nowMs);
      if (this.statements.getNonce.get(nonce) !== undefined) {
        return false;
      }
      this.statements.insertNonce.run(nonce, expiresAtMs, nowMs);
      return true;
    });
  }

  async put(record: StoredGrantRecord): Promise<void> {
    this.assertOpen();
    const parsed = StoredGrantRecordSchema.parse(record);
    const payload = canonicalJson(parsed);
    this.transaction(() => {
      const row = this.statements.getGrant.get(parsed.grantId) as PayloadRow | undefined;
      if (row) {
        if (row.payload !== payload) {
          throw new Error(
            `authorization grant identity conflict for ${parsed.grantId}: durable grant ids are immutable`,
          );
        }
        return;
      }
      this.statements.insertGrant.run(parsed.grantId, payload);
    });
  }

  async get(grantId: string): Promise<unknown> {
    this.assertOpen();
    const row = this.statements.getGrant.get(grantId) as PayloadRow | undefined;
    return row ? JSON.parse(row.payload) : null;
  }

  async hasAnyGrant(): Promise<boolean> {
    this.assertOpen();
    const row = this.statements.countGrants.get() as CountRow;
    return row.count > 0;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.database.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    this.database.close();
  }

  private compareAndSave(
    getter: StatementSync,
    upsert: StatementSync,
    next: AuthorityRecord | PolicySnapshotRecord,
    expectedPrior: unknown,
  ): boolean {
    return this.transaction(() => {
      const row = getter.get() as PayloadRow | undefined;
      const current = row ? this.parsePayload(row.payload) : undefined;
      const expectedAbsent = expectedPrior === null || expectedPrior === undefined;
      if (expectedAbsent ? current !== undefined : current === undefined) {
        return false;
      }
      if (!expectedAbsent && canonicalJson(current) !== canonicalJson(expectedPrior)) {
        return false;
      }
      upsert.run(canonicalJson(next));
      return true;
    });
  }

  private readPayload(statement: StatementSync): unknown {
    const row = statement.get() as PayloadRow | undefined;
    return row ? this.parsePayload(row.payload) : undefined;
  }

  private parsePayload(payload: string): unknown {
    return JSON.parse(payload) as unknown;
  }

  private transaction<T>(operation: () => T): T {
    this.database.exec('BEGIN IMMEDIATE');
    try {
      const result = operation();
      this.database.exec('COMMIT');
      return result;
    } catch (error) {
      this.rollbackQuietly();
      throw error;
    }
  }

  private rollbackQuietly(): void {
    try {
      this.database.exec('ROLLBACK');
    } catch {
      // No active transaction is already safely rolled back.
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new Error('DurableAuthorizationStore is closed');
    }
  }
}
