// Durable AuthorizationAuthority backing on the same SQLite database as ShunStore.
//
// L2 §4.6.1 requires current authority/policy state, one-shot issuance proofs,
// and authorization grants to survive process restarts and to be coherent
// across authority instances. The authorization package owns the schemas and
// authority semantics; this module owns only the durable SQLite adapter.
//
// Dedicated tables are intentional: authority records, grant records and
// issuance nonces are not mislabeled as unrelated generic ShunStoreRecordKind
// values. All compare-and-save and nonce check-and-set operations use
// BEGIN IMMEDIATE so distinct SQLite connections serialize the decision+write.
import type { StatementSync } from 'node:sqlite';
import {
  type AuthorityRecord,
  AuthorityRecordSchema,
  type GrantRecordStore,
  type PolicySnapshotRecord,
  PolicySnapshotRecordSchema,
  type PolicyStateStore,
  type StoredGrantRecord,
  StoredGrantRecordSchema,
} from '@shun/authorization';
import { canonicalJson } from '@shun/contracts';
import {
  ShunStoreAuthorizationConflictError,
  ShunStoreInvalidMutationError,
  ShunStoreWriteFailedError,
} from './errors.ts';
import type { ShunStore } from './shun-store.ts';

type Slot = 'authority' | 'policy';

interface StateRow {
  payload: string;
}

interface GrantRow {
  record: string;
}

export class ShunStoreAuthorizationAdapter implements PolicyStateStore, GrantRecordStore {
  readonly #store: ShunStore;
  readonly #statements: {
    readState: StatementSync;
    upsertState: StatementSync;
    insertGrant: StatementSync;
    readGrant: StatementSync;
    anyGrant: StatementSync;
    pruneNonces: StatementSync;
    insertNonce: StatementSync;
  };

  constructor(store: ShunStore) {
    this.#store = store;
    try {
      store.database.exec(`
        CREATE TABLE IF NOT EXISTS authorization_state (
          slot TEXT PRIMARY KEY CHECK (slot IN ('authority', 'policy')),
          payload TEXT NOT NULL
        )
      `);
      store.database.exec(`
        CREATE TABLE IF NOT EXISTS authorization_grants (
          grant_id TEXT PRIMARY KEY,
          record TEXT NOT NULL
        )
      `);
      store.database.exec(`
        CREATE TABLE IF NOT EXISTS authorization_issuance_nonces (
          nonce TEXT PRIMARY KEY,
          expires_at_ms INTEGER NOT NULL
        )
      `);
      this.#statements = {
        readState: store.database.prepare('SELECT payload FROM authorization_state WHERE slot = ?'),
        upsertState: store.database.prepare(`
          INSERT INTO authorization_state (slot, payload)
          VALUES (?, ?)
          ON CONFLICT(slot) DO UPDATE SET payload = excluded.payload
        `),
        insertGrant: store.database.prepare(
          'INSERT INTO authorization_grants (grant_id, record) VALUES (?, ?)',
        ),
        readGrant: store.database.prepare(
          'SELECT record FROM authorization_grants WHERE grant_id = ?',
        ),
        anyGrant: store.database.prepare('SELECT 1 AS present FROM authorization_grants LIMIT 1'),
        pruneNonces: store.database.prepare(
          'DELETE FROM authorization_issuance_nonces WHERE expires_at_ms < ?',
        ),
        insertNonce: store.database.prepare(
          'INSERT OR IGNORE INTO authorization_issuance_nonces (nonce, expires_at_ms) VALUES (?, ?)',
        ),
      };
    } catch (cause) {
      throw new ShunStoreWriteFailedError('failed to initialize durable authorization tables', {
        cause,
      });
    }
  }

  async loadAuthorityRecord(): Promise<unknown> {
    return this.#loadSlot('authority');
  }

  async loadCurrentPolicy(): Promise<unknown> {
    return this.#loadSlot('policy');
  }

  async saveAuthorityRecord(record: AuthorityRecord): Promise<void> {
    const parsed = AuthorityRecordSchema.safeParse(record);
    if (!parsed.success) {
      throw new ShunStoreInvalidMutationError('invalid authorization authority record', {
        cause: parsed.error,
      });
    }
    this.#transaction('save authority record', () => {
      this.#statements.upsertState.run('authority', canonicalJson(parsed.data));
    });
  }

  async savePolicySnapshot(snapshot: PolicySnapshotRecord): Promise<void> {
    const parsed = PolicySnapshotRecordSchema.safeParse(snapshot);
    if (!parsed.success) {
      throw new ShunStoreInvalidMutationError('invalid authorization policy snapshot', {
        cause: parsed.error,
      });
    }
    this.#transaction('save policy snapshot', () => {
      this.#statements.upsertState.run('policy', canonicalJson(parsed.data));
    });
  }

  async compareAndSavePolicySnapshot(
    snapshot: PolicySnapshotRecord,
    expectedPrior: unknown,
  ): Promise<boolean> {
    const parsed = PolicySnapshotRecordSchema.safeParse(snapshot);
    if (!parsed.success) {
      throw new ShunStoreInvalidMutationError('invalid authorization policy snapshot', {
        cause: parsed.error,
      });
    }
    return this.#compareAndSave('policy', parsed.data, expectedPrior);
  }

  async compareAndSaveAuthorityRecord(
    record: AuthorityRecord,
    expectedPrior: unknown,
  ): Promise<boolean> {
    const parsed = AuthorityRecordSchema.safeParse(record);
    if (!parsed.success) {
      throw new ShunStoreInvalidMutationError('invalid authorization authority record', {
        cause: parsed.error,
      });
    }
    return this.#compareAndSave('authority', parsed.data, expectedPrior);
  }

  async consumeIssuanceNonce(nonce: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    if (
      typeof nonce !== 'string' ||
      nonce.length === 0 ||
      nonce.length > 512 ||
      !Number.isSafeInteger(expiresAtMs) ||
      !Number.isSafeInteger(nowMs)
    ) {
      throw new ShunStoreInvalidMutationError('invalid authorization issuance nonce record');
    }
    if (expiresAtMs < nowMs) {
      return false;
    }
    return this.#transaction('consume issuance nonce', () => {
      this.#statements.pruneNonces.run(nowMs);
      const result = this.#statements.insertNonce.run(nonce, expiresAtMs);
      return Number(result.changes) === 1;
    });
  }

  async put(record: StoredGrantRecord): Promise<void> {
    const parsed = StoredGrantRecordSchema.safeParse(record);
    if (!parsed.success) {
      throw new ShunStoreInvalidMutationError('invalid durable authorization grant record', {
        cause: parsed.error,
      });
    }
    if (parsed.data.grantId !== parsed.data.grant.grantId) {
      throw new ShunStoreInvalidMutationError(
        'durable grant record id does not match the embedded authorization grant id',
      );
    }
    const encoded = canonicalJson(parsed.data);
    this.#transaction('persist authorization grant', () => {
      const existing = this.#statements.readGrant.get(parsed.data.grantId) as GrantRow | undefined;
      if (existing) {
        if (existing.record === encoded) return;
        throw new ShunStoreAuthorizationConflictError(
          `authorization grant identity conflict for ${parsed.data.grantId}`,
        );
      }
      this.#statements.insertGrant.run(parsed.data.grantId, encoded);
    });
  }

  async get(grantId: string): Promise<unknown> {
    if (typeof grantId !== 'string' || grantId.length === 0) {
      throw new ShunStoreInvalidMutationError('grantId must be a non-empty string');
    }
    try {
      const row = this.#statements.readGrant.get(grantId) as GrantRow | undefined;
      return row ? JSON.parse(row.record) : null;
    } catch (cause) {
      throw new ShunStoreWriteFailedError(`failed to read authorization grant ${grantId}`, {
        cause,
      });
    }
  }

  async hasAnyGrant(): Promise<boolean> {
    try {
      return this.#statements.anyGrant.get() !== undefined;
    } catch (cause) {
      throw new ShunStoreWriteFailedError('failed to inspect durable authorization grants', {
        cause,
      });
    }
  }

  #loadSlot(slot: Slot): unknown {
    try {
      const row = this.#statements.readState.get(slot) as StateRow | undefined;
      return row ? JSON.parse(row.payload) : null;
    } catch (cause) {
      throw new ShunStoreWriteFailedError(`failed to read authorization ${slot} state`, {
        cause,
      });
    }
  }

  #compareAndSave(slot: Slot, next: object, expectedPrior: unknown): boolean {
    return this.#transaction(`compare-and-save authorization ${slot}`, () => {
      const row = this.#statements.readState.get(slot) as StateRow | undefined;
      const matches =
        expectedPrior === null || expectedPrior === undefined
          ? row === undefined
          : row !== undefined && row.payload === canonicalJson(expectedPrior);
      if (!matches) return false;
      this.#statements.upsertState.run(slot, canonicalJson(next));
      return true;
    });
  }

  #transaction<T>(operation: string, action: () => T): T {
    try {
      this.#store.database.exec('BEGIN IMMEDIATE');
      const result = action();
      this.#store.database.exec('COMMIT');
      return result;
    } catch (cause) {
      try {
        this.#store.database.exec('ROLLBACK');
      } catch {
        // The database may already have rejected BEGIN or become unavailable.
      }
      if (
        cause instanceof ShunStoreInvalidMutationError ||
        cause instanceof ShunStoreAuthorizationConflictError
      ) {
        throw cause;
      }
      throw new ShunStoreWriteFailedError(`${operation} failed`, { cause });
    }
  }
}
