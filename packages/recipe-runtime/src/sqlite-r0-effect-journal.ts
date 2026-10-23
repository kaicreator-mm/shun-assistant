// T04 private SQLite pre-effect reservation ledger. NOT a grant verifier,
// executor, authorization policy, receipt verifier, or task PASS oracle.
// A durable STARTED row that outlives a process is UNKNOWN until a separate
// reconcile-first verifier proves its effect state; never auto-replay it.
import { createHash } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { type AuthorizedAction, AuthorizedActionSchema, canonicalJson } from '@shun/contracts';
import { ShunStore } from '@shun/store';

type TerminalObservation = 'OBSERVED_NOT_SEMANTICALLY_VERIFIED' | 'UNCERTAIN';
type JournalState = 'STARTED' | TerminalObservation;

export type ReservationDecision =
  | { ok: true; state: 'DURABLY_RESERVED'; semanticVerified: false }
  | { ok: false; code: 'RECONCILE_REQUIRED' | 'JOURNAL_REFUSED' };

export type JournalReadback =
  | { ok: true; state: JournalState; receiptSha256: string | null; semanticVerified: false }
  | { ok: false; code: 'NOT_FOUND' | 'JOURNAL_REFUSED' };

type Row = { intent_hash: string; state: string; receipt_sha256: string | null };

function intentOf(raw: unknown): { action: AuthorizedAction; digest: string } | null {
  const parsed = AuthorizedActionSchema.safeParse(raw);
  if (!parsed.success) return null;
  const action = parsed.data;
  if (
    action.action.op !== 'file.search' ||
    action.action.sideEffectClass !== 'R0' ||
    action.action.requiredPrivilege !== 'USER'
  )
    return null;
  return {
    action,
    digest: createHash('sha256').update(canonicalJson(action)).digest('hex'),
  };
}

function validReceiptHash(hash: unknown): hash is string {
  return typeof hash === 'string' && /^[a-f0-9]{64}$/.test(hash);
}

/**
 * A separate SQLite table, on the SAME local fixed-disk ShunStore DB, uses
 * BEGIN IMMEDIATE and a unique (task, action) identity to serialize attempts
 * across processes. It records an immutable pre-effect reservation; it cannot
 * retrospectively prove whether an interrupted OS effect ran.
 */
export class SqliteR0EffectJournal {
  private readonly store: ShunStore;
  private readonly backingFile: string;

  constructor(store: ShunStore) {
    if (!(store instanceof ShunStore)) throw new Error('R0_JOURNAL_CONFIGURATION_REFUSED');
    this.store = store;
    try {
      const candidate = this.readBackingFile();
      if (!candidate || !this.hasDurableMode()) {
        throw new Error('R0_JOURNAL_CONFIGURATION_REFUSED');
      }
      this.backingFile = candidate;
      store.database.exec(`
        CREATE TABLE IF NOT EXISTS recipe_r0_effect_journal_v02 (
          task_id TEXT NOT NULL,
          action_id TEXT NOT NULL,
          intent_hash TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN (
            'STARTED', 'OBSERVED_NOT_SEMANTICALLY_VERIFIED', 'UNCERTAIN'
          )),
          receipt_sha256 TEXT,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (task_id, action_id)
        )
      `);
    } catch {
      throw new Error('R0_JOURNAL_CONFIGURATION_REFUSED');
    }
  }

  reserve(raw: unknown): ReservationDecision {
    const intent = intentOf(raw);
    if (!intent) return { ok: false, code: 'JOURNAL_REFUSED' };
    const { action, digest } = intent;
    const db = this.store.database;
    try {
      if (!this.hasDurableMode() || this.readBackingFile() !== this.backingFile) {
        return { ok: false, code: 'JOURNAL_REFUSED' };
      }
      db.exec('BEGIN IMMEDIATE');
      const existing = db
        .prepare(
          'SELECT intent_hash, state, receipt_sha256 FROM recipe_r0_effect_journal_v02 WHERE task_id=? AND action_id=?',
        )
        .get(action.taskId, action.actionId) as Row | undefined;
      if (existing) {
        db.exec('ROLLBACK');
        // The same attempt is never auto-replayed after STARTED, even
        // when a previous receipt claims success or a different plan is used.
        return existing.intent_hash === digest
          ? { ok: false, code: 'RECONCILE_REQUIRED' }
          : { ok: false, code: 'JOURNAL_REFUSED' };
      }
      db.prepare(
        'INSERT INTO recipe_r0_effect_journal_v02 (task_id, action_id, intent_hash, state, receipt_sha256, updated_at) VALUES (?, ?, ?, ?, NULL, ?)',
      ).run(action.taskId, action.actionId, digest, 'STARTED', new Date().toISOString());
      db.exec('COMMIT');
      return { ok: true, state: 'DURABLY_RESERVED', semanticVerified: false };
    } catch {
      this.rollbackQuietly();
      return { ok: false, code: 'JOURNAL_REFUSED' };
    }
  }

  /**
   * The private reconciler may record its bounded observation, but the
   * ledger never upgrades it to semantic PASS or re-authorizes execution.
   */
  recordObservation(raw: unknown, state: TerminalObservation, receiptSha256: string): boolean {
    const intent = intentOf(raw);
    if (
      !intent ||
      !validReceiptHash(receiptSha256) ||
      (state !== 'OBSERVED_NOT_SEMANTICALLY_VERIFIED' && state !== 'UNCERTAIN')
    )
      return false;
    const db = this.store.database;
    try {
      if (!this.hasDurableMode() || this.readBackingFile() !== this.backingFile) return false;
      db.exec('BEGIN IMMEDIATE');
      const { action, digest } = intent;
      const existing = db
        .prepare(
          'SELECT intent_hash, state, receipt_sha256 FROM recipe_r0_effect_journal_v02 WHERE task_id=? AND action_id=?',
        )
        .get(action.taskId, action.actionId) as Row | undefined;
      if (!existing || existing.intent_hash !== digest) {
        db.exec('ROLLBACK');
        return false;
      }
      if (existing.state !== 'STARTED') {
        db.exec('ROLLBACK');
        return existing.state === state && existing.receipt_sha256 === receiptSha256;
      }
      db.prepare(
        "UPDATE recipe_r0_effect_journal_v02 SET state=?, receipt_sha256=?, updated_at=? WHERE task_id=? AND action_id=? AND intent_hash=? AND state='STARTED'",
      ).run(state, receiptSha256, new Date().toISOString(), action.taskId, action.actionId, digest);
      db.exec('COMMIT');
      return true;
    } catch {
      this.rollbackQuietly();
      return false;
    }
  }

  lookup(raw: unknown): JournalReadback {
    const intent = intentOf(raw);
    if (!intent) return { ok: false, code: 'JOURNAL_REFUSED' };
    try {
      const row = this.store.database
        .prepare(
          'SELECT intent_hash, state, receipt_sha256 FROM recipe_r0_effect_journal_v02 WHERE task_id=? AND action_id=?',
        )
        .get(intent.action.taskId, intent.action.actionId) as Row | undefined;
      if (!row) return { ok: false, code: 'NOT_FOUND' };
      if (
        row.intent_hash !== intent.digest ||
        !['STARTED', 'OBSERVED_NOT_SEMANTICALLY_VERIFIED', 'UNCERTAIN'].includes(row.state) ||
        (row.receipt_sha256 !== null && !validReceiptHash(row.receipt_sha256))
      )
        return { ok: false, code: 'JOURNAL_REFUSED' };
      return {
        ok: true,
        state: row.state as JournalState,
        receiptSha256: row.receipt_sha256,
        semanticVerified: false,
      };
    } catch {
      return { ok: false, code: 'JOURNAL_REFUSED' };
    }
  }

  /** An in-memory or temporary SQLite database cannot prove crash-safe reservation. */
  private readBackingFile(): string | null {
    const rows = this.store.database.prepare('PRAGMA database_list').all() as Array<{
      name: string;
      file: string;
    }>;
    const file = rows.find((row) => row.name === 'main')?.file;
    if (
      !file ||
      !isAbsolute(file) ||
      file.startsWith('\\\\') ||
      file.startsWith('//') ||
      file.includes('\0')
    )
      return null;
    return file;
  }

  private hasDurableMode(): boolean {
    const mode = this.store.database.prepare('PRAGMA main.journal_mode').get() as
      | { journal_mode: string }
      | undefined;
    const sync = this.store.database.prepare('PRAGMA main.synchronous').get() as
      | { synchronous: number }
      | undefined;
    return mode?.journal_mode.toLowerCase() === 'wal' && (sync?.synchronous ?? 0) >= 2;
  }

  private rollbackQuietly(): void {
    try {
      this.store.database.exec('ROLLBACK');
    } catch {
      // Transaction not active or connection closed; fail closed.
    }
  }
}
