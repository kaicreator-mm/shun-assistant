// T07 F03 private SQLite pre-effect reservation ledger for authorized file
// mutations (file.copy / file.move / file.rename). NOT a grant verifier,
// executor, authorization policy, receipt verifier, or reconcile authority.
// A durable STARTED row that outlives a process is UNKNOWN until a separate
// reconcile-first verifier (F04) proves its effect state; it is never
// auto-replayed — the same (task, action) identity is refused forever after,
// regardless of the row's terminal or the intent presented next.
import { createHash } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { type AuthorizedAction, AuthorizedActionSchema, canonicalJson } from '@shun/contracts';
import { ShunStore } from '@shun/store';

/** The three T07 F03 mutation ops (aligned with the F01 preview contract). */
export const FILE_MUTATION_OPS = ['file.copy', 'file.move', 'file.rename'] as const;
export type FileMutationOp = (typeof FILE_MUTATION_OPS)[number];

type MutationTerminal = 'COMMITTED_VERIFIED' | 'UNCERTAIN';
export type FileMutationJournalState = 'STARTED' | MutationTerminal;

export type MutationReservationDecision =
  | { ok: true; state: 'DURABLY_RESERVED' }
  | { ok: false; code: 'RECONCILE_REQUIRED' | 'JOURNAL_REFUSED' };

export type MutationJournalReadback =
  | { ok: true; state: FileMutationJournalState; evidenceSha256: string | null }
  | { ok: false; code: 'NOT_FOUND' | 'JOURNAL_REFUSED' };

type Row = { intent_hash: string; state: string; evidence_sha256: string | null };

function intentOf(raw: unknown): { action: AuthorizedAction; digest: string } | null {
  const parsed = AuthorizedActionSchema.safeParse(raw);
  if (!parsed.success) return null;
  const action = parsed.data;
  if (
    !(FILE_MUTATION_OPS as readonly string[]).includes(action.action.op) ||
    action.action.sideEffectClass !== 'R2' ||
    action.action.requiredPrivilege !== 'USER'
  )
    return null;
  return {
    action,
    digest: createHash('sha256').update(canonicalJson(action)).digest('hex'),
  };
}

function validEvidenceHash(hash: unknown): hash is string {
  return typeof hash === 'string' && /^[a-f0-9]{64}$/.test(hash);
}

/** Private-to-recipe-runtime SQLite admission: no volatile file/UNC/NUL alias. */
function isSafeJournalMainFile(file: string | undefined): file is string {
  return (
    typeof file === 'string' &&
    file.length > 0 &&
    isAbsolute(file) &&
    !file.startsWith('\\\\') &&
    !file.startsWith('//') &&
    !file.includes('\0')
  );
}

/**
 * A separate SQLite table on the SAME local fixed-disk ShunStore DB the
 * trusted host bootstraps, using BEGIN IMMEDIATE and a unique (task, action)
 * identity to serialize attempts across processes. It records an immutable
 * pre-effect reservation; it cannot retrospectively prove whether an
 * interrupted OS effect ran, and nothing here ever upgrades a row to a
 * semantic PASS or re-authorizes execution.
 */
export class SqliteFileMutationJournal {
  private readonly store: ShunStore;
  private readonly backingFile: string;

  constructor(store: ShunStore) {
    if (!(store instanceof ShunStore))
      throw new Error('FILE_MUTATION_JOURNAL_CONFIGURATION_REFUSED');
    this.store = store;
    try {
      const candidate = this.readBackingFile();
      if (!candidate || !this.hasDurableMode()) {
        throw new Error('FILE_MUTATION_JOURNAL_CONFIGURATION_REFUSED');
      }
      this.backingFile = candidate;
      store.database.exec(`
        CREATE TABLE IF NOT EXISTS recipe_file_mutation_journal_v02 (
          task_id TEXT NOT NULL,
          action_id TEXT NOT NULL,
          intent_hash TEXT NOT NULL,
          state TEXT NOT NULL CHECK (state IN (
            'STARTED', 'COMMITTED_VERIFIED', 'UNCERTAIN'
          )),
          evidence_sha256 TEXT,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (task_id, action_id)
        )
      `);
    } catch {
      throw new Error('FILE_MUTATION_JOURNAL_CONFIGURATION_REFUSED');
    }
  }

  /**
   * Durably reserve one mutation attempt BEFORE any file effect. The row is
   * write-once: ANY existing row for the (task, action) identity — STARTED,
   * COMMITTED_VERIFIED or UNCERTAIN, same or different intent — refuses a
   * second attempt. An interrupted effect therefore can never be replayed
   * through this ledger, not even by re-presenting the identical action.
   */
  reserve(raw: unknown): MutationReservationDecision {
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
          'SELECT intent_hash, state, evidence_sha256 FROM recipe_file_mutation_journal_v02 WHERE task_id=? AND action_id=?',
        )
        .get(action.taskId, action.actionId) as Row | undefined;
      if (existing) {
        db.exec('ROLLBACK');
        // No replay, no divergence disclosure: both outcomes refuse.
        return existing.intent_hash === digest
          ? { ok: false, code: 'RECONCILE_REQUIRED' }
          : { ok: false, code: 'JOURNAL_REFUSED' };
      }
      db.prepare(
        "INSERT INTO recipe_file_mutation_journal_v02 (task_id, action_id, intent_hash, state, evidence_sha256, updated_at) VALUES (?, ?, ?, 'STARTED', NULL, ?)",
      ).run(action.taskId, action.actionId, digest, new Date().toISOString());
      db.exec('COMMIT');
      return { ok: true, state: 'DURABLY_RESERVED' };
    } catch {
      this.rollbackQuietly();
      return { ok: false, code: 'JOURNAL_REFUSED' };
    }
  }

  /** Readback of the durable row (the host re-reads STARTED before any IO). */
  lookup(raw: unknown): MutationJournalReadback {
    const intent = intentOf(raw);
    if (!intent) return { ok: false, code: 'JOURNAL_REFUSED' };
    try {
      const row = this.store.database
        .prepare(
          'SELECT intent_hash, state, evidence_sha256 FROM recipe_file_mutation_journal_v02 WHERE task_id=? AND action_id=?',
        )
        .get(intent.action.taskId, intent.action.actionId) as Row | undefined;
      if (!row) return { ok: false, code: 'NOT_FOUND' };
      if (
        row.intent_hash !== intent.digest ||
        !['STARTED', 'COMMITTED_VERIFIED', 'UNCERTAIN'].includes(row.state) ||
        (row.evidence_sha256 !== null && !validEvidenceHash(row.evidence_sha256))
      )
        return { ok: false, code: 'JOURNAL_REFUSED' };
      return {
        ok: true,
        state: row.state as FileMutationJournalState,
        evidenceSha256: row.evidence_sha256,
      };
    } catch {
      return { ok: false, code: 'JOURNAL_REFUSED' };
    }
  }

  /**
   * Record the trusted host's bounded terminal classification. A STARTED row
   * transitions once; an identical re-record is idempotent, any divergence
   * refuses. The ledger never upgrades UNCERTAIN to COMMITTED on caller
   * assertion alone — only this CAS from STARTED, executed by the host that
   * owns the journal, writes COMMITTED_VERIFIED.
   */
  recordOutcome(raw: unknown, state: MutationTerminal, evidenceSha256: string): boolean {
    const intent = intentOf(raw);
    if (
      !intent ||
      !validEvidenceHash(evidenceSha256) ||
      (state !== 'COMMITTED_VERIFIED' && state !== 'UNCERTAIN')
    )
      return false;
    const db = this.store.database;
    try {
      if (!this.hasDurableMode() || this.readBackingFile() !== this.backingFile) return false;
      db.exec('BEGIN IMMEDIATE');
      const { action, digest } = intent;
      const existing = db
        .prepare(
          'SELECT intent_hash, state, evidence_sha256 FROM recipe_file_mutation_journal_v02 WHERE task_id=? AND action_id=?',
        )
        .get(action.taskId, action.actionId) as Row | undefined;
      if (!existing || existing.intent_hash !== digest) {
        db.exec('ROLLBACK');
        return false;
      }
      if (existing.state !== 'STARTED') {
        db.exec('ROLLBACK');
        return existing.state === state && existing.evidence_sha256 === evidenceSha256;
      }
      db.prepare(
        "UPDATE recipe_file_mutation_journal_v02 SET state=?, evidence_sha256=?, updated_at=? WHERE task_id=? AND action_id=? AND intent_hash=? AND state='STARTED'",
      ).run(
        state,
        evidenceSha256,
        new Date().toISOString(),
        action.taskId,
        action.actionId,
        digest,
      );
      db.exec('COMMIT');
      return true;
    } catch {
      this.rollbackQuietly();
      return false;
    }
  }

  /** An in-memory or temporary SQLite database cannot prove crash-safe reservation. */
  private readBackingFile(): string | null {
    const rows = this.store.database.prepare('PRAGMA database_list').all() as Array<{
      name: string;
      file: string;
    }>;
    const file = rows.find((row) => row.name === 'main')?.file;
    return isSafeJournalMainFile(file) ? file : null;
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
