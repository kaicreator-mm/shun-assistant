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

export type MutationPrecommitDecision =
  | { ok: true; state: 'DURABLY_PRECOMMITTED' }
  | { ok: false; code: 'PRECOMMIT_REFUSED' | 'PRECOMMIT_DIVERGENT' };

export type MutationPrecommitReadback =
  | { ok: true; commitment: unknown; commitmentSha256: string }
  | { ok: false; code: 'NOT_FOUND' | 'JOURNAL_REFUSED' };

export type MutationReconcileDispositionReadback =
  | {
      ok: true;
      disposition: FileMutationReconcileDisposition;
      evidenceSha256: string;
      automaticRetryAllowed: false;
    }
  | { ok: false; code: 'NOT_FOUND' | 'JOURNAL_REFUSED' };

/** T07 F04B2c post-hoc reconcile dispositions (never execution states).
 * PR #186 R1 P1-03: the *_PROVEN values were removed — no poststate
 * snapshot can witness that THIS attempt caused the observed world, so a
 * disposition may never claim proof of completion/non-execution. */
export const FILE_MUTATION_RECONCILE_DISPOSITIONS = [
  'COMPLETED_CONSISTENT',
  'NOT_EXECUTED_CONSISTENT',
  'MANUAL_RECONCILE_REQUIRED',
] as const;
export type FileMutationReconcileDisposition =
  (typeof FILE_MUTATION_RECONCILE_DISPOSITIONS)[number];

type Row = { intent_hash: string; state: string; evidence_sha256: string | null };
type PrecommitRow = { intent_hash: string; commitment_json: string; commitment_sha256: string };
type DispositionRow = { intent_hash: string; disposition: string; evidence_sha256: string };

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

const PRECOMMIT_SOURCE_KEYS = ['fileId', 'volumeSerial', 'size', 'sha256'] as const;
const PRECOMMIT_KEYS = [
  'kind',
  'actionId',
  'op',
  'sourcePath',
  'destinationPath',
  'source',
  'destinationPrestate',
] as const;
const PRECOMMIT_FILE_ID = /^\d{1,20}$/;

function plainOwnShape(value: unknown, keys: readonly string[]): boolean {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const own = Object.getOwnPropertyNames(value);
  return (
    own.length === keys.length &&
    keys.every((key) => Object.hasOwn(value as object, key)) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

/**
 * Fail-closed structural mirror of the F04B2a commitment the vertical-files
 * bridge mints (file-mutation-host.ts FileMutationPrecommitment), bound to
 * the exact action it is persisted for: actionId, op and both literal paths
 * must equal the action's own fields, so a commitment can never be filed
 * against a different intent than the one physically checkpointed. Only the
 * structural shape and binding are checked here — physical truth of the
 * pinned FileId/volume/size/digest belongs to the anchored bridge and the
 * independent poststate verifier.
 */
function admittedPrecommitment(
  raw: unknown,
  action: AuthorizedAction,
): { commitment: Record<string, unknown>; canonical: string } | null {
  if (!plainOwnShape(raw, PRECOMMIT_KEYS)) return null;
  const value = raw as Record<string, unknown>;
  if (value.kind !== 'file-mutation-precommit-v1') return null;
  if (value.actionId !== action.actionId) return null;
  if (value.op !== action.action.op) return null;
  const parameters = action.action.parameters as Record<string, unknown>;
  if (
    value.sourcePath !== parameters.sourcePath ||
    value.destinationPath !== parameters.destinationPath
  )
    return null;
  if (typeof value.actionId !== 'string' || typeof value.op !== 'string') return null;
  if (typeof value.sourcePath !== 'string' || typeof value.destinationPath !== 'string')
    return null;
  if (!plainOwnShape(value.source, PRECOMMIT_SOURCE_KEYS)) return null;
  const source = value.source as Record<string, unknown>;
  if (typeof source.fileId !== 'string' || !PRECOMMIT_FILE_ID.test(source.fileId)) return null;
  if (
    !Number.isSafeInteger(source.volumeSerial) ||
    (source.volumeSerial as number) < 0 ||
    (source.volumeSerial as number) > 0xffffffff
  )
    return null;
  if (
    !Number.isSafeInteger(source.size) ||
    (source.size as number) < 0 ||
    (source.size as number) > 8 << 20
  )
    return null;
  if (typeof source.sha256 !== 'string' || !validEvidenceHash(source.sha256)) return null;
  if (!plainOwnShape(value.destinationPrestate, ['destinationExisted'])) return null;
  if ((value.destinationPrestate as Record<string, unknown>).destinationExisted !== false)
    return null;
  return { commitment: value, canonical: canonicalJson(value) };
}

function db_row(store: ShunStore, action: AuthorizedAction): Row | undefined {
  return store.database
    .prepare(
      'SELECT intent_hash, state, evidence_sha256 FROM recipe_file_mutation_journal_v02 WHERE task_id=? AND action_id=?',
    )
    .get(action.taskId, action.actionId) as Row | undefined;
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
      // T07 F04B2a: the immutable pre-effect commitment, persisted write-once
      // with a durable readback BEFORE the first create or relocate exists.
      store.database.exec(`
        CREATE TABLE IF NOT EXISTS recipe_file_mutation_precommit_v02 (
          task_id TEXT NOT NULL,
          action_id TEXT NOT NULL,
          intent_hash TEXT NOT NULL,
          commitment_json TEXT NOT NULL,
          commitment_sha256 TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          PRIMARY KEY (task_id, action_id)
        )
      `);
      // T07 F04B2c: post-hoc reconcile dispositions. automatic_retry_allowed
      // is a constant 0 by CHECK: no disposition ever authorizes a retry.
      // PR #186 R1 P1-03: no *_PROVEN disposition exists (see
      // FILE_MUTATION_RECONCILE_DISPOSITIONS). Stores created by the earlier
      // F04B2 HEAD keep their wider historical CHECK; that superset can only
      // admit values this code no longer writes, and readback validates
      // against the narrowed vocabulary (an old *_PROVEN row reads
      // JOURNAL_REFUSED — fail-closed, never served as durable fact).
      store.database.exec(`
        CREATE TABLE IF NOT EXISTS recipe_file_mutation_reconcile_v02 (
          task_id TEXT NOT NULL,
          action_id TEXT NOT NULL,
          intent_hash TEXT NOT NULL,
          disposition TEXT NOT NULL CHECK (disposition IN (
            'COMPLETED_CONSISTENT', 'NOT_EXECUTED_CONSISTENT',
            'MANUAL_RECONCILE_REQUIRED'
          )),
          evidence_sha256 TEXT NOT NULL,
          automatic_retry_allowed INTEGER NOT NULL CHECK (automatic_retry_allowed = 0),
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

  /**
   * T07 F04B2a durable write-once pre-effect commitment. Requires the row to
   * be STARTED for the SAME intent; the commitment is structurally admitted
   * and bound to the exact action (actionId/op/literal paths). The FIRST
   * commitment for the (task, action) identity wins forever: an identical
   * re-write is idempotently accepted, any divergent payload refuses, and no
   * state transition can ever rewrite it. The stored bytes are verified by a
   * post-COMMIT readback before success is reported.
   */
  writePrecommit(raw: unknown, commitment: unknown): MutationPrecommitDecision {
    const intent = intentOf(raw);
    if (!intent) return { ok: false, code: 'PRECOMMIT_REFUSED' };
    const admitted = admittedPrecommitment(commitment, intent.action);
    if (!admitted) return { ok: false, code: 'PRECOMMIT_REFUSED' };
    const sha = createHash('sha256').update(admitted.canonical).digest('hex');
    const db = this.store.database;
    try {
      if (!this.hasDurableMode() || this.readBackingFile() !== this.backingFile) {
        return { ok: false, code: 'PRECOMMIT_REFUSED' };
      }
      db.exec('BEGIN IMMEDIATE');
      const { action, digest } = intent;
      const row = db
        .prepare(
          'SELECT intent_hash, state FROM recipe_file_mutation_journal_v02 WHERE task_id=? AND action_id=?',
        )
        .get(action.taskId, action.actionId) as { intent_hash: string; state: string } | undefined;
      if (!row || row.intent_hash !== digest || row.state !== 'STARTED') {
        db.exec('ROLLBACK');
        return { ok: false, code: 'PRECOMMIT_REFUSED' };
      }
      const existing = db
        .prepare(
          'SELECT intent_hash, commitment_sha256 FROM recipe_file_mutation_precommit_v02 WHERE task_id=? AND action_id=?',
        )
        .get(action.taskId, action.actionId) as
        | { intent_hash: string; commitment_sha256: string }
        | undefined;
      if (existing) {
        db.exec('ROLLBACK');
        return existing.intent_hash === digest && existing.commitment_sha256 === sha
          ? { ok: true, state: 'DURABLY_PRECOMMITTED' }
          : { ok: false, code: 'PRECOMMIT_DIVERGENT' };
      }
      db.prepare(
        'INSERT INTO recipe_file_mutation_precommit_v02 (task_id, action_id, intent_hash, commitment_json, commitment_sha256, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
      ).run(
        action.taskId,
        action.actionId,
        digest,
        admitted.canonical,
        sha,
        new Date().toISOString(),
      );
      db.exec('COMMIT');
      // Durable readback: the physically stored bytes must hash to the same
      // commitment before success is reported.
      const back = db
        .prepare(
          'SELECT commitment_sha256 FROM recipe_file_mutation_precommit_v02 WHERE task_id=? AND action_id=?',
        )
        .get(action.taskId, action.actionId) as { commitment_sha256: string } | undefined;
      if (!back || back.commitment_sha256 !== sha) {
        return { ok: false, code: 'PRECOMMIT_REFUSED' };
      }
      return { ok: true, state: 'DURABLY_PRECOMMITTED' };
    } catch {
      this.rollbackQuietly();
      return { ok: false, code: 'PRECOMMIT_REFUSED' };
    }
  }

  /**
   * Read back the immutable commitment for one attempt identity. The payload
   * is re-validated on read (shape + canonical hash) and returned as plain
   * data — never as execution authority of any kind.
   */
  readPrecommit(raw: unknown): MutationPrecommitReadback {
    const intent = intentOf(raw);
    if (!intent) return { ok: false, code: 'JOURNAL_REFUSED' };
    try {
      const { action, digest } = intent;
      const row = db_row(this.store, action);
      if (!row || row.intent_hash !== digest) return { ok: false, code: 'JOURNAL_REFUSED' };
      const precommit = this.store.database
        .prepare(
          'SELECT intent_hash, commitment_json, commitment_sha256 FROM recipe_file_mutation_precommit_v02 WHERE task_id=? AND action_id=?',
        )
        .get(action.taskId, action.actionId) as PrecommitRow | undefined;
      if (!precommit) return { ok: false, code: 'NOT_FOUND' };
      if (precommit.intent_hash !== digest) return { ok: false, code: 'JOURNAL_REFUSED' };
      let parsed: unknown;
      try {
        parsed = JSON.parse(precommit.commitment_json);
      } catch {
        return { ok: false, code: 'JOURNAL_REFUSED' };
      }
      if (
        createHash('sha256').update(canonicalJson(parsed)).digest('hex') !==
          precommit.commitment_sha256 ||
        !admittedPrecommitment(parsed, intent.action)
      )
        return { ok: false, code: 'JOURNAL_REFUSED' };
      return { ok: true, commitment: parsed, commitmentSha256: precommit.commitment_sha256 };
    } catch {
      return { ok: false, code: 'JOURNAL_REFUSED' };
    }
  }

  /**
   * T07 F04B2c: persist one post-hoc reconcile disposition, atomically and
   * idempotently. Write-once like every other durable fact here: an identical
   * re-record is accepted, any divergence refuses. This NEVER touches the
   * journal row's STARTED/UNCERTAIN/COMMITTED_VERIFIED state and carries
   * automatic_retry_allowed = 0 structurally — a disposition is an analysis
   * record, not a replay authorization.
   */
  recordReconcileDisposition(
    raw: unknown,
    disposition: FileMutationReconcileDisposition,
    evidenceSha256: string,
  ): boolean {
    const intent = intentOf(raw);
    if (
      !intent ||
      !validEvidenceHash(evidenceSha256) ||
      !(FILE_MUTATION_RECONCILE_DISPOSITIONS as readonly string[]).includes(disposition)
    )
      return false;
    const db = this.store.database;
    try {
      if (!this.hasDurableMode() || this.readBackingFile() !== this.backingFile) return false;
      db.exec('BEGIN IMMEDIATE');
      const { action, digest } = intent;
      const row = db
        .prepare(
          'SELECT intent_hash FROM recipe_file_mutation_journal_v02 WHERE task_id=? AND action_id=?',
        )
        .get(action.taskId, action.actionId) as { intent_hash: string } | undefined;
      if (!row || row.intent_hash !== digest) {
        db.exec('ROLLBACK');
        return false;
      }
      const existing = db
        .prepare(
          'SELECT intent_hash, disposition, evidence_sha256 FROM recipe_file_mutation_reconcile_v02 WHERE task_id=? AND action_id=?',
        )
        .get(action.taskId, action.actionId) as DispositionRow | undefined;
      if (existing) {
        db.exec('ROLLBACK');
        return (
          existing.intent_hash === digest &&
          existing.disposition === disposition &&
          existing.evidence_sha256 === evidenceSha256
        );
      }
      db.prepare(
        'INSERT INTO recipe_file_mutation_reconcile_v02 (task_id, action_id, intent_hash, disposition, evidence_sha256, automatic_retry_allowed, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?)',
      ).run(
        action.taskId,
        action.actionId,
        digest,
        disposition,
        evidenceSha256,
        new Date().toISOString(),
      );
      db.exec('COMMIT');
      return true;
    } catch {
      this.rollbackQuietly();
      return false;
    }
  }

  /** Read back the persisted reconcile disposition for one attempt identity. */
  readReconcileDisposition(raw: unknown): MutationReconcileDispositionReadback {
    const intent = intentOf(raw);
    if (!intent) return { ok: false, code: 'JOURNAL_REFUSED' };
    try {
      const { action, digest } = intent;
      const row = db_row(this.store, action);
      if (!row || row.intent_hash !== digest) return { ok: false, code: 'JOURNAL_REFUSED' };
      const disposition = this.store.database
        .prepare(
          'SELECT intent_hash, disposition, evidence_sha256 FROM recipe_file_mutation_reconcile_v02 WHERE task_id=? AND action_id=?',
        )
        .get(action.taskId, action.actionId) as DispositionRow | undefined;
      if (!disposition) return { ok: false, code: 'NOT_FOUND' };
      if (
        disposition.intent_hash !== digest ||
        !(FILE_MUTATION_RECONCILE_DISPOSITIONS as readonly string[]).includes(
          disposition.disposition,
        ) ||
        !validEvidenceHash(disposition.evidence_sha256)
      )
        return { ok: false, code: 'JOURNAL_REFUSED' };
      return {
        ok: true,
        disposition: disposition.disposition as FileMutationReconcileDisposition,
        evidenceSha256: disposition.evidence_sha256,
        automaticRetryAllowed: false,
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
