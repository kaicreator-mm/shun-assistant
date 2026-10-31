/**
 * Durable SQLite V10DocStore implementation for the ONE selected public
 * DomainHarness K. This is K's own CAS document persistence, not a second
 * ActionController/effect Journal or an alternative dispatcher.
 *
 * The Store is created from a trusted Host filesystem path, never HTTP.
 */
import { DatabaseSync } from 'node:sqlite';

export type V10WriteCondition =
  | Readonly<{ kind: 'create' }>
  | Readonly<{ kind: 'revision'; revision: number }>;

type Row = { readonly value_json: string; readonly revision: number };

export class SqliteKernelDocStore {
  readonly #db: DatabaseSync;
  constructor(file: string) {
    if (!file || file === ':memory:') throw new TypeError('K_DOC_STORE_DURABLE_FILE_REQUIRED');
    this.#db = new DatabaseSync(file);
    this.#db.exec('PRAGMA journal_mode=WAL');
    this.#db.exec('PRAGMA synchronous=FULL');
    this.#db.exec('PRAGMA busy_timeout=5000');
    this.#db.exec(`CREATE TABLE IF NOT EXISTS k_v10_docs (
      doc_key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL,
      revision INTEGER NOT NULL
    )`);
  }

  async get(key: string): Promise<{ value: unknown; revision: number } | null> {
    this.#key(key);
    const row = this.#find(key);
    return row ? { value: JSON.parse(row.value_json) as unknown, revision: row.revision } : null;
  }

  async put(
    key: string, value: unknown, condition: V10WriteCondition,
  ): Promise<{ revision: number }> {
    this.#key(key);
    const text = this.#serialize(value);
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const old = this.#find(key);
      if (condition.kind === 'create') {
        if (old) throw new TypeError('K_DOC_CAS_CONFLICT');
        this.#db.prepare('INSERT INTO k_v10_docs(doc_key,value_json,revision) VALUES(?,?,0)')
          .run(key, text);
        this.#db.exec('COMMIT');
        return { revision: 0 };
      }
      if (condition.kind !== 'revision' || !Number.isSafeInteger(condition.revision) ||
          !old || old.revision !== condition.revision) {
        throw new TypeError('K_DOC_CAS_CONFLICT');
      }
      const next = old.revision + 1;
      const changed = this.#db.prepare(`UPDATE k_v10_docs SET value_json=?,revision=?
        WHERE doc_key=? AND revision=?`)
        .run(text, next, key, condition.revision);
      if (changed.changes !== 1) throw new TypeError('K_DOC_CAS_CONFLICT');
      this.#db.exec('COMMIT');
      return { revision: next };
    } catch {
      this.#rollback();
      throw new TypeError('K_DOC_CAS_OR_WRITE_FAILED');
    }
  }

  async remove(key: string, condition: V10WriteCondition): Promise<void> {
    this.#key(key);
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const old = this.#find(key);
      if (condition.kind === 'create') {
        if (old) throw new TypeError('K_DOC_CAS_CONFLICT');
      } else {
        if (condition.kind !== 'revision' || !old ||
            !Number.isSafeInteger(condition.revision) ||
            old.revision !== condition.revision) throw new TypeError('K_DOC_CAS_CONFLICT');
        const changed = this.#db.prepare('DELETE FROM k_v10_docs WHERE doc_key=? AND revision=?')
          .run(key, condition.revision);
        if (changed.changes !== 1) throw new TypeError('K_DOC_CAS_CONFLICT');
      }
      this.#db.exec('COMMIT');
    } catch {
      this.#rollback();
      throw new TypeError('K_DOC_CAS_OR_WRITE_FAILED');
    }
  }

  close(): void { this.#db.close(); }

  #find(key: string): Row | null {
    return (this.#db.prepare('SELECT value_json,revision FROM k_v10_docs WHERE doc_key=?')
      .get(key) as Row | undefined) ?? null;
  }
  #key(key: string): void {
    if (typeof key !== 'string' || key.length < 1 || key.length > 512 ||
        key.includes('\0')) throw new TypeError('K_DOC_KEY_REFUSED');
  }
  #serialize(value: unknown): string {
    const text = JSON.stringify(value);
    if (text === undefined || text.length > 1_048_576) {
      throw new TypeError('K_DOC_VALUE_REFUSED');
    }
    return text;
  }
  #rollback(): void {
    try { this.#db.exec('ROLLBACK'); } catch { /* do not claim successful CAS */ }
  }
}
