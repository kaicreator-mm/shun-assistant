/** Durable Host issuance fence: one (Case, source revision) is minted once.
 * This is a provenance replay ledger, not Kernel's effect Journal or approval.
 */
import { DatabaseSync } from 'node:sqlite';

const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;

export class SqliteHostObservationFence {
  readonly #db: DatabaseSync;
  constructor(file: string) {
    if (typeof file !== 'string' || !file || file === ':memory:') {
      throw new Error('HOST_OBSERVATION_DURABLE_FILE_REQUIRED');
    }
    this.#db = new DatabaseSync(file);
    this.#db.exec('PRAGMA journal_mode=WAL');
    this.#db.exec('PRAGMA synchronous=FULL');
    this.#db.exec('PRAGMA busy_timeout=5000');
    this.#db.exec(`CREATE TABLE IF NOT EXISTS host_observation_issues (
      task_id TEXT NOT NULL, source_ref TEXT NOT NULL, revision TEXT NOT NULL,
      issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      PRIMARY KEY (task_id,source_ref,revision)
    )`);
  }
  /** One atomic issuance; false on reuse, malformed or storage uncertainty. */
  accept(record: {
    readonly taskId: string; readonly sourceRef: string; readonly revision: string;
    readonly issuedAtUnixMs: number; readonly expiresAtUnixMs: number;
  }, nowUnixMs: number): boolean {
    if (!record || ![record.taskId,record.sourceRef,record.revision].every(
      (s) => typeof s === 'string' && TOKEN.test(s)) ||
      !Number.isSafeInteger(record.issuedAtUnixMs) ||
      !Number.isSafeInteger(record.expiresAtUnixMs) ||
      !Number.isSafeInteger(nowUnixMs) ||
      nowUnixMs < record.issuedAtUnixMs || nowUnixMs >= record.expiresAtUnixMs) return false;
    try {
      const result = this.#db.prepare(`INSERT OR IGNORE INTO host_observation_issues
        (task_id,source_ref,revision,issued_at,expires_at) VALUES(?,?,?,?,?)`)
        .run(record.taskId,record.sourceRef,record.revision,
          record.issuedAtUnixMs,record.expiresAtUnixMs);
      return result.changes === 1;
    } catch {
      return false;
    }
  }
  close(): void { this.#db.close(); }
}
