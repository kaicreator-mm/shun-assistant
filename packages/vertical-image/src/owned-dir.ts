// Ownership-guarded directories for benchmark/scratch tooling (VI-P1-05).
//
// A tool may only ever delete what it provably created. Deleting a
// user-supplied path (e.g. an arbitrary --corpus-dir) is a data-loss bug even
// when the path "looks like" scratch. The guard writes a run-unique nonce
// marker at creation time; removal refuses — without touching anything —
// when the marker is missing or does not match the nonce recorded at
// creation. Directories are created exclusively ('wx' marker) so a
// pre-existing directory with foreign content is never silently adopted.
import { randomBytes } from 'node:crypto';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export const OWNERSHIP_MARKER = '.shun-owned';

/** Refusal to delete a directory the current run did not create and mark. */
export class NotOwnedError extends Error {
  readonly path: string;

  constructor(path: string, reason: string) {
    super(`refusing to delete ${path}: ${reason}`);
    this.name = 'NotOwnedError';
    this.path = path;
  }
}

export interface OwnedDir {
  path: string;
  /** Run-unique nonce recorded in the marker; removal requires an exact match. */
  nonce: string;
}

/**
 * Creates a directory (recursively) and claims ownership with a fresh nonce
 * marker. Refuses when the directory already holds any content — a directory
 * with prior files is never adopted silently — and throws (EEXIST) when the
 * marker itself already exists.
 */
export async function createOwnedDir(path: string): Promise<OwnedDir> {
  await mkdir(path, { recursive: true });
  const entries = await readdir(path);
  if (entries.length > 0) {
    throw new NotOwnedError(
      path,
      `directory is not empty (${entries.length} entr${entries.length === 1 ? 'y' : 'ies'})`,
    );
  }
  const nonce = randomBytes(16).toString('hex');
  await writeFile(join(path, OWNERSHIP_MARKER), `${nonce}\n`, { flag: 'wx' });
  return { path, nonce };
}

/**
 * Deletes a directory recursively ONLY when the ownership marker exists and
 * carries the exact nonce recorded at creation. Any mismatch — missing
 * marker, stale nonce, unreadable directory — refuses without deleting.
 */
export async function removeOwnedDir(dir: OwnedDir): Promise<void> {
  let content: string;
  try {
    content = await readFile(join(dir.path, OWNERSHIP_MARKER), 'utf8');
  } catch (cause) {
    throw new NotOwnedError(
      dir.path,
      `ownership marker unreadable (${cause instanceof Error ? cause.message : String(cause)})`,
    );
  }
  if (content.trim() !== dir.nonce) {
    throw new NotOwnedError(dir.path, 'ownership marker nonce mismatch');
  }
  await rm(dir.path, { recursive: true, force: true });
}
