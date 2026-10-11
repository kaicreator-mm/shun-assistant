import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  createOwnedDir,
  NotOwnedError,
  OWNERSHIP_MARKER,
  removeOwnedDir,
} from '../src/owned-dir.ts';
import { type FixtureDir, fixtureDir } from './helpers.ts';

const execFileAsync = promisify(execFile);

let victim: FixtureDir;

beforeEach(async () => {
  victim = await fixtureDir('shun-owned-victim-');
});

afterEach(async () => {
  await victim.cleanup();
});

describe('owned-dir guard (VI-P1-05)', () => {
  it('refuses to delete a foreign directory containing user data', async () => {
    await victim.write('precious.txt', Buffer.from('user data — must survive'));
    // A buggy tool claims ownership it never established.
    await expect(
      removeOwnedDir({ path: victim.path, nonce: 'deadbeef'.repeat(4) }),
    ).rejects.toBeInstanceOf(NotOwnedError);
    expect(existsSync(join(victim.path, 'precious.txt'))).toBe(true);
    expect(await readFile(join(victim.path, 'precious.txt'), 'utf8')).toBe(
      'user data — must survive',
    );
  });

  it('refuses to adopt a pre-existing directory with content', async () => {
    await victim.write('already-here.txt', Buffer.from('not ours'));
    await expect(createOwnedDir(victim.path)).rejects.toBeInstanceOf(NotOwnedError);
    expect(existsSync(join(victim.path, 'already-here.txt'))).toBe(true);
    // A stale/forged marker is not ownership either: the nonce recorded at
    // creation time never matches a claim made up after the fact.
    await writeFile(join(victim.path, OWNERSHIP_MARKER), 'forged-by-attacker\n');
    await expect(
      removeOwnedDir({ path: victim.path, nonce: 'deadbeef'.repeat(4) }),
    ).rejects.toBeInstanceOf(NotOwnedError);
    expect(existsSync(join(victim.path, 'already-here.txt'))).toBe(true);
  });

  it('deletes exactly the directory it created and marked', async () => {
    const owned = await createOwnedDir(join(victim.path, 'scratch'));
    await writeFile(join(owned.path, 'junk.bin'), Buffer.from('x'));
    await removeOwnedDir(owned);
    expect(existsSync(owned.path)).toBe(false);
  });

  it('run-b037 refuses a user corpus directory and deletes nothing (VI-P1-05)', async () => {
    await victim.write('family-photo.jpg', Buffer.from('precious'));
    // Point the benchmark at a directory it does not own: it must abort
    // BEFORE generation/cleanup and leave every byte intact.
    const proc = execFileAsync(
      process.execPath,
      ['scripts/run-b037.ts', '--corpus-dir', victim.path],
      { cwd: join(import.meta.dirname, '..') },
    );
    await expect(proc).rejects.toBeTruthy();
    expect(existsSync(join(victim.path, 'family-photo.jpg'))).toBe(true);
    expect(await readFile(join(victim.path, 'family-photo.jpg'), 'utf8')).toBe('precious');
  });
});
