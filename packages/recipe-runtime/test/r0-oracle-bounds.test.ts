// T04 R3 falsifiers: a bounded post-state oracle MUST NEVER certify partial
// content hashes as a complete independent state verification.
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { captureOracleWalk } from '../src/r0-independent-poststate-oracle.ts';

const folders: string[] = [];
afterEach(() => {
  for (const folder of folders.splice(0)) rmSync(folder, { recursive: true, force: true });
});

function scope() {
  const root = mkdtempSync(join(tmpdir(), 'shun-oracle-bounds-'));
  folders.push(root);
  return root;
}

describe.skipIf(process.platform !== 'win32')('T04 R3 complete-content Oracle bounds', () => {
  it('refuses a 256KiB+1 file even when only the unhashed tail changes with identical metadata', () => {
    const root = scope();
    const file = join(root, 'large.txt');
    const bytes = Buffer.alloc(262_145, 0x41);
    writeFileSync(file, bytes);
    const sameTime = new Date('2026-01-01T00:00:00.000Z');
    utimesSync(file, sameTime, sameTime);
    const before = captureOracleWalk(root, '*.txt');
    expect(before).toEqual({ ok: false, code: 'ORACLE_BOUNDS_EXCEEDED' });
    bytes[262_144] = 0x42;
    writeFileSync(file, bytes);
    utimesSync(file, sameTime, sameTime);
    const after = captureOracleWalk(root, '*.txt');
    expect(after).toEqual({ ok: false, code: 'ORACLE_BOUNDS_EXCEEDED' });
    // Neither walk may be supplied as a positive independent post-state proof.
  }, 30_000);

  it('refuses a scope whose late file crosses the 32MiB cumulative content budget', () => {
    const root = scope();
    const block = Buffer.alloc(262_144, 0x58);
    for (let i = 0; i < 129; i++) {
      writeFileSync(join(root, `unmatched-${String(i).padStart(3, '0')}.dat`), block);
    }
    // The 129th file would previously get CONTENT_UNREAD_BUDGET; a successful
    // walk would have returned the same fingerprint for arbitrary late data.
    expect(captureOracleWalk(root, '*.txt')).toEqual({
      ok: false,
      code: 'ORACLE_BOUNDS_EXCEEDED',
    });
  }, 60_000);
});
