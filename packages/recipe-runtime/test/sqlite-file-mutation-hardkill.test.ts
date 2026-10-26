// T07 F04B3a (P0 only): ACTUAL process death after a durable STARTED row.
//
// A child Node24 process opens the real recipe-runtime mutation journal,
// commits an actual STARTED row, reads it back, then remains alive. The
// supervising Vitest process forcibly kills that *other OS process* (SIGKILL
// or the Windows TerminateProcess equivalent), creates a NEW ShunStore
// connection and proves that the original intent still has a STARTED row and
// the same task/action can never be replayed. No mocked crash/throw,
// synthetic SQLite state, fake native file effects or JS cleanup in the child.
//
// P1-P4 (after precommit/create/flush/rename) require separate actual
// Windows-native subprocess canaries and are NOT claimed by this test.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AuthorizedAction } from '@shun/contracts';
import { ShunStore } from '@shun/store';
import { describe, expect, it } from 'vitest';
import { SqliteFileMutationJournal } from '../src/sqlite-file-mutation-journal.ts';

const originalAction: AuthorizedAction = {
  taskId: 'f04b3a-p0-task',
  actionId: 'f04b3a-p0-effect',
  planHash: 'a'.repeat(64),
  policySnapshotRevision: 'policy-f04b3a',
  authorizationKind: 'DURABLE_POLICY',
  authorizationRef: 'grant-f04b3a',
  expiresAt: '2099-10-26T00:00:00.000Z',
  action: {
    actionId: 'f04b3a-p0-effect',
    bindingRef: 'binding-f04b3a',
    op: 'file.copy',
    parameters: {
      sourcePath: 'C:\\P0\\source\\file.txt',
      destinationPath: 'C:\\P0\\target\\file.txt',
    },
    sideEffectClass: 'R2',
    requiredPrivilege: 'USER',
    filesystemScope: {
      read: ['C:\\P0\\source'],
      write: ['C:\\P0\\target'],
    },
  },
};

const childMarker = 'F04B3_P0_DURABLE_STARTED_RECHECKED';

function childCode(): string {
  const storeUrl = new URL('../../store/src/index.ts', import.meta.url).href;
  const journalUrl = new URL('../src/sqlite-file-mutation-journal.ts', import.meta.url).href;
  return [
    `import { ShunStore } from ${JSON.stringify(storeUrl)};`,
    `import { SqliteFileMutationJournal } from ${JSON.stringify(journalUrl)};`,
    `const originalAction = ${JSON.stringify(originalAction)};`,
    'const dbFile = process.argv[1];',
    'const store = new ShunStore({ file: dbFile });',
    'const journal = new SqliteFileMutationJournal(store);',
    'const reserved = journal.reserve(originalAction);',
    "if (!reserved.ok) throw new Error('P0_RESERVE_FAILED');",
    'const readback = journal.lookup(originalAction);',
    "if (!readback.ok || readback.state !== 'STARTED') throw new Error('P0_DURABLE_READBACK_FAILED');",
    `process.stdout.write('${childMarker}\\n');`,
    // A live process is deliberately required: parent must forcefully kill
    // it rather than observing a successful child return/normal cleanup.
    'setInterval(() => {}, 1000);',
  ].join('\\n');
}

describe('T07 F04B3a — real OS process kill: STARTED before precommit', () => {
  it('survives a genuinely killed child and refuses all same-identity replays after a fresh open', async () => {
    const folder = mkdtempSync(join(tmpdir(), 'shun-f04b3a-real-kill-'));
    const dbFile = join(folder, 'real-journal.sqlite');
    const child = spawn(
      process.execPath,
      ['--experimental-transform-types', '--input-type=module', '--eval', childCode(), dbFile],
      {
        cwd: process.cwd(),
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        env: { ...process.env },
      },
    );
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (data: string) => {
      stderr = (stderr + data).slice(-2000);
    });
    try {
      let lineBuffer = '';
      await new Promise<void>((resolve, reject) => {
        let done = false;
        const finish = (error?: Error) => {
          if (done) return;
          done = true;
          clearTimeout(timeout);
          if (error) reject(error);
          else resolve();
        };
        const timeout = setTimeout(() => finish(new Error(`P0_CHILD_NO_READY: ${stderr}`)), 15000);
        child.stdout.setEncoding('utf8');
        child.stdout.on('data', (chunk: string) => {
          lineBuffer += chunk;
          if (lineBuffer.includes(childMarker)) finish();
        });
        child.once('error', (error) => finish(error));
        child.once('close', (code) =>
          finish(new Error(`P0_CHILD_EARLY_EXIT_${code}: ${stderr}`)),
        );
      });
      expect(child.exitCode).toBeNull(); // Definitely alive at the kill point.
      // This is a forced OS-level termination, not a throw, a voluntary exit
      // or a fake "crash" inside an executor mock.
      expect(child.kill('SIGKILL')).toBe(true);
      const termination = await new Promise<{ code: number | null; signal: string | null }>(
        (resolve, reject) => {
          const timeout = setTimeout(() => reject(new Error('P0_KILL_TIMEOUT')), 15000);
          child.once('close', (code, signal) => {
            clearTimeout(timeout);
            resolve({ code, signal });
          });
        },
      );
      expect(termination.signal !== null || termination.code !== 0).toBe(true);

      // This store was NOT opened by the child. The process is dead, so this
      // read proves a new live host can recover the durable journal state.
      const recovered = new ShunStore({ file: dbFile });
      try {
        const journal = new SqliteFileMutationJournal(recovered);
        expect(journal.lookup(originalAction)).toEqual({
          ok: true,
          state: 'STARTED',
          evidenceSha256: null,
        });
        expect(journal.readPrecommit(originalAction)).toEqual({ ok: false, code: 'NOT_FOUND' });
        expect(journal.reserve(originalAction)).toEqual({
          ok: false,
          code: 'RECONCILE_REQUIRED',
        });
        const forgedIntent = {
          ...originalAction,
          authorizationRef: 'different-issued-grant',
        };
        expect(journal.reserve(forgedIntent)).toEqual({ ok: false, code: 'JOURNAL_REFUSED' });
        expect(journal.lookup(originalAction)).toMatchObject({ ok: true, state: 'STARTED' });
      } finally {
        await recovered.close();
      }
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      rmSync(folder, { recursive: true, force: true });
    }
  }, 40000);
});
