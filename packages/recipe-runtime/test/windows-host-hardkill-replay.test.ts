// T04 physical forced-process-death falsifier through the FULL composed host.
// A real child Node process runs the real persisted-policy authorization, the
// real ActionController grant, and the real durable SQLite STARTED commit,
// acknowledges synchronously, and is then SIGKILLed before any receipt. The
// restarted host view must never auto-replay: journal readback stays STARTED,
// an exact-intent reserve is RECONCILE_REQUIRED, a changed intent is
// JOURNAL_REFUSED, a fresh composition run dispatches zero effects, and the
// read-only scope is byte-for-byte unmutated (independent oracle fingerprint).
import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuthorizedAction } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { captureOracleWalk, oracleWalksEqual } from '../src/r0-independent-poststate-oracle.ts';
import { SqliteR0EffectJournal } from '../src/sqlite-r0-effect-journal.ts';
import { type HostFixture, makeHostFixture } from './helpers/win-e2e-fixture.ts';

const here = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function waitForPreEffect(child: ReturnType<typeof spawn>, timeoutMs: number): Promise<string> {
  return new Promise((resolveLine, rejectLine) => {
    let buffer = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      rejectLine(new Error('child never acknowledged PRE_EFFECT'));
    }, timeoutMs);
    child.stdout?.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      const line = buffer.split('\n').find((candidate) => candidate.startsWith('PRE_EFFECT '));
      if (line) {
        clearTimeout(timer);
        resolveLine(line.slice('PRE_EFFECT '.length).trim());
      }
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      if (buffer.length < 8192) buffer += chunk.toString('utf8');
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      rejectLine(error);
    });
  });
}

describe.skipIf(process.platform !== 'win32')(
  'T04 hard kill between durable STARTED and receipt: restart refuses replay',
  () => {
    it('kills a real composed host child post-commit and never re-dispatches', async () => {
      const f: HostFixture = await makeHostFixture('shun-e2e-kill');
      const { plan, host: parentHost } = f.compose();
      const before = captureOracleWalk(f.tree.rootNative, '*.txt');
      if (!before.ok) throw new Error('fixture oracle pre-walk failed');

      const child = spawn(
        process.execPath,
        [
          '--experimental-transform-types',
          'test/helpers/hardkill-child.ts',
          f.dbPath,
          JSON.stringify(f.identity),
          JSON.stringify(plan),
        ],
        { cwd: here, stdio: ['ignore', 'pipe', 'pipe'] },
      );
      let childAction: AuthorizedAction | null = null;
      try {
        const payload = await waitForPreEffect(child, 30_000);
        childAction = JSON.parse(payload) as AuthorizedAction;
      } finally {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      }
      const exit = await new Promise<{ code: number | null; signal: string | null }>(
        (resolveExit) => {
          child.on('close', (code, signal) => resolveExit({ code, signal }));
        },
      );
      expect(childAction).not.toBeNull();
      // Real forced termination, not a graceful child exit.
      expect(exit.code === 0).toBe(false);
      expect(childAction?.taskId).toBe(f.identity.taskId);

      // Readback-only observation of the durable row (same store, new view).
      const rows = f.store.database
        .prepare(
          'SELECT task_id, action_id, state, receipt_sha256 FROM recipe_r0_effect_journal_v02',
        )
        .all() as Array<{
        task_id: string;
        action_id: string;
        state: string;
        receipt_sha256: string | null;
      }>;
      expect(rows).toEqual([
        { task_id: f.identity.taskId, action_id: 'read', state: 'STARTED', receipt_sha256: null },
      ]);

      const journal = new SqliteR0EffectJournal(f.store);
      const action = childAction as AuthorizedAction;
      expect(journal.lookup(action)).toMatchObject({ ok: true, state: 'STARTED' });
      expect(journal.reserve(action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });
      expect(journal.reserve({ ...action, planHash: 'e'.repeat(64) })).toEqual({
        ok: false,
        code: 'JOURNAL_REFUSED',
      });

      // A fresh composition on the restarted store refuses the identity and
      // dispatches zero native effects (the reserved row is never replayed).
      expect(await parentHost.runner.run(f.identity)).toEqual({
        ok: false,
        code: 'RECIPE_EXECUTION_UNCERTAIN',
      });
      expect(f.scans()).toBe(0);

      // Read-only scope untouched by the killed attempt (oracle fingerprint).
      const after = captureOracleWalk(f.tree.rootNative, '*.txt');
      if (!after.ok) throw new Error('fixture oracle post-walk failed');
      expect(oracleWalksEqual(before.walk, after.walk)).toBe(true);
      console.log('E2E_HARDKILL_START_COMMITTED=PASS E2E_RESTART_NO_REPLAY=PASS');
    }, 60_000);
  },
);
