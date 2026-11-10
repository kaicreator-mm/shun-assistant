// T04 physical forced-process-death falsifier through the FULL composed host.
// A real child Node process runs the real persisted-policy authorization, the
// real ActionController grant, and the real durable SQLite STARTED commit,
// acknowledges synchronously, stays provably alive, and is then force-killed
// by the PARENT before any receipt. The kill proof requires the #172 R2
// evidence identity: a parent-issued kill request accepted against an
// observed-still-running child, closing with the platform's forced-termination
// exit identity — an ordinary child exit (negative control) can never pass.
// The restarted host view must never auto-replay: journal readback stays
// STARTED, an exact-intent reserve is RECONCILE_REQUIRED, a changed intent is
// JOURNAL_REFUSED, a fresh composition run dispatches zero effects, and the
// read-only scope is unmutated (independent oracle fingerprint).
import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuthorizedAction } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { captureOracleWalk, oracleWalksEqual } from '../src/r0-independent-poststate-oracle.ts';
import { SqliteR0EffectJournal } from '../src/sqlite-r0-effect-journal.ts';
import { type HostFixture, makeHostFixture } from './helpers/win-e2e-fixture.ts';
import { physicalHostSuiteActive } from './helpers/win-token.ts';

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

type DeathEvidence = Readonly<{
  acknowledged: boolean;
  observedAliveAfterAck: boolean;
  parentKillAccepted: boolean;
  code: number | null;
  signal: NodeJS.Signals | null;
}>;

/**
 * The forced-death predicate: the child acknowledged, was OBSERVED still
 * running after the acknowledgement, and the PARENT's kill request was
 * accepted. POSIX proves it with a SIGKILL signal and a null exit code; on
 * Windows TerminateProcess reports the exit-code-1/null-signal identity —
 * valid ONLY on top of the observed-alive + parent-issued requirements. A
 * child that exits on its own after the acknowledgement (negative control)
 * fails `observedAliveAfterAck`/`parentKillAccepted` and is rejected.
 */
function isProvenForcedDeath(evidence: DeathEvidence): boolean {
  if (!evidence.acknowledged || !evidence.observedAliveAfterAck || !evidence.parentKillAccepted)
    return false;
  if (evidence.signal === 'SIGKILL' && evidence.code === null) return true;
  return process.platform === 'win32' && evidence.signal === null && evidence.code === 1;
}

describe.skipIf(process.platform !== 'win32' || !physicalHostSuiteActive())(
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
      let exitedBeforeKill = false;
      let parentKillAccepted = false;
      let observedAliveAfterKill = false;
      child.once('exit', () => {
        exitedBeforeKill = true;
      });
      let childAction: AuthorizedAction | null = null;
      try {
        const payload = await waitForPreEffect(child, 30_000);
        childAction = JSON.parse(payload) as AuthorizedAction;
        // Liveness probe: the acknowledged child must still be running a
        // bounded moment later, so a self-exiting child can never pass as a
        // forced death below.
        await new Promise((resolvePause) => setTimeout(resolvePause, 750));
        expect(exitedBeforeKill).toBe(false);
        expect(child.exitCode).toBeNull();
        expect(child.signalCode).toBeNull();
        // The PARENT issues the real force-termination request.
        parentKillAccepted = child.kill('SIGKILL');
        expect(parentKillAccepted).toBe(true);
        // Snapshot the liveness evidence AT KILL TIME: the exit event fires
        // on the kill itself and would otherwise overwrite this flag.
        observedAliveAfterKill = !exitedBeforeKill;
      } finally {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      }
      const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
        (resolveExit) => {
          child.on('close', (code, signal) => resolveExit({ code, signal }));
        },
      );
      expect(childAction).not.toBeNull();
      // Real forced termination with the platform kill identity — proven by
      // the same predicate an ordinary exit must fail.
      expect(
        isProvenForcedDeath({
          acknowledged: childAction !== null,
          observedAliveAfterAck: observedAliveAfterKill,
          parentKillAccepted: parentKillAccepted === true,
          code: exit.code,
          signal: exit.signal,
        }),
      ).toBe(true);
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
      console.log(
        `E2E_HARDKILL_START_COMMITTED=PASS E2E_KILL_IDENTITY=code:${exit.code},signal:${exit.signal} E2E_RESTART_NO_REPLAY=PASS`,
      );
    }, 60_000);

    it('rejects an ordinary child exit as forced-death evidence (negative control)', async () => {
      // A child that acknowledges and then exits on its own must fail the
      // kill-proof predicate, whatever its exit code — including the Windows
      // forced-termination exit code 1 itself, with or without a kill flag.
      for (const ordinaryCode of [13, 1, 0]) {
        const child = spawn(
          process.execPath,
          ['-e', `process.stdout.write('PRE_EFFECT {}\\n'); process.exit(${ordinaryCode});`],
          { stdio: ['ignore', 'pipe', 'pipe'] },
        );
        const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
          (resolveExit) => {
            child.on('close', (code, signal) => resolveExit({ code, signal }));
          },
        );
        for (const claimedKillAccepted of [false, true]) {
          expect(
            isProvenForcedDeath({
              acknowledged: true,
              observedAliveAfterAck: false,
              parentKillAccepted: claimedKillAccepted,
              code: exit.code,
              signal: exit.signal,
            }),
            `ordinary exit ${ordinaryCode} (killAccepted=${claimedKillAccepted}) must not count as a forced death`,
          ).toBe(false);
        }
      }
      console.log('E2E_HARDKILL_ORDINARY_EXIT_REJECTED=PASS');
    });
  },
);
