// T03 post-merge security correction (Issue #36, C05). The pre-existing
// hard-exit test in crash-atomicity.test.ts drops the store handle inside the
// SAME live process and reopens a second connection — that proves committed-
// state visibility across connections, not persistence across process death.
// This fixture is the real evidence: a child process writes effects through
// ShunStore, the parent HARD-KILLS it mid-run (SIGKILL on POSIX; taskkill /F
// on Windows, where SIGKILL is not honored), and only afterwards a brand-new
// process opens the database and verifies every effect the child reported as
// committed survived the kill.
import { type ChildProcess, spawn } from 'node:child_process';
import { once } from 'node:events';
import { join } from 'node:path';
import type { ShunStoreMutation } from '@shun/contracts';
import { beforeEach, describe, expect, it } from 'vitest';
import { ShunStore } from '../src/index.ts';
import { tempStoreFile } from './helpers.ts';

const FIXTURE = join(import.meta.dirname, 'fixtures', 'write-effects.ts');
const KILL_AFTER = 5;

function effectMutation(i: number): ShunStoreMutation {
  return {
    recordKind: 'execution_receipt',
    recordId: `receipt-${i}`,
    payload: { seq: i, actionId: `action-${i}`, terminal: 'SUCCEEDED' },
  };
}

/** Force-kill a child with no teardown opportunity; wait until it is gone. */
async function hardKill(child: ChildProcess, exitPromise: Promise<unknown[]>): Promise<void> {
  if (process.platform === 'win32') {
    // Windows does not honor SIGKILL; taskkill /F /T force-kills the tree.
    const killer = spawn('taskkill', ['/pid', String(child.pid), '/f', '/t'], {
      stdio: 'ignore',
    });
    await once(killer, 'exit');
  } else {
    child.kill('SIGKILL');
  }
  await exitPromise;
}

let file: string;

beforeEach(() => {
  file = tempStoreFile();
});

describe('ShunStore — hard-kill subprocess durability (C05)', () => {
  it('effects committed before a hard kill survive in a brand-new process', async () => {
    const child = spawn(process.execPath, [FIXTURE, file], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const exitPromise = once(child, 'exit');
    let childError = '';
    child.stderr.on('data', (chunk: Buffer) => {
      childError += chunk.toString('utf8');
    });

    // Watch stdout line-by-line until the child reports KILL_AFTER commits.
    const reported: number[] = [];
    let sawAllDone = false;
    let wakeWaiter: (() => void) | undefined;
    let buffer = '';
    child.stdout.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      let newline = buffer.indexOf('\n');
      while (newline >= 0) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (line.length > 0) {
          if (line === 'ALL-DONE') {
            sawAllDone = true;
          } else if (line.startsWith('APPLIED ')) {
            reported.push(Number(line.slice('APPLIED '.length)));
          }
        }
        newline = buffer.indexOf('\n');
      }
      wakeWaiter?.();
    });

    const waitForReports = async (count: number): Promise<void> => {
      const deadline = Date.now() + 20_000;
      while (reported.length < count) {
        if (Date.now() > deadline) {
          throw new Error(
            `child reported only ${reported.length} effects before timeout; stderr: ${childError}`,
          );
        }
        if (child.exitCode !== null) {
          throw new Error(`child exited early (code ${String(child.exitCode)}): ${childError}`);
        }
        const arrived = new Promise<void>((resolve) => {
          wakeWaiter = resolve;
        });
        const guard = new Promise<void>((resolve) => setTimeout(resolve, 200));
        await Promise.race([arrived, guard]);
      }
    };

    await waitForReports(KILL_AFTER);
    const committedCount = reported.length;
    expect(committedCount).toBeGreaterThanOrEqual(KILL_AFTER);
    expect(sawAllDone).toBe(false);

    // HARD KILL mid-run: no close, no checkpoint, no exit handlers.
    await hardKill(child, exitPromise);
    expect(sawAllDone).toBe(false);
    expect(child.exitCode).not.toBe(0);

    // A brand-new process (this test) reopens the database and verifies
    // every effect the child reported as committed survived the kill.
    const postCrash = new ShunStore({ file });
    try {
      for (let i = 1; i <= committedCount; i += 1) {
        await expect(postCrash.getEffectReceipt(`effect-${i}`)).resolves.toMatchObject({
          effectId: `effect-${i}`,
          applied: true,
        });
        await expect(
          postCrash.getRecord('execution_receipt', `receipt-${i}`),
        ).resolves.toMatchObject({ payload: effectMutation(i).payload });
      }
      // Idempotent replay of the last committed effect: applied=false.
      const replay = await postCrash.apply(`effect-${committedCount}`, {
        recordKind: 'execution_receipt',
        recordId: `receipt-${committedCount}`,
        payload: {
          seq: committedCount,
          actionId: `action-${committedCount}`,
          terminal: 'SUCCEEDED',
        },
      });
      expect(replay.applied).toBe(false);
    } finally {
      await postCrash.close();
    }
  }, 30_000);
});
