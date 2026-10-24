// T04 deterministic process-kill falsifier, not an installed Windows Host E2E.
// The child uses the ACTUAL ShunStore+SQLite journal in another Node process,
// synchronously acknowledges a committed STARTED row then terminates without
// close()/checkpoint() or a receipt. The parent must never auto-dispatch again.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuthorizedActionSchema } from '@shun/contracts';
import { ShunStore } from '@shun/store';
import { describe, expect, it } from 'vitest';
import { SqliteR0EffectJournal } from '../src/sqlite-r0-effect-journal.ts';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const abruptlyKilledChild = [
  "import { writeSync } from 'node:fs';",
  "import { ShunStore } from '@shun/store';",
  "import { SqliteR0EffectJournal } from './src/sqlite-r0-effect-journal.ts';",
  'const db = new ShunStore({ file: process.argv[1] });',
  'const journal = new SqliteR0EffectJournal(db);',
  'const reservation = journal.reserve(JSON.parse(process.argv[2]));',
  "if (!reservation.ok) { writeSync(2, 'RESERVATION_REFUSED'); process.exit(12); }",
  "writeSync(1, 'DURABLY_RESERVED');",
  '// No graceful close, journal update, or cleanup: real process termination.',
  "process.kill(process.pid, 'SIGKILL');",
  'process.exit(13);',
].join('\n');

function authorizedAction() {
  return AuthorizedActionSchema.parse({
    taskId: 'durable-task-1',
    actionId: 'native-read-1',
    planHash: '1'.repeat(64),
    policySnapshotRevision: 'policy-v0.2',
    authorizationKind: 'AUTOMATIC',
    authorizationRef: 'grant-issued-by-controller-upstream',
    action: {
      actionId: 'native-read-1',
      bindingRef: 'binding-1',
      op: 'file.search',
      sideEffectClass: 'R0',
      requiredPrivilege: 'USER',
      parameters: { root: 'C:/approved', query: '*.txt' },
      filesystemScope: { read: ['C:/approved'], write: [] },
    },
  });
}

describe('T04 journal real forced-process-death recovery contract', () => {
  it('never retries same identity after child hard kill between committed STARTED and receipt', async () => {
    const folder = mkdtempSync(join(tmpdir(), 'shun-r0-hard-kill-'));
    const file = join(folder, 'shun.sqlite');
    const action = authorizedAction();
    try {
      const child = spawnSync(
        process.execPath,
        [
          '--experimental-strip-types',
          '--input-type=module',
          '-e',
          abruptlyKilledChild,
          file,
          JSON.stringify(action),
        ],
        { cwd: packageRoot, encoding: 'utf8', timeout: 15_000 },
      );
      expect(child.error).toBeUndefined();
      // Child really reached the durable commit and was then killed, not
      // silently skipped by a child startup or TypeScript resolution error.
      expect(child.stdout, child.stderr).toContain('DURABLY_RESERVED');
      expect(child.status).not.toBe(0);

      const recovered = new ShunStore({ file });
      try {
        const journal = new SqliteR0EffectJournal(recovered);
        expect(journal.lookup(action)).toEqual({
          ok: true,
          state: 'STARTED',
          receiptSha256: null,
          semanticVerified: false,
        });
        expect(journal.reserve(action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });
        expect(journal.reserve({ ...action, planHash: '2'.repeat(64) })).toEqual({
          ok: false,
          code: 'JOURNAL_REFUSED',
        });

        // Even a conservative reconcile record never licenses re-dispatch.
        expect(journal.recordObservation(action, 'UNCERTAIN', 'a'.repeat(64))).toBe(true);
        expect(journal.reserve(action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });
        expect(journal.lookup(action)).toMatchObject({
          ok: true,
          state: 'UNCERTAIN',
          semanticVerified: false,
        });
      } finally {
        await recovered.close();
      }
    } finally {
      rmSync(folder, { recursive: true, force: true });
    }
  }, 30_000);
});
