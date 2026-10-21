import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type AuthorizedAction, AuthorizedActionSchema } from '@shun/contracts';
import { ShunStore } from '@shun/store';
import { describe, expect, it } from 'vitest';
import { SqliteR0EffectJournal } from '../src/sqlite-r0-effect-journal.ts';

function actionOf(planHash = 'a'.repeat(64)): AuthorizedAction {
  return AuthorizedActionSchema.parse({
    taskId: 'task-1',
    actionId: 'search-once',
    planHash,
    policySnapshotRevision: 'policy-1',
    authorizationKind: 'AUTOMATIC',
    authorizationRef: 'issued-grant-1',
    action: {
      actionId: 'search-once',
      bindingRef: 'binding-1',
      op: 'file.search',
      sideEffectClass: 'R0',
      requiredPrivilege: 'USER',
      parameters: { root: 'C:/approved', query: '*.txt' },
      filesystemScope: { read: ['C:/approved'], write: [] },
    },
  });
}

describe('T04 SQLite pre-effect journal: source-only durable reservation', () => {
  it('serializes two real connections and refuses a replay after DB reopen', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r0-journal-'));
    const path = join(dir, 'shun.sqlite');
    const a = new ShunStore({ file: path });
    const b = new ShunStore({ file: path });
    try {
      const first = new SqliteR0EffectJournal(a);
      const second = new SqliteR0EffectJournal(b);
      const action = actionOf();
      expect(first.reserve(action)).toEqual({
        ok: true,
        state: 'DURABLY_RESERVED',
        semanticVerified: false,
      });
      expect(second.reserve(action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });
      expect(second.reserve(actionOf('b'.repeat(64)))).toEqual({
        ok: false,
        code: 'JOURNAL_REFUSED',
      });
      expect(second.lookup(action)).toEqual({
        ok: true,
        state: 'STARTED',
        receiptSha256: null,
        semanticVerified: false,
      });
      await a.close();
      await b.close();

      const reopened = new ShunStore({ file: path });
      try {
        const afterRestart = new SqliteR0EffectJournal(reopened);
        expect(afterRestart.reserve(action)).toEqual({
          ok: false,
          code: 'RECONCILE_REQUIRED',
        });
        const digest = '1'.repeat(64);
        expect(afterRestart.recordObservation(
          action,
          'OBSERVED_NOT_SEMANTICALLY_VERIFIED',
          digest,
        )).toBe(true);
        expect(afterRestart.lookup(action)).toEqual({
          ok: true,
          state: 'OBSERVED_NOT_SEMANTICALLY_VERIFIED',
          receiptSha256: digest,
          semanticVerified: false,
        });
        // Matching observation is idempotent; conflicting proof is refused.
        expect(afterRestart.recordObservation(
          action,
          'OBSERVED_NOT_SEMANTICALLY_VERIFIED',
          digest,
        )).toBe(true);
        expect(afterRestart.recordObservation(action, 'UNCERTAIN', '2'.repeat(64))).toBe(false);
        expect(afterRestart.reserve(action)).toEqual({
          ok: false,
          code: 'RECONCILE_REQUIRED',
        });
      } finally {
        await reopened.close();
      }
    } finally {
      try { await a.close(); } catch { /* already closed */ }
      try { await b.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses a fake action and never mints a new grant or semantic PASS', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r0-deny-'));
    const db = new ShunStore({ file: join(dir, 'shun.sqlite') });
    try {
      const journal = new SqliteR0EffectJournal(db);
      const action = actionOf();
      const elevated = {
        ...action,
        action: { ...action.action, requiredPrivilege: 'ELEVATED' },
      };
      expect(journal.reserve(elevated)).toEqual({ ok: false, code: 'JOURNAL_REFUSED' });
      expect(journal.lookup(elevated)).toEqual({ ok: false, code: 'JOURNAL_REFUSED' });
      expect(journal.recordObservation(action, 'UNCERTAIN', 'bad-digest')).toBe(false);
      expect(journal.lookup(action)).toEqual({ ok: false, code: 'NOT_FOUND' });
    } finally {
      await db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
