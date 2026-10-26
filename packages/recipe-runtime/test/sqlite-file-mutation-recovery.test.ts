import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AuthorizedAction } from '@shun/contracts';
import { ShunStore } from '@shun/store';
import { describe, expect, it } from 'vitest';
import { SqliteFileMutationJournal } from '../src/sqlite-file-mutation-journal.ts';
import { SqliteFileMutationRecoveryReader } from '../src/sqlite-file-mutation-recovery.ts';

function action(actionId: string): AuthorizedAction {
  return {
    taskId: 'task-f04b1',
    actionId,
    planHash: 'a'.repeat(64),
    policySnapshotRevision: 'policy-1',
    authorizationKind: 'DURABLE_POLICY',
    authorizationRef: 'grant-f04b1',
    expiresAt: '2026-10-26T12:00:00.000Z',
    action: {
      actionId,
      bindingRef: 'binding-1',
      op: 'file.copy',
      parameters: {
        sourcePath: 'C:\\allowed\\src\\source.txt',
        destinationPath: 'C:\\allowed\\dst\\dest.txt',
      },
      sideEffectClass: 'R2',
      requiredPrivilege: 'USER',
      filesystemScope: {
        read: ['C:\\allowed\\src'],
        write: ['C:\\allowed\\dst'],
      },
    },
  };
}

const evidenceDigest = createHash('sha256').update('trusted-effect-receipt').digest('hex');

async function withDurableStore(
  run: (store: ShunStore, path: string) => Promise<void> | void,
): Promise<void> {
  const folder = mkdtempSync(join(tmpdir(), 'shun-f04b1-'));
  const path = join(folder, 'recovery.sqlite');
  const store = new ShunStore({ file: path });
  try {
    await run(store, path);
  } finally {
    await store.close();
    rmSync(folder, { recursive: true, force: true });
  }
}

describe('T07 F04B1 private real-SQLite mutation recovery readback', () => {
  it('refuses ephemeral, caller-created non-durable storage', async () => {
    const store = new ShunStore({ file: ':memory:' });
    try {
      expect(() => new SqliteFileMutationRecoveryReader(store)).toThrow(
        'FILE_RECOVERY_JOURNAL_CONFIGURATION_REFUSED',
      );
    } finally {
      await store.close();
    }
  });

  it('does not confuse a missing attempt with proof that no file effect ran', async () => {
    await withDurableStore((store) => {
      const reader = new SqliteFileMutationRecoveryReader(store);
      const result = reader.read(action('not-recorded'));
      expect(result).toMatchObject({
        ok: true,
        snapshot: {
          provenance: 'HOST_DURABLE_SAME_STORE_JOURNAL',
          state: 'NO_MATCHING_RECORD_UNPROVEN',
          recordPresent: false,
          automaticRetryAllowed: false,
          effectCompletionReproven: false,
          semanticVerified: false,
          postStateIndependentlyVerified: false,
        },
      });
      if (!result.ok) return;
      expect(Object.isFrozen(result.snapshot)).toBe(true);
      expect(Object.isFrozen(result)).toBe(true);
    });
  });

  it('finds a real STARTED row after closing and reopening SQLite, never authorizes replay', async () => {
    const folder = mkdtempSync(join(tmpdir(), 'shun-f04b1-reopen-'));
    const path = join(folder, 'recovery.sqlite');
    const attempt = action('started-reopen');
    const first = new ShunStore({ file: path });
    try {
      const journal = new SqliteFileMutationJournal(first);
      expect(journal.reserve(attempt)).toEqual({ ok: true, state: 'DURABLY_RESERVED' });
    } finally {
      await first.close();
    }
    const reopened = new ShunStore({ file: path });
    try {
      const reader = new SqliteFileMutationRecoveryReader(reopened);
      const result = reader.read(attempt);
      expect(result).toMatchObject({
        ok: true,
        snapshot: {
          state: 'STARTED_RECONCILE_REQUIRED',
          recordPresent: true,
          trustedJournalRead: true,
          evidenceDigestRecorded: false,
          fileMutationAllowed: false,
          automaticRetryAllowed: false,
        },
      });
      expect(new SqliteFileMutationJournal(reopened).reserve(attempt)).toEqual({
        ok: false,
        code: 'RECONCILE_REQUIRED',
      });
      expect(reader.read(attempt)).toEqual(result);
    } finally {
      await reopened.close();
      rmSync(folder, { recursive: true, force: true });
    }
  });

  it('classifies durable UNKNOWN and historical COMMITTED as recheck-only, never PASS', async () => {
    await withDurableStore((store) => {
      const journal = new SqliteFileMutationJournal(store);
      const uncertain = action('uncertain-attempt');
      const committed = action('committed-attempt');
      expect(journal.reserve(uncertain).ok).toBe(true);
      expect(journal.reserve(committed).ok).toBe(true);
      expect(journal.recordOutcome(uncertain, 'UNCERTAIN', evidenceDigest)).toBe(true);
      expect(journal.recordOutcome(committed, 'COMMITTED_VERIFIED', evidenceDigest)).toBe(true);
      const reader = new SqliteFileMutationRecoveryReader(store);
      expect(reader.read(uncertain)).toMatchObject({
        ok: true,
        snapshot: {
          state: 'UNCERTAIN_RECONCILE_REQUIRED',
          evidenceDigestRecorded: true,
          automaticRetryAllowed: false,
          effectCompletionReproven: false,
        },
      });
      expect(reader.read(committed)).toMatchObject({
        ok: true,
        snapshot: {
          state: 'COMMITTED_REVALIDATION_REQUIRED',
          recordPresent: true,
          postStateIndependentlyVerified: false,
          semanticVerified: false,
          fileMutationAllowed: false,
        },
      });
    });
  });

  it('refuses divergent intent, corrupted state and forged journal evidence', async () => {
    await withDurableStore((store) => {
      const original = action('same-identity');
      const journal = new SqliteFileMutationJournal(store);
      expect(journal.reserve(original).ok).toBe(true);
      const reader = new SqliteFileMutationRecoveryReader(store);
      const altered = { ...original, authorizationRef: 'different-grant' };
      expect(reader.read(altered)).toEqual({
        ok: false,
        code: 'FILE_RECOVERY_JOURNAL_REFUSED',
      });
      store.database
        .prepare(
          'UPDATE recipe_file_mutation_journal_v02 SET evidence_sha256=? WHERE task_id=? AND action_id=?',
        )
        .run(evidenceDigest, original.taskId, original.actionId);
      expect(reader.read(original)).toEqual({
        ok: false,
        code: 'FILE_RECOVERY_JOURNAL_REFUSED',
      });
    });
  });

  it('refuses non-mutation and malformed action instead of trusting caller assertions', async () => {
    await withDurableStore((store) => {
      const reader = new SqliteFileMutationRecoveryReader(store);
      const forged = { ...action('bad-op'), action: { ...action('bad-op').action, op: 'shell.exec' } };
      expect(reader.read(forged)).toEqual({
        ok: false,
        code: 'FILE_RECOVERY_JOURNAL_REFUSED',
      });
      expect(reader.read({ state: 'COMMITTED_VERIFIED', semanticVerified: true } as never)).toEqual({
        ok: false,
        code: 'FILE_RECOVERY_JOURNAL_REFUSED',
      });
    });
  });
});
