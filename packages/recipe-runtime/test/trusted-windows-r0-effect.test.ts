// T04 trusted effect phase-binding falsifiers (R2 P1-02). A positive
// receipt (SUCCEEDED + COMPLETED_VERIFIED) exists ONLY after the exact
// task/action/intent + immutable expected-state commitment has been
// durably persisted as a phase receipt in the trusted host's journal and
// re-read back with a consistent digest. These falsifiers prove the
// negative half mechanically:
//   - no phase journal wired  -> no positive receipt, ever;
//   - phase persistence refused -> UNCERTAIN;
//   - phase readback corrupt or divergent -> UNCERTAIN;
//   - the durable phase receipt itself refuses unreserved attempts,
//     divergence, and tampered rows.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type AuthorizedAction, AuthorizedActionSchema } from '@shun/contracts';
import { ShunStore } from '@shun/store';
import { describe, expect, it } from 'vitest';
import { SqliteR0EffectJournal } from '../src/sqlite-r0-effect-journal.ts';
import {
  executeTrustedWindowsR0Search,
  type R0EffectPhaseCommitment,
  type R0EffectPhasePort,
} from '../src/trusted-windows-r0-effect.ts';

function actionFor(root: string): AuthorizedAction {
  return AuthorizedActionSchema.parse({
    taskId: 'task-phase',
    actionId: 'phase-1',
    planHash: 'a'.repeat(64),
    policySnapshotRevision: 'policy-1',
    authorizationKind: 'AUTOMATIC',
    authorizationRef: 'grant-1',
    action: {
      actionId: 'phase-1',
      bindingRef: 'binding-1',
      op: 'file.search',
      parameters: { root, query: '*.txt' },
      sideEffectClass: 'R0',
      requiredPrivilege: 'USER',
      filesystemScope: { read: [root], write: [] },
    },
  });
}

function makeScope(prefix: string) {
  const dir = mkdtempSync(join(tmpdir(), `${prefix}-`));
  const scope = join(dir, 'scope');
  mkdirSync(scope, { recursive: true });
  writeFileSync(join(scope, 'a.txt'), 'alpha');
  return {
    dir,
    rootForward: scope.split('\\').join('/'),
    dispose: () => rmSync(dir, { recursive: true, force: true }),
  };
}

const stubCommitment = {
  expectedStateSha256: 'a'.repeat(64),
  observationSha256: 'b'.repeat(64),
  postStateSha256: 'c'.repeat(64),
};

describe.skipIf(process.platform !== 'win32')('T04 effect phase binding (R2 P1-02)', () => {
  it('never mints a positive receipt without a trusted phase journal', async () => {
    const scope = makeScope('shun-phase-none');
    try {
      const receipt = await executeTrustedWindowsR0Search(actionFor(scope.rootForward));
      expect(receipt.terminal).toBe('UNCERTAIN');
      expect(receipt.sideEffectEvidence).toMatchObject({
        recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        postStateVerified: false,
      });
      expect(receipt.sideEffectEvidence.journalRef).toBeUndefined();
      console.log('PHASE_NO_JOURNAL_NO_POSITIVE=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('stays UNCERTAIN when phase persistence is refused', async () => {
    const scope = makeScope('shun-phase-refused');
    try {
      const action = actionFor(scope.rootForward);
      const phaseJournal: R0EffectPhasePort = {
        recordEffectPhase: () => ({ ok: false }),
        lookupEffectPhase: () => ({ ok: false }),
      };
      const receipt = await executeTrustedWindowsR0Search(action, { phaseJournal });
      expect(receipt.terminal).toBe('UNCERTAIN');
      expect(receipt.sideEffectEvidence.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
      console.log('PHASE_RECORD_REFUSED_UNCERTAIN=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('stays UNCERTAIN when the phase readback is corrupt or divergent', async () => {
    const scope = makeScope('shun-phase-corrupt');
    try {
      const action = actionFor(scope.rootForward);
      const recordedDigest = 'd'.repeat(64);
      const phaseJournal: R0EffectPhasePort = {
        recordEffectPhase: () => ({ ok: true, phaseReceiptSha256: recordedDigest }),
        // A corrupt/differing readback must never back a positive receipt.
        lookupEffectPhase: () => ({
          ok: true,
          commitment: stubCommitment,
          phaseReceiptSha256: 'e'.repeat(64),
        }),
      };
      const receipt = await executeTrustedWindowsR0Search(action, { phaseJournal });
      expect(receipt.terminal).toBe('UNCERTAIN');
      console.log('PHASE_READBACK_CORRUPT_UNCERTAIN=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('cites the real phase receipt digest in a positive receipt', async () => {
    const scope = makeScope('shun-phase-positive');
    try {
      const action = actionFor(scope.rootForward);
      let issuedDigest: string | null = null;
      let stored: R0EffectPhaseCommitment | null = null;
      const phaseJournal: R0EffectPhasePort = {
        recordEffectPhase: (_a, commitment) => {
          // A stub cannot fabricate the real fingerprints: accept whatever
          // the effect committed and hand back a stable digest.
          expect(commitment.expectedStateSha256).toMatch(/^[0-9a-f]{64}$/);
          expect(commitment.postStateSha256).toMatch(/^[0-9a-f]{64}$/);
          stored = commitment;
          issuedDigest = '1'.repeat(64);
          return { ok: true, phaseReceiptSha256: issuedDigest };
        },
        lookupEffectPhase: () => ({
          ok: true,
          commitment: stored ?? stubCommitment,
          phaseReceiptSha256: issuedDigest ?? '',
        }),
      };
      const receipt = await executeTrustedWindowsR0Search(action, { phaseJournal });
      expect(receipt.terminal).toBe('SUCCEEDED');
      expect(receipt.sideEffectEvidence).toMatchObject({
        recoveryClassification: 'COMPLETED_VERIFIED',
        postStateVerified: true,
        journalRef: `recipe_r0_effect_phase_v02:${issuedDigest}`,
      });
      console.log('PHASE_POSITIVE_CITES_REAL_RECEIPT=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('durably refuses unreserved attempts, divergence and tampered phase rows', () => {
    const scope = makeScope('shun-phase-journal');
    const store = new ShunStore({ file: join(scope.dir, 'phase.sqlite') });
    try {
      const action = actionFor(scope.rootForward);
      const journal = new SqliteR0EffectJournal(store);
      const commitment = {
        expectedStateSha256: 'a'.repeat(64),
        observationSha256: 'b'.repeat(64),
        postStateSha256: 'c'.repeat(64),
      };
      // No durable STARTED reservation for this identity yet.
      expect(journal.recordEffectPhase(action, commitment)).toEqual({
        ok: false,
        code: 'JOURNAL_REFUSED',
      });
      expect(journal.reserve(action)).toMatchObject({ ok: true });
      const first = journal.recordEffectPhase(action, commitment);
      expect(first.ok).toBe(true);
      const phaseDigest = first.ok ? first.phaseReceiptSha256 : '';
      // Identical re-record is idempotent; any divergence is refused.
      expect(journal.recordEffectPhase(action, commitment)).toEqual({
        ok: true,
        phaseReceiptSha256: phaseDigest,
      });
      expect(
        journal.recordEffectPhase(action, { ...commitment, postStateSha256: 'f'.repeat(64) }),
      ).toEqual({ ok: false, code: 'PHASE_DIVERGED' });
      // The readback binds the intent and recomputes the row digest.
      const readback = journal.lookupEffectPhase(action);
      expect(readback.ok).toBe(true);
      if (readback.ok) {
        expect(readback.phaseReceiptSha256).toBe(phaseDigest);
        expect(readback.commitment).toEqual(commitment);
      }
      // A tampered row can never back a positive receipt.
      store.database
        .prepare(
          'UPDATE recipe_r0_effect_phase_v02 SET observation_sha256=? WHERE task_id=? AND action_id=?',
        )
        .run('0'.repeat(64), action.taskId, action.actionId);
      expect(journal.lookupEffectPhase(action)).toEqual({ ok: false, code: 'JOURNAL_REFUSED' });
      console.log('PHASE_JOURNAL_IMMUTABILITY=PASS');
    } finally {
      store.close();
      scope.dispose();
    }
  });
});
