// T04 C09/C10/C11/C15 — recovery classification honesty:
//   C09  an EXEC_DONE journaled effect with a LOST receipt must never be
//        classified FAILED_BEFORE_EFFECT ("no effect") — the journal itself
//        proves effects ran. Without post-state proof it is UNCERTAIN.
//   C10  a post-state MISMATCH (content/value dimension) must not be read as
//        proof of "no effect" — only an existence-dimension failure
//        (provesAbsence) resolves an interruption to FAILED_BEFORE_EFFECT.
//   C11  a SUCCEEDED receipt without independent post-state evidence is
//        transport optimism: COMPLETED_VERIFIED requires independent proof.
//   C15  a UAC_DECLINED relay verdict contradicting a non-empty journal
//        (especially EXEC_START) must fail closed, never NOT_STARTED.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  isTorn,
  JournalWriter,
  journalPhases,
  type ReplayEvent,
  readJournal,
} from '../src/journal.ts';
import { reconcileExpectedState } from '../src/poststate.ts';
import { classifyRecovery } from '../src/recovery.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  ON_WINDOWS,
  type TestAuthority,
} from './helpers.ts';

function journalWith(write: (w: JournalWriter) => void): ReplayEvent[] {
  const file = join(mkdtempSync(join(tmpdir(), 'shun-honest-')), 'j.jsonl');
  const w = new JournalWriter(file, 1);
  write(w);
  return readJournal(file);
}

const MUTATING_DONE = (w: JournalWriter) => {
  w.append('RECEIVED');
  w.append('EXEC_BEGIN', { detail: { totalSteps: 1 } });
  w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
  w.append('EXEC_DONE', { step: 0, op: 'windows.fs.write', detail: { bytes: 3 } });
};

describe('classifyRecovery — C09 EXEC_DONE without receipt', () => {
  it('EXEC_DONE journaled + receipt ABSENT + no post-state → UNCERTAIN, never FAILED_BEFORE_EFFECT', () => {
    const r = classifyRecovery({ journal: journalWith(MUTATING_DONE) });
    expect(r.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(r.basis).not.toContain('before any side effect');
  });

  it('same journal + post-state proving the effect landed → COMPLETED_VERIFIED', () => {
    const r = classifyRecovery({
      journal: journalWith(MUTATING_DONE),
      postState: { verified: true, holds: true, basis: 'expected file present' },
    });
    expect(r.recoveryClassification).toBe('COMPLETED_VERIFIED');
  });

  it('same journal + post-state proving absence → FAILED_BEFORE_EFFECT (resolved by post-state)', () => {
    const r = classifyRecovery({
      journal: journalWith(MUTATING_DONE),
      postState: {
        verified: true,
        holds: false,
        provesAbsence: true,
        basis: 'expected file provably absent',
      },
    });
    expect(r.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
    expect(r.resolvedByPostState).toBe(true);
  });
});

describe('classifyRecovery — C10 mismatch is not absence', () => {
  it('interrupted window + content-dimension mismatch (provesAbsence=false) → UNCERTAIN', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
    });
    const r = classifyRecovery({
      journal: j,
      postState: {
        verified: true,
        holds: false,
        provesAbsence: false,
        basis: 'file present but content differs — partial effect possible',
      },
    });
    expect(r.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(r.resolvedByPostState).toBe(false);
  });

  it('interrupted window + existence-dimension failure (provesAbsence=true) → FAILED_BEFORE_EFFECT', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
    });
    const r = classifyRecovery({
      journal: j,
      postState: {
        verified: true,
        holds: false,
        provesAbsence: true,
        basis: 'expected file provably absent',
      },
    });
    expect(r.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
    expect(r.resolvedByPostState).toBe(true);
  });

  it('settled FAILED receipt + mismatch post-state → UNCERTAIN (mutating op)', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.registry.setValue' });
      w.append('EXEC_STEP_FAILED', { step: 0, op: 'windows.registry.setValue', detail: {} });
    });
    const r = classifyRecovery({
      journal: j,
      receipt: { terminal: 'FAILED' },
      allStepsSettled: true,
      postState: {
        verified: true,
        holds: false,
        provesAbsence: false,
        basis: 'value differs — partial write possible',
      },
    });
    expect(r.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
  });
});

describe('classifyRecovery — C11 no false verified', () => {
  it('SUCCEEDED receipt + all steps settled + NO independent post-state → UNCERTAIN', () => {
    const j = journalWith((w) => {
      MUTATING_DONE(w);
      w.append('RECEIPT_WRITTEN', { detail: { terminal: 'SUCCEEDED' } });
    });
    const r = classifyRecovery({
      journal: j,
      receipt: { terminal: 'SUCCEEDED' },
      allStepsSettled: true,
    });
    expect(r.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(r.basis).toContain('no independent post-state');
  });

  it('read-only op failure after EXEC_START stays FAILED_BEFORE_EFFECT (no mutation possible)', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.fs.verify' });
      w.append('EXEC_STEP_FAILED', { step: 0, op: 'windows.fs.verify', detail: {} });
    });
    const r = classifyRecovery({
      journal: j,
      receipt: { terminal: 'FAILED' },
      allStepsSettled: true,
    });
    expect(r.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
  });
});

describe('classifyRecovery — C15 UAC_DECLINED vs journal', () => {
  it('UAC_DECLINED + empty journal → NOT_STARTED (unchanged)', () => {
    const r = classifyRecovery({ journal: [], relay: { kind: 'UAC_DECLINED' } });
    expect(r.recoveryClassification).toBe('NOT_STARTED');
  });

  it('UAC_DECLINED + journal proves EXEC_START → UNCERTAIN (relay verdict contradicts the journal)', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
    });
    const r = classifyRecovery({ journal: j, relay: { kind: 'UAC_DECLINED' } });
    expect(r.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(r.basis).toContain('fail closed');
  });

  it('UAC_DECLINED + journal non-empty but pre-effects → FAILED_BEFORE_EFFECT', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('GRANT_OK');
    });
    const r = classifyRecovery({ journal: j, relay: { kind: 'UAC_DECLINED' } });
    expect(r.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
  });
});

// ---- reconcileExpectedState dimension honesty (real fs, C10 integration). ----

describe.skipIf(!ON_WINDOWS)(
  'reconcileExpectedState — existence vs content dimension (C10)',
  () => {
    let authority: TestAuthority;

    beforeAll(async () => {
      authority = await createTestAuthority('shun-honest-');
    });

    afterAll(() => disposeTestAuthority(authority));

    function actionWith(expectedState: Record<string, unknown>, target: string) {
      return buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: target, content: 'intended' },
        requiredPrivilege: 'USER',
        filesystemScope: { read: [authority.workspaceRoot], write: [authority.workspaceRoot] },
        expectedState,
      });
    }

    it('expected file ABSENT → provesAbsence (retry-safe no-effect proof)', async () => {
      const target = join(authority.workspaceRoot, 'reconcile-absent.txt');
      const { action } = actionWith({ path: target, exists: true, content: 'intended' }, target);
      const journal = new JournalWriter(
        join(authority.workspaceRoot, 'reconcile-absent.journal.jsonl'),
        1,
      );
      const outcome = await reconcileExpectedState(
        action,
        { filesystem: { read: [authority.workspaceRoot], write: [authority.workspaceRoot] } },
        journal,
      );
      expect(outcome.verified).toBe(true);
      if (outcome.verified) {
        expect(outcome.holds).toBe(false);
        expect(outcome.provesAbsence).toBe(true);
      }
    });

    it('expected file PRESENT with wrong content → mismatch, NOT absence (partial effect possible)', async () => {
      const { writeFileSync } = await import('node:fs');
      const target = join(authority.workspaceRoot, 'reconcile-partial.txt');
      writeFileSync(target, 'attacker-or-partial-content', 'utf8');
      const { action } = actionWith({ path: target, exists: true, content: 'intended' }, target);
      const journal = new JournalWriter(
        join(authority.workspaceRoot, 'reconcile-partial.journal.jsonl'),
        1,
      );
      const outcome = await reconcileExpectedState(
        action,
        { filesystem: { read: [authority.workspaceRoot], write: [authority.workspaceRoot] } },
        journal,
      );
      expect(outcome.verified).toBe(true);
      if (outcome.verified) {
        expect(outcome.holds).toBe(false);
        // A mismatch must NOT claim absence: the property is omitted entirely.
        expect(outcome.provesAbsence).toBeUndefined();
      }
    });

    it('torn tail in the journal under reconciliation stays a torn marker, not an event', () => {
      const file = join(authority.workspaceRoot, 'reconcile-torn-check.jsonl');
      const w = new JournalWriter(file, 1);
      w.append('RECEIVED');
      w.appendTornForTest('{"ts":"x","phase":"EXEC_D');
      const events = readJournal(file);
      expect(events.filter(isTorn)).toHaveLength(1);
      expect(journalPhases(events)).toEqual(['RECEIVED']);
    });
  },
);
