// §9.4 recovery classification matrix — every classification derives ONLY
// from the journal + independent post-state verification.

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ReplayEvent } from '../src/journal.ts';
import { JournalWriter, readJournal } from '../src/journal.ts';
import { classifyRecovery, terminalForClassification } from '../src/recovery.ts';

function journalWith(write: (w: JournalWriter) => void): ReplayEvent[] {
  const file = join(mkdtempSync(join(tmpdir(), 'shun-rec-')), 'j.jsonl');
  const w = new JournalWriter(file, 1);
  write(w);
  return readJournal(file);
}

describe('classifyRecovery — §9.4 matrix', () => {
  it('UAC_DECLINED with empty journal → NOT_STARTED (helper provably never started)', () => {
    const r = classifyRecovery({
      journal: [],
      relay: { kind: 'UAC_DECLINED', hresult: '0x800704C7' },
    });
    expect(r.recoveryClassification).toBe('NOT_STARTED');
    expect(terminalForClassification(r)).toBe('REFUSED');
  });

  it('no journal at all → NOT_STARTED', () => {
    const r = classifyRecovery({ journal: [], relay: { kind: 'NO_RELAY' } });
    expect(r.recoveryClassification).toBe('NOT_STARTED');
  });

  it('journal stops before first EXEC_START → FAILED_BEFORE_EFFECT', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('VALIDATED');
      w.append('REFUSED', { detail: { why: 'grant' } });
      w.append('RECEIPT_WRITTEN', { detail: { terminal: 'REFUSED' } });
    });
    const r = classifyRecovery({
      journal: j,
      receipt: { terminal: 'REFUSED' },
      allStepsSettled: true,
    });
    expect(r.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
    expect(terminalForClassification(r)).toBe('FAILED');
  });

  it('crash before EXEC_START (no receipt) → FAILED_BEFORE_EFFECT', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('GRANT_OK');
    });
    expect(classifyRecovery({ journal: j }).recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
  });

  it('interrupt inside [EXEC_START, EXEC_DONE) without expected state → honestly UNCERTAIN', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_BEGIN', { detail: { totalSteps: 1 } });
      w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
    });
    const r = classifyRecovery({ journal: j });
    expect(r.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(terminalForClassification(r)).toBe('UNCERTAIN');
  });

  it('reconcile-first: interrupted window + expected state HOLDING resolves to COMPLETED_VERIFIED', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
    });
    const r = classifyRecovery({
      journal: j,
      postState: { verified: true, holds: true, basis: 'marker file present with expected digest' },
    });
    expect(r.recoveryClassification).toBe('COMPLETED_VERIFIED');
    expect(r.resolvedByPostState).toBe(true);
  });

  it('reconcile-first: interrupted window + expected state ABSENT resolves to FAILED_BEFORE_EFFECT', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
    });
    const r = classifyRecovery({
      journal: j,
      postState: { verified: true, holds: false, basis: 'expected file provably absent' },
    });
    expect(r.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
    expect(r.resolvedByPostState).toBe(true);
  });

  it('clean SUCCEEDED receipt + independent verify pass → COMPLETED_VERIFIED', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.fs.verify' });
      w.append('EXEC_DONE', { step: 0, op: 'windows.fs.verify', detail: {} });
      w.append('RECEIPT_WRITTEN', { detail: { terminal: 'SUCCEEDED' } });
    });
    const r = classifyRecovery({
      journal: j,
      receipt: { terminal: 'SUCCEEDED' },
      allStepsSettled: true,
      postState: { verified: true, holds: true, basis: 'launcher re-ran windows.fs.verify' },
    });
    expect(r.recoveryClassification).toBe('COMPLETED_VERIFIED');
    expect(terminalForClassification(r)).toBe('SUCCEEDED');
  });

  it('SUCCEEDED receipt that CONFLICTS with independent verification downgrades to UNCERTAIN (never transport optimism)', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
      w.append('EXEC_DONE', { step: 0, op: 'windows.fs.write', detail: {} });
      w.append('RECEIPT_WRITTEN', { detail: { terminal: 'SUCCEEDED' } });
    });
    const r = classifyRecovery({
      journal: j,
      receipt: { terminal: 'SUCCEEDED' },
      allStepsSettled: true,
      postState: { verified: true, holds: false, basis: 'expected file absent' },
    });
    expect(r.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
  });

  it('SUCCEEDED receipt without declared verify → COMPLETED_VERIFIED, honest basis, no claimed independence', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
      w.append('EXEC_DONE', { step: 0, op: 'windows.fs.write', detail: {} });
      w.append('RECEIPT_WRITTEN', { detail: { terminal: 'SUCCEEDED' } });
    });
    const r = classifyRecovery({
      journal: j,
      receipt: { terminal: 'SUCCEEDED' },
      allStepsSettled: true,
    });
    expect(r.recoveryClassification).toBe('COMPLETED_VERIFIED');
  });

  it('mutating step structured failure after EXEC_START stays in the uncertain bucket (reconcile-first upstream)', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.registry.setValue' });
      w.append('EXEC_STEP_FAILED', {
        step: 0,
        op: 'windows.registry.setValue',
        detail: { reason: 'exit 1' },
      });
      w.append('RECEIPT_WRITTEN', { detail: { terminal: 'FAILED' } });
    });
    const r = classifyRecovery({
      journal: j,
      receipt: { terminal: 'FAILED' },
      allStepsSettled: true,
    });
    expect(r.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
    const reconciled = classifyRecovery({
      journal: j,
      receipt: { terminal: 'FAILED' },
      allStepsSettled: true,
      postState: { verified: true, holds: false, basis: 'value provably not set' },
    });
    expect(reconciled.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
  });

  it('torn final append never upgrades a classification', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
      w.appendTornForTest('{"ts":"x","phase":"EXEC_D');
    });
    expect(classifyRecovery({ journal: j }).recoveryClassification).toBe(
      'MAY_HAVE_EXECUTED_UNCERTAIN',
    );
  });

  it('cancel inside the effect window is uncertain until reconciled', () => {
    const j = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.proc.exec' });
      w.append('CANCELLED', { detail: { where: 'step:windows.proc.exec' } });
    });
    expect(classifyRecovery({ journal: j }).recoveryClassification).toBe(
      'MAY_HAVE_EXECUTED_UNCERTAIN',
    );
  });
});
