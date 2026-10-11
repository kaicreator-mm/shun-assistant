// VJ-P1-04 negative controls: one actionId can carry MULTIPLE attempts (the
// reconcile-first retry re-uses the same stable actionId). Classification
// must isolate the LATEST attempt — an earlier attempt's RECEIPT_WRITTEN or
// NO_EFFECT marker must never mask a torn new attempt.
import { describe, expect, it } from 'vitest';
import type { JournalEntry } from '../src/journal.ts';
import { classifyFromJournal } from '../src/journal.ts';

function entry(
  seq: number,
  phase: JournalEntry['phase'],
  attemptId: string | undefined,
  detail?: string,
): JournalEntry {
  return {
    seq,
    ts: `2026-10-10T08:00:0${seq}.000Z`,
    phase,
    actionId: 'a1',
    ...(attemptId !== undefined ? { attemptId } : {}),
    ...(detail ? { detail } : {}),
  };
}

describe('journal attempt isolation (VJ-P1-04)', () => {
  it('a torn NEW attempt classifies UNCERTAIN despite an earlier COMPLETED attempt', () => {
    const entries: JournalEntry[] = [
      entry(1, 'RECEIVED', 'att-1'),
      entry(2, 'EXEC_START', 'att-1'),
      entry(3, 'EXEC_DONE', 'att-1'),
      entry(4, 'RECEIPT_WRITTEN', 'att-1'),
      // Retry under the SAME actionId: transport dies inside the effect window.
      entry(5, 'RECEIVED', 'att-2'),
      entry(6, 'EXEC_START', 'att-2'),
    ];
    expect(classifyFromJournal(entries, 'a1')).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
  });

  it('a journal-complete new attempt remains UNCERTAIN until independent post-state verification', () => {
    const entries: JournalEntry[] = [
      entry(1, 'RECEIVED', 'att-1'),
      entry(2, 'EXEC_START', 'att-1'),
      entry(3, 'RECEIVED', 'att-2'),
      entry(4, 'EXEC_START', 'att-2'),
      entry(5, 'EXEC_DONE', 'att-2'),
      entry(6, 'RECEIPT_WRITTEN', 'att-2'),
    ];
    expect(classifyFromJournal(entries, 'a1')).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
  });

  it('an OLD NO_EFFECT marker does not dominate a later torn attempt', () => {
    const entries: JournalEntry[] = [
      entry(1, 'RECEIVED', 'att-1'),
      entry(2, 'RECEIPT_WRITTEN', 'att-1', 'NO_EFFECT:UAC_DECLINED — elevation refused'),
      // A later attempt did start the effect and was interrupted.
      entry(3, 'RECEIVED', 'att-2'),
      entry(4, 'EXEC_START', 'att-2'),
    ];
    expect(classifyFromJournal(entries, 'a1')).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
  });

  it('entries without attemptId keep the legacy single-attempt semantics', () => {
    const entries: JournalEntry[] = [
      entry(1, 'RECEIVED', undefined),
      entry(2, 'EXEC_START', undefined),
      entry(3, 'EXEC_DONE', undefined),
      entry(4, 'RECEIPT_WRITTEN', undefined),
    ];
    expect(classifyFromJournal(entries, 'a1')).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
  });
});
