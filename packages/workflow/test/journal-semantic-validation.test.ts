// T03 post-merge security correction (Issue #36, C04): journal replay is a
// semantic authority boundary, not a syntax check. ACTION_RECEIPTED rows must
// carry a frozen-schema receipt bound to the row's actionId, and
// ACTION_RECONCILED rows must carry a writer-set classification
// (FAILED_BEFORE_EFFECT | COMPLETED_VERIFIED) plus an evidence record. A
// malformed row must be rejected with JournalIntegrityError — never silently
// accepted, never allowed to close (or downgrade) an action.
import { appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { JournalIntegrityError, WorkflowEffectJournal } from '../src/index.ts';
import { executionReceipt, tempDir } from './helpers.ts';

let dir: string;
let file: string;

beforeEach(() => {
  dir = tempDir();
  file = join(dir, 'journal.jsonl');
});

function appendLine(event: Record<string, unknown>): void {
  appendFileSync(file, `${JSON.stringify(event)}\n`, 'utf8');
}

const intentEvent = {
  seq: 1,
  ts: '2026-10-10T12:00:00.000Z',
  kind: 'ACTION_INTENT',
  taskId: 't1',
  actionId: 'a1',
  payload: { planHash: 'p1', riskClass: 'R2', expectedState: { moved: 200 } },
};

const dispatchedEvent = {
  seq: 2,
  ts: '2026-10-10T12:00:01.000Z',
  kind: 'ACTION_DISPATCHED',
  taskId: 't1',
  actionId: 'a1',
  payload: {},
};

describe('C04 — semantic journal validation for action outcome rows', () => {
  it('rejects an ACTION_RECEIPTED row whose receipt violates the frozen schema', () => {
    appendLine(intentEvent);
    appendLine(dispatchedEvent);
    appendLine({
      seq: 3,
      ts: '2026-10-10T12:00:02.000Z',
      kind: 'ACTION_RECEIPTED',
      taskId: 't1',
      actionId: 'a1',
      payload: { receipt: { bogus: true } },
    });

    expect(() => new WorkflowEffectJournal({ file })).toThrow(JournalIntegrityError);
  });

  it('rejects an ACTION_RECEIPTED row whose receipt carries a foreign actionId', () => {
    appendLine(intentEvent);
    appendLine(dispatchedEvent);
    appendLine({
      seq: 3,
      ts: '2026-10-10T12:00:02.000Z',
      kind: 'ACTION_RECEIPTED',
      taskId: 't1',
      actionId: 'a1',
      // A receipt for a DIFFERENT action must never close action a1.
      payload: { receipt: executionReceipt({ actionId: 'a1-impostor' }) },
    });

    expect(() => new WorkflowEffectJournal({ file })).toThrow(JournalIntegrityError);
  });

  it('rejects an ACTION_RECEIPTED row without an actionId', () => {
    appendLine(intentEvent);
    appendLine(dispatchedEvent);
    appendLine({
      seq: 3,
      ts: '2026-10-10T12:00:02.000Z',
      kind: 'ACTION_RECEIPTED',
      taskId: 't1',
      payload: { receipt: executionReceipt({ actionId: 'a1' }) },
    });

    expect(() => new WorkflowEffectJournal({ file })).toThrow(JournalIntegrityError);
  });

  it('rejects an ACTION_RECONCILED row with a classification outside the writer set', () => {
    appendLine(intentEvent);
    appendLine(dispatchedEvent);
    // The kernel only ever closes reconciliations as FAILED_BEFORE_EFFECT or
    // COMPLETED_VERIFIED; a forged NOT_STARTED would mark a destructive
    // action resolvable — fail closed.
    appendLine({
      seq: 3,
      ts: '2026-10-10T12:00:02.000Z',
      kind: 'ACTION_RECONCILED',
      taskId: 't1',
      actionId: 'a1',
      payload: { classification: 'NOT_STARTED', evidence: { probe: true } },
    });

    expect(() => new WorkflowEffectJournal({ file })).toThrow(JournalIntegrityError);
  });

  it('rejects an ACTION_RECONCILED row without an evidence record', () => {
    appendLine(intentEvent);
    appendLine(dispatchedEvent);
    appendLine({
      seq: 3,
      ts: '2026-10-10T12:00:02.000Z',
      kind: 'ACTION_RECONCILED',
      taskId: 't1',
      actionId: 'a1',
      payload: { classification: 'COMPLETED_VERIFIED' },
    });

    expect(() => new WorkflowEffectJournal({ file })).toThrow(JournalIntegrityError);
  });

  it('rejects an ACTION_INTENT row with an invalid riskClass (forged destructive downgrade)', () => {
    appendLine({
      ...intentEvent,
      payload: { planHash: 'p1', riskClass: 'R9' },
    });

    expect(() => new WorkflowEffectJournal({ file })).toThrow(JournalIntegrityError);
  });

  it('accepts rows written by the kernel itself (round-trip stays green)', () => {
    const journal = new WorkflowEffectJournal({ file });
    journal.append({
      kind: 'ACTION_INTENT',
      taskId: 't1',
      actionId: 'a1',
      payload: { planHash: 'p1', riskClass: 'R2', expectedState: { moved: 200 } },
    });
    journal.append({ kind: 'ACTION_DISPATCHED', taskId: 't1', actionId: 'a1', payload: {} });
    journal.append({
      kind: 'ACTION_RECEIPTED',
      taskId: 't1',
      actionId: 'a1',
      payload: { receipt: executionReceipt({ actionId: 'a1' }) },
    });
    journal.append({
      kind: 'ACTION_RECONCILED',
      taskId: 't1',
      actionId: 'a1',
      payload: { classification: 'FAILED_BEFORE_EFFECT', evidence: { moved: 0 } },
    });
    journal.close();

    const reopened = new WorkflowEffectJournal({ file });
    expect(reopened.events).toHaveLength(4);
    reopened.close();
  });
});
