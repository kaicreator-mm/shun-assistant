// T03 required evidence — crash/torn journal (L2 §9.4): journal replay MUST
// tolerate torn appends (a torn trailing line is isolated; earlier phases
// stay intact) and fail closed on mid-file corruption.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { JournalIntegrityError, WorkflowEffectJournal } from '../src/index.ts';
import { tempDir } from './helpers.ts';

let dir: string;
let file: string;

beforeEach(() => {
  dir = tempDir();
  file = join(dir, 'journal.jsonl');
});

describe('WorkflowEffectJournal replay', () => {
  it('appends durably and replays events with contiguous sequence numbers', () => {
    const journal = new WorkflowEffectJournal({ file });
    journal.append({ kind: 'EFFECT_INTENT', taskId: 't1', effectId: 'e1', payload: { n: 1 } });
    journal.append({ kind: 'EFFECT_RECORDED', taskId: 't1', effectId: 'e1', payload: {} });
    journal.close();

    const reopened = new WorkflowEffectJournal({ file });
    expect(reopened.events.map((event) => event.seq)).toEqual([1, 2]);
    expect(reopened.events[0]).toMatchObject({ kind: 'EFFECT_INTENT', effectId: 'e1' });
    reopened.close();
  });

  it('isolates a torn trailing append and keeps earlier phases intact', () => {
    const journal = new WorkflowEffectJournal({ file });
    journal.append({ kind: 'EFFECT_INTENT', taskId: 't1', effectId: 'e1', payload: {} });
    journal.append({ kind: 'ACTION_INTENT', taskId: 't1', actionId: 'a1', payload: {} });
    journal.close();

    // Simulate a crash mid-append: a partial JSON line without a newline.
    const raw = readFileSync(file, 'utf8');
    writeFileSync(file, `${raw}{"seq":3,"kind":"ACTION_DIS`, 'utf8');

    const reopened = new WorkflowEffectJournal({ file });
    expect(reopened.events).toHaveLength(2);
    expect(reopened.tornTailBytes).toBeGreaterThan(0);
    expect(reopened.events.map((event) => event.seq)).toEqual([1, 2]);

    // The torn tail is excised; appends continue with correct sequencing.
    reopened.append({ kind: 'EFFECT_RECORDED', taskId: 't1', effectId: 'e1', payload: {} });
    expect(reopened.events[2]).toMatchObject({ seq: 3, kind: 'EFFECT_RECORDED' });
    reopened.close();

    const final = new WorkflowEffectJournal({ file });
    expect(final.events).toHaveLength(3);
    expect(final.tornTailBytes).toBe(0);
    final.close();
  });

  it('fails closed on a complete but corrupt line inside the journal', () => {
    const journal = new WorkflowEffectJournal({ file });
    journal.append({ kind: 'EFFECT_INTENT', taskId: 't1', effectId: 'e1', payload: {} });
    journal.close();

    const raw = readFileSync(file, 'utf8');
    writeFileSync(file, `${raw}not-json-at-all\n`, 'utf8');

    expect(() => new WorkflowEffectJournal({ file })).toThrow(JournalIntegrityError);
  });
});
