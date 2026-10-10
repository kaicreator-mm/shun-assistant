// Phase journal tests: append/replay, torn-append tolerance (§9.4), step
// result extraction and digest stability.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  isTorn,
  JournalWriter,
  journalDigest,
  journalPhases,
  journalStepResults,
  readJournal,
} from '../src/journal.ts';

function tmpJournalFile(): string {
  return join(mkdtempSync(join(tmpdir(), 'shun-journal-')), 'journal.jsonl');
}

describe('JournalWriter / readJournal', () => {
  it('roundtrips events through strict JSONL replay', () => {
    const file = tmpJournalFile();
    const w = new JournalWriter(file, 1234);
    w.append('RECEIVED', { detail: { envelopeFile: 'e.json' } });
    w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
    w.append('EXEC_DONE', { step: 0, op: 'windows.fs.write', detail: { bytes: 3 } });
    const events = readJournal(file);
    expect(events).toHaveLength(3);
    expect(journalPhases(events)).toEqual(['RECEIVED', 'EXEC_START', 'EXEC_DONE']);
    expect(events.every((e) => !isTorn(e))).toBe(true);
  });

  it('isolates a torn final append — earlier phases stay intact (§9.4)', () => {
    const file = tmpJournalFile();
    const w = new JournalWriter(file, 1);
    w.append('RECEIVED');
    w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
    w.appendTornForTest('{"ts":"torn","phase":"EXEC_ST'); // crash mid-append
    const events = readJournal(file);
    expect(journalPhases(events)).toEqual(['RECEIVED', 'EXEC_START']);
    expect(events.filter(isTorn)).toHaveLength(1);
  });

  it('missing journal file reads as empty — "provably never started" is data, not an error', () => {
    expect(readJournal(join(tmpdir(), 'definitely-missing-journal.jsonl'))).toEqual([]);
  });

  it('step results extract EXEC_DONE and EXEC_STEP_FAILED in order', () => {
    const file = tmpJournalFile();
    const w = new JournalWriter(file, 1);
    w.append('EXEC_DONE', { step: 0, op: 'windows.fs.write', detail: { bytes: 5 } });
    w.append('EXEC_STEP_FAILED', {
      step: 1,
      op: 'windows.fs.verify',
      detail: { reason: 'mismatch' },
    });
    const results = journalStepResults(readJournal(file));
    expect(results).toEqual([
      { step: 0, op: 'windows.fs.write', ok: true, detail: { bytes: 5 } },
      { step: 1, op: 'windows.fs.verify', ok: false, detail: { reason: 'mismatch' } },
    ]);
  });

  it('digest changes with content and is stable across replays', () => {
    const file = tmpJournalFile();
    const w = new JournalWriter(file, 7);
    w.append('RECEIVED');
    const events = readJournal(file);
    expect(journalDigest(events)).toBe(journalDigest(readJournal(file)));
    const file2 = tmpJournalFile();
    new JournalWriter(file2, 7).append('RECEIVED');
    new JournalWriter(file2, 7).append('SCOPE_OK');
    expect(journalDigest(events)).not.toBe(journalDigest(readJournal(file2)));
  });
});
