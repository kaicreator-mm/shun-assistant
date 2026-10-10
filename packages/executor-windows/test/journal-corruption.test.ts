// T04 C16 — torn-tail tolerance must be limited to a PHYSICALLY INCOMPLETE
// final append (crash mid-write). A complete line (terminated, or any
// schema-invalid record anywhere in the file) is corruption/tampering
// evidence and must surface as a distinct corrupt marker that fails
// classification closed — never be silently swallowed as "torn and ignored".
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  isCorrupt,
  isTorn,
  JournalWriter,
  journalDigest,
  journalPhases,
  readJournal,
} from '../src/journal.ts';
import { classifyRecovery } from '../src/recovery.ts';

function journalWith(write: (w: JournalWriter) => void): string {
  const file = join(mkdtempSync(join(tmpdir(), 'shun-jcor-')), 'j.jsonl');
  write(new JournalWriter(file, 1));
  return file;
}

describe('journal replay — torn tail vs corrupt line (C16)', () => {
  it('a physically incomplete FINAL append is still isolated as torn (§9.4)', () => {
    const file = journalWith((w) => {
      w.append('RECEIVED');
      w.appendTornForTest('{"ts":"x","phase":"EXEC_ST'); // no trailing newline
    });
    const events = readJournal(file);
    expect(events.filter(isTorn)).toHaveLength(1);
    expect(events.filter(isCorrupt)).toHaveLength(0);
    expect(journalPhases(events)).toEqual(['RECEIVED']);
  });

  it('a COMPLETE malformed line mid-file is corrupt, not torn', () => {
    const file = journalWith((w) => {
      w.append('RECEIVED');
      w.appendTornForTest('{"ts":"x","phase":"EXEC_ST');
      w.appendTornForTest('}\n'); // completed AFTER the fact — not a crash tail
      w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
    });
    const events = readJournal(file);
    expect(events.filter(isCorrupt)).toHaveLength(1);
    expect(events.filter(isTorn)).toHaveLength(0);
    expect(journalPhases(events)).toEqual(['RECEIVED', 'EXEC_START']);
  });

  it('a schema-invalid but newline-terminated final line is corrupt (tamper-shaped, not crash-shaped)', () => {
    const file = journalWith((w) => {
      w.append('RECEIVED');
      w.appendTornForTest(
        '{"schemaVersion":"evil.attacker/1","ts":"x","pid":1,"phase":"RECEIPT_WRITTEN"}\n',
      );
    });
    const events = readJournal(file);
    expect(events.filter(isCorrupt)).toHaveLength(1);
    expect(events.filter(isTorn)).toHaveLength(0);
  });

  it('digest covers corrupt lines distinctly from torn ones', () => {
    const corrupt = journalWith((w) => {
      w.append('RECEIVED');
      w.appendTornForTest('garbage-line\n');
    });
    const torn = journalWith((w) => {
      w.append('RECEIVED');
      w.appendTornForTest('garbage-line'); // same bytes, incomplete
    });
    expect(journalDigest(readJournal(corrupt))).not.toBe(journalDigest(readJournal(torn)));
  });

  it('classification fails CLOSED on corruption: never NOT_STARTED, never COMPLETED_VERIFIED', () => {
    const file = journalWith((w) => {
      w.append('RECEIVED');
      w.appendTornForTest('{"schemaVersion":"evil/1","ts":"x","pid":1,"phase":"RECEIVED"}\n');
    });
    // Corrupt journal claiming only pre-effect phases: must not claim
    // FAILED_BEFORE_EFFECT either — integrity of the record itself is gone.
    const r = classifyRecovery({ journal: readJournal(file) });
    expect(r.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(r.basis).toContain('integrity');
  });

  it('corruption overrides even a SUCCEEDED receipt + post-state pass', () => {
    const file = journalWith((w) => {
      w.append('RECEIVED');
      w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
      w.append('EXEC_DONE', { step: 0, op: 'windows.fs.write', detail: {} });
      w.appendTornForTest('{"schemaVersion":"evil/1","ts":"x","pid":1,"phase":"EXEC_DONE"}\n');
    });
    const r = classifyRecovery({
      journal: readJournal(file),
      receipt: { terminal: 'SUCCEEDED' },
      allStepsSettled: true,
      postState: { verified: true, holds: true, basis: 'independent verify' },
    });
    expect(r.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
  });
});
