// T04 C17 — the phase journal must cross a durable fsync barrier on every
// append: it is the recovery authority (L2 §9.4), and a journal event that
// survives only in the page cache is not evidence after a power loss.
// Negative controls: fsyncSync must be invoked for every append, and a torn
// simulation append must stay raw (a crash mid-write produces no barrier).
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { JournalWriter, durableWriteFileSync, readJournal } from '../src/journal.ts';

const { fsyncMock } = vi.hoisted(() => ({ fsyncMock: vi.fn() }));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    fsyncSync: ((...args: Parameters<typeof actual.fsyncSync>) => {
      fsyncMock(...args);
      return actual.fsyncSync(...args);
    }) as typeof actual.fsyncSync,
  };
});

describe('JournalWriter durable append barrier (C17)', () => {
  it('append() fsyncs the journal fd on every event', () => {
    fsyncMock.mockClear();
    const file = join(mkdtempSync(join(tmpdir(), 'shun-jdur-')), 'journal.jsonl');
    const w = new JournalWriter(file, 42);
    w.append('RECEIVED');
    w.append('EXEC_START', { step: 0, op: 'windows.fs.write' });
    // One fsync per appended event — the durability barrier is per-event,
    // not best-effort batching.
    expect(fsyncMock).toHaveBeenCalledTimes(2);
    expect(readJournal(file)).toHaveLength(2);
  });

  it('appendTornForTest deliberately writes WITHOUT a barrier (crash simulation stays raw)', () => {
    fsyncMock.mockClear();
    const file = join(mkdtempSync(join(tmpdir(), 'shun-jdur-')), 'journal.jsonl');
    const w = new JournalWriter(file, 1);
    w.append('RECEIVED');
    const callsAfterAppend = fsyncMock.mock.calls.length;
    w.appendTornForTest('{"ts":"x","phase":"EXEC_ST');
    // A torn half-append simulates a crash mid-write: it must NOT claim a
    // durability barrier it never got.
    expect(fsyncMock.mock.calls.length).toBe(callsAfterAppend);
  });

  it('the helper receipt channel fsyncs its tmp file (durableWriteFileSync)', () => {
    fsyncMock.mockClear();
    const dir = mkdtempSync(join(tmpdir(), 'shun-jdur-'));
    durableWriteFileSync(join(dir, 'receipt.json.tmp'), '{}\n');
    expect(fsyncMock).toHaveBeenCalled();
  });
});
