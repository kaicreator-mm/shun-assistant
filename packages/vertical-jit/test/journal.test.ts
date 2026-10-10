// Privileged phase journal: torn-append-tolerant replay (U-06 D5) and the
// journal-only recovery classification matrix (L2 §9.4).
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { FileJournal } from '../src/adapters/node.ts';
import type { JournalEntry } from '../src/journal.ts';
import { classifyFromJournal, MemoryJournal } from '../src/journal.ts';

function entry(phase: JournalEntry['phase'], detail?: string): JournalEntry {
  return {
    seq: 0,
    ts: '2026-10-10T08:00:00.000Z',
    phase,
    actionId: 'a1',
    ...(detail ? { detail } : {}),
  };
}

async function seedJournal(lines: string[]): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'jit-journal-'));
  const path = join(dir, 'a1.jsonl');
  await writeFile(path, lines.join('\n'), 'utf8');
  return path;
}

describe('phase journal replay', () => {
  it('replays complete JSONL journals in order', async () => {
    const path = await seedJournal([
      JSON.stringify({ seq: 1, ts: 't1', phase: 'RECEIVED', actionId: 'a1' }),
      JSON.stringify({ seq: 2, ts: 't2', phase: 'EXEC_START', actionId: 'a1' }),
    ]);
    const entries = await new FileJournal(path).replay();
    expect(entries.map((entry) => entry.phase)).toEqual(['RECEIVED', 'EXEC_START']);
  });

  it('isolates a torn final line and keeps earlier phases intact', async () => {
    const complete = [
      JSON.stringify({ seq: 1, ts: 't1', phase: 'RECEIVED', actionId: 'a1' }),
      JSON.stringify({ seq: 2, ts: 't2', phase: 'EXEC_START', actionId: 'a1' }),
      JSON.stringify({ seq: 3, ts: 't3', phase: 'EXEC_DONE', actionId: 'a1' }),
    ];
    const path = await seedJournal([...complete, '{"seq":4,"ts":"t4","phas']);
    const entries = await new FileJournal(path).replay();
    expect(entries.map((entry) => entry.phase)).toEqual(['RECEIVED', 'EXEC_START', 'EXEC_DONE']);
    // The torn bytes are still on disk for forensics — replay never truncates.
    expect(await readFile(path, 'utf8')).toContain('"phas');
  });

  it('memory journal round-trips and supports test-time tearing', async () => {
    const journal = new MemoryJournal();
    await journal.append({ seq: 0, ts: 't', phase: 'RECEIVED', actionId: 'a1' });
    await journal.append({ seq: 0, ts: 't', phase: 'EXEC_START', actionId: 'a1' });
    expect((await journal.replay()).length).toBe(2);
    journal.tearLast();
    expect((await journal.replay()).length).toBe(1);
  });
});

describe('journal-only recovery classification', () => {
  it('classifies the frozen four-state matrix', () => {
    expect(classifyFromJournal([], 'a1')).toBe('NO_ENTRIES');
    expect(classifyFromJournal([entry('RECEIVED')], 'a1')).toBe('FAILED_BEFORE_EFFECT');
    expect(classifyFromJournal([entry('RECEIVED'), entry('EXEC_START')], 'a1')).toBe(
      'MAY_HAVE_EXECUTED_UNCERTAIN',
    );
    expect(
      classifyFromJournal(
        [entry('RECEIVED'), entry('EXEC_START'), entry('EXEC_DONE'), entry('RECEIPT_WRITTEN')],
        'a1',
      ),
    ).toBe('COMPLETED_VERIFIED');
  });

  it('classifies UAC-style NO_EFFECT markers as NOT_STARTED', () => {
    const entries = [
      entry('RECEIVED'),
      entry('VALIDATED'),
      entry(
        'RECEIPT_WRITTEN',
        'NO_EFFECT:UAC_DECLINED — elevation refused before the effect phase',
      ),
    ];
    expect(classifyFromJournal(entries, 'a1')).toBe('NOT_STARTED');
  });

  it('is per-actionId: another action’s phases do not leak into the classification', () => {
    const entries: JournalEntry[] = [
      { seq: 1, ts: 't', phase: 'EXEC_START', actionId: 'other' },
      { seq: 2, ts: 't', phase: 'EXEC_DONE', actionId: 'other' },
      { seq: 3, ts: 't', phase: 'RECEIVED', actionId: 'a1' },
    ];
    expect(classifyFromJournal(entries, 'a1')).toBe('FAILED_BEFORE_EFFECT');
  });
});
