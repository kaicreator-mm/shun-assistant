// Privileged phase journal (L2 §9.4).
//
// Every privileged action appends one JSONL line per phase:
//   RECEIVED → VALIDATED → EXEC_START → EXEC_DONE → RECEIPT_WRITTEN
// Recovery classifications derive ONLY from this journal plus independent
// post-state verification — never from transport or exit-code optimism.
//
// Replay tolerates torn appends: a final line that cannot be parsed (crash
// mid-write) is isolated and dropped; earlier lines stay intact (U-06 D5
// semantics).
import { createHash } from 'node:crypto';

export const JOURNAL_PHASES = [
  'RECEIVED',
  'VALIDATED',
  'EXEC_START',
  'EXEC_DONE',
  'RECEIPT_WRITTEN',
] as const;
export type JournalPhase = (typeof JOURNAL_PHASES)[number];

export interface JournalEntry {
  readonly seq: number;
  readonly ts: string;
  readonly phase: JournalPhase;
  readonly actionId: string;
  readonly detail?: string;
}

/** Append-only journal seam. Real impl is a JSONL file; tests use memory. */
export interface JournalPort {
  append(entry: JournalEntry): Promise<void>;
  /** Torn-tolerant replay: returns the well-formed entries in order. */
  replay(): Promise<JournalEntry[]>;
}

export function newJournalId(prefix: string): string {
  return `${prefix}-${createHash('sha256')
    .update(`${Date.now()}:${Math.random()}`)
    .digest('hex')
    .slice(0, 12)}`;
}

/** In-memory journal (tests, mock backends). */
export class MemoryJournal implements JournalPort {
  readonly #entries: JournalEntry[] = [];
  #nextSeq = 1;

  async append(entry: JournalEntry): Promise<void> {
    this.#entries.push({ ...entry, seq: this.#nextSeq++ });
  }

  async replay(): Promise<JournalEntry[]> {
    return this.#entries.map((entry) => ({ ...entry }));
  }

  /** Test seam: simulate a torn append (partial line) without corrupting earlier entries. */
  tearLast(): void {
    this.#entries.pop();
  }
}

export const PHASE_ORDER: ReadonlyMap<JournalPhase, number> = new Map(
  JOURNAL_PHASES.map((phase, index) => [phase, index]),
);

export type RecoveryClassification =
  | 'NOT_STARTED'
  | 'FAILED_BEFORE_EFFECT'
  | 'MAY_HAVE_EXECUTED_UNCERTAIN'
  | 'COMPLETED_VERIFIED';

/**
 * Journal-only classification (L2 §9.4). `MAY_HAVE_EXECUTED_UNCERTAIN` means
 * the interruption happened inside a step's [EXEC_START, EXEC_DONE) window;
 * resolving it to a concrete outcome requires post-state reconciliation —
 * this function deliberately cannot resolve it.
 *
 * A `NO_EFFECT:` detail marker (written by the privileged backend when the
 * elevation seam refuses before any effect phase, e.g. UAC_DECLINED) proves
 * the helper never started, which classifies NOT_STARTED exactly like the
 * empty-journal case.
 */
export function classifyFromJournal(
  entries: readonly JournalEntry[],
  actionId: string,
): RecoveryClassification | 'NO_ENTRIES' {
  const mine = entries.filter((entry) => entry.actionId === actionId);
  const phases = new Set(mine.map((entry) => entry.phase));
  if (mine.some((entry) => entry.detail?.startsWith('NO_EFFECT:'))) {
    return 'NOT_STARTED';
  }
  if (!phases.has('RECEIVED')) {
    return 'NO_ENTRIES';
  }
  if (!phases.has('EXEC_START')) {
    return 'FAILED_BEFORE_EFFECT';
  }
  if (!phases.has('EXEC_DONE')) {
    return 'MAY_HAVE_EXECUTED_UNCERTAIN';
  }
  return phases.has('RECEIPT_WRITTEN') ? 'COMPLETED_VERIFIED' : 'MAY_HAVE_EXECUTED_UNCERTAIN';
}
