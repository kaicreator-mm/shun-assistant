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
  /**
   * Identity of ONE attempt of this actionId. The reconcile-first retry
   * re-uses a stable actionId, so a single journal can hold several
   * attempts; classification must isolate the latest (VJ-P1-04). Entries
   * without an attemptId are treated as one legacy attempt.
   */
  readonly attemptId?: string;
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
 * A `NO_EFFECT:` detail marker is authoritative evidence that the effect
 * did not occur; it does NOT erase a durable RECEIVED. After RECEIVED, a
 * refusal with no effect classifies FAILED_BEFORE_EFFECT (frozen §9.4).
 * NOT_STARTED is reserved for a helper that never emitted RECEIVED.
 *
 * Attempt isolation (VJ-P1-04): one actionId may carry MULTIPLE attempts —
 * the reconcile-first retry keeps the SAME actionId and starts a new
 * attempt. Only the LATEST attempt describes the current recovery
 * situation: an earlier attempt's receipt must not mask a torn new attempt,
 * and an earlier NO_EFFECT marker must not dominate a later attempt that did
 * reach the effect phase. Critically, a journal can prove phase completion
 * but cannot independently verify post-state, so journal replay alone NEVER
 * upgrades an effectful attempt to COMPLETED_VERIFIED. Entries without
 * an attemptId form a single legacy attempt (replay order is the order
 * truth: the attempt of the LAST replayed entry wins).
 */
export function classifyFromJournal(
  entries: readonly JournalEntry[],
  actionId: string,
): RecoveryClassification | 'NO_ENTRIES' {
  const mine = entries.filter((entry) => entry.actionId === actionId);
  if (mine.length === 0) {
    return 'NO_ENTRIES';
  }
  const latestAttemptId = mine[mine.length - 1]?.attemptId ?? 'legacy';
  const attempt = mine.filter((entry) => (entry.attemptId ?? 'legacy') === latestAttemptId);
  const phases = new Set(attempt.map((entry) => entry.phase));
  if (!phases.has('RECEIVED')) {
    return 'NO_ENTRIES';
  }
  if (attempt.some((entry) => entry.detail?.startsWith('NO_EFFECT:'))) {
    // If a contradictory EXEC_DONE also exists, proof is incoherent;
    // fail closed as uncertain rather than trusting the no-effect marker.
    return phases.has('EXEC_DONE') ? 'MAY_HAVE_EXECUTED_UNCERTAIN' : 'FAILED_BEFORE_EFFECT';
  }
  if (!phases.has('EXEC_START')) {
    return 'FAILED_BEFORE_EFFECT';
  }
  if (!phases.has('EXEC_DONE')) {
    return 'MAY_HAVE_EXECUTED_UNCERTAIN';
  }
  // EXEC_DONE proves the worker left the effect phase; it does not prove
  // the declared post-state. Only the orchestrator's independent verifier
  // may promote an action to COMPLETED_VERIFIED.
  return 'MAY_HAVE_EXECUTED_UNCERTAIN';
}
