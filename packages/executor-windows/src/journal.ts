// Privileged phase journal (L2 §8.2.1, §9.4).
//
// The journal is the recovery authority: every classification in §9.4 derives
// ONLY from this journal plus independent post-state verification — never
// from transport/exit optimism. Append-only JSONL, UTF-8 without BOM, one
// event per line; replay MUST tolerate a torn final append (crash mid-write
// isolates the torn line, earlier phases stay intact).
//
// Phase order (all validation strictly precedes the first side effect):
//   RECEIVED → VALIDATED → PLAN_IDENTITY_OK → GRANT_OK → SCOPE_OK →
//   PRIVILEGE_OK → EXEC_BEGIN → (EXEC_START → EXEC_DONE | EXEC_STEP_FAILED)*
//   → RECEIPT_WRITTEN
// with CANCELLED / TIMED_OUT markers emitted at the point of observation.

import { createHash } from 'node:crypto';
import {
  appendFileSync,
  closeSync,
  fsyncSync,
  openSync,
  readFileSync,
  writeSync,
} from 'node:fs';
import { z } from 'zod';

export const JOURNAL_SCHEMA_VERSION = 'shun.executor-windows.journal/1';

export const JOURNAL_PHASES = [
  'RECEIVED',
  'REFUSED',
  'VALIDATED',
  'PLAN_IDENTITY_OK',
  'GRANT_OK',
  'SCOPE_OK',
  'PRIVILEGE_OK',
  'EXEC_BEGIN',
  'EXEC_START',
  'EXEC_DONE',
  'EXEC_STEP_FAILED',
  'CANCELLED',
  'TIMED_OUT',
  'RECEIPT_WRITTEN',
  // Launcher-only phases (launch.jsonl, a separate artifact from the
  // privileged journal.jsonl; classification never keys on them).
  'LAUNCH_BEGIN',
  'LAUNCH_RELAY',
] as const;
export type JournalPhase = (typeof JOURNAL_PHASES)[number];

export const JournalEventSchema = z.strictObject({
  schemaVersion: z.literal(JOURNAL_SCHEMA_VERSION),
  ts: z.string().min(1),
  pid: z.number().int(),
  phase: z.enum(JOURNAL_PHASES),
  step: z.number().int().nonnegative().optional(),
  op: z.string().min(1).optional(),
  detail: z.record(z.string(), z.unknown()).optional(),
});
export type JournalEvent = z.infer<typeof JournalEventSchema>;

/** A line that could not be parsed: isolated, never corrupts earlier phases (§9.4 torn-append rule). */
export interface TornJournalLine {
  readonly torn: true;
  readonly line: string;
}

/**
 * A COMPLETE line (newline-terminated, or anywhere but the physically
 * incomplete final append) that is not a valid journal event (C16): this is
 * corruption or tampering evidence, not a crash artifact — a torn-append
 * tolerance that silently swallowed it would let a doctored journal replay
 * as "helper crashed mid-write". Recovery fails closed on any corrupt line.
 */
export interface CorruptJournalLine {
  readonly corrupt: true;
  readonly line: string;
}

export type ReplayEvent = JournalEvent | TornJournalLine | CorruptJournalLine;

export function isTorn(e: ReplayEvent): e is TornJournalLine {
  return (e as TornJournalLine).torn === true;
}

export function isCorrupt(e: ReplayEvent): e is CorruptJournalLine {
  return (e as CorruptJournalLine).corrupt === true;
}

/** True when replay found corruption/tampering evidence (C16) — classification must fail closed. */
export function journalHasCorrupt(events: readonly ReplayEvent[]): boolean {
  return events.some(isCorrupt);
}

export class JournalWriter {
  private readonly file: string;
  private readonly pid: number;

  constructor(file: string, pid: number) {
    this.file = file;
    this.pid = pid;
  }

  append(
    phase: JournalPhase,
    fields?: { step?: number; op?: string; detail?: Record<string, unknown> },
  ): void {
    const event: JournalEvent = {
      schemaVersion: JOURNAL_SCHEMA_VERSION,
      ts: new Date().toISOString(),
      pid: this.pid,
      phase,
      ...(fields?.step !== undefined ? { step: fields.step } : {}),
      ...(fields?.op !== undefined ? { op: fields.op } : {}),
      ...(fields?.detail ? { detail: fields.detail } : {}),
    };
    appendFileSyncDurable(this.file, `${JSON.stringify(event)}\n`);
  }

  /**
   * Deliberately torn half-append: crash-simulation support for recovery
   * tests. Raw append, NO fsync barrier — it simulates a write that died
   * mid-flight, so claiming durability would defeat the simulation.
   */
  appendTornForTest(text: string): void {
    appendFileSync(this.file, text, { encoding: 'utf8' });
  }
}

/**
 * Append `text` to `file` behind a durable barrier (C17): open, write, fsync,
 * close. The journal is the §9.4 recovery authority — every event must survive
 * a process crash AND a power loss before the next phase begins, otherwise
 * the classification derived from "the journal proves…" is built on cache.
 */
export function appendFileSyncDurable(file: string, text: string): void {
  const fd = openSync(file, 'a');
  try {
    writeSync(fd, text, null, 'utf8');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Write a complete file behind a durable barrier (fsync before close). Used
 * for the helper's receipt tmp file so the subsequent atomic rename cannot
 * publish content that exists only in the page cache.
 */
export function durableWriteFileSync(file: string, text: string): void {
  const fd = openSync(file, 'w');
  try {
    writeSync(fd, text, null, 'utf8');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Tolerant journal replay (launcher side). Missing file → empty journal
 * ("helper provably never started" is a classification INPUT, not an error).
 * A torn line becomes a TornJournalLine marker; everything before it remains
 * authoritative.
 */
export function readJournal(file: string): ReplayEvent[] {
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch {
    return [];
  }
  const events: ReplayEvent[] = [];
  const lines = raw.split(/\r?\n/);
  const endsWithNewline = raw.endsWith('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().length === 0) continue;
    try {
      events.push(JournalEventSchema.parse(JSON.parse(line)));
    } catch {
      // Torn-tail tolerance is limited to a PHYSICALLY INCOMPLETE final
      // append (C16): the journal writer emits each event as one
      // write+fsync of `line + '\n'`, so a crash can only truncate the final
      // append (bytes missing → no trailing newline). Anything else —
      // malformed bytes mid-file, or a newline-terminated line that parses
      // as JSON but violates the event schema — is corruption/tampering.
      const physicallyIncompleteFinal = i === lines.length - 1 && !endsWithNewline;
      events.push({
        ...(physicallyIncompleteFinal ? { torn: true } : { corrupt: true }),
        line: line.slice(0, 200),
      });
    }
  }
  return events;
}

export function journalPhases(events: readonly ReplayEvent[]): JournalPhase[] {
  return events
    .filter((e): e is JournalEvent => !isTorn(e) && !isCorrupt(e))
    .map((e) => e.phase);
}

/** True once the journal proves the helper began validation (first durable record). */
export function journalHasReceived(events: readonly ReplayEvent[]): boolean {
  return journalPhases(events).includes('RECEIVED');
}

/** True once any side-effecting step has opened its effect window. */
export function journalHasExecStart(events: readonly ReplayEvent[]): boolean {
  return journalPhases(events).includes('EXEC_START');
}

/** Durable step results recorded in EXEC_DONE details (receipt-reconstruction input). */
export interface JournalStepResult {
  readonly step: number;
  readonly op: string;
  readonly ok: boolean;
  readonly detail: Record<string, unknown>;
}

export function journalStepResults(events: readonly ReplayEvent[]): JournalStepResult[] {
  const results: JournalStepResult[] = [];
  for (const event of events) {
    if (isTorn(event)) continue;
    if (isCorrupt(event)) continue;
    if (event.phase === 'EXEC_DONE' && event.step !== undefined && event.op !== undefined) {
      results.push({ step: event.step, op: event.op, ok: true, detail: event.detail ?? {} });
    }
    if (event.phase === 'EXEC_STEP_FAILED' && event.step !== undefined && event.op !== undefined) {
      results.push({ step: event.step, op: event.op, ok: false, detail: event.detail ?? {} });
    }
  }
  return results;
}

/** Stable digest over the journal content — evidence identity, not a classification input. */
export function journalDigest(events: readonly ReplayEvent[]): string {
  const hash = createHash('sha256');
  for (const event of events) {
    hash.update(
      isTorn(event)
        ? `TORN\t${event.line}\n`
        : isCorrupt(event)
          ? `CORRUPT\t${event.line}\n`
          : `${JSON.stringify(event)}\n`,
    );
  }
  return hash.digest('hex');
}
