// Privileged phase journal for the bounded cleanup action (L2 §9.4): recovery
// classifications derive ONLY from this journal plus independent post-state
// verification — never from exit-code optimism. The append protocol tolerates
// torn appends: a trailing partial line is isolated and ignored, earlier
// phases stay intact.
import { promises as fsp } from 'node:fs';
import { z } from 'zod';

export const JournalPhaseSchema = z.enum([
  'RECEIVED',
  'GRANT_VALIDATED',
  'TARGET_VALIDATED',
  'EXEC_START',
  'EXEC_DONE',
  'EXEC_BLOCKED',
  'RECEIPT_WRITTEN',
]);
export type JournalPhase = z.infer<typeof JournalPhaseSchema>;

export const JournalEntrySchema = z.strictObject({
  at: z.string().min(1),
  phase: JournalPhaseSchema,
  actionId: z.string().min(1),
  /** File the phase refers to (EXEC_* entries). */
  file: z.string().optional(),
  /** Bytes attributed at the moment of a successful deletion. */
  bytes: z.number().int().nonnegative().optional(),
  /** Error class for EXEC_BLOCKED entries (e.g. EPERM). */
  errorKind: z.string().optional(),
});
export type JournalEntry = z.infer<typeof JournalEntrySchema>;

export class PhaseJournal {
  private constructor(private readonly filePath: string) {}

  static async open(filePath: string): Promise<PhaseJournal> {
    const parent = filePath.replace(/[\\/][^\\/]+$/, '');
    await fsp.mkdir(parent, { recursive: true });
    await fsp.appendFile(filePath, '', 'utf8');
    return new PhaseJournal(filePath);
  }

  async append(entry: JournalEntry): Promise<void> {
    await fsp.appendFile(this.filePath, `${JSON.stringify(entry)}\n`, 'utf8');
  }

  get path(): string {
    return this.filePath;
  }
}

export interface JournalReplay {
  /** Entries recovered from complete lines, in append order. */
  entries: JournalEntry[];
  /** True when a torn trailing line (or a corrupt interior line) was isolated. */
  tornAppendDetected: boolean;
}

/**
 * Tolerant replay: split on newlines, parse each complete line, isolate any
 * line that is not intact JSON (a torn append mid-crash) without discarding
 * the intact phases around it.
 */
export async function replayJournal(filePath: string): Promise<JournalReplay> {
  let raw: string;
  try {
    raw = await fsp.readFile(filePath, 'utf8');
  } catch {
    return { entries: [], tornAppendDetected: false };
  }
  const lines = raw.split('\n');
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  const entries: JournalEntry[] = [];
  let torn = false;
  for (const line of lines) {
    if (line.trim() === '') {
      torn = true;
      continue;
    }
    try {
      entries.push(JournalEntrySchema.parse(JSON.parse(line)));
    } catch {
      torn = true;
    }
  }
  return { entries, tornAppendDetected: torn };
}

export type RecoveryClassification =
  | 'NOT_STARTED'
  | 'FAILED_BEFORE_EFFECT'
  | 'MAY_HAVE_EXECUTED_UNCERTAIN'
  | 'COMPLETED_VERIFIED';

/**
 * Classify what happened to one actionId from the journal alone (L2 §9.4).
 * An EXEC_START without its EXEC_DONE inside a torn tail means the process may
 * have died mid-deletion — the honest classification is uncertainty, resolved
 * only by reconcile-first against the checkpoint manifest.
 */
export function classifyFromJournal(
  entries: JournalEntry[],
  actionId: string,
): RecoveryClassification {
  const relevant = entries.filter((e) => e.actionId === actionId);
  if (relevant.length === 0) return 'NOT_STARTED';
  const received = relevant.some((e) => e.phase === 'RECEIVED');
  const execStart = relevant.some((e) => e.phase === 'EXEC_START');
  if (!received) return 'NOT_STARTED';
  if (!execStart) return 'FAILED_BEFORE_EFFECT';
  const startedFiles = relevant.filter((e) => e.phase === 'EXEC_START');
  const doneFiles = new Set(relevant.filter((e) => e.phase === 'EXEC_DONE').map((e) => e.file));
  const uncertain = startedFiles.some((e) => e.file !== undefined && !doneFiles.has(e.file));
  if (uncertain) return 'MAY_HAVE_EXECUTED_UNCERTAIN';
  return 'COMPLETED_VERIFIED';
}
