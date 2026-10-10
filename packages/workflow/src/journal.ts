// Durable workflow effect/action journal (L2 §5.4, §9.4).
//
// Append-only JSONL with fsync on every append: this journal is what proves
// intent and attempt mechanics for store effects and privileged actions.
// Replay tolerates torn appends exactly as L2 §9.4 requires — a torn
// trailing line is isolated (and excised so appends can continue), while a
// complete but corrupt line inside the journal is a hard integrity failure.
import {
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  readFileSync,
  truncateSync,
  writeSync,
} from 'node:fs';
import { type ShunStoreMutation, ShunStoreMutationSchema } from '@shun/contracts';
import { JournalIntegrityError } from './errors.ts';

export const JOURNAL_EVENT_KINDS = [
  'EFFECT_INTENT',
  'EFFECT_UNCERTAIN',
  'EFFECT_RECORDED',
  'ACTION_INTENT',
  'ACTION_DISPATCHED',
  'ACTION_RECEIPTED',
  'ACTION_UNCERTAIN',
  'ACTION_RECONCILED',
] as const;

export type WorkflowJournalEventKind = (typeof JOURNAL_EVENT_KINDS)[number];

export interface WorkflowJournalEvent {
  seq: number;
  ts: string;
  kind: WorkflowJournalEventKind;
  taskId: string;
  effectId?: string;
  actionId?: string;
  payload: Record<string, unknown>;
}

export type JournalAppendRequest = Omit<WorkflowJournalEvent, 'seq' | 'ts'>;

export interface WorkflowEffectJournalOptions {
  file: string;
}

const LINE_SEPARATOR = 10; // '\n'

export class WorkflowEffectJournal {
  readonly file: string;

  private eventLog: WorkflowJournalEvent[] = [];
  private tornTail = 0;

  constructor(options: WorkflowEffectJournalOptions) {
    this.file = options.file;
    if (existsSync(this.file)) {
      this.load();
    }
  }

  get events(): readonly WorkflowJournalEvent[] {
    return this.eventLog;
  }

  /** Bytes of an isolated torn trailing append detected at load (0 when clean). */
  get tornTailBytes(): number {
    return this.tornTail;
  }

  append(request: JournalAppendRequest): WorkflowJournalEvent {
    const lastSeq =
      this.eventLog.length > 0 ? (this.eventLog[this.eventLog.length - 1]?.seq ?? 0) : 0;
    const event: WorkflowJournalEvent = {
      seq: lastSeq + 1,
      ts: new Date().toISOString(),
      ...request,
    };
    const line = `${JSON.stringify(event)}\n`;
    const fd = openSync(this.file, 'a');
    try {
      writeSync(fd, Buffer.from(line, 'utf8'));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    this.eventLog.push(event);
    this.tornTail = 0;
    return event;
  }

  close(): void {
    // Append-only file journal: no buffered state to flush (each append fsyncs).
  }

  private load(): void {
    const raw = readFileSync(this.file, 'utf8');
    let tornBytes = 0;
    let completeText = raw;
    if (raw.length > 0 && raw.charCodeAt(raw.length - 1) !== LINE_SEPARATOR) {
      const cut = raw.lastIndexOf(String.fromCharCode(LINE_SEPARATOR));
      tornBytes = cut >= 0 ? raw.length - cut - 1 : raw.length;
      completeText = cut >= 0 ? raw.slice(0, cut + 1) : '';
    }

    const events: WorkflowJournalEvent[] = [];
    for (const line of completeText.split('\n')) {
      if (line.length === 0) {
        continue;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        throw new JournalIntegrityError(
          `journal ${this.file} contains a corrupt complete line at seq ${events.length + 1}`,
        );
      }
      events.push(this.validateEvent(parsed, events.length + 1));
    }

    if (tornBytes > 0) {
      // Isolate the torn tail by excising it; earlier phases stay intact.
      truncateSync(this.file, Buffer.byteLength(completeText, 'utf8'));
    }
    this.eventLog = events;
    this.tornTail = tornBytes;
  }

  private validateEvent(parsed: unknown, expectedSeq: number): WorkflowJournalEvent {
    if (typeof parsed !== 'object' || parsed === null) {
      throw new JournalIntegrityError(`journal event ${expectedSeq} is not an object`);
    }
    const event = parsed as Record<string, unknown>;
    if (event.seq !== expectedSeq) {
      throw new JournalIntegrityError(
        `journal sequence break: expected seq ${expectedSeq}, found ${String(event.seq)}`,
      );
    }
    if (typeof event.ts !== 'string' || typeof event.taskId !== 'string') {
      throw new JournalIntegrityError(`journal event ${expectedSeq} is missing ts/taskId`);
    }
    if (
      typeof event.kind !== 'string' ||
      !JOURNAL_EVENT_KINDS.includes(event.kind as WorkflowJournalEventKind)
    ) {
      throw new JournalIntegrityError(`journal event ${expectedSeq} has unknown kind`);
    }
    if (event.effectId !== undefined && typeof event.effectId !== 'string') {
      throw new JournalIntegrityError(`journal event ${expectedSeq} has invalid effectId`);
    }
    if (event.actionId !== undefined && typeof event.actionId !== 'string') {
      throw new JournalIntegrityError(`journal event ${expectedSeq} has invalid actionId`);
    }
    const payload = event.payload as Record<string, unknown> | undefined;
    if (typeof payload !== 'object' || payload === null) {
      throw new JournalIntegrityError(`journal event ${expectedSeq} is missing payload`);
    }
    if (
      event.kind === 'EFFECT_INTENT' &&
      !ShunStoreMutationSchema.safeParse((payload as { mutation?: unknown }).mutation).success
    ) {
      throw new JournalIntegrityError(
        `journal event ${expectedSeq} has an invalid effect mutation`,
      );
    }
    return {
      seq: expectedSeq,
      ts: event.ts,
      kind: event.kind as WorkflowJournalEventKind,
      taskId: event.taskId,
      effectId: event.effectId as string | undefined,
      actionId: event.actionId as string | undefined,
      payload,
    };
  }
}

/** Convenience read: the journaled intended mutation of an effect intent. */
export function journaledMutation(event: WorkflowJournalEvent): ShunStoreMutation {
  return (event.payload as { mutation: ShunStoreMutation }).mutation;
}
