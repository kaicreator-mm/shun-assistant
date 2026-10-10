// Side-effect recovery classification (L2 §9.4).
//
// Every side-effecting action carries exactly ONE durable recovery
// classification, derived ONLY from the privileged phase journal plus
// independent post-state verification — never from transport/exit optimism.
//
// Classification rules implemented here (in order):
//   NOT_STARTED                  — the journal proves the helper never began
//                                  (absent/empty journal, UAC_DECLINED with
//                                  an empty journal ONLY — a decline verdict
//                                  contradicting a non-empty journal fails
//                                  closed, C15);
//   FAILED_BEFORE_EFFECT         — journal stops before the first EXEC_START
//                                  (all validation phases precede any side
//                                  effect): structured refusal, cancelled
//                                  before effects, or a crash before effects;
//                                  OR an interruption/settled failure whose
//                                  independent post-state check proves the
//                                  effect ABSENT on the existence dimension
//                                  (C10: a content/value mismatch proves
//                                  nothing about effect-liveness);
//   MAY_HAVE_EXECUTED_UNCERTAIN  — interruption inside a step's
//                                  [EXEC_START, EXEC_DONE) window; an
//                                  effect window that opened and closed with
//                                  the receipt lost and no absence proof
//                                  (C09: EXEC_DONE + no receipt must NOT be
//                                  read as "no effect"); a SUCCEEDED receipt
//                                  with no independent post-state evidence
//                                  (C11); any post-state mismatch that is not
//                                  an existence-dimension absence proof;
//   COMPLETED_VERIFIED           — RECEIPT_WRITTEN (or full EXEC_DONE set) +
//                                  independent post-state verification pass.
import type { ExecutionTerminal, RecoveryClassification } from '@shun/contracts';
import type { JournalEvent, ReplayEvent } from './journal.ts';
import {
  isCorrupt,
  isTorn,
  journalHasExecStart,
  journalHasReceived,
  journalPhases,
  journalStepResults,
} from './journal.ts';
import { READONLY_OPS } from './ops.ts';

/**
 * Post-state outcome of a reconcile-first verification run.
 * `provesAbsence` (C10): true ONLY when the check failed on the EXISTENCE
 * dimension (expected file/key provably absent, or expected-absent file/key
 * provably present) — the only outcome that licenses a "no effect" claim and
 * therefore a PROVEN_NOT_EXECUTED retry. A content/value mismatch leaves a
 * partial effect possible and must stay honestly UNCERTAIN.
 */
export type PostStateOutcome =
  | { verified: true; holds: boolean; basis: string; provesAbsence?: boolean }
  | { verified: false; basis: string };

export interface ClassificationInput {
  /** Relay verdict for the elevation attempt; undefined for non-elevated runs. */
  relay?: {
    kind: 'RAN' | 'UAC_DECLINED' | 'NO_RELAY';
    exitCode?: number;
    hresult?: string;
    error?: string;
  };
  /** Tolerant journal replay (empty when the helper provably never started). */
  journal: readonly ReplayEvent[];
  /** Structured receipt from the helper, when one survived. */
  receipt?: { terminal: string };
  /** True when every step has a matching EXEC_DONE/EXEC_STEP_FAILED record. */
  allStepsSettled?: boolean;
  /** Independent post-state verification (launcher-side re-run of read-only verify steps / expectedState). */
  postState?: PostStateOutcome;
}

export interface ClassificationResult {
  recoveryClassification: RecoveryClassification;
  /** Whether reconciliation actually resolved an otherwise-uncertain interruption. */
  resolvedByPostState: boolean;
  basis: string;
}

export function classifyRecovery(input: ClassificationInput): ClassificationResult {
  // C16: corruption/tampering evidence overrides every other rule. A journal
  // containing a complete-but-malformed line cannot prove ANYTHING — not
  // "never started", not "failed before effect", not "completed verified".
  if (input.journal.some(isCorrupt)) {
    return {
      recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      resolvedByPostState: false,
      basis:
        'journal integrity violation: complete but malformed line(s) present — fail closed (torn-tail tolerance applies only to a physically incomplete final append)',
    };
  }
  const phases = journalPhases(input.journal);
  const received = journalHasReceived(input.journal);
  const execStart = journalHasExecStart(input.journal);

  // C15: a UAC decline verdict may only mean "helper provably never started"
  // when the journal is EMPTY. A non-empty journal contradicting the relay
  // verdict (helper actually ran — worst case an effect window opened) fails
  // closed: never NOT_STARTED.
  if (input.relay?.kind === 'UAC_DECLINED') {
    if (execStart) {
      return {
        recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        resolvedByPostState: false,
        basis:
          'UAC relay reported decline but the journal proves an EXEC_START — the verdict contradicts the durable record; fail closed to uncertain',
      };
    }
    if (received) {
      return {
        recoveryClassification: 'FAILED_BEFORE_EFFECT',
        resolvedByPostState: false,
        basis:
          'UAC relay reported decline but the journal is non-empty pre-effects — the helper began; no effect window opened',
      };
    }
    return {
      recoveryClassification: 'NOT_STARTED',
      resolvedByPostState: false,
      basis: 'UAC consent refused/timed out; empty journal — helper provably never started',
    };
  }

  if (!received && !execStart) {
    return {
      recoveryClassification: 'NOT_STARTED',
      resolvedByPostState: false,
      basis: 'no RECEIVED in journal — helper provably never began; no side effect possible',
    };
  }

  if (!execStart) {
    return {
      recoveryClassification: 'FAILED_BEFORE_EFFECT',
      resolvedByPostState: false,
      basis:
        'journal stops before the first EXEC_START — every phase that ran precedes any side effect',
    };
  }

  const settled = input.allStepsSettled ?? allStepsSettled(input.journal);
  if (!settled) {
    return classifyInterrupted(input, phases);
  }

  if (input.receipt?.terminal === 'SUCCEEDED') {
    if (input.postState?.verified && input.postState.holds) {
      return {
        recoveryClassification: 'COMPLETED_VERIFIED',
        resolvedByPostState: false,
        basis: `RECEIPT_WRITTEN + independent post-state verification pass (${input.postState.basis})`,
      };
    }
    if (input.postState?.verified && !input.postState.holds) {
      return {
        recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        resolvedByPostState: false,
        basis: `receipt SUCCEEDED but independent post-state verification conflicts: ${input.postState.basis}`,
      };
    }
    // C11: a structured SUCCEEDED receipt with NO independent post-state
    // evidence is transport optimism, never COMPLETED_VERIFIED. The journal
    // proves the effect window closed cleanly; the honest value for what
    // landed on disk is UNCERTAIN.
    return {
      recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      resolvedByPostState: false,
      basis:
        'structured SUCCEEDED receipt and all steps settled, but no independent post-state evidence — never transport optimism',
    };
  }

  // All steps settled on a FAILED/CANCELLED/TIMED_OUT/ABSENT receipt. The
  // effect window opened and closed; without post-state proof nothing here
  // may claim "no effect".
  if (input.postState?.verified && input.postState.holds) {
    return {
      recoveryClassification: 'COMPLETED_VERIFIED',
      resolvedByPostState: false,
      basis: `independent post-state verification passes despite receipt '${input.receipt?.terminal ?? 'ABSENT'}' — the declared expected state holds (${input.postState.basis})`,
    };
  }
  if (input.postState?.verified && !input.postState.holds) {
    if (input.postState.provesAbsence) {
      return {
        recoveryClassification: 'FAILED_BEFORE_EFFECT',
        resolvedByPostState: true,
        basis: `independent post-state proves the effect absent (existence dimension): ${input.postState.basis}`,
      };
    }
    // C10: a content/value mismatch cannot prove the effect did not land.
    return {
      recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      resolvedByPostState: false,
      basis: `post-state mismatch without absence proof — a partial effect is possible: ${input.postState.basis}`,
    };
  }
  // C09: receipt lost (or a bare structured failure) with no verifiable
  // expected state. For read-only ops the effect window cannot have mutated
  // anything, so FAILED_BEFORE_EFFECT stays sound; for mutating ops the
  // journal proves an effect window ran and nothing proves absence.
  if (onlyReadOnlyEffectWindowOps(input.journal)) {
    return {
      recoveryClassification: 'FAILED_BEFORE_EFFECT',
      resolvedByPostState: false,
      basis: `helper terminal '${input.receipt?.terminal ?? 'ABSENT'}'; every effect-window step is a read-only op — no mutation possible`,
    };
  }
  return {
    recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
    resolvedByPostState: false,
    basis: `helper terminal '${input.receipt?.terminal ?? 'ABSENT'}' with no independent post-state evidence — the journal proves an effect window opened; no absence claim is possible`,
  };
}

function classifyInterrupted(input: ClassificationInput, phases: string[]): ClassificationResult {
  if (phases.includes('TIMED_OUT')) {
    return {
      recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      resolvedByPostState: false,
      basis: 'helper-side deadline fired inside an effect window',
    };
  }
  if (phases.includes('CANCELLED')) {
    return {
      recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      resolvedByPostState: false,
      basis: 'cancel sentinel observed inside an effect window',
    };
  }
  return reconcileInterrupted(input);
}

/**
 * Reconcile-first (§9.4): an interruption inside [EXEC_START, EXEC_DONE) is
 * resolved ONLY by the interrupted step's declared, verifiable expected
 * state; absent that, honestly UNCERTAIN and (for R2/R3) no blind retry.
 */
function reconcileInterrupted(input: ClassificationInput): ClassificationResult {
  if (input.postState?.verified) {
    if (input.postState.holds) {
      return {
        recoveryClassification: 'COMPLETED_VERIFIED',
        resolvedByPostState: true,
        basis: `interrupted inside an effect window; expected state verified present (${input.postState.basis})`,
      };
    }
    if (input.postState.provesAbsence) {
      return {
        recoveryClassification: 'FAILED_BEFORE_EFFECT',
        resolvedByPostState: true,
        basis: `interrupted inside an effect window; expected state proven absent on the existence dimension — effect provably did not land (${input.postState.basis})`,
      };
    }
    // C10: content/value mismatch — a partial effect is possible, so the
    // honest value stays UNCERTAIN (and no blind PROVEN_NOT_EXECUTED retry).
    return {
      recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      resolvedByPostState: false,
      basis: `interrupted inside an effect window; post-state mismatch without absence proof (${input.postState.basis})`,
    };
  }
  return {
    recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
    resolvedByPostState: false,
    basis:
      'crash/interruption inside a step [EXEC_START, EXEC_DONE) window and no verifiable expected state resolves it',
  };
}

/**
 * True when every step that entered an effect window (EXEC_START /
 * EXEC_DONE / EXEC_STEP_FAILED) is a read-only op — read-only steps cannot
 * mutate state, so a settled failure on them licenses FAILED_BEFORE_EFFECT
 * without post-state evidence.
 */
function onlyReadOnlyEffectWindowOps(journal: readonly ReplayEvent[]): boolean {
  const events = journal.filter((e): e is JournalEvent => !isTorn(e) && !isCorrupt(e));
  const ops = new Set<string>();
  for (const e of events) {
    if (
      (e.phase === 'EXEC_START' || e.phase === 'EXEC_DONE' || e.phase === 'EXEC_STEP_FAILED') &&
      typeof e.op === 'string'
    ) {
      ops.add(e.op);
    }
  }
  if (ops.size === 0) return false;
  for (const op of ops) {
    if (!(READONLY_OPS as readonly string[]).includes(op)) return false;
  }
  return true;
}

function allStepsSettled(journal: readonly ReplayEvent[]): boolean {
  const events = journal.filter((e): e is JournalEvent => !isTorn(e));
  const started = new Set<number>();
  const settled = new Set<number>();
  let planned = -1;
  for (const e of events) {
    if (e.phase === 'EXEC_BEGIN') {
      const total = (e.detail as { totalSteps?: unknown } | undefined)?.totalSteps;
      if (typeof total === 'number') planned = total;
    }
    if (e.phase === 'EXEC_START' && e.step !== undefined) started.add(e.step);
    if ((e.phase === 'EXEC_DONE' || e.phase === 'EXEC_STEP_FAILED') && e.step !== undefined) {
      settled.add(e.step);
    }
  }
  for (const step of started) {
    if (!settled.has(step)) return false;
  }
  return planned < 0 ? settled.size > 0 || started.size === 0 : settled.size >= planned;
}

/** The execution terminal a classification implies when no helper receipt survived. */
export function terminalForClassification(c: ClassificationResult): ExecutionTerminal {
  switch (c.recoveryClassification) {
    case 'NOT_STARTED':
      return 'REFUSED';
    case 'FAILED_BEFORE_EFFECT':
      return 'FAILED';
    case 'MAY_HAVE_EXECUTED_UNCERTAIN':
      return 'UNCERTAIN';
    case 'COMPLETED_VERIFIED':
      return 'SUCCEEDED';
  }
}

/** Receipt-shape step results, for launcher-side reconstruction of lost receipts. */
export { journalStepResults };
