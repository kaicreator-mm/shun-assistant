// Side-effect recovery classification (L2 §9.4).
//
// Every side-effecting action carries exactly ONE durable recovery
// classification, derived ONLY from the privileged phase journal plus
// independent post-state verification — never from transport/exit optimism.
//
// Classification rules implemented here (in order):
//   NOT_STARTED                  — the journal proves the helper never began
//                                  (absent/empty journal, UAC_DECLINED);
//   FAILED_BEFORE_EFFECT         — journal stops before the first EXEC_START
//                                  (all validation phases precede any side
//                                  effect): structured refusal, cancelled
//                                  before effects, or a crash before effects;
//   MAY_HAVE_EXECUTED_UNCERTAIN  — interruption inside a step's
//                                  [EXEC_START, EXEC_DONE) window; resolved
//                                  to a concrete outcome ONLY when the
//                                  interrupted step's plan declares
//                                  verifiable expected state (reconcile-
//                                  first), otherwise honestly UNCERTAIN;
//   COMPLETED_VERIFIED           — RECEIPT_WRITTEN (or full EXEC_DONE set) +
//                                  independent post-state verification.
import type { ExecutionTerminal, RecoveryClassification } from '@shun/contracts';
import type { JournalEvent, ReplayEvent } from './journal.ts';
import {
  isTorn,
  journalHasExecStart,
  journalHasReceived,
  journalPhases,
  journalStepResults,
} from './journal.ts';

/** Post-state outcome of a reconcile-first verification run. */
export type PostStateOutcome =
  | { verified: true; holds: boolean; basis: string }
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
  const phases = journalPhases(input.journal);
  const received = journalHasReceived(input.journal);
  const execStart = journalHasExecStart(input.journal);

  if (input.relay?.kind === 'UAC_DECLINED' || (!received && !execStart)) {
    return {
      recoveryClassification: 'NOT_STARTED',
      resolvedByPostState: false,
      basis:
        input.relay?.kind === 'UAC_DECLINED'
          ? 'UAC consent refused/timed out; empty journal — helper provably never started'
          : 'no RECEIVED in journal — helper provably never began; no side effect possible',
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
    // Structured SUCCEEDED receipt with no declared verifiable post-state:
    // the journal proves the effect window closed cleanly (U-06 frozen
    // contract). Honest residual: nothing INDEPENDENT was checked — recorded
    // in the basis and postStateVerified=false.
    return {
      recoveryClassification: 'COMPLETED_VERIFIED',
      resolvedByPostState: false,
      basis:
        'structured SUCCEEDED receipt, all steps settled; action declares no independent post-state check',
    };
  }

  // All steps settled on a non-SUCCEEDED receipt (FAILED/CANCELLED/…): the
  // failure is structured, its point is journaled, and no window is open.
  return {
    recoveryClassification: input.postState?.verified
      ? input.postState.holds
        ? 'COMPLETED_VERIFIED'
        : 'FAILED_BEFORE_EFFECT'
      : 'FAILED_BEFORE_EFFECT',
    resolvedByPostState: false,
    basis: `helper terminal '${input.receipt?.terminal ?? 'ABSENT'}' with all steps settled — failure is structured and located`,
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
    return {
      recoveryClassification: 'FAILED_BEFORE_EFFECT',
      resolvedByPostState: true,
      basis: `interrupted inside an effect window; expected state verified absent — effect provably did not land (${input.postState.basis})`,
    };
  }
  return {
    recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
    resolvedByPostState: false,
    basis:
      'crash/interruption inside a step [EXEC_START, EXEC_DONE) window and no verifiable expected state resolves it',
  };
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
