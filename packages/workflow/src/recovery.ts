// Four-state side-effect recovery model (L2 §9.4, closes P0-RECOVERY-01).
//
// Classifications derive ONLY from the durable journal plus declared
// post-state verification — never from transport or exit-code optimism.
// The kernel exposes the classification and the only legal continuation
// (same-actionId resume, reconcile-first); it never executes or retries an
// unresolved destructive action by itself.
import type {
  ExecutionReceipt,
  RecoveryClassification,
  RiskClass,
  TaskWorkflowState,
} from '@shun/contracts';

export interface ActionRecoveryView {
  actionId: string;
  taskId: string;
  planHash: string;
  riskClass: RiskClass;
  classification: RecoveryClassification;
  /** false only while the action sits in MAY_HAVE_EXECUTED_UNCERTAIN. */
  resolved: boolean;
  /**
   * true only when the journal/verification PROVES a retry is safe
   * (NOT_STARTED / FAILED_BEFORE_EFFECT) — and then only on the SAME actionId.
   */
  canResume: boolean;
  receipt: ExecutionReceipt | null;
  expectedState?: unknown;
}

export interface DestructiveReconcileProbeInput {
  taskId: string;
  actionId: string;
  planHash: string;
  riskClass: RiskClass;
  expectedState?: unknown;
}

export type DestructiveReconcileVerdict =
  | { outcome: 'CONFIRMED_EXECUTED'; evidence: Record<string, unknown> }
  | { outcome: 'CONFIRMED_NOT_EXECUTED'; evidence: Record<string, unknown> }
  | { outcome: 'UNKNOWN'; evidence: Record<string, unknown> };

/**
 * Declared post-state verification for an interrupted action (the
 * reconcile-first step of L2 §9.4). Implemented above the privileged backend
 * seam; the kernel only consumes verdicts.
 */
export interface DestructiveReconcileProbe {
  verifyExpectedState(input: DestructiveReconcileProbeInput): Promise<DestructiveReconcileVerdict>;
}

export interface RecoveryReport {
  taskId: string;
  state: TaskWorkflowState;
  actionRecoveries: ActionRecoveryView[];
  /** Store effects resolved to a durable receipt during this recovery pass. */
  resolvedEffectIds: string[];
  /** Store effects that remain uncommitted/unresolved (task escalates). */
  unresolvedEffectIds: string[];
  /** Actions still sitting in MAY_HAVE_EXECUTED_UNCERTAIN after reconcile-first. */
  unresolvedActionIds: string[];
  interventionReason?: string;
  redeliveredMessageIds: string[];
  failedMessageIds: string[];
}
