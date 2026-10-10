// Human-comprehensible preview rendering (T08, L2 §12).
//
// Every sentence is a deterministic template over plan STRUCTURE. Free-text
// fields inside a plan (op names, parameter keys) are rendered as opaque
// identifiers, never as instructions, and parameter values are not rendered at
// all — a crafted plan cannot reframe what an approval means (misleading
// preview prevention, Issue #19 acceptance). Risk wording is the fixed L2 §9.2
// table: the class, not the action name, decides the sentence.
import type { ActionPlan, PlanAction, RiskClass } from '@shun/contracts';
import type { PlanPreview, PreviewAction } from './ports.ts';

/** Fixed risk wording (L2 §9.2). R2/R3 mean explicit approval; wording never softens. */
const RISK_STATEMENTS: Record<RiskClass, string> = {
  R0: 'Read-only operation. No files or settings are changed.',
  R1: 'Reversible, bounded writes on this computer. The result is verified after execution.',
  R2:
    'Destructive or potentially harmful operation. It requires a plan, this preview, a recovery ' +
    'disposition, and your explicit approval (or an equally specific durable policy) before ' +
    'anything runs, followed by verification.',
  R3:
    'High-impact, hard-to-reverse operation. It requires explicit approval plus stronger ' +
    'backup/checkpoint protection. This surface does not streamline R3 approvals.',
};

export function riskStatement(risk: RiskClass): string {
  return RISK_STATEMENTS[risk];
}

/** R2 and R3 need explicit approval or a sufficiently specific durable policy (L2 §9.2). */
export function requiresExplicitApproval(risk: RiskClass): boolean {
  return risk === 'R2' || risk === 'R3';
}

const PRIVILEGE_LABELS: Record<PlanAction['requiredPrivilege'], string> = {
  NONE: 'no special permissions',
  USER: 'standard user permissions',
  ELEVATED: 'administrator (elevated) permission — a system prompt will ask you to confirm',
};

function quoteList(paths: string[]): string {
  return paths.map((p) => `“${p}”`).join(', ');
}

/** One action rendered as fixed sentences over its declared scope — nothing else. */
export function describeAction(action: PlanAction): string {
  const parts: string[] = [];
  parts.push(
    `Step \`${action.actionId}\` runs \`${action.op}\` with ${PRIVILEGE_LABELS[action.requiredPrivilege]}.`,
  );
  if (action.filesystemScope) {
    const { read, write } = action.filesystemScope;
    if (read.length > 0) parts.push(`It reads: ${quoteList(read)}.`);
    if (write.length > 0) parts.push(`It writes only inside: ${quoteList(write)}.`);
  }
  if (action.networkScope) {
    parts.push(
      action.networkScope.allowed
        ? `Network access is allowed${action.networkScope.domains ? ` (limited to: ${action.networkScope.domains.join(', ')})` : ''}.`
        : 'Network access is disabled.',
    );
  }
  if (action.registryScope && action.registryScope.write.length > 0) {
    parts.push(`It may write these registry keys: ${quoteList(action.registryScope.write)}.`);
  }
  if (action.cancellation) {
    parts.push(
      action.cancellation.supported
        ? `You can cancel this step while it runs (${action.cancellation.mode.toLowerCase()} cancellation).`
        : 'This step cannot be cancelled once started.',
    );
  }
  return parts.join(' ');
}

function describeVerification(plan: ActionPlan): PlanPreview['verification'] {
  const oracle = plan.verificationPlan.oracle;
  return {
    summary:
      `After execution Shun verifies the outcome with \`${plan.verificationPlan.verifierId}\` ` +
      `(revision ${plan.verificationPlan.verifierRevision})` +
      (oracle ? ', against success criteria fixed BEFORE execution started.' : '.'),
    checks: plan.verificationPlan.checks.map((check) =>
      check.description ? `${check.checkId} — ${check.description}` : check.checkId,
    ),
  };
}

function describeRecovery(plan: ActionPlan): PlanPreview['recovery'] {
  const retry = plan.recoveryPlan.retryAllowedWhen;
  const retryText =
    retry === 'PROVEN_NOT_EXECUTED'
      ? 'a retry happens only after recovery proves the step never ran'
      : 'a retry happens only because this exact step is declared safely repeatable';
  return {
    summary:
      'If something interrupts this task, Shun classifies what happened from its execution journal ' +
      `and the actual on-disk state (never from optimism), and reconciles before retrying. ${retryText[0]!.toUpperCase()}${retryText.slice(1)}.`,
  };
}

/**
 * Deterministic preview for one plan. Same plan (+ same time inputs) → byte
 * equal preview; tests pin this. `expiresAt` is the approval window propagated
 * from the controller's approval record.
 */
export function previewForPlan(
  plan: ActionPlan,
  opts: { generatedAt: string; expiresAt?: string },
): PlanPreview {
  // Recompute the worst declared risk in the plan; previews never rely on a
  // caller-supplied label for the safety sentence.
  const worst = worstRiskClass(plan);
  return {
    taskId: plan.taskId,
    planHash: plan.planHash,
    capabilityId: plan.capabilityId,
    riskClass: worst,
    riskStatement: riskStatement(worst),
    actions: plan.actions.map((action) => ({
      actionId: action.actionId,
      op: action.op,
      description: describeAction(action),
      requiredPrivilege: action.requiredPrivilege,
      filesystem: action.filesystemScope
        ? { read: [...action.filesystemScope.read], write: [...action.filesystemScope.write] }
        : undefined,
      network: action.networkScope
        ? { allowed: action.networkScope.allowed, domains: action.networkScope.domains }
        : { allowed: false },
      cancellation: action.cancellation
        ? { supported: action.cancellation.supported, mode: action.cancellation.mode }
        : undefined,
    })),
    verification: describeVerification(plan),
    recovery: describeRecovery(plan),
    requiresExplicitApproval: requiresExplicitApproval(worst),
    policySnapshotRevision: plan.policySnapshotRevision,
    generatedAt: opts.generatedAt,
    expiresAt: opts.expiresAt,
  };
}

const RISK_ORDER: RiskClass[] = ['R0', 'R1', 'R2', 'R3'];

/** Conservative reading: the plan's effective risk is its highest declared class (L2 §9.1/§9.2). */
export function worstRiskClass(plan: ActionPlan): RiskClass {
  let worstIndex = 0;
  for (const action of plan.actions) {
    const index = RISK_ORDER.indexOf(action.sideEffectClass);
    if (index > worstIndex) worstIndex = index;
  }
  return RISK_ORDER[worstIndex]!;
}
