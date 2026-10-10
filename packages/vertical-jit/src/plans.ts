// Plan construction for the Loop B vertical.
//
// Provider adapters produce plan PROPOSALS, never authority (L2 §9.1): every
// side-effecting step here becomes a single-action ActionPlan with a computed
// canonical planHash, and execution only ever happens through an
// AuthorizedAction bound to an authority-issued grant. The privileged
// boundary re-validates the presentation independently (contracts §4.6.1).
import {
  type ActionPlan,
  computePlanHash,
  type PlanAction,
  type RecoveryPlan,
  type VerificationPlan,
} from '@shun/contracts';

/** Post-state expectation recorded on privileged actions (L2 §9.4 reconcile-first). */
export type ProviderExpectedState =
  | { readonly providerPresent: true; readonly version: string }
  | { readonly providerPresent: false };

export interface JitPlanSpec {
  readonly taskId: string;
  readonly capabilityId: string;
  readonly bindingId: string;
  readonly rankingPolicyRevision: string;
  readonly policySnapshotRevision: string;
  readonly action: PlanAction;
  readonly verificationPlan: VerificationPlan;
  readonly recoveryPlan: RecoveryPlan;
}

export function buildActionPlan(spec: JitPlanSpec): ActionPlan {
  const plan: Omit<ActionPlan, 'planHash'> = {
    taskId: spec.taskId,
    capabilityId: spec.capabilityId,
    bindingRefs: [spec.bindingId],
    rankingPolicyRevision: spec.rankingPolicyRevision,
    policySnapshotRevision: spec.policySnapshotRevision,
    actions: [spec.action],
    verificationPlan: spec.verificationPlan,
    recoveryPlan: spec.recoveryPlan,
  };
  return { ...plan, planHash: computePlanHash(plan as ActionPlan) };
}

export function installAction(input: {
  actionId: string;
  bindingId: string;
  packageId: string;
  version: string;
  installRoots: readonly string[];
  networkDomains: readonly string[];
  elevated: boolean;
  timeoutMs: number;
}): PlanAction {
  return {
    actionId: input.actionId,
    bindingRef: input.bindingId,
    op: 'software.install',
    parameters: { packageId: input.packageId, version: input.version },
    sideEffectClass: 'R1',
    requiredPrivilege: input.elevated ? 'ELEVATED' : 'USER',
    filesystemScope: {
      read: [],
      write: [...input.installRoots],
    },
    networkScope: { allowed: true, domains: [...input.networkDomains] },
    timeoutMs: input.timeoutMs,
    cancellation: { supported: false, mode: 'FORCED' },
    expectedState: {
      providerPresent: true,
      version: input.version,
    } satisfies ProviderExpectedState,
  };
}

export function taskAction(input: {
  actionId: string;
  bindingId: string;
  executable: string;
  argv: readonly string[];
  outputDir: string;
  timeoutMs: number;
}): PlanAction {
  return {
    actionId: input.actionId,
    bindingRef: input.bindingId,
    op: 'process.argv',
    parameters: { executable: input.executable, argv: [...input.argv] },
    sideEffectClass: 'R1',
    requiredPrivilege: 'USER',
    filesystemScope: {
      read: [input.executable],
      write: [input.outputDir],
    },
    timeoutMs: input.timeoutMs,
    cancellation: { supported: true, mode: 'COOPERATIVE' },
    expectedState: { outputWritten: true },
  };
}

export function uninstallAction(input: {
  actionId: string;
  bindingId: string;
  packageId: string;
  version: string;
  /** Deletion scope: program-owned and cache roots ONLY. Configuration/user paths never enter the scope. */
  deleteRoots: readonly string[];
  elevated: boolean;
  timeoutMs: number;
}): PlanAction {
  return {
    actionId: input.actionId,
    bindingRef: input.bindingId,
    op: 'software.uninstall',
    parameters: { packageId: input.packageId, version: input.version },
    sideEffectClass: 'R2',
    requiredPrivilege: input.elevated ? 'ELEVATED' : 'USER',
    filesystemScope: {
      read: [...input.deleteRoots],
      write: [...input.deleteRoots],
    },
    timeoutMs: input.timeoutMs,
    cancellation: { supported: false, mode: 'FORCED' },
    expectedState: { providerPresent: false } satisfies ProviderExpectedState,
  };
}
