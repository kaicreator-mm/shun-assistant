// Hard gates (L2 §7.2 ranking policy, Product resolver v0.1).
//
// Gates execute before ranking, in the frozen HARD_GATES order, on each
// candidate Provider × Environment binding. Risk is never folded into a score:
// risk escalation that current policy disallows is REJECTED here, and permitted
// escalation is surfaced as ESCALATION_REQUIRED so the selected binding/plan
// carries it explicitly (L2 §16 P2-02).
import type {
  CapabilityDefinition,
  Constraints,
  EnvironmentFacts,
  EnvironmentPolicy,
  HARD_GATES,
  HardGateDisposition,
  PrivacyPolicy,
  ProviderCapabilityBinding,
  ProviderDefinition,
} from '@shun/contracts';
import { deriveFeasibility } from './feasibility.ts';
import { revisionInRange } from './revision.ts';

/** Curated provider safety facts (fact class 1, L2 §7.1) carried in provenanceFacts. */
export interface SafetyProfile {
  riskEscalationRequired: true;
  escalationReason: string;
}

export function readSafetyProfile(provider: ProviderDefinition): SafetyProfile | undefined {
  const profile = provider.provenanceFacts.safetyProfile;
  if (
    typeof profile === 'object' &&
    profile !== null &&
    (profile as Record<string, unknown>).riskEscalationRequired === true &&
    typeof (profile as Record<string, unknown>).escalationReason === 'string'
  ) {
    return {
      riskEscalationRequired: true,
      escalationReason: (profile as Record<string, unknown>).escalationReason as string,
    };
  }
  return undefined;
}

export interface BindingGateOutcome {
  binding: ProviderCapabilityBinding;
  /** Dispositions for the gates actually evaluated, in frozen gate order. */
  dispositions: HardGateDisposition[];
  passed: boolean;
  escalation?: SafetyProfile & { acknowledged: boolean };
}

export interface GateContext {
  capability: CapabilityDefinition;
  environment: EnvironmentFacts;
  privacyPolicy: PrivacyPolicy;
  environmentPolicy: EnvironmentPolicy;
  constraints: Constraints;
}

function disposition(
  gate: (typeof HARD_GATES)[number],
  bindingId: string,
  outcome: HardGateDisposition['outcome'],
  reason: string,
): HardGateDisposition {
  return { gate, bindingId, outcome, reason };
}

/**
 * Run the five hard gates in frozen order against one binding. Short-circuits
 * at the first REJECT — a binding rejected by trust never reaches feasibility
 * evaluation, and the recorded dispositions show exactly where it stopped.
 */
export function runHardGates(
  binding: ProviderCapabilityBinding,
  provider: ProviderDefinition,
  context: GateContext,
): BindingGateOutcome {
  const dispositions: HardGateDisposition[] = [];

  // Gate 1 — Capability fit: contract match precedes any scoring.
  const fitProblems: string[] = [];
  if (binding.capabilityId !== context.capability.capabilityId) {
    fitProblems.push(`binding targets ${binding.capabilityId}`);
  }
  if (!revisionInRange(context.capability.revision, binding.capabilityRevisionRange)) {
    fitProblems.push(
      `capability revision ${context.capability.revision} outside supported range ${binding.capabilityRevisionRange.min}..${binding.capabilityRevisionRange.max ?? '*'}`,
    );
  }
  if (!context.capability.allowedInterfaceClasses.includes(binding.interfaceClass)) {
    fitProblems.push(`interface class ${binding.interfaceClass} not allowed by capability`);
  }
  if (binding.verifierId !== context.capability.verificationContract.verifierId) {
    fitProblems.push(
      `binding verifier ${binding.verifierId} != capability verifier ${context.capability.verificationContract.verifierId}`,
    );
  }
  const providerInterfaceMatches = provider.interfaces.some(
    (iface) => iface.interfaceClass === binding.interfaceClass,
  );
  if (!providerInterfaceMatches) {
    fitProblems.push(`provider declares no ${binding.interfaceClass} interface`);
  }
  if (fitProblems.length > 0) {
    dispositions.push(
      disposition(
        'CAPABILITY_FIT',
        binding.bindingId,
        'REJECT',
        `contract match failed: ${fitProblems.join('; ')}`,
      ),
    );
    return { binding, dispositions, passed: false };
  }
  dispositions.push(
    disposition(
      'CAPABILITY_FIT',
      binding.bindingId,
      'PASS',
      `capability ${context.capability.capabilityId}@${context.capability.revision} contract match`,
    ),
  );

  // Gate 2 — Trust / supply chain: provenance is fail-closed; UNKNOWN/missing
  // provenance is never trusted by confirmation alone, and outcome evidence
  // cannot upgrade it (L2 §4.3, §7.3).
  const trustState = provider.provenanceFacts.trustState;
  if (trustState !== 'TRUSTED') {
    dispositions.push(
      disposition(
        'TRUST_SUPPLY_CHAIN',
        binding.bindingId,
        'REJECT',
        `provenance ${String(trustState)} is not TRUSTED — fail-closed; unknown provenance cannot be converted by confirmation or outcome evidence`,
      ),
    );
    return { binding, dispositions, passed: false };
  }
  dispositions.push(
    disposition('TRUST_SUPPLY_CHAIN', binding.bindingId, 'PASS', 'provenance TRUSTED'),
  );

  // Gate 3 — Provider × Environment binding feasibility (requirements first,
  // against the currently allowed environment candidates only).
  const feasibility = deriveFeasibility({
    binding,
    provider,
    environment: context.environment,
    environmentPolicy: context.environmentPolicy,
  });
  if (!feasibility.feasible) {
    dispositions.push(
      disposition(
        'PROVIDER_ENVIRONMENT_FEASIBILITY',
        binding.bindingId,
        'REJECT',
        `binding infeasible on ${context.environment.environmentId}: ${feasibility.rejectionReasons.join(', ')}`,
      ),
    );
    return { binding, dispositions, passed: false };
  }
  dispositions.push(
    disposition(
      'PROVIDER_ENVIRONMENT_FEASIBILITY',
      binding.bindingId,
      'PASS',
      `feasible on ${context.environment.environmentId}`,
    ),
  );

  // Gate 4 — User / organization policy: user constraints precede ranking.
  const requirements = binding.environmentRequirements;
  const policyProblems: string[] = [];
  if (context.privacyPolicy.localOnly && requirements.networkAccess === 'REQUIRED') {
    policyProblems.push('local-only privacy policy forbids network-transferring bindings');
  }
  if (context.constraints.other?.offline === true && requirements.networkAccess === 'REQUIRED') {
    policyProblems.push('offline constraint forbids network access');
  }
  if (
    !context.environmentPolicy.allowElevation &&
    requirements.privilegeMode === 'ELEVATED_ADMIN'
  ) {
    policyProblems.push('goal policy disallows elevated execution');
  }
  if (policyProblems.length > 0) {
    dispositions.push(
      disposition('USER_ORG_POLICY', binding.bindingId, 'REJECT', policyProblems.join('; ')),
    );
    return { binding, dispositions, passed: false };
  }
  dispositions.push(
    disposition('USER_ORG_POLICY', binding.bindingId, 'PASS', 'no user/org policy violation'),
  );

  // Gate 5 — Required safety constraints: curated escalation posture is
  // explicit, never a score component (P2-02).
  const safetyProfile = readSafetyProfile(provider);
  if (safetyProfile !== undefined) {
    const acknowledged = context.constraints.other?.riskEscalationAcknowledged === true;
    if (!acknowledged) {
      dispositions.push(
        disposition(
          'SAFETY_CONSTRAINTS',
          binding.bindingId,
          'REJECT',
          `safety escalation required and not acknowledged by current constraints: ${safetyProfile.escalationReason}`,
        ),
      );
      return { binding, dispositions, passed: false };
    }
    dispositions.push(
      disposition(
        'SAFETY_CONSTRAINTS',
        binding.bindingId,
        'ESCALATION_REQUIRED',
        safetyProfile.escalationReason,
      ),
    );
    return {
      binding,
      dispositions,
      passed: true,
      escalation: { ...safetyProfile, acknowledged },
    };
  }
  dispositions.push(
    disposition('SAFETY_CONSTRAINTS', binding.bindingId, 'PASS', 'no safety escalation required'),
  );

  return { binding, dispositions, passed: true };
}
