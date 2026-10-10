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

/**
 * Strict parse result of a provider's curated safetyProfile (P1-03): ABSENT
 * means the fact class is not declared (no escalation posture known); VALID
 * parses into the SafetyProfile shape; MALFORMED means a safetyProfile IS
 * present but does not parse — it never degrades to "no profile".
 */
export type SafetyProfileRead =
  | { status: 'ABSENT' }
  | { status: 'VALID'; profile: SafetyProfile }
  | { status: 'MALFORMED'; reason: string };

export function readSafetyProfile(provider: ProviderDefinition): SafetyProfileRead {
  const profile = provider.provenanceFacts.safetyProfile;
  if (profile === undefined) {
    return { status: 'ABSENT' };
  }
  if (typeof profile !== 'object' || profile === null || Array.isArray(profile)) {
    return {
      status: 'MALFORMED',
      reason: `safetyProfile must be an object, got ${typeof profile}`,
    };
  }
  const record = profile as Record<string, unknown>;
  if (record.riskEscalationRequired !== true) {
    return {
      status: 'MALFORMED',
      reason:
        'safetyProfile.riskEscalationRequired must be the literal true (missing/false is not a parseable safety posture)',
    };
  }
  if (typeof record.escalationReason !== 'string' || record.escalationReason.length === 0) {
    return {
      status: 'MALFORMED',
      reason: 'safetyProfile.escalationReason must be a non-empty string',
    };
  }
  return {
    status: 'VALID',
    profile: { riskEscalationRequired: true, escalationReason: record.escalationReason },
  };
}

/**
 * Bounded curated format facts (P1-04): the frozen binding/capability
 * contracts carry no per-binding output-format metadata, so the resolver
 * reads an opt-in `formatSupport: string[]` fact from provider.provenanceFacts
 * (the one unconstrained curated record in the frozen ProviderDefinition).
 * ABSENT = no curated fact (constraints cannot be gate-evaluated and are
 * explicitly deferred); MALFORMED = a present fact that does not parse fails
 * closed like any other curated fact.
 */
export type FormatSupportRead =
  | { status: 'ABSENT' }
  | { status: 'VALID'; formats: readonly string[] }
  | { status: 'MALFORMED'; reason: string };

export function readFormatSupport(provider: ProviderDefinition): FormatSupportRead {
  const fact = provider.provenanceFacts.formatSupport;
  if (fact === undefined) {
    return { status: 'ABSENT' };
  }
  if (!Array.isArray(fact) || fact.length === 0) {
    return {
      status: 'MALFORMED',
      reason: 'curated formatSupport must be a non-empty array of format tokens',
    };
  }
  if (!fact.every((entry) => typeof entry === 'string' && entry.trim().length > 0)) {
    return {
      status: 'MALFORMED',
      reason: 'curated formatSupport entries must be non-empty strings',
    };
  }
  return { status: 'VALID', formats: fact as string[] };
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

  // Disclosure dimension (P1-02): a no-disclosure privacy policy (localOnly,
  // or externalDisclosure FORBIDDEN) admits only bindings whose requirements
  // explicitly declare networkAccess FORBIDDEN — that declaration is the only
  // machine-checkable disclosure-compatibility evidence in the frozen binding
  // contract. REQUIRED is an unconditional network-transfer posture, OPTIONAL
  // is an unproven posture (no proven no-disclosure execution mode), and an
  // absent declaration is an unknown posture; all three fail closed instead
  // of silently passing a disclosure-forbidding policy.
  const noDisclosurePolicy =
    context.privacyPolicy.localOnly || context.privacyPolicy.externalDisclosure === 'FORBIDDEN';
  if (noDisclosurePolicy && requirements.networkAccess !== 'FORBIDDEN') {
    if (requirements.networkAccess === 'REQUIRED') {
      policyProblems.push(
        'local-only / no-disclosure privacy policy forbids network-transferring bindings',
      );
    } else if (requirements.networkAccess === 'OPTIONAL') {
      policyProblems.push(
        'local-only / no-disclosure privacy policy rejects networkAccess OPTIONAL — optional network use is not a proven no-disclosure execution mode',
      );
    } else {
      policyProblems.push(
        'binding declares no network-access posture; an unknown transport posture fails closed under a local-only / no-disclosure privacy policy',
      );
    }
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

  // Capability-required policy facts (P1-04): requiredPolicyFacts are keys
  // that must be current in the goal constraints before side-effecting
  // execution. A key absent from constraints.other cannot be proven current —
  // fail closed instead of ranking a binding whose required policy facts are
  // unevaluated.
  for (const factKey of context.capability.requiredPolicyFacts) {
    if (context.constraints.other?.[factKey] === undefined) {
      policyProblems.push(
        `capability requires policy fact "${factKey}" to be current; it is missing from the goal constraints — fail closed`,
      );
    }
  }

  // Licensing constraint (P1-04): when the goal declares a licensing
  // constraint, it is enforced deterministically as an exact, case-insensitive
  // license identity match against provider.licenseFacts.license. Anything the
  // provider license facts do not satisfy verbatim is rejected — a forbidden
  // or merely different license can no longer pass the gates and win ranking.
  const licensing = context.constraints.licensing;
  if (licensing !== undefined) {
    const requested = licensing.trim().toLowerCase();
    const provided = provider.licenseFacts.license.trim().toLowerCase();
    if (requested !== provided) {
      policyProblems.push(
        `provider license "${provider.licenseFacts.license}" does not satisfy the requested licensing constraint "${licensing}" (exact license identity required — fail closed)`,
      );
    }
  }

  // Format constraint (P1-04): evaluated only against explicit curated
  // formatSupport facts. A covered-but-different requested format is a REJECT;
  // with no curated facts the constraint is not silently certified — the PASS
  // reason records the explicit deferral to downstream verification.
  const formatDeferredNotes: string[] = [];
  const format = context.constraints.format;
  if (format !== undefined) {
    const formatSupport = readFormatSupport(provider);
    if (formatSupport.status === 'MALFORMED') {
      policyProblems.push(`malformed curated format facts — fail closed: ${formatSupport.reason}`);
    } else if (formatSupport.status === 'ABSENT') {
      formatDeferredNotes.push(
        `requested format "${format}" is not gate-evaluable for this binding (no curated format facts on the provider); deferred to downstream verification`,
      );
    } else if (
      !formatSupport.formats.some(
        (entry) => entry.trim().toLowerCase() === format.trim().toLowerCase(),
      )
    ) {
      policyProblems.push(
        `provider does not declare support for the requested format "${format}" (curated format facts: ${formatSupport.formats.join(', ')})`,
      );
    }
  }

  if (policyProblems.length > 0) {
    dispositions.push(
      disposition('USER_ORG_POLICY', binding.bindingId, 'REJECT', policyProblems.join('; ')),
    );
    return { binding, dispositions, passed: false };
  }
  dispositions.push(
    disposition(
      'USER_ORG_POLICY',
      binding.bindingId,
      'PASS',
      formatDeferredNotes.length > 0
        ? `no user/org policy violation; ${formatDeferredNotes.join('; ')}`
        : 'no user/org policy violation',
    ),
  );

  // Gate 5 — Required safety constraints: curated escalation posture is
  // explicit, never a score component (P2-02). A present-but-malformed
  // safetyProfile fails closed (P1-03) — it is never read as "no profile".
  const safetyRead = readSafetyProfile(provider);
  if (safetyRead.status === 'MALFORMED') {
    dispositions.push(
      disposition(
        'SAFETY_CONSTRAINTS',
        binding.bindingId,
        'REJECT',
        `provider safetyProfile is present but malformed — fail closed: ${safetyRead.reason}`,
      ),
    );
    return { binding, dispositions, passed: false };
  }
  if (safetyRead.status === 'VALID') {
    const safetyProfile = safetyRead.profile;
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
