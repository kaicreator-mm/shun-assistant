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

/**
 * Trusted policy-fact evaluation seam (P1-04, R1): capability-required policy
 * facts (e.g. userApprovedDelete) are CURRENT facts owned by a policy
 * authority, never derivable from the caller's goal constraints — a value the
 * requester supplies is a claim, not proof. The integration layer injects an
 * evaluator backed by the trusted policy source; where the evaluator cannot
 * verify a required fact, the gate fails closed.
 *
 * R2 (fresh review P2): the evaluator carries a provenance identity — who
 * issued the verdicts (evaluatorId, the composition-root wiring) and for
 * which policy-state revision (policyRevision, currentness). The composition
 * layer owns both; the resolver records them in the gate evidence so a PASS
 * is auditable instead of resting on an anonymous callable.
 */
export type PolicyFactVerdict =
  | { status: 'SATISFIED'; evidence: string }
  | { status: 'UNSATISFIED'; reason: string }
  | { status: 'UNVERIFIABLE'; reason: string };

export interface PolicyFactEvaluator {
  /** Stable identity of the trusted evaluator wiring (composition root). */
  readonly evaluatorId: string;
  /** Policy-state revision the evaluator's verdicts are current for. */
  readonly policyRevision: string;
  /** Evaluate one capability-required policy fact key against the trusted current policy state. */
  evaluate(factKey: string): PolicyFactVerdict;
}

export interface GateContext {
  capability: CapabilityDefinition;
  environment: EnvironmentFacts;
  privacyPolicy: PrivacyPolicy;
  environmentPolicy: EnvironmentPolicy;
  constraints: Constraints;
  /**
   * Trusted policy-fact evaluator (P1-04, R1). Absent whenever a capability
   * requires policy facts → the gate REJECTs: key presence in caller-supplied
   * constraints is not verification.
   */
  policyFacts?: PolicyFactEvaluator;
}

/**
 * Evaluate one required policy fact through a provenance-identified trusted
 * evaluator (R2, fresh review P2). A verdict is returned only when the
 * evaluator exists AND carries a non-empty provenance identity — an anonymous
 * callable is not a trusted authority. The identity strings are returned for
 * gate-evidence recording.
 */
function evaluateWithProvenance(
  evaluator: PolicyFactEvaluator | undefined,
  factKey: string,
): { verdict?: PolicyFactVerdict; evaluatorId: string; policyRevision: string } {
  if (evaluator === undefined) {
    return { evaluatorId: '', policyRevision: '' };
  }
  const evaluatorId = typeof evaluator.evaluatorId === 'string' ? evaluator.evaluatorId.trim() : '';
  const policyRevision =
    typeof evaluator.policyRevision === 'string' ? evaluator.policyRevision.trim() : '';
  if (evaluatorId.length === 0 || policyRevision.length === 0) {
    return { evaluatorId, policyRevision };
  }
  return { verdict: evaluator.evaluate(factKey), evaluatorId, policyRevision };
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
  // Explicit deterministic dispositions recorded on a PASS: verified facts and
  // declared-but-unevaluated constraints are surfaced in the gate reason, so
  // the record never silently certifies an unevaluated condition.
  const policyNotes: string[] = [];

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

  // Offline constraint (P1 supplemental, R1): an offline execution requirement
  // admits only bindings whose requirements explicitly declare networkAccess
  // FORBIDDEN — the binding-level no-network declaration is the trusted
  // machine-checkable offline evidence in the frozen binding contract.
  // REQUIRED (network transfer), OPTIONAL (unproven offline mode) and an
  // absent declaration all fail closed; an explicit FORBIDDEN posture stays
  // eligible.
  if (context.constraints.other?.offline === true && requirements.networkAccess !== 'FORBIDDEN') {
    if (requirements.networkAccess === 'REQUIRED') {
      policyProblems.push('offline constraint forbids network access');
    } else {
      policyProblems.push(
        'offline constraint requires a proven no-network execution mode: networkAccess OPTIONAL / undeclared is an unproven offline posture — fail closed',
      );
    }
  }
  if (
    !context.environmentPolicy.allowElevation &&
    requirements.privilegeMode === 'ELEVATED_ADMIN'
  ) {
    policyProblems.push('goal policy disallows elevated execution');
  }

  // Capability-required policy facts (P1-04, R1): requiredPolicyFacts are
  // CURRENT facts owned by a policy authority. They are evaluated exclusively
  // through the trusted evaluator — key presence (or any value) in the
  // caller-supplied constraints is never proof. R2 (fresh review P2): the
  // evaluator itself must carry a provenance identity (evaluatorId +
  // policyRevision); an anonymous callable is not a trusted authority and
  // fails closed. Where no evaluator is configured, the identity is missing,
  // or the verdict is UNSATISFIED/UNVERIFIABLE, the gate fails closed.
  for (const factKey of context.capability.requiredPolicyFacts) {
    const evaluation = evaluateWithProvenance(context.policyFacts, factKey);
    if (evaluation.verdict?.status === 'SATISFIED') {
      policyNotes.push(
        `policy fact "${factKey}" verified by trusted policy evaluator "${evaluation.evaluatorId}" at policy revision "${evaluation.policyRevision}" (${evaluation.verdict.evidence})`,
      );
    } else {
      const detail = evaluation.verdict
        ? evaluation.verdict.reason
        : context.policyFacts === undefined
          ? 'no trusted policy fact evaluator is configured'
          : 'the configured policy evaluator carries no trusted provenance identity (evaluatorId / policyRevision)';
      policyProblems.push(
        `capability requires policy fact "${factKey}" current per trusted policy authority — ${detail}; caller-provided constraint values are not verification — fail closed`,
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

  // Format constraint (P1-04, R1): a REQUIRED output format is a necessary
  // condition (frozen Product resolver v0.1: necessary output format before
  // ranking). It is evaluated only against explicit curated formatSupport
  // facts: a covered-but-different requested format is a REJECT, and a format
  // that cannot be proven (no curated facts, or malformed facts) is a REJECT —
  // an unprovable mandatory format is never a deferred PASS.
  const format = context.constraints.format;
  if (format !== undefined) {
    const formatSupport = readFormatSupport(provider);
    if (formatSupport.status === 'MALFORMED') {
      policyProblems.push(`malformed curated format facts — fail closed: ${formatSupport.reason}`);
    } else if (formatSupport.status === 'ABSENT') {
      policyProblems.push(
        `required format "${format}" cannot be proven for this binding: the provider declares no curated format facts — an unprovable mandatory format is never a deferred PASS`,
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

  // Descriptive constraints (P1-04, R1; tightened R2 review blocker 3): the
  // frozen contract layer carries these as descriptive strings and no curated
  // fact class can evaluate them at resolver v0.1. The R1 record surfaced
  // them as a PASS note and allowed selection — a free-text disclaimer is NOT
  // a typed unresolved mandatory condition (frozen Product resolver v0.1
  // requires necessary user constraints before ranking; C-000 lists
  // resource/time and retain/remove constraints). A present descriptive
  // constraint therefore REJECTs the binding: when the frozen schema lacks
  // the proof, the typed outcome is a REJECT — never a successful selection
  // under an unevaluated mandatory condition.
  const descriptiveConstraints: readonly (keyof Constraints)[] = [
    'privacy',
    'executionEnvironment',
    'resourceLimits',
    'retainRemove',
  ];
  for (const key of descriptiveConstraints) {
    const value = context.constraints[key];
    if (value !== undefined) {
      policyProblems.push(
        `mandatory descriptive constraint "${key}" ("${String(value)}") cannot be evaluated against curated facts at resolver v0.1 — an unevaluated mandatory user constraint is never a policy PASS; fail closed (typed REJECT; resolvable only after the constraint is expressed in gate-evaluable contracts)`,
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
      policyNotes.length > 0
        ? `no user/org policy violation — ${policyNotes.join('; ')}`
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
