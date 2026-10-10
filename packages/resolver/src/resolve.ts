// Goal → Capability → Provider × local Environment resolution orchestration
// (C-000, L2 §7 resolver flow). Resolution itself is read-only: acquisition,
// configuration and execution are separate steps with their own risk gates.
//
// Pipeline: normalize goal → check registry currentness (fail closed) →
// discover candidate bindings → derive requirements → evaluate hard gates in
// frozen order → deterministic explainable ranking → ResolutionRecord, or an
// explicit typed failureDisposition. The record is re-parsed with the frozen
// contract parser before returning, so a resolver bug fails closed instead of
// emitting a contract-violating record.
import {
  type BindingCandidate,
  type GoalRequest,
  parseResolutionRecord,
  type ResolutionRecord,
  type VerificationPlan,
} from '@shun/contracts';
import { type BindingGateOutcome, runHardGates } from './gates.ts';
import { type GoalNormalization, normalizeGoal } from './normalize.ts';
import {
  type BindingScoreFacts,
  RANKING_POLICY_REVISION,
  rankFeasibleBindings,
} from './ranking.ts';
import { RESOLVER_REVISION, type ShunRegistry } from './registry.ts';

export type ExecutionPlanClass = ResolutionRecord['executionPlanClass'];

export type GoalResolution =
  | { stage: 'GOAL_NOT_READY'; normalization: GoalNormalization }
  | { stage: 'RESOLUTION'; record: ResolutionRecord; resolverRevision: string };

export interface ResolveGoalInput {
  request: GoalRequest;
  registry: ShunRegistry;
  objectExists?: (ref: string) => boolean;
  /** Curated per-binding score facts; absence selects the deterministic fallback ranking. */
  scoreFacts?: readonly BindingScoreFacts[];
  /** Planning layer actually used (planner seam sets PLANNER_INTERPRETED). */
  planClass?: ExecutionPlanClass;
}

function buildVerificationPlan(
  capability: NonNullable<ReturnType<ShunRegistry['capability']>>,
): VerificationPlan {
  return {
    verifierId: capability.verificationContract.verifierId,
    verifierRevision: capability.verificationContract.verifierRevision,
    checks: capability.verificationContract.checks.map((check) => ({
      checkId: check.checkId,
      description: check.description,
    })),
  };
}

export function resolveGoal(input: ResolveGoalInput): GoalResolution {
  const {
    request,
    registry,
    objectExists,
    scoreFacts,
    planClass = 'KNOWN_CAPABILITY_DETERMINISTIC',
  } = input;

  const normalization = normalizeGoal({ request, registry, objectExists });
  if (normalization.status === 'NOT_READY') {
    return { stage: 'GOAL_NOT_READY', normalization };
  }
  const goalContract = normalization.goalContract;
  const capability = registry.matchCapabilities(goalContract.objective)[0];
  if (!capability) {
    throw new Error('resolution invariant violated: capability lost between normalize and resolve');
  }

  const verificationPlan = buildVerificationPlan(capability);
  const privacyNotes: string[] = [];
  if (goalContract.privacyPolicy.localOnly) {
    privacyNotes.push(
      'local-only policy: remote planners and network-transferring providers are ineligible',
    );
  }
  if (goalContract.constraints.other?.offline === true) {
    privacyNotes.push('offline constraint: network-required bindings are policy-rejected');
  }
  const privacyDisclosurePlan = {
    externalDisclosure: goalContract.privacyPolicy.localOnly
      ? ('FORBIDDEN' as const)
      : goalContract.privacyPolicy.externalDisclosure,
    notes: privacyNotes,
  };

  const bindings = registry.bindingsForCapability(capability.capabilityId);

  // Registry currentness before any gate (P1-06): a registry collected via
  // sequential async reads without a verified snapshot seal has unverifiable
  // currentness — reads-between-changed cannot be excluded, so resolution
  // fails closed instead of trusting an unbound snapshot. The
  // observationRevision string alone is a durable identity input, never
  // freshness proof.
  if (!registry.currentnessAttested) {
    return {
      stage: 'RESOLUTION',
      resolverRevision: RESOLVER_REVISION,
      record: parseResolutionRecord({
        taskId: request.taskId,
        resolvedCapabilityId: capability.capabilityId,
        capabilityRevision: capability.revision,
        normalizedConstraints: goalContract.constraints,
        candidates: [],
        feasibleBindings: [],
        hardGateDispositions: [],
        selectedBindingId: null,
        selectionReasons: [],
        riskClass: capability.sideEffectClass,
        executionPlanClass: planClass,
        verificationPlan,
        privacyDisclosurePlan,
        failureDisposition: {
          failureCode: 'REGISTRY_CURRENTNESS_INSUFFICIENT',
          detail:
            'registry currentness unverifiable — the snapshot was collected through sequential async reads without a trusted snapshot seal binding the collected facts (P1-06); reads-between-changed cannot be excluded, fail closed',
        },
      }),
    };
  }

  // Registry currentness before any gate: a binding whose provider fact is
  // missing (or whose verifier binding is unresolvable) means stale/incomplete
  // registry state — fail closed, never silently skip (L2 §13).
  const currentnessProblems: string[] = [];
  for (const binding of bindings) {
    const provider = registry.provider(binding.providerId);
    if (!provider) {
      currentnessProblems.push(
        `binding ${binding.bindingId} references provider ${binding.providerId} absent from the registry`,
      );
    }
  }
  if (currentnessProblems.length > 0) {
    return {
      stage: 'RESOLUTION',
      resolverRevision: RESOLVER_REVISION,
      record: parseResolutionRecord({
        taskId: request.taskId,
        resolvedCapabilityId: capability.capabilityId,
        capabilityRevision: capability.revision,
        normalizedConstraints: goalContract.constraints,
        candidates: [],
        feasibleBindings: [],
        hardGateDispositions: [],
        selectedBindingId: null,
        selectionReasons: [],
        riskClass: capability.sideEffectClass,
        executionPlanClass: planClass,
        verificationPlan,
        privacyDisclosurePlan,
        failureDisposition: {
          failureCode: 'REGISTRY_CURRENTNESS_INSUFFICIENT',
          detail: `registry currentness insufficient — ${currentnessProblems.join('; ')}`,
        },
      }),
    };
  }

  const candidates: BindingCandidate[] = bindings.map((binding) => ({
    bindingId: binding.bindingId,
    providerId: binding.providerId,
    environmentId: registry.observedEnvironment().environmentId,
    interfaceClass: binding.interfaceClass,
  }));

  const outcomes: BindingGateOutcome[] = [];
  for (const binding of bindings) {
    const provider = registry.provider(binding.providerId);
    if (!provider) continue; // excluded by the currentness gate above
    outcomes.push(
      runHardGates(binding, provider, {
        capability,
        environment: registry.observedEnvironment(),
        privacyPolicy: goalContract.privacyPolicy,
        environmentPolicy: goalContract.environmentPolicy,
        constraints: goalContract.constraints,
      }),
    );
  }
  const dispositions = outcomes.flatMap((outcome) => outcome.dispositions);
  const feasible = outcomes.filter((outcome) => outcome.passed);

  const failWith = (
    failureCode: 'NO_TRUSTED_PROVIDER' | 'NO_FEASIBLE_BINDING' | 'POLICY_BLOCKED',
    detail: string,
  ): GoalResolution => ({
    stage: 'RESOLUTION',
    resolverRevision: RESOLVER_REVISION,
    record: parseResolutionRecord({
      taskId: request.taskId,
      resolvedCapabilityId: capability.capabilityId,
      capabilityRevision: capability.revision,
      normalizedConstraints: goalContract.constraints,
      candidates,
      feasibleBindings: [],
      hardGateDispositions: dispositions,
      selectedBindingId: null,
      selectionReasons: [],
      riskClass: capability.sideEffectClass,
      executionPlanClass: planClass,
      verificationPlan,
      privacyDisclosurePlan,
      failureDisposition: { failureCode, detail },
    }),
  });

  if (feasible.length === 0) {
    if (bindings.length === 0) {
      return failWith(
        'NO_TRUSTED_PROVIDER',
        `capability ${capability.capabilityId} has no discovered provider in the registry`,
      );
    }
    const trustPassers = outcomes.filter((outcome) =>
      outcome.dispositions.some(
        (entry) => entry.gate === 'TRUST_SUPPLY_CHAIN' && entry.outcome === 'PASS',
      ),
    );
    if (trustPassers.length === 0) {
      return failWith(
        'NO_TRUSTED_PROVIDER',
        `all ${bindings.length} candidate binding(s) failed the trust/supply-chain gate — provenance fail-closed`,
      );
    }
    const policyRejectedOnly = trustPassers.every((outcome) => {
      const terminal = outcome.dispositions[outcome.dispositions.length - 1];
      return terminal?.gate === 'USER_ORG_POLICY' || terminal?.gate === 'SAFETY_CONSTRAINTS';
    });
    if (policyRejectedOnly) {
      return failWith(
        'POLICY_BLOCKED',
        'every trust-passing binding was rejected by user/org policy or unacknowledged safety constraints',
      );
    }
    return failWith(
      'NO_FEASIBLE_BINDING',
      `no Provider × Environment binding is feasible for capability ${capability.capabilityId} on ${registry.observedEnvironment().environmentId}`,
    );
  }

  const ranked = rankFeasibleBindings({
    bindings: feasible.map((outcome) => ({
      ...outcome.binding,
      gateEscalation: outcome.escalation,
    })),
    scoreFacts,
  });
  const top = ranked[0];
  if (!top) {
    throw new Error('resolution invariant violated: empty ranking for non-empty feasible set');
  }

  const selectionReasons = [...top.reasons];
  if (feasible.length === 1) {
    selectionReasons.unshift(
      `single trusted binding surviving all hard gates — selected directly without manufactured competition (L2 §7.2), resolver ${RESOLVER_REVISION}`,
    );
  } else {
    selectionReasons.unshift(
      `ranked #1 of ${ranked.length} feasible binding(s) under ${RANKING_POLICY_REVISION} after all hard gates`,
    );
  }
  if (top.escalation) {
    selectionReasons.push(
      `selected with acknowledged safety escalation: ${top.escalation.escalationReason}`,
    );
  }

  return {
    stage: 'RESOLUTION',
    resolverRevision: RESOLVER_REVISION,
    record: parseResolutionRecord({
      taskId: request.taskId,
      resolvedCapabilityId: capability.capabilityId,
      capabilityRevision: capability.revision,
      normalizedConstraints: goalContract.constraints,
      candidates,
      feasibleBindings: feasible.map((outcome) => outcome.binding.bindingId),
      hardGateDispositions: dispositions,
      selectedBindingId: top.bindingId,
      selectionReasons,
      riskClass: capability.sideEffectClass,
      executionPlanClass: planClass,
      verificationPlan,
      privacyDisclosurePlan,
      failureDisposition: null,
    }),
  };
}
