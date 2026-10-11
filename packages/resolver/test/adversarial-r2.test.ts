// T01 R2 adversarial regressions (Issue #33 fresh independent review R1
// blockers 1–3 + P2 provenance). Each test reproduces one source-level
// counterexample from the R1 review of PR #42@f3756ee:
//
// - blocker 1: a self-computed `authorityRevision` (or the public
//   `asyncCollectionAttested` option) attests a synchronous snapshot without
//   any trusted authority — self-attestation must be impossible;
// - blocker 2: a caller-labeled `transport: 'LOCAL'` pair and the publicly
//   mintable `localPlannerAdapter` both let a remote-backed PlannerPort run
//   under local-only/offline policy — LOCAL provenance must be bound at the
//   trusted composition boundary, with zero remote invocations;
// - blocker 3: mandatory descriptive constraints (resource limits et al.)
//   produce USER_ORG_POLICY PASS and a selected binding without any typed
//   evaluation — an unevaluated mandatory constraint must never PASS;
// - P2: a policy-fact evaluator is trusted without any provenance identity.
//
// Casts (`as unknown as …`) mark exactly the removed/never-existing API
// surface the counterexamples relied on.
import type { GoalProposal, GoalRequest, PlannerPort } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { type PolicyFactEvaluator, runHardGates } from '../src/gates.ts';
import {
  type InterpretGoalViaPlannerInput,
  interpretGoalViaPlanner,
  localPlannerAdapter,
  remotePlannerAdapter,
} from '../src/planner-seam.ts';
import { ShunRegistry, snapshotFactsRevision } from '../src/registry.ts';
import { resolveGoal } from '../src/resolve.ts';
import {
  bindingDef,
  capabilityDef,
  ENV_LOCAL,
  goalRequest,
  providerDef,
  requirements,
} from './scenarios.ts';

const imageCapabilityId = 'image.batch_process';

function baseSnapshot() {
  const capability = capabilityDef({ capabilityId: 'image.batch_process' });
  const provider = providerDef({ providerId: 'imageProvider.imagemagick' });
  const binding = bindingDef({
    bindingId: 'b-im',
    providerId: provider.providerId,
    capabilityId: imageCapabilityId,
    // Scenario policy is local-only/FORBIDDEN — declare the no-network
    // posture explicitly so any rejection below is provably currentness- or
    // policy-driven, not disclosure-driven.
    environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
  });
  return {
    capabilities: [capability],
    providers: [provider],
    bindings: [binding],
    environment: ENV_LOCAL,
  };
}

function resolvingRequest(): GoalRequest {
  const request = goalRequest({ goal: 'image.batch_process: batch resize my photos offline' });
  request.constraints.other = { offline: true };
  return request;
}

/** Test double standing in for the TRUSTED registry currentness authority. */
function authorityFor(snapshot: ReturnType<typeof baseSnapshot>) {
  return { currentRevision: async () => snapshotFactsRevision(snapshot) };
}

function gateScenario(constraints: GoalRequest['constraints']) {
  const capability = capabilityDef({ capabilityId: imageCapabilityId });
  const request = goalRequest({ goal: 'image.batch_process: resize photos' });
  const provider = providerDef({ providerId: 'imageProvider.imagemagick' });
  const binding = bindingDef({
    bindingId: 'b-1',
    providerId: provider.providerId,
    capabilityId: imageCapabilityId,
    environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
  });
  return runHardGates(binding, provider, {
    capability,
    environment: ENV_LOCAL,
    privacyPolicy: request.policyContext.privacyPolicy,
    environmentPolicy: request.policyContext.environmentPolicy,
    constraints,
  });
}

function registry() {
  // The planner seam does not consult registry currentness; a plain local
  // view is sufficient for proposal interpretation.
  return ShunRegistry.fromSnapshot(baseSnapshot());
}

function spyPlanner(proposal: unknown): PlannerPort & { calls: number } {
  const spy = { calls: 0 };
  return {
    get calls() {
      return spy.calls;
    },
    interpretGoal: async () => {
      spy.calls += 1;
      return proposal as GoalProposal;
    },
  } as PlannerPort & { calls: number };
}

function validProposal(requestInput: GoalRequest): GoalProposal {
  return {
    proposalId: 'prop-1',
    plannerEvidence: { operationId: 'op-1', modelEvidence: 'local-model-x' },
    goalContract: {
      taskId: requestInput.taskId,
      objective: 'image.batch_process: make my vacation photos smaller',
      objects: requestInput.objects,
      constraints: requestInput.constraints,
      privacyPolicy: requestInput.policyContext.privacyPolicy,
      environmentPolicy: requestInput.policyContext.environmentPolicy,
      ambiguityDisposition: 'READY',
    },
  };
}

describe('R2 blocker 1 — synchronous snapshot self-attestation is impossible', () => {
  it('a self-computed authorityRevision does not attest a synchronous snapshot — resolution fails closed', async () => {
    const snapshot = baseSnapshot();
    // The R1 counterexample: the caller derives the "source-issued" revision
    // from the very snapshot it passes in. Nothing external attests it.
    const registry = ShunRegistry.fromSnapshot(snapshot, {
      authorityRevision: snapshotFactsRevision(snapshot),
    } as unknown as Parameters<typeof ShunRegistry.fromSnapshot>[1]);
    expect(registry.currentnessAttested).toBe(false);
    const result = resolveGoal({
      request: resolvingRequest(),
      registry,
      objectExists: () => true,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBeNull();
    expect(result.record.failureDisposition?.failureCode).toBe('REGISTRY_CURRENTNESS_INSUFFICIENT');
  });

  it('the pre-attestation option cannot mark a snapshot attested without a trusted authority', async () => {
    const snapshot = baseSnapshot();
    // The R1 counterexample: a public option flipped currentnessAttested with
    // no authority, no digest and no comparison of any kind.
    const registry = ShunRegistry.fromSnapshot(snapshot, {
      asyncCollectionAttested: true,
    } as unknown as Parameters<typeof ShunRegistry.fromSnapshot>[1]);
    expect(registry.currentnessAttested).toBe(false);
    const result = resolveGoal({
      request: resolvingRequest(),
      registry,
      objectExists: () => true,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.failureDisposition?.failureCode).toBe('REGISTRY_CURRENTNESS_INSUFFICIENT');
  });

  it('a snapshot is attested only against the trusted authority’s CURRENT revision — stale-but-consistent state fails closed', async () => {
    // Snapshot A is internally consistent (it would pass every gate) but the
    // trusted authority has moved on: its CURRENT revision binds snapshot B
    // (provider trust revoked). Attestation is a comparison against the
    // authority's current state, so A stays unattested and resolution fails
    // closed — the provider in A is never selected.
    const stale = baseSnapshot();
    const current = baseSnapshot();
    current.providers[0] = providerDef({
      providerId: 'imageProvider.imagemagick',
      provenanceFacts: { trustState: 'UNTRUSTED', formatSupport: ['JPG'] },
    });
    const registry = await ShunRegistry.fromAttestedSnapshot(stale, {
      currentnessAuthority: authorityFor(current),
    });
    expect(registry.currentnessAttested).toBe(false);
    const result = resolveGoal({
      request: resolvingRequest(),
      registry,
      objectExists: () => true,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBeNull();
    expect(result.record.failureDisposition?.failureCode).toBe('REGISTRY_CURRENTNESS_INSUFFICIENT');
  });

  it('a trusted authority that confirms the exact collected facts still attests — the legitimate path resolves (positive control)', async () => {
    const snapshot = baseSnapshot();
    const registry = await ShunRegistry.fromAttestedSnapshot(snapshot, {
      currentnessAuthority: authorityFor(snapshot),
    });
    expect(registry.currentnessAttested).toBe(true);
    const result = resolveGoal({
      request: resolvingRequest(),
      registry,
      objectExists: () => true,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBe('b-im');
  });
});

describe('R2 blocker 2 — LOCAL planner provenance is bound only at the trusted composition boundary', () => {
  it('a caller-labeled LOCAL transport next to a remote-backed planner is refused with zero invocations', async () => {
    // The R1 counterexample: the explicit {planner, transport} pair skipped
    // the adapter brand branch and the rejection checked only the caller
    // string — a remote-backed planner labeled 'LOCAL' ran under
    // local-only/FORBIDDEN policy.
    const input = goalRequest({ goal: 'make my vacation photos smaller please' });
    const planner = spyPlanner(validProposal(input));
    const pair = {
      request: input,
      registry: registry(),
      planner,
      transport: 'LOCAL',
      objectExists: () => true,
    } as unknown as InterpretGoalViaPlannerInput;
    const result = await interpretGoalViaPlanner(pair);
    expect(result).toMatchObject({
      status: 'PLANNER_UNAVAILABLE',
      reason: expect.stringContaining('trusted adapter factory'),
    });
    expect(planner.calls).toBe(0);
  });

  it('localPlannerAdapter refuses a planner whose local provenance was never declared', () => {
    // The R1 counterexample: the factory minted a LOCAL binding for any
    // PlannerPort — the private brand proved only that the wrapper ran, not
    // that the planner is local. Minting now requires the composition-root
    // provenance declaration.
    const planner = spyPlanner(validProposal(goalRequest({ goal: 'make my vacation photos smaller please' })));
    expect(() => localPlannerAdapter(planner)).toThrow(/local provenance/);
    expect(planner.calls).toBe(0);
  });

  it('a REMOTE adapter under local-only policy stays ineligible without invocation (kept regression)', async () => {
    const input = goalRequest({ goal: 'make my vacation photos smaller please' });
    const planner = spyPlanner(validProposal(input));
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      adapter: remotePlannerAdapter(planner),
    });
    expect(result).toMatchObject({
      status: 'PLANNER_UNAVAILABLE',
      reason: expect.stringContaining('local-only'),
    });
    expect(planner.calls).toBe(0);
  });
});

describe('R2 blocker 3 — mandatory descriptive constraints never PASS unevaluated', () => {
  const descriptiveKeys = [
    'privacy',
    'executionEnvironment',
    'resourceLimits',
    'retainRemove',
  ] as const;

  it('a present descriptive constraint is a typed USER_ORG_POLICY REJECT naming the constraint', () => {
    for (const key of descriptiveKeys) {
      const request = goalRequest({ goal: 'image.batch_process: resize photos' });
      const constraints = { ...request.constraints } as Record<string, string>;
      constraints[key] = key === 'retainRemove' ? 'RETAIN' : 'keep it under 2 GB of disk';
      const outcome = gateScenario(constraints as GoalRequest['constraints']);
      expect(outcome.passed, `descriptive constraint ${key} must not pass unevaluated`).toBe(false);
      const policyRow = outcome.dispositions.find((entry) => entry.gate === 'USER_ORG_POLICY');
      expect(policyRow, `descriptive constraint ${key}`).toMatchObject({
        outcome: 'REJECT',
        reason: expect.stringContaining(key),
      });
    }
  });

  it('a resource-limited goal cannot select a binding end-to-end', async () => {
    const snapshot = baseSnapshot();
    const registry = ShunRegistry.fromSnapshot(snapshot, {
      authorityRevision: snapshotFactsRevision(snapshot),
    } as unknown as Parameters<typeof ShunRegistry.fromSnapshot>[1]);
    const request = goalRequest({ goal: 'image.batch_process: batch resize my photos offline' });
    request.constraints.other = { offline: true };
    request.constraints.resourceLimits = 'keep under 2 GB disk';
    const result = resolveGoal({ request, registry, objectExists: () => true });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    const record = result.record;
    expect(record.selectedBindingId).toBeNull();
    expect(record.feasibleBindings).toEqual([]);
    expect(record.failureDisposition?.failureCode).toBe('POLICY_BLOCKED');
    const policyRow = record.hardGateDispositions.find((entry) => entry.gate === 'USER_ORG_POLICY');
    expect(policyRow).toMatchObject({
      outcome: 'REJECT',
      reason: expect.stringContaining('resourceLimits'),
    });
  });
});

describe('R2 P2 — policy-fact evaluator carries trusted provenance identity', () => {
  it('an evaluator without provenance identity cannot satisfy a required policy fact', () => {
    const request = goalRequest({ goal: 'image.batch_process: resize photos' });
    request.constraints.other = { userApprovedDelete: true };
    const capability = capabilityDef({
      capabilityId: imageCapabilityId,
      requiredPolicyFacts: ['userApprovedDelete'],
    });
    const provider = providerDef({ providerId: 'imageProvider.imagemagick' });
    const binding = bindingDef({
      bindingId: 'b-1',
      providerId: provider.providerId,
      capabilityId: imageCapabilityId,
      environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
    });
    const outcome = runHardGates(binding, provider, {
      capability,
      environment: ENV_LOCAL,
      privacyPolicy: request.policyContext.privacyPolicy,
      environmentPolicy: request.policyContext.environmentPolicy,
      constraints: request.constraints,
      policyFacts: {
        evaluatorId: '',
        policyRevision: '',
        evaluate: () => ({ status: 'SATISFIED', evidence: 'self-asserted' }),
      } as unknown as PolicyFactEvaluator,
    });
    expect(outcome.passed).toBe(false);
    const last = outcome.dispositions[outcome.dispositions.length - 1];
    expect(last).toMatchObject({
      gate: 'USER_ORG_POLICY',
      outcome: 'REJECT',
      reason: expect.stringContaining('provenance'),
    });
  });
});
