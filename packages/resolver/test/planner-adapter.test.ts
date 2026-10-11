// R1 blocker 6 (P2, Issue #33): planner transport provenance must be minted
// and pinned by the trusted adapter factory, not asserted by callers. A
// caller-supplied `transport: 'LOCAL'` string next to an arbitrary
// PlannerPort is a caller assertion, not a transport attestation.
//
// R2 (fresh review blocker 2): the factory no longer binds LOCAL for an
// arbitrary PlannerPort — LOCAL requires the composition-root provenance
// declaration (declareLocalPlanner), and the caller-supplied pair form is
// removed from the seam input entirely.
import type { GoalProposal, GoalRequest, PlannerPort } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import {
  declareLocalPlanner,
  type InterpretGoalViaPlannerInput,
  interpretGoalViaPlanner,
  localPlannerAdapter,
  remotePlannerAdapter,
} from '../src/planner-seam.ts';
import { ShunRegistry } from '../src/registry.ts';
import { bindingDef, capabilityDef, goalRequest, providerDef } from './scenarios.ts';

function registry() {
  return ShunRegistry.fromSnapshot({
    capabilities: [capabilityDef({ capabilityId: 'image.batch_process' })],
    providers: [providerDef({ providerId: 'imageProvider.imagemagick' })],
    bindings: [
      bindingDef({
        bindingId: 'b-im',
        providerId: 'imageProvider.imagemagick',
        capabilityId: 'image.batch_process',
      }),
    ],
    environment: {
      environmentId: 'env',
      backendKind: 'LOCAL_WINDOWS',
      os: 'WINDOWS',
      arch: 'X64',
      observationRevision: 'obs-1',
      runtimeCapabilities: [],
      privilegeMode: 'FILTERED_ADMIN',
      guiSession: true,
      filesystemCapabilities: [],
      networkPolicy: 'POLICY_CONTROLLED',
      resources: { cpuCores: 4, memoryMb: 8192, freeDiskMb: 102400 },
    },
  });
}

function request(): GoalRequest {
  return goalRequest({ goal: 'make my vacation photos smaller please' });
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

describe('trusted planner adapter factory pins transport provenance (P2 R1)', () => {
  it('a factory-minted remote adapter carries its transport binding — local-only policy still makes it ineligible without invocation', async () => {
    // The caller never names the transport; the factory bound it at minting.
    const planner = spyPlanner(validProposal(request()));
    const result = await interpretGoalViaPlanner({
      request: request(), // scenario policy is local-only/FORBIDDEN
      registry: registry(),
      adapter: remotePlannerAdapter(planner),
    });
    expect(result).toMatchObject({
      status: 'PLANNER_UNAVAILABLE',
      reason: expect.stringContaining('local-only'),
    });
    expect(planner.calls).toBe(0);
  });

  it('a forged adapter object carrying a self-made brand symbol is refused fail-closed and never invoked', async () => {
    const planner = spyPlanner(validProposal(request()));
    const forged = {
      request: request(),
      registry: registry(),
      adapter: { planner, transport: 'LOCAL', brand: Symbol('shun.trusted-planner-adapter') },
    } as unknown as InterpretGoalViaPlannerInput;
    const result = await interpretGoalViaPlanner(forged);
    expect(result).toMatchObject({
      status: 'PLANNER_UNAVAILABLE',
      reason: expect.stringContaining('trusted adapter factory'),
    });
    expect(planner.calls).toBe(0);
  });

  it('a factory-minted adapter is frozen — transport cannot be re-asserted after minting', () => {
    const adapter = localPlannerAdapter(declareLocalPlanner(spyPlanner(validProposal(request()))));
    expect(Object.isFrozen(adapter)).toBe(true);
    expect(() => {
      (adapter as { transport: string }).transport = 'REMOTE';
    }).toThrow(TypeError);
    expect(adapter.transport).toBe('LOCAL');
  });

  it('localPlannerAdapter refuses to bind a planner whose local provenance was never declared (R2 blocker 2)', () => {
    // The R1 counterexample: the factory minted LOCAL for any PlannerPort —
    // the private brand proved only that the wrapper ran. Minting now throws
    // unless the composition root declared the planner local.
    const planner = spyPlanner(validProposal(request()));
    expect(() => localPlannerAdapter(planner)).toThrow(/declareLocalPlanner/);
    expect(planner.calls).toBe(0);
  });

  it('a provenance-declared local planner is bound by the factory and accepted under a local-only policy (R2 positive control)', async () => {
    const input = request();
    const planner = spyPlanner(validProposal(input));
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      adapter: localPlannerAdapter(declareLocalPlanner(planner)),
      objectExists: () => true,
    });
    expect(result.status).toBe('PROPOSAL_ACCEPTED');
    expect(planner.calls).toBe(1);
  });

  it('the adapter-bound transport drives policy: a remote adapter under the offline constraint is unavailable without invocation', async () => {
    const input = request();
    input.constraints.other = { offline: true };
    input.policyContext.privacyPolicy = { localOnly: false, externalDisclosure: 'ALLOWED' };
    const planner = spyPlanner(validProposal(input));
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      adapter: remotePlannerAdapter(planner),
    });
    expect(result).toMatchObject({
      status: 'PLANNER_UNAVAILABLE',
      reason: expect.stringContaining('offline'),
    });
    expect(planner.calls).toBe(0);
  });
});

describe('R3 public provenance minting does not authorize local-only network disclosure', () => {
  it('refuses a remote-backed planner even when the caller invokes exported declareLocalPlanner', async () => {
    const input = request();
    const remoteBacked = spyPlanner(validProposal(input));
    // The public issuer is available to UNTRUSTED callers. In the rejected
    // R2 implementation, this call minted the same brand used by the LOCAL
    // acceptance path, then invoked the remote model under localOnly.
    const forgedLocal = localPlannerAdapter(declareLocalPlanner(remoteBacked));
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      adapter: forgedLocal,
      objectExists: () => true,
    });
    expect(result.status).toBe('PLANNER_UNAVAILABLE');
    expect(remoteBacked.calls).toBe(0);
  });
});
