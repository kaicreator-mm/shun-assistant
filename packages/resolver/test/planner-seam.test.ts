// PlannerPort seam: proposal-only interpretation, local-only enforcement,
// deterministic re-validation (L2 §6.1–§6.3).

import type { GoalProposal, GoalRequest, PlannerPort } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { interpretGoalViaPlanner } from '../src/planner-seam.ts';
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
      if (typeof proposal === 'function') {
        return (proposal as () => GoalProposal)();
      }
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

describe('PlannerPort seam stays proposal-only and policy-bounded', () => {
  it('local-only policy makes a remote planner ineligible WITHOUT calling it', async () => {
    const planner = spyPlanner(validProposal(request()));
    const result = await interpretGoalViaPlanner({
      request: request(),
      registry: registry(),
      planner,
      transport: 'REMOTE',
    });
    expect(result).toMatchObject({
      status: 'PLANNER_UNAVAILABLE',
      reason: expect.stringContaining('local-only'),
    });
    expect(planner.calls).toBe(0);
  });

  it('no configured planner is a typed unavailable, deterministic paths remain usable', async () => {
    const result = await interpretGoalViaPlanner({ request: request(), registry: registry() });
    expect(result).toMatchObject({
      status: 'PLANNER_UNAVAILABLE',
      reason: expect.stringContaining('no PlannerPort configured'),
    });
  });

  it('a local planner proposal is accepted only as data, then re-validated deterministically', async () => {
    const input = request();
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      planner: spyPlanner(validProposal(input)),
      transport: 'LOCAL',
    });
    expect(result.status).toBe('PROPOSAL_ACCEPTED');
    if (result.status !== 'PROPOSAL_ACCEPTED') return;
    expect(result.normalization.status).toBe('READY');
    expect(result.planClass).toBe('PLANNER_INTERPRETED');
    expect(result.proposal.goalContract.objective).toContain('image.batch_process');
  });

  it('a proposal whose objective names no capability is accepted as data but stays CAPABILITY_UNRESOLVED', async () => {
    const input = request();
    const proposal = validProposal(input);
    proposal.goalContract.objective = 'make photos smaller with magic';
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      planner: spyPlanner(proposal),
    });
    expect(result.status).toBe('PROPOSAL_ACCEPTED');
    if (result.status !== 'PROPOSAL_ACCEPTED') return;
    expect(result.normalization).toMatchObject({
      status: 'NOT_READY',
      failureCode: 'CAPABILITY_UNRESOLVED',
    });
  });

  it('a proposal that broadens privacy policy is rejected — policy is request authority', async () => {
    const input = request();
    const proposal = validProposal(input);
    proposal.goalContract.privacyPolicy = { localOnly: false, externalDisclosure: 'ALLOWED' };
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      planner: spyPlanner(proposal),
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REJECTED',
      reason: expect.stringContaining('policy'),
    });
  });

  it('a proposal inventing objects outside the request scope is rejected', async () => {
    const input = request();
    const proposal = validProposal(input);
    proposal.goalContract.objects = [...input.objects, { kind: 'DIRECTORY', ref: 'D:\\elsewhere' }];
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      planner: spyPlanner(proposal),
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REJECTED',
      reason: expect.stringContaining('D:\\elsewhere'),
    });
  });

  it('a remote proposal without external-model disclosure evidence is rejected', async () => {
    const openRequest = goalRequest({ goal: 'make my vacation photos smaller please' });
    openRequest.policyContext.privacyPolicy = {
      localOnly: false,
      externalDisclosure: 'POLICY_CONTROLLED',
    };
    const proposal = validProposal(openRequest);
    delete proposal.plannerEvidence;
    const result = await interpretGoalViaPlanner({
      request: openRequest,
      registry: registry(),
      planner: spyPlanner(proposal),
      transport: 'REMOTE',
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REJECTED',
      reason: expect.stringContaining('plannerEvidence'),
    });
  });

  it('a structurally invalid proposal is rejected by the frozen contract schema', async () => {
    const input = request();
    const malformed = { ...validProposal(input) } as Record<string, unknown>;
    delete malformed.proposalId;
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      planner: spyPlanner(malformed),
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REJECTED',
      reason: expect.stringContaining('GoalProposal contract'),
    });
  });

  it('a crashing planner yields a typed rejection, never a fabricated plan', async () => {
    const input = request();
    const failing: PlannerPort = {
      interpretGoal: async () => {
        throw new Error('model backend exploded');
      },
    };
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      planner: failing,
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REJECTED',
      reason: expect.stringContaining('model backend exploded'),
    });
  });
});
