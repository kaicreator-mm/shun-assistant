// PlannerPort seam: proposal-only interpretation, local-only enforcement,
// deterministic re-validation (L2 §6.1–§6.3).

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

function permitRemoteDisclosure(input: GoalRequest): GoalRequest {
  input.policyContext.privacyPolicy = { localOnly: false, externalDisclosure: 'ALLOWED' };
  return input;
}

describe('PlannerPort seam stays proposal-only and policy-bounded', () => {
  it('local-only policy makes a remote planner ineligible WITHOUT calling it', async () => {
    const planner = spyPlanner(validProposal(request()));
    const result = await interpretGoalViaPlanner({
      request: request(),
      registry: registry(),
      adapter: remotePlannerAdapter(planner),
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
    const input = permitRemoteDisclosure(request());
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      adapter: remotePlannerAdapter(spyPlanner(validProposal(input))),
      objectExists: () => true,
    });
    expect(result.status).toBe('PROPOSAL_ACCEPTED');
    if (result.status !== 'PROPOSAL_ACCEPTED') return;
    expect(result.normalization.status).toBe('READY');
    expect(result.planClass).toBe('PLANNER_INTERPRETED');
    expect(result.proposal.goalContract.objective).toContain('image.batch_process');
  });

  it('a proposal whose objective names no capability is accepted as data but stays CAPABILITY_UNRESOLVED', async () => {
    const input = permitRemoteDisclosure(request());
    const proposal = validProposal(input);
    proposal.goalContract.objective = 'make photos smaller with magic';
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      adapter: remotePlannerAdapter(spyPlanner(proposal)),
      objectExists: () => true,
    });
    expect(result.status).toBe('PROPOSAL_ACCEPTED');
    if (result.status !== 'PROPOSAL_ACCEPTED') return;
    expect(result.normalization).toMatchObject({
      status: 'NOT_READY',
      failureCode: 'CAPABILITY_UNRESOLVED',
    });
  });

  it('a proposal that broadens privacy policy is rejected — policy is request authority', async () => {
    const input = permitRemoteDisclosure(request());
    const proposal = validProposal(input);
    proposal.goalContract.privacyPolicy = { localOnly: true, externalDisclosure: 'FORBIDDEN' };
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      adapter: remotePlannerAdapter(spyPlanner(proposal)),
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REJECTED',
      reason: expect.stringContaining('policy'),
    });
  });

  it('a proposal inventing objects outside the request scope is rejected', async () => {
    const input = permitRemoteDisclosure(request());
    const proposal = validProposal(input);
    proposal.goalContract.objects = [...input.objects, { kind: 'DIRECTORY', ref: 'D:\\elsewhere' }];
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      adapter: remotePlannerAdapter(spyPlanner(proposal)),
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REJECTED',
      reason: 'PLANNER_OBJECT_SCOPE_MISMATCH',
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
      adapter: remotePlannerAdapter(spyPlanner(proposal)),
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REJECTED',
      reason: expect.stringContaining('plannerEvidence'),
    });
  });

  it('a structurally invalid proposal is rejected by the frozen contract schema', async () => {
    const input = permitRemoteDisclosure(request());
    const malformed = { ...validProposal(input) } as Record<string, unknown>;
    delete malformed.proposalId;
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      adapter: remotePlannerAdapter(spyPlanner(malformed)),
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REJECTED',
      reason: expect.stringContaining('GoalProposal contract'),
    });
  });

  it('a crashing planner yields a typed rejection, never a fabricated plan', async () => {
    const input = permitRemoteDisclosure(request());
    const failing: PlannerPort = {
      interpretGoal: async () => {
        throw new Error('model backend exploded');
      },
    };
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      adapter: remotePlannerAdapter(failing),
    });
    expect(result).toMatchObject({
      status: 'PROPOSAL_REJECTED',
      reason: 'PLANNER_EXECUTION_REFUSED',
    });
  });

  it('never reflects poisoned planner errors, object paths or task IDs into nonthrow rejection', async () => {
    const token = 'SHUN_FAKE_BEARER_SECRET_12345';
    const input = permitRemoteDisclosure(request());
    const badPlanner: PlannerPort = {
      interpretGoal: async () => {
        throw new Error(`Authorization: Bearer ${token} C:/Users/Secret/private.txt`);
      },
    };
    const thrown = await interpretGoalViaPlanner({
      request: input, registry: registry(), adapter: remotePlannerAdapter(badPlanner),
    });
    expect(JSON.stringify(thrown)).not.toContain(token);
    expect(JSON.stringify(thrown)).not.toContain('C:/Users/Secret');

    const obj = validProposal(input);
    obj.goalContract.objects = [...input.objects, { kind: 'DIRECTORY', ref: `C:/Users/${token}` }];
    const out = await interpretGoalViaPlanner({
      request: input, registry: registry(), adapter: remotePlannerAdapter(spyPlanner(obj)),
    });
    expect(out).toMatchObject({ status: 'PROPOSAL_REJECTED', reason: 'PLANNER_OBJECT_SCOPE_MISMATCH' });
    expect(JSON.stringify(out)).not.toContain(token);

    const changed = validProposal(input);
    changed.goalContract.taskId = token;
    const mismatch = await interpretGoalViaPlanner({
      request: input, registry: registry(), adapter: remotePlannerAdapter(spyPlanner(changed)),
    });
    expect(mismatch).toMatchObject({ status: 'PROPOSAL_REJECTED', reason: 'PLANNER_TASK_SCOPE_MISMATCH' });
    expect(JSON.stringify(mismatch)).not.toContain(token);
  });

  it('a remote-backed adapter that omits transport fails closed and is never invoked (P1-01)', async () => {
    const planner = spyPlanner(validProposal(request()));
    // Simulates the untyped / misconfigured caller the type signature now
    // forbids: a planner is configured but its transport provenance is absent.
    // It must NOT default to LOCAL and must NOT reach the adapter.
    const omitted = {
      request: request(),
      registry: registry(),
      planner,
      transport: undefined,
    } as unknown as InterpretGoalViaPlannerInput;
    const result = await interpretGoalViaPlanner(omitted);
    expect(result).toMatchObject({
      status: 'PLANNER_UNAVAILABLE',
      reason: expect.stringContaining('transport'),
    });
    expect(planner.calls).toBe(0);
  });

  it('an unknown transport value fails closed instead of being treated as LOCAL (P1-01)', async () => {
    const planner = spyPlanner(validProposal(request()));
    const unknown = {
      request: request(),
      registry: registry(),
      planner,
      transport: 'UNVERIFIED_REMOTE_GATEWAY',
    } as unknown as InterpretGoalViaPlannerInput;
    const result = await interpretGoalViaPlanner(unknown);
    expect(result).toMatchObject({
      status: 'PLANNER_UNAVAILABLE',
      reason: expect.stringContaining('transport'),
    });
    expect(planner.calls).toBe(0);
  });

  it('an offline constraint makes a remote planner ineligible WITHOUT calling it, even when disclosure is allowed (P1 supplemental R1)', async () => {
    // Review counterexample: schema-valid request with offline=true and an
    // open privacy policy reached the remote adapter. External disclosure
    // permission never overrides a separately required offline execution.
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

  it('offline/local-planner execution fails closed when the runtime cannot attest transport origin (R3)', async () => {
    const input = request();
    input.constraints.other = { offline: true };
    input.policyContext.privacyPolicy = { localOnly: false, externalDisclosure: 'ALLOWED' };
    const planner = spyPlanner(validProposal(input));
    const result = await interpretGoalViaPlanner({
      request: input,
      registry: registry(),
      adapter: localPlannerAdapter(declareLocalPlanner(planner)),
      objectExists: () => true,
    });
    expect(result.status).toBe('PLANNER_UNAVAILABLE');
    expect(planner.calls).toBe(0);
  });
});
