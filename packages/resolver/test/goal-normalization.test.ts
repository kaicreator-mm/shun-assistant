// Deterministic goal normalization: typed ambiguity is first-class (L2 §4.1).
import { describe, expect, it } from 'vitest';
import { normalizeGoal } from '../src/normalize.ts';
import { ShunRegistry } from '../src/registry.ts';
import { capabilityDef, goalRequest } from './scenarios.ts';

const registry = ShunRegistry.fromSnapshot({
  capabilities: [
    capabilityDef({ capabilityId: 'image.batch_process' }),
    capabilityDef({ capabilityId: 'system.storage.diagnose_bounded_action' }),
  ],
  providers: [],
  bindings: [],
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

function normalize(goal: string, objectExists?: (ref: string) => boolean) {
  return normalizeGoal({ request: goalRequest({ goal }), registry, objectExists });
}

describe('deterministic goal normalization', () => {
  it('explicit capability id resolves READY with the goal contract authority form', () => {
    const result = normalize('image.batch_process: resize my photos to 1600px');
    expect(result.status).toBe('READY');
    if (result.status !== 'READY') return;
    expect(result.goalContract.ambiguityDisposition).toBe('READY');
    expect(result.goalContract.objective).toBe('image.batch_process: resize my photos to 1600px');
    expect(result.goalContract.taskId).toBe('task-t01-001');
    expect(result.goalContract.privacyPolicy).toEqual({
      localOnly: true,
      externalDisclosure: 'FORBIDDEN',
    });
    expect(result.goalContract.environmentPolicy).toEqual({
      allowedBackendKinds: ['LOCAL_WINDOWS'],
      allowElevation: false,
    });
    expect(result.goalContract.objects).toEqual([
      { kind: 'DIRECTORY', ref: 'C:\\fixtures\\images' },
    ]);
  });

  it('registered alias phrases resolve without a planner', () => {
    const result = normalize('Please batch resize my photos to max 1600px');
    expect(result.status).toBe('READY');
  });

  it('a goal naming two capabilities is ambiguous, never silently picked', () => {
    const result = normalize(
      'image.batch_process and system.storage.diagnose_bounded_action for my disk',
    );
    expect(result).toEqual({
      status: 'NOT_READY',
      disposition: 'NEEDS_CLARIFICATION',
      failureCode: 'GOAL_AMBIGUOUS',
      detail: expect.stringContaining(
        'image.batch_process, system.storage.diagnose_bounded_action',
      ),
    });
  });

  it('an unknown long-tail goal yields typed CAPABILITY_UNRESOLVED, not a fabricated plan', () => {
    const result = normalize('help me cook pasta for dinner');
    expect(result).toEqual({
      status: 'NOT_READY',
      disposition: 'UNRESOLVED_CAPABILITY',
      failureCode: 'CAPABILITY_UNRESOLVED',
      detail: expect.stringContaining('PlannerPort'),
    });
  });

  it('a missing referenced object is reported by ref (C-000 precondition)', () => {
    const request = goalRequest({ goal: 'image.batch_process: resize photos' });
    request.objects = [{ kind: 'DIRECTORY', ref: 'C:\\missing' }];
    const result = normalizeGoal({
      request,
      registry,
      objectExists: (ref) => ref !== 'C:\\missing',
    });
    expect(result).toEqual({
      status: 'NOT_READY',
      disposition: 'UNRESOLVED_OBJECT',
      failureCode: 'OBJECT_UNRESOLVED',
      detail: expect.stringContaining('C:\\missing'),
    });
  });

  it('a contradictory privacy policy is ambiguous input, not a configuration', () => {
    const request = goalRequest({ goal: 'image.batch_process: resize photos' });
    request.policyContext.privacyPolicy = { localOnly: true, externalDisclosure: 'ALLOWED' };
    const result = normalizeGoal({ request, registry });
    expect(result).toEqual({
      status: 'NOT_READY',
      disposition: 'NEEDS_CLARIFICATION',
      failureCode: 'GOAL_AMBIGUOUS',
      detail: expect.stringContaining('contradictory'),
    });
  });

  it('a capability without required semantic checks is VERIFICATION_UNSPECIFIABLE', () => {
    const unverifiable = ShunRegistry.fromSnapshot({
      capabilities: [
        capabilityDef({
          capabilityId: 'image.batch_process',
          verificationContract: {
            verifierId: 'verifier.generic',
            verifierRevision: 'r1',
            checks: [{ checkId: 'optional-only', required: false }],
          },
        }),
      ],
      providers: [],
      bindings: [],
      environment: registry.observedEnvironment(),
    });
    const result = normalizeGoal({
      request: goalRequest({ goal: 'image.batch_process: resize photos' }),
      registry: unverifiable,
    });
    expect(result).toEqual({
      status: 'NOT_READY',
      disposition: 'VERIFICATION_UNSPECIFIABLE',
      failureCode: 'VERIFICATION_UNSPECIFIABLE',
      detail: expect.stringContaining('no required semantic check'),
    });
  });

  it('matchers only resolve capabilities actually present in the registry', () => {
    const result = normalize('software.jit_capability_lifecycle: acquire and remove a tool');
    expect(result.status).toBe('NOT_READY');
    if (result.status !== 'NOT_READY') return;
    expect(result.failureCode).toBe('CAPABILITY_UNRESOLVED');
  });
});
