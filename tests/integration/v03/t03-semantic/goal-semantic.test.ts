import { describe, expect, it } from 'vitest';
import {
  HOST_OBJECT_OBSERVATION_SCHEMA,
  selectGoalSemantic,
} from '../../../../packages/domain-computer/src/semantic/goal-semantic.ts';
import {
  ShunRegistry,
  snapshotFactsRevision,
} from '../../../../packages/resolver/src/registry.ts';
import {
  capabilityDef,
  ENV_LOCAL,
  goalRequest,
} from '../../../../packages/resolver/test/scenarios.ts';
import type { GoalProposal, GoalRequest } from '../../../../packages/contracts/src/index.ts';

function snapshot(capabilityIds = ['image.batch_process']) {
  return {
    capabilities: capabilityIds.map((capabilityId) => capabilityDef({ capabilityId })),
    providers: [],
    bindings: [],
    environment: ENV_LOCAL,
  };
}

async function attestedRegistry(capabilityIds?: string[]) {
  const facts = snapshot(capabilityIds);
  return ShunRegistry.fromAttestedSnapshot(facts, {
    currentnessAuthority: {
      currentRevision: async () => snapshotFactsRevision(facts),
    },
  });
}

function hostObservation(request: GoalRequest) {
  return {
    schema: HOST_OBJECT_OBSERVATION_SCHEMA,
    sourceRef: 'host-observation:fixture-01',
    revision: 'obs-0042',
    observedObjectRefs: request.objects.map((object) => `${object.kind}:${object.ref}`),
  };
}

function validProposal(request: GoalRequest): GoalProposal {
  return {
    proposalId: 'proposal-01',
    plannerEvidence: {
      operationId: 'operation-01',
      modelEvidence: 'evidence-ref:operation-01',
    },
    goalContract: {
      taskId: request.taskId,
      objective: 'image.batch_process: resize the selected photos',
      objects: request.objects,
      constraints: request.constraints,
      privacyPolicy: request.policyContext.privacyPolicy,
      environmentPolicy: request.policyContext.environmentPolicy,
      verificationIntent: request.verificationIntent,
      ambiguityDisposition: 'READY',
    },
  };
}

describe('T03 typed Goal/Proposal semantic and registered capability selection', () => {
  it('selects one registered capability from a direct structured request', async () => {
    const registry = await attestedRegistry();
    const request = goalRequest({ goal: 'image.batch_process: resize my photos' });
    const result = selectGoalSemantic({
      request,
      registry,
      hostObservation: hostObservation(request),
    });

    expect(result.status).toBe('SELECTED');
    if (result.status !== 'SELECTED') return;
    expect(result.semantic.schema).toBe('shun.goal-semantic.v1');
    expect(result.semantic.goalContract.objects).toEqual(request.objects);
    expect(result.semantic.capabilityId).toBe('image.batch_process');
    expect(result.semantic.capabilityRevision).toBe('r1');
    expect(result.semantic.provenance.source).toBe('REQUEST');
    expect(result.capability.capabilityId).toBe('image.batch_process');
    expect(Object.isFrozen(result.semantic)).toBe(true);
    expect(Object.isFrozen(result.semantic.goalContract.objects)).toBe(true);
  });

  it('maps a strict planner proposal while retaining request-owned authority inputs', async () => {
    const registry = await attestedRegistry();
    const request = goalRequest({ goal: 'please make my selected photos smaller' });
    const proposal = validProposal(request);
    const result = selectGoalSemantic({
      request,
      proposal,
      registry,
      hostObservation: hostObservation(request),
    });

    expect(result.status).toBe('SELECTED');
    if (result.status !== 'SELECTED') return;
    expect(result.semantic.provenance).toMatchObject({
      source: 'PLANNER_PROPOSAL',
      proposalId: 'proposal-01',
      plannerEvidence: {
        operationId: 'operation-01',
        modelEvidence: 'evidence-ref:operation-01',
      },
      hostObservationRef: 'host-observation:fixture-01',
      hostObservationRevision: 'obs-0042',
    });
    expect(result.semantic.goalContract.objective).toBe(proposal.goalContract.objective);
    expect(result.semantic.goalContract.objects).toEqual(request.objects);
    expect(result.semantic.goalContract.constraints).toEqual(request.constraints);
    expect(result.semantic.goalContract.privacyPolicy).toEqual(request.policyContext.privacyPolicy);
    expect(result.semantic.goalContract.environmentPolicy).toEqual(request.policyContext.environmentPolicy);
  });

  it('rejects a proposal that widens or changes the selected folder/object set', async () => {
    const registry = await attestedRegistry();
    const request = goalRequest({ goal: 'make these photos smaller' });
    const proposal = validProposal(request);
    proposal.goalContract.objects = [
      ...request.objects,
      { kind: 'DIRECTORY', ref: 'D:\\outside-selected-root' },
    ];
    const result = selectGoalSemantic({
      request,
      proposal,
      registry,
      hostObservation: hostObservation(request),
    });
    expect(result).toMatchObject({ status: 'REJECTED', code: 'PROPOSAL_OBJECT_SCOPE_CHANGED' });
  });

  it('rejects model changes to request-owned constraints, privacy, environment and verification intent', async () => {
    const registry = await attestedRegistry();
    const request = goalRequest({
      goal: 'make these photos smaller',
      verificationIntent: { successConditions: ['all selected photos are resized'] },
    });
    const host = hostObservation(request);

    const constraints = validProposal(request);
    constraints.goalContract.constraints = { format: 'PNG' };
    expect(selectGoalSemantic({ request, proposal: constraints, registry, hostObservation: host }))
      .toMatchObject({ status: 'REJECTED', code: 'PROPOSAL_CONSTRAINTS_CHANGED' });

    const privacy = validProposal(request);
    privacy.goalContract.privacyPolicy = { localOnly: false, externalDisclosure: 'ALLOWED' };
    expect(selectGoalSemantic({ request, proposal: privacy, registry, hostObservation: host }))
      .toMatchObject({ status: 'REJECTED', code: 'PROPOSAL_PRIVACY_CHANGED' });

    const environment = validProposal(request);
    environment.goalContract.environmentPolicy = {
      allowedBackendKinds: ['LOCAL_WINDOWS', 'REMOTE_ECF'],
      allowElevation: true,
    };
    expect(selectGoalSemantic({ request, proposal: environment, registry, hostObservation: host }))
      .toMatchObject({ status: 'REJECTED', code: 'PROPOSAL_ENVIRONMENT_CHANGED' });

    const verification = validProposal(request);
    verification.goalContract.verificationIntent = { successConditions: ['unrelated condition'] };
    expect(selectGoalSemantic({ request, proposal: verification, registry, hostObservation: host }))
      .toMatchObject({ status: 'REJECTED', code: 'PROPOSAL_VERIFICATION_CHANGED' });
  });

  it('rejects model-invented lifecycle authority and missing planner evidence', async () => {
    const registry = await attestedRegistry();
    const request = goalRequest({ goal: 'make these photos smaller' });
    const lifecycle = {
      ...validProposal(request),
      goalContract: {
        ...validProposal(request).goalContract,
        lifecyclePolicy: { retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' },
      },
    };
    expect(selectGoalSemantic({ request, proposal: lifecycle, registry, hostObservation: hostObservation(request) }))
      .toMatchObject({ status: 'REJECTED', code: 'PROPOSAL_LIFECYCLE_POLICY_UNAUTHORIZED' });

    const missingEvidence = validProposal(request);
    delete missingEvidence.plannerEvidence;
    expect(selectGoalSemantic({
      request,
      proposal: missingEvidence,
      registry,
      hostObservation: hostObservation(request),
    })).toMatchObject({ status: 'REJECTED', code: 'PROPOSAL_EVIDENCE_MISSING' });
  });

  it('rejects extra command/grant fields through the frozen strict GoalProposal schema', async () => {
    const registry = await attestedRegistry();
    const request = goalRequest({ goal: 'make these photos smaller' });
    const proposal = {
      ...validProposal(request),
      grant: { approved: true },
      command: 'delete everything',
    };
    expect(selectGoalSemantic({
      request,
      proposal,
      registry,
      hostObservation: hostObservation(request),
    })).toMatchObject({ status: 'REJECTED', code: 'PROPOSAL_SCHEMA_REFUSED' });
  });

  it('rejects missing, malformed, forged or scope-mismatched Host observation evidence', async () => {
    const registry = await attestedRegistry();
    const request = goalRequest({ goal: 'image.batch_process: resize photos' });

    expect(selectGoalSemantic({ request, registry }))
      .toMatchObject({ status: 'REJECTED', code: 'HOST_OBSERVATION_REQUIRED' });

    expect(selectGoalSemantic({
      request,
      registry,
      hostObservation: { schema: 'shun.fake-observation.v1', sourceRef: 'fake', revision: '1', observedObjectRefs: [] },
    })).toMatchObject({ status: 'REJECTED', code: 'HOST_OBSERVATION_INVALID' });

    expect(selectGoalSemantic({
      request,
      registry,
      hostObservation: {
        schema: HOST_OBJECT_OBSERVATION_SCHEMA,
        sourceRef: 'host-observation:fixture-02',
        revision: 'obs-0043',
        observedObjectRefs: ['DIRECTORY:C:\\different-folder'],
      },
    })).toMatchObject({ status: 'REJECTED', code: 'HOST_OBSERVATION_SCOPE_MISMATCH' });
  });

  it('rejects unattested registry currentness before selecting any capability', async () => {
    const facts = snapshot();
    const registry = ShunRegistry.fromSnapshot(facts);
    const request = goalRequest({ goal: 'image.batch_process: resize photos' });
    expect(selectGoalSemantic({
      request,
      registry,
      hostObservation: hostObservation(request),
    })).toMatchObject({ status: 'REJECTED', code: 'REGISTRY_CURRENTNESS_INSUFFICIENT' });
  });

  it('does not select an undeclared or ambiguous capability', async () => {
    const registry = await attestedRegistry();
    const unknown = goalRequest({ goal: 'cook pasta for dinner' });
    const unknownResult = selectGoalSemantic({
      request: unknown,
      registry,
      hostObservation: hostObservation(unknown),
    });
    expect(unknownResult.status).toBe('NOT_READY');
    if (unknownResult.status === 'NOT_READY') {
      expect(unknownResult.normalization).toMatchObject({ failureCode: 'CAPABILITY_UNRESOLVED' });
    }

    const ambiguousRegistry = await attestedRegistry([
      'image.batch_process',
      'system.storage.diagnose_bounded_action',
    ]);
    const ambiguous = goalRequest({
      goal: 'image.batch_process and system.storage.diagnose_bounded_action',
    });
    const ambiguousResult = selectGoalSemantic({
      request: ambiguous,
      registry: ambiguousRegistry,
      hostObservation: hostObservation(ambiguous),
    });
    expect(ambiguousResult.status).toBe('NOT_READY');
    if (ambiguousResult.status === 'NOT_READY') {
      expect(ambiguousResult.normalization).toMatchObject({ failureCode: 'GOAL_AMBIGUOUS' });
    }
  });

  it('keeps the zero-object structured fast path and creates no authority/effect fields', async () => {
    const registry = await attestedRegistry();
    const request = goalRequest({
      goal: 'image.batch_process: resize photos',
      objects: [],
    });
    const result = selectGoalSemantic({ request, registry });
    expect(result.status).toBe('SELECTED');
    if (result.status !== 'SELECTED') return;
    expect(Object.keys(result.semantic).sort()).toEqual([
      'capabilityId',
      'capabilityRevision',
      'goalContract',
      'provenance',
      'schema',
      'taskId',
    ]);
    expect(result.semantic).not.toHaveProperty('grant');
    expect(result.semantic).not.toHaveProperty('approval');
    expect(result.semantic).not.toHaveProperty('command');
  });
});
