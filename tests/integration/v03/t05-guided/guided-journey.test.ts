import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  APPROVED_STEP_TEMPLATES,
  type GuidedGoalSemanticSelection,
  type HostGuidedObservation,
  type StepOutcome,
  type StepSpec,
} from '../../../../packages/domain-computer/src/guided/guided-contract.ts';
import {
  createNextGuidedStep,
  validateGuidedAdvisory,
  validateGuidedStepOutcome,
} from '../../../../packages/domain-computer/src/guided/guided-journey.ts';

const NOW = 2_000;

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, stableValue(record[key])]));
  }
  return value;
}

function stableJson(value: unknown): string {
  return JSON.stringify(stableValue(value));
}

function hostObservation(overrides: Partial<HostGuidedObservation> = {}): HostGuidedObservation {
  return {
    schema: 'shun.guided.host-observation.v1',
    taskId: 'task-01',
    journeyId: 'journey-01',
    sourceRef: 'host:observation:01',
    revision: 'obs-01',
    caseRef: { snapshotId: 'snapshot-01', digest: 'a'.repeat(64) },
    observedAtUnixMs: 1_000,
    validUntilUnixMs: 60_000,
    evidenceRefs: ['host:scope:01'],
    ...overrides,
  };
}

function selectedSemantic(): Extract<GuidedGoalSemanticSelection, { status: 'SELECTED' }> {
  return {
    status: 'SELECTED',
    semantic: {
      schema: 'shun.goal-semantic.v1',
      taskId: 'task-01',
      goalContract: { taskId: 'task-01', objective: 'inspect the selected folder' },
      capabilityId: 'system.storage.diagnose_bounded_action',
      capabilityRevision: 'r1',
      provenance: { resolverRevision: 'resolver-v03' },
    },
  };
}

function notReadySemantic(failureCode: string): GuidedGoalSemanticSelection {
  return {
    status: 'NOT_READY',
    normalization: { failureCode, detail: 'bounded resolver outcome' },
  };
}

function issueStep(
  semantic: GuidedGoalSemanticSelection = selectedSemantic(),
  observation: HostGuidedObservation = hostObservation(),
) {
  const result = createNextGuidedStep({
    semanticSelection: semantic,
    observation,
    nowUnixMs: NOW,
  });
  expect(result.status).toBe('STEP');
  if (result.status !== 'STEP') throw new Error(result.code);
  return result.step;
}

function userOutcome(
  step: StepSpec,
  fieldId: string,
  value: string | boolean,
  overrides: Partial<StepOutcome> = {},
): StepOutcome {
  return {
    schema: 'shun.guided.step-outcome.v1',
    journeyId: step.journeyId,
    taskId: step.taskId,
    stepId: step.stepId,
    caseRef: step.caseRef,
    event: 'USER_SUBMIT',
    source: 'USER',
    sourceRef: 'ui:session-01',
    answers: [{ fieldId, value }],
    evidenceRefs: [],
    occurredAtUnixMs: 2_500,
    ...overrides,
  };
}

function validate(
  step: StepSpec,
  semantic: GuidedGoalSemanticSelection,
  observation: HostGuidedObservation,
  outcome: unknown,
  overrides: Partial<Parameters<typeof validateGuidedStepOutcome>[0]> = {},
) {
  return validateGuidedStepOutcome({
    stepSpec: step,
    currentObservation: observation,
    currentSemanticSelection: semantic,
    currentStepId: step.stepId,
    currentStepState: 'CURRENT',
    outcome,
    nowUnixMs: 3_000,
    ...overrides,
  });
}

describe('T05 bounded one-step Guided Journey and answer provenance', () => {
  it('keeps the template catalog fixed, versioned and digest-bound', () => {
    expect(APPROVED_STEP_TEMPLATES).toHaveLength(5);
    for (const template of APPROVED_STEP_TEMPLATES) {
      const { digest, ...material } = template;
      const observed = createHash('sha256').update(stableJson(material)).digest('hex');
      expect(observed).toBe(digest);
    }
    expect(new Set(APPROVED_STEP_TEMPLATES.map((template) => template.templateId)).size).toBe(5);
  });

  it('issues exactly one current select-root StepSpec when the Host has no selected root', () => {
    const observation = hostObservation();
    const result = createNextGuidedStep({
      semanticSelection: selectedSemantic(),
      observation,
      nowUnixMs: NOW,
    });
    expect(result.status).toBe('STEP');
    if (result.status !== 'STEP') return;
    expect(Array.isArray(result.step)).toBe(false);
    expect(result.step.templateRef.artifactId).toBe('shun.guided.select-root');
    expect(result.step.caseRef).toEqual(observation.caseRef);
    expect(result.step.formSchema.fields).toHaveLength(1);
    expect(result.step.formSchema.fields[0]).toMatchObject({ id: 'selectedRoot', type: 'TEXT', required: true });
    expect(result.step.capabilityRef).toMatchObject({
      capabilityId: 'system.storage.diagnose_bounded_action',
      revision: 'r1',
      resolverRevision: 'resolver-v03',
    });
    expect(result.step).not.toHaveProperty('grant');
    expect(result.step).not.toHaveProperty('approval');
    const repeated = createNextGuidedStep({ semanticSelection: selectedSemantic(), observation, nowUnixMs: NOW });
    expect(repeated.status).toBe('STEP');
    if (repeated.status === 'STEP') expect(repeated.step.stepId).toBe(result.step.stepId);
  });

  it('uses T03 typed NOT_READY outcomes for clarification, never raw model text', () => {
    const observation = hostObservation({ selectedRootRef: 'host:root:01' });
    const ambiguous = createNextGuidedStep({
      semanticSelection: notReadySemantic('GOAL_AMBIGUOUS'),
      observation,
      nowUnixMs: NOW,
    });
    expect(ambiguous).toMatchObject({
      status: 'STEP',
      step: { templateRef: { artifactId: 'shun.guided.clarify-goal' } },
    });
    const unresolved = createNextGuidedStep({
      semanticSelection: notReadySemantic('CAPABILITY_UNRESOLVED'),
      observation,
      nowUnixMs: NOW,
    });
    expect(unresolved).toMatchObject({
      status: 'STEP',
      step: { templateRef: { artifactId: 'shun.guided.clarify-goal' } },
    });
    expect(createNextGuidedStep({
      semanticSelection: notReadySemantic('REGISTRY_CURRENTNESS_INSUFFICIENT'),
      observation,
      nowUnixMs: NOW,
    })).toMatchObject({ status: 'BLOCKED', code: 'GUIDED_STEP_NOT_ELIGIBLE' });
  });

  it('requires privacy notice acknowledgement before exposing a disclosure preview step', () => {
    const observation = hostObservation({
      selectedRootRef: 'host:root:01',
      externalDisclosureRequired: true,
      privacyNoticeAcknowledged: false,
    });
    const result = createNextGuidedStep({
      semanticSelection: selectedSemantic(),
      observation,
      nowUnixMs: NOW,
    });
    expect(result).toMatchObject({
      status: 'STEP',
      step: { templateRef: { artifactId: 'shun.guided.privacy-notice' } },
    });
    if (result.status !== 'STEP') return;
    const field = result.step.formSchema.fields[0];
    if (!field) return;
    expect(field).toMatchObject({ id: 'privacyRoute', type: 'CHOICE' });
    if (field.type === 'CHOICE') {
      expect(field.options.map((option) => option.id)).toEqual(['keep-local', 'show-disclosure-preview']);
    }
    expect(result.step).not.toHaveProperty('grant');
    expect(result.step).not.toHaveProperty('externalDisclosureConsent');
    const acknowledgement = userOutcome(result.step, 'privacyRoute', 'keep-local');
    const accepted = validate(result.step, selectedSemantic(), observation, acknowledgement);
    expect(accepted.status).toBe('ACCEPTED');
    if (accepted.status === 'ACCEPTED') {
      expect(accepted.outcome).not.toHaveProperty('grant');
      expect(accepted.outcome).not.toHaveProperty('externalDisclosureConsent');
    }
  });

  it('accepts a bounded user folder answer as local data, not as Host observation proof', () => {
    const observation = hostObservation();
    const semantic = selectedSemantic();
    const step = issueStep(semantic, observation);
    const candidatePath = 'C:\\\\Users\\\\15549\\\\Pictures';
    const outcome = userOutcome(step, 'selectedRoot', candidatePath);
    const result = validate(step, semantic, observation, outcome);
    expect(result.status).toBe('ACCEPTED');
    if (result.status !== 'ACCEPTED') return;
    expect(result.outcome.answers[0]?.value).toBe(candidatePath);
    expect(result.answerProvenance).toMatchObject({
      source: 'USER',
      sourceRef: 'ui:session-01',
      stepId: step.stepId,
      caseRef: observation.caseRef,
    });
    expect(result.outcome).not.toHaveProperty('grant');
    expect(result.outcome).not.toHaveProperty('approval');
  });

  it('uses a review-plan step for a Host-issued preview; continuing is not approval', () => {
    const observation = hostObservation({
      selectedRootRef: 'host:root:01',
      actionPreviewRef: 'host:preview:01',
    });
    const semantic = selectedSemantic();
    const step = issueStep(semantic, observation);
    expect(step.templateRef.artifactId).toBe('shun.guided.review-plan');
    expect(step.actionPreviewRef).toBe('host:preview:01');

    const outcome = userOutcome(step, 'continue', 'continue-to-independent-approval');
    const result = validate(step, semantic, observation, outcome);
    expect(result.status).toBe('ACCEPTED');
    if (result.status !== 'ACCEPTED') return;
    expect(result.outcome.answers[0]?.value).toBe('continue-to-independent-approval');
    expect(result.outcome).not.toHaveProperty('grant');
    expect(result.outcome).not.toHaveProperty('approval');
    expect(result.answerProvenance).toMatchObject({
      source: 'USER',
      sourceRef: 'ui:session-01',
      stepId: step.stepId,
      caseRef: observation.caseRef,
    });
  });

  it('accepts a Host observation receipt only when source and evidence refs match', () => {
    const observation = hostObservation({ selectedRootRef: 'host:root:01' });
    const semantic = selectedSemantic();
    const step = issueStep(semantic, observation);
    expect(step.templateRef.artifactId).toBe('shun.guided.inspect-scope');
    const receipt: StepOutcome = {
      schema: 'shun.guided.step-outcome.v1',
      journeyId: step.journeyId,
      taskId: step.taskId,
      stepId: step.stepId,
      caseRef: step.caseRef,
      event: 'OBSERVATION_RECEIPT',
      source: 'HOST',
      sourceRef: observation.sourceRef,
      answers: [],
      evidenceRefs: ['host:scope:01'],
      occurredAtUnixMs: 2_500,
    };
    expect(validate(step, semantic, observation, receipt).status).toBe('ACCEPTED');
    expect(validate(step, semantic, observation, {
      ...receipt,
      sourceRef: 'host:forged',
    })).toMatchObject({ status: 'REJECTED', code: 'OBSERVATION_RECEIPT_PROVENANCE_REFUSED' });
  });

  it('rejects old, replayed, consumed and cross-Case outcomes', () => {
    const observation = hostObservation({ selectedRootRef: 'host:root:01' });
    const semantic = selectedSemantic();
    const step = issueStep(semantic, observation);
    const outcome = userOutcome(step, 'continue', 'continue-to-independent-approval');

    expect(validate(step, semantic, observation, outcome, { currentStepId: 'guided:old-step' }))
      .toMatchObject({ status: 'REJECTED', code: 'STEP_SUPERSEDED' });
    expect(validate(step, semantic, observation, outcome, { currentStepState: 'CONSUMED' }))
      .toMatchObject({ status: 'REJECTED', code: 'STEP_ALREADY_CONSUMED_OR_SUPERSEDED' });
    expect(validate(step, semantic, observation, outcome, { currentStepState: 'SUPERSEDED' }))
      .toMatchObject({ status: 'REJECTED', code: 'STEP_ALREADY_CONSUMED_OR_SUPERSEDED' });

    const changedCase = hostObservation({
      selectedRootRef: 'host:root:01',
      caseRef: { snapshotId: 'snapshot-02', digest: 'b'.repeat(64) },
    });
    expect(validateGuidedStepOutcome({
      stepSpec: step,
      currentObservation: changedCase,
      currentSemanticSelection: semantic,
      currentStepId: step.stepId,
      currentStepState: 'CURRENT',
      outcome,
      nowUnixMs: 3_000,
    })).toMatchObject({ status: 'REJECTED', code: 'STEP_SPEC_STALE_OR_UNAPPROVED' });
  });

  it('rejects missing required answers, invalid choices and undeclared authority fields', () => {
    const rootObservation = hostObservation();
    const rootStep = issueStep(selectedSemantic(), rootObservation);
    const missing = userOutcome(rootStep, 'selectedRoot', 'C:\\Users\\15549\\Pictures', { answers: [] });
    expect(validate(rootStep, selectedSemantic(), rootObservation, missing))
      .toMatchObject({ status: 'REJECTED', code: 'ANSWER_REQUIRED_FIELD_MISSING' });

    const privacyObservation = hostObservation({
      selectedRootRef: 'host:root:01',
      externalDisclosureRequired: true,
    });
    const privacyStep = issueStep(selectedSemantic(), privacyObservation);
    const invalidChoice = userOutcome(privacyStep, 'privacyRoute', 'auto-consent');
    expect(validate(privacyStep, selectedSemantic(), privacyObservation, invalidChoice))
      .toMatchObject({ status: 'REJECTED', code: 'ANSWER_VALUE_REFUSED' });

    const forged = {
      ...userOutcome(rootStep, 'selectedRoot', 'C:\\Users\\15549\\Pictures'),
      grant: { approved: true },
      approval: true,
    };
    expect(validate(rootStep, selectedSemantic(), rootObservation, forged))
      .toMatchObject({ status: 'REJECTED', code: 'STEP_OUTCOME_SCHEMA_REFUSED' });
  });

  it('rejects missing, forged, expired and malformed Host observations', () => {
    expect(createNextGuidedStep({
      semanticSelection: selectedSemantic(),
      observation: null,
      nowUnixMs: NOW,
    })).toMatchObject({ status: 'BLOCKED', code: 'HOST_OBSERVATION_INVALID' });

    expect(createNextGuidedStep({
      semanticSelection: selectedSemantic(),
      observation: { ...hostObservation(), schema: 'shun.fake-host-observation.v1' },
      nowUnixMs: NOW,
    })).toMatchObject({ status: 'BLOCKED', code: 'HOST_OBSERVATION_INVALID' });

    expect(createNextGuidedStep({
      semanticSelection: selectedSemantic(),
      observation: hostObservation({ validUntilUnixMs: 1_500 }),
      nowUnixMs: NOW,
    })).toMatchObject({ status: 'BLOCKED', code: 'HOST_OBSERVATION_INVALID' });

    expect(createNextGuidedStep({
      semanticSelection: selectedSemantic(),
      observation: hostObservation({ evidenceRefs: ['ui:forged-evidence'] }),
      nowUnixMs: NOW,
    })).toMatchObject({ status: 'BLOCKED', code: 'HOST_OBSERVATION_INVALID' });
  });

  it('keeps optional advisory text-only and refuses advisory grant/approval fields', () => {
    const observation = hostObservation({ selectedRootRef: 'host:root:01' });
    const semantic = selectedSemantic();
    const advisory = {
      schema: 'shun.guided.advisory.v1',
      journeyId: observation.journeyId,
      caseRef: observation.caseRef,
      reasonCode: 'SCOPE_CLARIFICATION',
      explanation: 'The selected folder is ready for a read-only inspection.',
      evidenceRefs: ['host:scope:01'],
    };
    expect(validateGuidedAdvisory(advisory, observation, NOW)).toMatchObject({ status: 'ADVISORY_ONLY' });
    const withAdvisory = createNextGuidedStep({
      semanticSelection: semantic,
      observation,
      nowUnixMs: NOW,
      advisory,
    });
    expect(withAdvisory).toMatchObject({
      status: 'STEP',
      step: { templateRef: { artifactId: 'shun.guided.inspect-scope' } },
      advisory: { reasonCode: 'SCOPE_CLARIFICATION' },
    });

    const forgedAdvisory = { ...advisory, grant: { approved: true }, templateId: 'shun.guided.review-plan' };
    expect(validateGuidedAdvisory(forgedAdvisory, observation, NOW))
      .toMatchObject({ status: 'REJECTED', code: 'ADVISORY_SCHEMA_REFUSED' });
    expect(createNextGuidedStep({
      semanticSelection: semantic,
      observation,
      nowUnixMs: NOW,
      advisory: forgedAdvisory,
    })).toMatchObject({ status: 'BLOCKED', code: 'ADVISORY_SCHEMA_REFUSED' });
  });

  it('does not accept a forged StepSpec or a mismatched T03 semantic selection', () => {
    const observation = hostObservation({ selectedRootRef: 'host:root:01' });
    const semantic = selectedSemantic();
    const step = issueStep(semantic, observation);
    const forgedStep = {
      ...step,
      templateRef: { ...step.templateRef, digest: 'f'.repeat(64) },
    };
    expect(validate(step, semantic, observation, userOutcome(step, 'continue', 'continue-to-independent-approval'), {
      stepSpec: forgedStep,
    })).toMatchObject({ status: 'REJECTED', code: 'STEP_SPEC_STALE_OR_UNAPPROVED' });

    const wrongSemantic = {
      status: 'SELECTED',
      semantic: {
        ...semantic.semantic,
        taskId: 'other-task',
        goalContract: { taskId: 'other-task', objective: 'different' },
      },
    };
    expect(createNextGuidedStep({
      semanticSelection: wrongSemantic,
      observation,
      nowUnixMs: NOW,
    })).toMatchObject({ status: 'BLOCKED', code: 'GOAL_SEMANTIC_SELECTION_INVALID' });
  });
});
