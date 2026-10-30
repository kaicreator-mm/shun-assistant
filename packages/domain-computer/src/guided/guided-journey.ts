/**
 * Deterministic one-step Guided Journey Business adapter.
 *
 * This module consumes T03's typed GoalSemanticSelection and Host-only current
 * observation. It emits one fixed StepSpec, validates one bound StepOutcome,
 * and never persists state, calls a provider, invokes a renderer, grants
 * authority, or performs an OS/Kernel effect.
 */
import {
  findApprovedStepTemplate,
  type CaseRef,
  type GuidedAdvisory,
  type GuidedEvent,
  type GuidedGoalSemanticSelection,
  type HostGuidedObservation,
  type StepOutcome,
  type StepSpec,
  type StepTemplate,
} from './guided-contract.ts';

export type GuidedStepDecision =
  | { readonly status: 'STEP'; readonly step: StepSpec; readonly advisory?: GuidedAdvisory }
  | { readonly status: 'BLOCKED'; readonly code: string };

export type GuidedAdvisoryResult =
  | {
      readonly status: 'ADVISORY_ONLY';
      readonly reasonCode: string;
      readonly explanation: string;
      readonly evidenceRefs: readonly string[];
    }
  | { readonly status: 'REJECTED'; readonly code: string };

export type GuidedOutcomeResult =
  | {
      readonly status: 'ACCEPTED';
      readonly outcome: StepOutcome;
      readonly answerProvenance: {
        readonly source: 'USER' | 'HOST';
        readonly sourceRef: string;
        readonly caseRef: CaseRef;
        readonly stepId: string;
        readonly evidenceRefs: readonly string[];
      };
    }
  | { readonly status: 'REJECTED'; readonly code: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  return required.every((key) => Object.hasOwn(value, key)) && keys.every((key) => allowed.has(key));
}

function safeToken(value: unknown, maxLength = 128): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxLength &&
    value.trim() === value &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(value)
  );
}

function isSha256(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function hasControlCharacters(value: string): boolean {
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (code < 32 || (code >= 127 && code <= 159)) return true;
  }
  return false;
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, stableValue(record[key])]));
  }
  return value;
}

function equal(left: unknown, right: unknown): boolean {
  return JSON.stringify(stableValue(left)) === JSON.stringify(stableValue(right));
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const entry of Object.values(value as Record<string, unknown>)) deepFreeze(entry);
    Object.freeze(value);
  }
  return value;
}

function parseCaseRef(value: unknown): CaseRef | null {
  if (!isRecord(value) || !exactKeys(value, ['snapshotId', 'digest'])) return null;
  if (!safeToken(value.snapshotId) || !isSha256(value.digest)) return null;
  return Object.freeze({ snapshotId: value.snapshotId, digest: value.digest });
}

function parseHostObservation(value: unknown, nowUnixMs: number): HostGuidedObservation | null {
  if (!isRecord(value)) return null;
  const required = [
    'schema', 'taskId', 'journeyId', 'sourceRef', 'revision', 'caseRef',
    'observedAtUnixMs', 'validUntilUnixMs', 'evidenceRefs',
  ];
  const optional = ['selectedRootRef', 'externalDisclosureRequired', 'privacyNoticeAcknowledged', 'actionPreviewRef'];
  if (!exactKeys(value, required, optional)) return null;
  if (value.schema !== 'shun.guided.host-observation.v1') return null;
  if (!safeToken(value.taskId, 96) || !safeToken(value.journeyId, 48) || !safeToken(value.revision, 64)) return null;
  if (typeof value.sourceRef !== 'string' || !value.sourceRef.startsWith('host:') || value.sourceRef.length <= 5 || value.sourceRef.length > 256 || value.sourceRef.trim() !== value.sourceRef || hasControlCharacters(value.sourceRef)) return null;
  const caseRef = parseCaseRef(value.caseRef);
  if (!caseRef) return null;
  if (
    !Number.isSafeInteger(value.observedAtUnixMs) ||
    !Number.isSafeInteger(value.validUntilUnixMs) ||
    typeof value.observedAtUnixMs !== 'number' ||
    typeof value.validUntilUnixMs !== 'number' ||
    value.observedAtUnixMs <= 0 ||
    value.validUntilUnixMs <= value.observedAtUnixMs ||
    nowUnixMs < value.observedAtUnixMs ||
    nowUnixMs > value.validUntilUnixMs
  ) return null;
  if (
    !Array.isArray(value.evidenceRefs) ||
    value.evidenceRefs.length > 24 ||
    !value.evidenceRefs.every((entry) => typeof entry === 'string' && entry.startsWith('host:') && entry.length > 5 && entry.length <= 256 && entry.trim() === entry && !hasControlCharacters(entry))
  ) return null;
  if (new Set(value.evidenceRefs).size !== value.evidenceRefs.length) return null;
  if (value.selectedRootRef !== undefined && (typeof value.selectedRootRef !== 'string' || !value.selectedRootRef.startsWith('host:') || value.selectedRootRef.length <= 5 || value.selectedRootRef.length > 256 || value.selectedRootRef.trim() !== value.selectedRootRef || hasControlCharacters(value.selectedRootRef))) return null;
  if (value.actionPreviewRef !== undefined && (typeof value.actionPreviewRef !== 'string' || !value.actionPreviewRef.startsWith('host:') || value.actionPreviewRef.length <= 5 || value.actionPreviewRef.length > 256 || value.actionPreviewRef.trim() !== value.actionPreviewRef || hasControlCharacters(value.actionPreviewRef))) return null;
  if (value.externalDisclosureRequired !== undefined && typeof value.externalDisclosureRequired !== 'boolean') return null;
  if (value.privacyNoticeAcknowledged !== undefined && typeof value.privacyNoticeAcknowledged !== 'boolean') return null;
  return deepFreeze({
    schema: 'shun.guided.host-observation.v1',
    taskId: value.taskId,
    journeyId: value.journeyId,
    sourceRef: value.sourceRef,
    revision: value.revision,
    caseRef,
    observedAtUnixMs: value.observedAtUnixMs,
    validUntilUnixMs: value.validUntilUnixMs,
    evidenceRefs: [...value.evidenceRefs],
    ...(value.selectedRootRef === undefined ? {} : { selectedRootRef: value.selectedRootRef }),
    ...(value.externalDisclosureRequired === undefined ? {} : { externalDisclosureRequired: value.externalDisclosureRequired }),
    ...(value.privacyNoticeAcknowledged === undefined ? {} : { privacyNoticeAcknowledged: value.privacyNoticeAcknowledged }),
    ...(value.actionPreviewRef === undefined ? {} : { actionPreviewRef: value.actionPreviewRef }),
  });
}

function validateSemanticSelection(
  value: unknown,
  taskId: string,
): GuidedGoalSemanticSelection | null {
  if (!isRecord(value) || typeof value.status !== 'string') return null;
  if (value.status === 'SELECTED') {
    if (!isRecord(value.semantic)) return null;
    const semantic = value.semantic;
    if (
      semantic.schema !== 'shun.goal-semantic.v1' ||
      semantic.taskId !== taskId ||
      !isRecord(semantic.goalContract) ||
      semantic.goalContract.taskId !== taskId ||
      typeof semantic.goalContract.objective !== 'string' ||
      semantic.goalContract.objective.length === 0 ||
      !safeToken(semantic.capabilityId) ||
      !safeToken(semantic.capabilityRevision) ||
      !isRecord(semantic.provenance) ||
      !safeToken(semantic.provenance.resolverRevision)
    ) return null;
    return value as unknown as GuidedGoalSemanticSelection;
  }
  if (value.status === 'NOT_READY') {
    if (!isRecord(value.normalization) || typeof value.normalization.failureCode !== 'string') return null;
    return value as unknown as GuidedGoalSemanticSelection;
  }
  if (value.status === 'REJECTED') {
    if (typeof value.code !== 'string' || value.code.length === 0) return null;
    return value as unknown as GuidedGoalSemanticSelection;
  }
  return null;
}

interface GuidedTemplateSelection {
  readonly template: StepTemplate;
  readonly eligibilityCode: string;
}

function chooseTemplate(
  semantic: GuidedGoalSemanticSelection,
  observation: HostGuidedObservation,
): GuidedTemplateSelection | null {
  if (semantic.status === 'REJECTED') {
    if (
      !observation.selectedRootRef &&
      (semantic.code === 'HOST_OBSERVATION_REQUIRED' || semantic.code === 'HOST_OBSERVATION_SCOPE_MISMATCH')
    ) {
      const template = findApprovedStepTemplate('shun.guided.select-root');
      return template ? { template, eligibilityCode: semantic.code } : null;
    }
    return null;
  }
  if (semantic.status === 'NOT_READY') {
    if (semantic.normalization.failureCode === 'OBJECT_UNRESOLVED') {
      if (observation.selectedRootRef) return null;
      const template = findApprovedStepTemplate('shun.guided.select-root');
      return template ? { template, eligibilityCode: 'OBJECT_UNRESOLVED' } : null;
    }
    if (
      semantic.normalization.failureCode === 'CAPABILITY_UNRESOLVED' ||
      semantic.normalization.failureCode === 'GOAL_AMBIGUOUS'
    ) {
      const template = findApprovedStepTemplate('shun.guided.clarify-goal');
      return template ? { template, eligibilityCode: semantic.normalization.failureCode } : null;
    }
    return null;
  }
  if (!observation.selectedRootRef) {
    const template = findApprovedStepTemplate('shun.guided.select-root');
    return template ? { template, eligibilityCode: 'SELECTED_ROOT_MISSING' } : null;
  }
  if (observation.externalDisclosureRequired && !observation.privacyNoticeAcknowledged) {
    const template = findApprovedStepTemplate('shun.guided.privacy-notice');
    return template ? { template, eligibilityCode: 'EXTERNAL_DISCLOSURE_REQUIRED' } : null;
  }
  if (observation.actionPreviewRef) {
    const template = findApprovedStepTemplate('shun.guided.review-plan');
    return template ? { template, eligibilityCode: 'ACTION_PREVIEW_AVAILABLE' } : null;
  }
  const template = findApprovedStepTemplate('shun.guided.inspect-scope');
  return template ? { template, eligibilityCode: 'SELECTED_SCOPE_READY' } : null;
}

export function validateGuidedAdvisory(
  value: unknown,
  observationValue: unknown,
  nowUnixMs: number,
): GuidedAdvisoryResult {
  const observation = parseHostObservation(observationValue, nowUnixMs);
  if (!observation) return { status: 'REJECTED', code: 'HOST_OBSERVATION_INVALID' };
  if (!isRecord(value) || !exactKeys(value, ['schema', 'journeyId', 'caseRef', 'reasonCode', 'explanation', 'evidenceRefs'])) {
    return { status: 'REJECTED', code: 'ADVISORY_SCHEMA_REFUSED' };
  }
  const caseRef = parseCaseRef(value.caseRef);
  if (
    value.schema !== 'shun.guided.advisory.v1' ||
    value.journeyId !== observation.journeyId ||
    !caseRef ||
    !equal(caseRef, observation.caseRef) ||
    !safeToken(value.reasonCode, 128) ||
    value.reasonCode.length > 128 ||
    typeof value.explanation !== 'string' ||
    value.explanation.length > 500 ||
    hasControlCharacters(value.explanation) ||
    !Array.isArray(value.evidenceRefs) ||
    value.evidenceRefs.length > 24 ||
    !value.evidenceRefs.every((entry) => typeof entry === 'string' && observation.evidenceRefs.includes(entry)) ||
    new Set(value.evidenceRefs).size !== value.evidenceRefs.length
  ) return { status: 'REJECTED', code: 'ADVISORY_PROVENANCE_REFUSED' };
  return {
    status: 'ADVISORY_ONLY',
    reasonCode: value.reasonCode,
    explanation: value.explanation,
    evidenceRefs: Object.freeze([...value.evidenceRefs]),
  };
}

export function createNextGuidedStep(input: {
  readonly semanticSelection: unknown;
  readonly observation: unknown;
  readonly nowUnixMs: number;
  readonly advisory?: unknown;
}): GuidedStepDecision {
  if (!Number.isSafeInteger(input.nowUnixMs) || input.nowUnixMs <= 0) {
    return { status: 'BLOCKED', code: 'CLOCK_INPUT_INVALID' };
  }
  const observation = parseHostObservation(input.observation, input.nowUnixMs);
  if (!observation) return { status: 'BLOCKED', code: 'HOST_OBSERVATION_INVALID' };
  const semantic = validateSemanticSelection(input.semanticSelection, observation.taskId);
  if (!semantic) return { status: 'BLOCKED', code: 'GOAL_SEMANTIC_SELECTION_INVALID' };

  let advisory: GuidedAdvisory | undefined;
  if (input.advisory !== undefined) {
    const checked = validateGuidedAdvisory(input.advisory, observation, input.nowUnixMs);
    if (checked.status !== 'ADVISORY_ONLY') return { status: 'BLOCKED', code: checked.code };
    advisory = deepFreeze({
      schema: 'shun.guided.advisory.v1',
      journeyId: observation.journeyId,
      caseRef: observation.caseRef,
      reasonCode: checked.reasonCode,
      explanation: checked.explanation,
      evidenceRefs: checked.evidenceRefs,
    });
  }

  const selection = chooseTemplate(semantic, observation);
  if (!selection) return { status: 'BLOCKED', code: 'GUIDED_STEP_NOT_ELIGIBLE' };
  const template = selection.template;
  const capabilityRef =
    semantic.status === 'SELECTED'
      ? {
          capabilityId: semantic.semantic.capabilityId,
          revision: semantic.semantic.capabilityRevision,
          resolverRevision: semantic.semantic.provenance.resolverRevision,
        }
      : undefined;
  const step: StepSpec = deepFreeze({
    schema: 'shun.guided.step-spec.v1',
    journeyId: observation.journeyId,
    taskId: observation.taskId,
    stepId: `guided:${observation.journeyId}:${template.templateId}:${observation.revision}:${observation.caseRef.digest.slice(0, 12)}`,
    caseRef: observation.caseRef,
    eligibilityCode: selection.eligibilityCode,
    templateRef: {
      artifactId: template.templateId,
      version: template.version,
      digest: template.digest,
    },
    kind: template.kind,
    titleKey: template.titleKey,
    formSchema: template.formSchema,
    allowedEvents: template.allowedEvents,
    evidenceRefs: observation.evidenceRefs,
    ...(capabilityRef ? { capabilityRef } : {}),
    ...(template.templateId === 'shun.guided.review-plan' && observation.actionPreviewRef
      ? { actionPreviewRef: observation.actionPreviewRef }
      : {}),
    issuedAtUnixMs: input.nowUnixMs,
    validUntilUnixMs: Math.min(observation.validUntilUnixMs, input.nowUnixMs + 5 * 60_000),
  });
  return { status: 'STEP', step, ...(advisory ? { advisory } : {}) };
}

function validateStepSpec(
  value: unknown,
  observation: HostGuidedObservation,
  semantic: GuidedGoalSemanticSelection,
  nowUnixMs: number,
): StepSpec | null {
  if (!isRecord(value)) return null;
  const required = [
    'schema', 'journeyId', 'taskId', 'stepId', 'caseRef', 'eligibilityCode', 'templateRef',
    'kind', 'titleKey', 'formSchema', 'allowedEvents', 'evidenceRefs',
    'issuedAtUnixMs', 'validUntilUnixMs',
  ];
  const optional = ['capabilityRef', 'actionPreviewRef'];
  if (!exactKeys(value, required, optional)) return null;
  if (
    value.schema !== 'shun.guided.step-spec.v1' ||
    !safeToken(value.eligibilityCode) ||
    value.journeyId !== observation.journeyId ||
    value.taskId !== observation.taskId ||
    !safeToken(value.stepId, 160) ||
    !equal(value.caseRef, observation.caseRef) ||
    !isRecord(value.templateRef) ||
    typeof value.templateRef.artifactId !== 'string' ||
    typeof value.templateRef.version !== 'string' ||
    typeof value.templateRef.digest !== 'string'
  ) return null;
  const expectedSelection = chooseTemplate(semantic, observation);
  const template = findApprovedStepTemplate(value.templateRef.artifactId);
  if (
    !expectedSelection ||
    !template ||
    value.stepId !== `guided:${observation.journeyId}:${template.templateId}:${observation.revision}:${observation.caseRef.digest.slice(0, 12)}` ||
    expectedSelection.template.templateId !== template.templateId ||
    expectedSelection.eligibilityCode !== value.eligibilityCode ||
    value.templateRef.version !== template.version ||
    value.templateRef.digest !== template.digest ||
    value.kind !== template.kind ||
    value.titleKey !== template.titleKey ||
    !equal(value.formSchema, template.formSchema) ||
    !equal(value.allowedEvents, template.allowedEvents) ||
    !equal(value.evidenceRefs, observation.evidenceRefs)
  ) return null;
  if (
    typeof value.issuedAtUnixMs !== 'number' ||
    typeof value.validUntilUnixMs !== 'number' ||
    !Number.isSafeInteger(value.issuedAtUnixMs) ||
    !Number.isSafeInteger(value.validUntilUnixMs) ||
    value.issuedAtUnixMs < observation.observedAtUnixMs ||
    value.validUntilUnixMs > observation.validUntilUnixMs ||
    value.validUntilUnixMs <= value.issuedAtUnixMs ||
    value.validUntilUnixMs > value.issuedAtUnixMs + 5 * 60_000 ||
    nowUnixMs < value.issuedAtUnixMs ||
    nowUnixMs > value.validUntilUnixMs
  ) return null;
  const expectedActionPreviewRef = template.templateId === 'shun.guided.review-plan' ? observation.actionPreviewRef : undefined;
  if (value.actionPreviewRef !== expectedActionPreviewRef) return null;
  const expectedCapabilityRef = semantic.status === 'SELECTED'
    ? {
        capabilityId: semantic.semantic.capabilityId,
        revision: semantic.semantic.capabilityRevision,
        resolverRevision: semantic.semantic.provenance.resolverRevision,
      }
    : undefined;
  if (!equal(value.capabilityRef, expectedCapabilityRef)) return null;
  if (value.capabilityRef !== undefined) {
    if (
      !isRecord(value.capabilityRef) ||
      !exactKeys(value.capabilityRef, ['capabilityId', 'revision', 'resolverRevision']) ||
      !safeToken(value.capabilityRef.capabilityId) ||
      !safeToken(value.capabilityRef.revision) ||
      !safeToken(value.capabilityRef.resolverRevision)
    ) return null;
  }
  return value as unknown as StepSpec;
}

function validateAnswerValue(field: StepSpec['formSchema']['fields'][number], value: unknown): boolean {
  if (field.type === 'TEXT') {
    return (
      typeof value === 'string' &&
      value.length > 0 &&
      value.trim().length > 0 &&
      value.length <= field.maxLength &&
      !hasControlCharacters(value)
    );
  }
  if (field.type === 'CHOICE') {
    return typeof value === 'string' && field.options.some((option) => option.id === value && option.eligible);
  }
  return typeof value === 'boolean';
}

/**
 * Pure validator. ACCEPTED means the answer is well-bound data only; the
 * trusted Host must atomically mark currentStepState CONSUMED before any next
 * evaluation. This module never persists or advances journey state itself.
 */
export function validateGuidedStepOutcome(input: {
  readonly stepSpec: unknown;
  readonly currentObservation: unknown;
  readonly currentSemanticSelection: unknown;
  readonly currentStepId: string;
  readonly currentStepState: 'CURRENT' | 'CONSUMED' | 'SUPERSEDED';
  readonly outcome: unknown;
  readonly nowUnixMs: number;
}): GuidedOutcomeResult {
  if (!Number.isSafeInteger(input.nowUnixMs) || input.nowUnixMs <= 0) {
    return { status: 'REJECTED', code: 'CLOCK_INPUT_INVALID' };
  }
  const observation = parseHostObservation(input.currentObservation, input.nowUnixMs);
  if (!observation) return { status: 'REJECTED', code: 'HOST_OBSERVATION_INVALID' };
  const semantic = validateSemanticSelection(input.currentSemanticSelection, observation.taskId);
  if (!semantic) return { status: 'REJECTED', code: 'GOAL_SEMANTIC_SELECTION_INVALID' };
  const step = validateStepSpec(input.stepSpec, observation, semantic, input.nowUnixMs);
  if (!step) return { status: 'REJECTED', code: 'STEP_SPEC_STALE_OR_UNAPPROVED' };
  if (input.currentStepState !== 'CURRENT') {
    return { status: 'REJECTED', code: 'STEP_ALREADY_CONSUMED_OR_SUPERSEDED' };
  }
  if (input.currentStepId !== step.stepId) {
    return { status: 'REJECTED', code: 'STEP_SUPERSEDED' };
  }
  const value = input.outcome;
  const required = [
    'schema', 'journeyId', 'taskId', 'stepId', 'caseRef', 'event',
    'source', 'sourceRef', 'answers', 'evidenceRefs', 'occurredAtUnixMs',
  ];
  if (!isRecord(value) || !exactKeys(value, required)) {
    return { status: 'REJECTED', code: 'STEP_OUTCOME_SCHEMA_REFUSED' };
  }
  if (
    value.schema !== 'shun.guided.step-outcome.v1' ||
    value.journeyId !== step.journeyId ||
    value.taskId !== step.taskId ||
    value.stepId !== step.stepId ||
    !equal(value.caseRef, step.caseRef) ||
    typeof value.event !== 'string' ||
    !step.allowedEvents.includes(value.event as GuidedEvent) ||
    (value.source !== 'USER' && value.source !== 'HOST') ||
    typeof value.sourceRef !== 'string' ||
    !Array.isArray(value.answers) ||
    !Array.isArray(value.evidenceRefs) ||
    value.evidenceRefs.length > 24 ||
    !value.evidenceRefs.every((entry) => typeof entry === 'string' && observation.evidenceRefs.includes(entry)) ||
    new Set(value.evidenceRefs).size !== value.evidenceRefs.length ||
    typeof value.occurredAtUnixMs !== 'number' ||
    !Number.isSafeInteger(value.occurredAtUnixMs) ||
    value.occurredAtUnixMs < step.issuedAtUnixMs ||
    value.occurredAtUnixMs > step.validUntilUnixMs ||
    value.occurredAtUnixMs > input.nowUnixMs
  ) return { status: 'REJECTED', code: 'STEP_OUTCOME_PROVENANCE_REFUSED' };

  if (value.event === 'OBSERVATION_RECEIPT') {
    if (
      value.source !== 'HOST' ||
      value.sourceRef !== observation.sourceRef ||
      value.answers.length !== 0 ||
      value.evidenceRefs.length === 0
    ) return { status: 'REJECTED', code: 'OBSERVATION_RECEIPT_PROVENANCE_REFUSED' };
  } else {
    if (value.source !== 'USER' || value.sourceRef.length <= 3 || value.sourceRef.length > 256 || !value.sourceRef.startsWith('ui:') || value.sourceRef.trim() !== value.sourceRef || hasControlCharacters(value.sourceRef)) {
      return { status: 'REJECTED', code: 'USER_ANSWER_SOURCE_REFUSED' };
    }
  }

  const answers = value.answers as unknown[];
  if (answers.length > step.formSchema.fields.length) return { status: 'REJECTED', code: 'ANSWER_COUNT_EXCEEDED' };
  const seen = new Set<string>();
  for (const answer of answers) {
    if (!isRecord(answer) || !exactKeys(answer, ['fieldId', 'value']) || typeof answer.fieldId !== 'string') {
      return { status: 'REJECTED', code: 'ANSWER_SCHEMA_REFUSED' };
    }
    if (seen.has(answer.fieldId)) return { status: 'REJECTED', code: 'ANSWER_DUPLICATE_FIELD' };
    seen.add(answer.fieldId);
    const field = step.formSchema.fields.find((candidate) => candidate.id === answer.fieldId);
    if (!field || !validateAnswerValue(field, answer.value)) {
      return { status: 'REJECTED', code: 'ANSWER_VALUE_REFUSED' };
    }
  }

  if (value.event === 'USER_SUBMIT') {
    if (step.formSchema.fields.some((field) => field.required && !seen.has(field.id))) {
      return { status: 'REJECTED', code: 'ANSWER_REQUIRED_FIELD_MISSING' };
    }
  } else if (value.answers.length !== 0 || value.evidenceRefs.length !== 0) {
    return { status: 'REJECTED', code: 'NON_SUBMIT_EVENT_HAS_ANSWERS_OR_EVIDENCE' };
  }

  const outcome = deepFreeze({
    schema: 'shun.guided.step-outcome.v1',
    journeyId: step.journeyId,
    taskId: step.taskId,
    stepId: step.stepId,
    caseRef: step.caseRef,
    event: value.event,
    source: value.source,
    sourceRef: value.sourceRef,
    answers: value.answers,
    evidenceRefs: value.evidenceRefs,
    occurredAtUnixMs: value.occurredAtUnixMs,
  }) as StepOutcome;
  return {
    status: 'ACCEPTED',
    outcome,
    answerProvenance: {
      source: outcome.source,
      sourceRef: outcome.sourceRef,
      caseRef: outcome.caseRef,
      stepId: outcome.stepId,
      evidenceRefs: outcome.evidenceRefs,
    },
  };
}
