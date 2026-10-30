// Pure view-model for the bounded v03 Control UI (T10, Issue #238).
//
// No DOM, no fetch: every function maps guided-journey data to what a human
// should see, and every authorization boundary is guarded here so the DOM
// layer cannot bypass it. Hard boundaries enforced below:
// - the UI is never a grant source: approve/refuse only ever produce a
//   "pending user decision" envelope to be relayed over same-origin /api,
//   and never construct a grant/approval/permit object;
// - effectful (R2) steps require an explicit, confirmed user decision;
// - a replayed StepOutcome (same stepId + case digest) is refused;
// - advisory text is never authority;
// - scope and consent sentences must be bound to a supported locale;
// - REFUSED and UNKNOWN states have real display paths and can never render
//   as success.
// Plain ES with JSDoc types so the browser loads it without a build step and
// the tests type-check the same file via checkJs.

import { t, tf } from './strings.js';

/** Template ids approved for guided steps (T05 catalog, pinned by tests). */
export const APPROVED_TEMPLATE_IDS = Object.freeze([
  'shun.guided.select-root',
  'shun.guided.clarify-goal',
  'shun.guided.privacy-notice',
  'shun.guided.review-plan',
  'shun.guided.inspect-scope',
]);

const HEX_64 = /^[0-9a-f]{64}$/;

/** Exact key set a StepOutcome may carry; anything else is forged authority. */
const OUTCOME_KEYS = Object.freeze([
  'schema',
  'journeyId',
  'taskId',
  'stepId',
  'caseRef',
  'event',
  'source',
  'sourceRef',
  'answers',
  'evidenceRefs',
  'occurredAtUnixMs',
]);

/** Exact key set a GuidedAdvisory may carry; anything else is authority smuggling. */
const ADVISORY_KEYS = Object.freeze([
  'schema',
  'journeyId',
  'caseRef',
  'reasonCode',
  'explanation',
  'evidenceRefs',
]);

/**
 * @typedef {Object} CurrentStep
 * @property {'CURRENT'} status
 * @property {string} journeyId
 * @property {string} taskId
 * @property {string} stepId
 * @property {{ snapshotId: string, digest: string }} caseRef
 * @property {string} templateId
 * @property {string} templateVersion
 * @property {string} templateDigest
 * @property {string} kind
 * @property {string} titleKey
 * @property {{ id: string, type: string, labelKey: string, required: boolean, options?: { id: string, labelKey: string }[], maxLength?: number }[]} fields
 * @property {string[]} allowedEvents
 * @property {number} issuedAtUnixMs
 * @property {number} validUntilUnixMs
 * @property {{ capabilityId: string, revision: string, resolverRevision: string } | undefined} capabilityRef
 * @property {string | undefined} actionPreviewRef
 * @property {boolean} requiresExplicitApproval True only for REVIEW_EFFECT (R2) steps.
 */
/**
 * @typedef {Object} RefusedStep
 * @property {'REFUSED'} status
 * @property {'STEP_EXPIRED'|'STEP_SPEC_INVALID'|'TEMPLATE_UNKNOWN'} code
 * @property {string} reason
 * @property {false} success
 */
/**
 * @typedef {Object} UnknownStep
 * @property {'UNKNOWN'} status
 * @property {'CLOCK_UNKNOWN'} code
 * @property {string} reason
 * @property {false} success
 */
/** @typedef {CurrentStep|RefusedStep|UnknownStep} StepModel */

/**
 * Map a raw StepSpec onto what the surface may show as the current step.
 * Forgery, unknown templates and expired windows are refused; an unusable
 * clock yields an explicit UNKNOWN. The model never carries grant/approval
 * fields because it never reads them.
 *
 * @param {unknown} step
 * @param {unknown} nowUnixMs
 * @returns {StepModel}
 */
export function currentStepModel(step, nowUnixMs) {
  if (typeof nowUnixMs !== 'number' || !Number.isFinite(nowUnixMs)) {
    return {
      status: 'UNKNOWN',
      code: 'CLOCK_UNKNOWN',
      reason: 'The current time could not be established, so this step cannot be shown as actionable.',
      success: false,
    };
  }
  const shape = stepShape(step);
  if (!shape.ok) {
    return {
      status: 'REFUSED',
      code: 'STEP_SPEC_INVALID',
      reason: shape.reason,
      success: false,
    };
  }
  const spec = /** @type {Record<string, any>} */ (step);
  if (!APPROVED_TEMPLATE_IDS.includes(spec.templateRef.artifactId)) {
    return {
      status: 'REFUSED',
      code: 'TEMPLATE_UNKNOWN',
      reason: `Template "${spec.templateRef.artifactId}" is not in the approved guided catalog.`,
      success: false,
    };
  }
  if (nowUnixMs > spec.validUntilUnixMs) {
    return {
      status: 'REFUSED',
      code: 'STEP_EXPIRED',
      reason: 'The step window (validUntil) has closed; nothing can be decided on it.',
      success: false,
    };
  }
  return Object.freeze({
    status: 'CURRENT',
    journeyId: spec.journeyId,
    taskId: spec.taskId,
    stepId: spec.stepId,
    caseRef: { snapshotId: spec.caseRef.snapshotId, digest: spec.caseRef.digest },
    templateId: spec.templateRef.artifactId,
    templateVersion: spec.templateRef.version,
    templateDigest: spec.templateRef.digest,
    kind: spec.kind,
    titleKey: spec.titleKey,
    fields: spec.formSchema.fields.map(/** @returns {any} */ (/** @type {any} */ field) => {
      const base = { id: field.id, type: field.type, labelKey: field.labelKey, required: field.required };
      if (field.type === 'CHOICE') {
        return Object.freeze({
          ...base,
          options: field.options.map((/** @type {any} */ option) => ({
            id: option.id,
            labelKey: option.labelKey,
          })),
        });
      }
      if (field.type === 'TEXT') {
        return Object.freeze({ ...base, maxLength: field.maxLength });
      }
      return Object.freeze(base);
    }),
    allowedEvents: [...spec.allowedEvents],
    issuedAtUnixMs: spec.issuedAtUnixMs,
    validUntilUnixMs: spec.validUntilUnixMs,
    capabilityRef: spec.capabilityRef
      ? {
          capabilityId: spec.capabilityRef.capabilityId,
          revision: spec.capabilityRef.revision,
          resolverRevision: spec.capabilityRef.resolverRevision,
        }
      : undefined,
    actionPreviewRef: spec.actionPreviewRef,
    requiresExplicitApproval: spec.kind === 'REVIEW_EFFECT',
  });
}

/**
 * Structural validation of the StepSpec fields the view-model depends on.
 *
 * @param {unknown} step
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
function stepShape(step) {
  if (!step || typeof step !== 'object' || Array.isArray(step)) {
    return { ok: false, reason: 'Step is not an object.' };
  }
  const spec = /** @type {Record<string, any>} */ (step);
  if (spec.schema !== 'shun.guided.step-spec.v1') {
    return { ok: false, reason: 'Step schema is not shun.guided.step-spec.v1.' };
  }
  for (const key of ['journeyId', 'taskId', 'stepId', 'kind', 'titleKey']) {
    if (typeof spec[key] !== 'string' || spec[key].length === 0) {
      return { ok: false, reason: `Step field "${key}" must be a non-empty string.` };
    }
  }
  const caseRef = spec.caseRef;
  if (
    !caseRef ||
    typeof caseRef !== 'object' ||
    typeof caseRef.snapshotId !== 'string' ||
    caseRef.snapshotId.length === 0 ||
    typeof caseRef.digest !== 'string' ||
    !HEX_64.test(caseRef.digest)
  ) {
    return { ok: false, reason: 'Step caseRef must carry a snapshotId and a 64-hex digest.' };
  }
  const templateRef = spec.templateRef;
  if (
    !templateRef ||
    typeof templateRef !== 'object' ||
    typeof templateRef.artifactId !== 'string' ||
    typeof templateRef.version !== 'string' ||
    typeof templateRef.digest !== 'string' ||
    !HEX_64.test(templateRef.digest)
  ) {
    return { ok: false, reason: 'Step templateRef must carry artifactId, version and a 64-hex digest.' };
  }
  if (!spec.formSchema || typeof spec.formSchema !== 'object' || !Array.isArray(spec.formSchema.fields)) {
    return { ok: false, reason: 'Step formSchema.fields is missing.' };
  }
  for (const field of spec.formSchema.fields) {
    if (!field || typeof field.id !== 'string' || typeof field.type !== 'string') {
      return { ok: false, reason: 'Every form field needs an id and a type.' };
    }
    if (!['TEXT', 'CHOICE', 'CONFIRM'].includes(field.type)) {
      return { ok: false, reason: `Unknown form field type "${field.type}".` };
    }
  }
  if (!Array.isArray(spec.allowedEvents) || spec.allowedEvents.length === 0) {
    return { ok: false, reason: 'Step allowedEvents is missing.' };
  }
  if (
    typeof spec.issuedAtUnixMs !== 'number' ||
    !Number.isFinite(spec.issuedAtUnixMs) ||
    typeof spec.validUntilUnixMs !== 'number' ||
    !Number.isFinite(spec.validUntilUnixMs)
  ) {
    return { ok: false, reason: 'Step issuance and expiry timestamps must be finite numbers.' };
  }
  return { ok: true };
}

/**
 * @typedef {Object} ScopeSelected
 * @property {'SELECTED'} status
 * @property {string} root
 * @property {string} label
 * @property {undefined} [code]
 */
/**
 * @typedef {Object} ScopeNone
 * @property {'NONE'} status
 * @property {string} label
 * @property {undefined} [code]
 */
/**
 * @typedef {Object} ScopeUnknown
 * @property {'UNKNOWN'} status
 * @property {string} label
 * @property {undefined} [code]
 */
/**
 * @typedef {Object} ScopeRefused
 * @property {'REFUSED'} status
 * @property {'LOCALE_UNBOUND'} code
 * @property {string} reason
 */
/** @typedef {ScopeSelected|ScopeNone|ScopeUnknown|ScopeRefused} ScopeModel */

/**
 * Selected-root scope summary, localized. The surface shows at most the one
 * selected root; a missing root is an honest NONE, an unusable root an
 * explicit UNKNOWN, an unbound locale a refusal (never a guessed language).
 *
 * @param {{ selectedRootRef?: unknown } | undefined} scope
 * @param {string} locale
 * @returns {ScopeModel}
 */
export function scopeSummary(scope, locale) {
  const title = t(locale, 'state.selectedScope');
  const body = t(locale, 'scope.none');
  if (!title.ok) {
    return { status: 'REFUSED', code: 'LOCALE_UNBOUND', reason: title.reason };
  }
  if (!body.ok) {
    return { status: 'REFUSED', code: 'LOCALE_UNBOUND', reason: body.reason };
  }
  const root = /** @type {{ selectedRootRef?: unknown } | undefined} */ (scope)?.selectedRootRef;
  if (root === undefined || root === null) {
    return { status: 'NONE', label: body.text };
  }
  if (typeof root !== 'string' || root.length === 0) {
    const unknown = t(locale, 'scope.unknown');
    if (!unknown.ok) {
      return { status: 'REFUSED', code: 'LOCALE_UNBOUND', reason: unknown.reason };
    }
    return { status: 'UNKNOWN', label: unknown.text };
  }
  const rootLabel = t(locale, 'scope.selectedRoot');
  if (!rootLabel.ok) {
    return { status: 'REFUSED', code: 'LOCALE_UNBOUND', reason: rootLabel.reason };
  }
  return { status: 'SELECTED', root, label: `${title.text}: ${rootLabel.text} = ${root}` };
}

/**
 * Scope fence: content may only be rendered when its scope ref IS the
 * selected root. Anything else (other drives, other users' folders, nested
 * discoveries outside the case) is refused, never rendered.
 *
 * @param {unknown} selectedRootRef
 * @param {readonly unknown[]} candidateRefs
 * @returns {{ allowed: true } | { allowed: false, code: 'OUTSIDE_SCOPE_REFUSED', reason: string }}
 */
export function scopeContentGuard(selectedRootRef, candidateRefs) {
  if (typeof selectedRootRef !== 'string' || selectedRootRef.length === 0) {
    return {
      allowed: false,
      code: 'OUTSIDE_SCOPE_REFUSED',
      reason: 'No confirmed selected root exists; no content may be shown.',
    };
  }
  for (const ref of candidateRefs) {
    if (ref !== selectedRootRef) {
      return {
        allowed: false,
        code: 'OUTSIDE_SCOPE_REFUSED',
        reason: 'Content outside the selected root is never rendered.',
      };
    }
  }
  return { allowed: true };
}

/**
 * Localized consent disclosures for effectful (R2) steps. Refused, not
 * guessed, when the locale is unbound.
 *
 * @param {string} locale
 * @returns {{ ok: true, lines: string[] } | { ok: false, code: 'LOCALE_UNBOUND', reason: string }}
 */
export function consentView(locale) {
  /** @type {string[]} */
  const lines = [];
  for (const key of ['consent.explicitRequired', 'consent.humanRelay', 'consent.notGrant']) {
    const line = t(locale, key);
    if (!line.ok) {
      return { ok: false, code: 'LOCALE_UNBOUND', reason: line.reason };
    }
    lines.push(line.text);
  }
  return { ok: true, lines };
}

/**
 * @typedef {Object} StepOutcomeLike
 * @property {string} schema
 * @property {string} journeyId
 * @property {string} taskId
 * @property {string} stepId
 * @property {{ snapshotId: string, digest: string }} caseRef
 * @property {string} event
 * @property {string} source
 * @property {string} sourceRef
 * @property {{ fieldId: string, value: string|boolean }[]} answers
 * @property {string[]} evidenceRefs
 * @property {number} occurredAtUnixMs
 */

/**
 * Build the USER's answer envelope for the current step. This only packages
 * what the user actually answered — it creates no authority of any kind.
 *
 * @param {{ step: unknown, answers: { fieldId: string, value: string|boolean }[], sourceRef: string, occurredAtUnixMs: number }} input
 * @returns {{ ok: true, outcome: StepOutcomeLike } | { ok: false, code: string, reason: string }}
 */
export function buildStepOutcome({ step, answers, sourceRef, occurredAtUnixMs }) {
  const shape = stepShape(step);
  if (!shape.ok) {
    return { ok: false, code: 'STEP_SPEC_INVALID', reason: shape.reason };
  }
  const spec = /** @type {Record<string, any>} */ (step);
  if (!Array.isArray(answers)) {
    return { ok: false, code: 'ANSWERS_INVALID', reason: 'Answers must be an array.' };
  }
  const declared = new Map(
    spec.formSchema.fields.map((/** @type {any} */ field) => [field.id, field]),
  );
  for (const answer of answers) {
    if (!answer || typeof answer !== 'object') {
      return { ok: false, code: 'ANSWERS_INVALID', reason: 'Each answer must be an object.' };
    }
    const keys = Object.keys(answer);
    if (keys.length !== 2 || !keys.includes('fieldId') || !keys.includes('value')) {
      return { ok: false, code: 'ANSWERS_INVALID', reason: 'Each answer carries exactly fieldId and value.' };
    }
    const field = declared.get(answer.fieldId);
    if (!field) {
      return { ok: false, code: 'ANSWER_FIELD_UNDECLARED', reason: `Field "${answer.fieldId}" is not part of this step.` };
    }
    if (field.type === 'CONFIRM' && typeof answer.value !== 'boolean') {
      return { ok: false, code: 'ANSWER_VALUE_TYPE_REFUSED', reason: `Field "${answer.fieldId}" expects a boolean.` };
    }
    if ((field.type === 'TEXT' || field.type === 'CHOICE') && typeof answer.value !== 'string') {
      return { ok: false, code: 'ANSWER_VALUE_TYPE_REFUSED', reason: `Field "${answer.fieldId}" expects a string.` };
    }
  }
  if (typeof sourceRef !== 'string' || sourceRef.length === 0) {
    return { ok: false, code: 'SOURCE_REF_REQUIRED', reason: 'A user session sourceRef is required.' };
  }
  if (typeof occurredAtUnixMs !== 'number' || !Number.isFinite(occurredAtUnixMs)) {
    return { ok: false, code: 'CLOCK_UNKNOWN', reason: 'A finite timestamp is required.' };
  }
  return {
    ok: true,
    outcome: {
      schema: 'shun.guided.step-outcome.v1',
      journeyId: spec.journeyId,
      taskId: spec.taskId,
      stepId: spec.stepId,
      caseRef: { snapshotId: spec.caseRef.snapshotId, digest: spec.caseRef.digest },
      event: 'USER_SUBMIT',
      source: 'USER',
      sourceRef,
      answers: answers.map((answer) => ({ fieldId: answer.fieldId, value: answer.value })),
      evidenceRefs: [],
      occurredAtUnixMs,
    },
  };
}

/**
 * Deep-freeze a plain data object (no cycles: relay payloads are built here).
 * @template T
 * @param {T} value
 * @returns {T}
 */
function freezeDeep(value) {
  if (Array.isArray(value)) {
    for (const item of value) freezeDeep(item);
    return Object.freeze(value);
  }
  if (value !== null && typeof value === 'object') {
    for (const item of Object.values(value)) freezeDeep(item);
    return Object.freeze(value);
  }
  return value;
}

/**
 * @typedef {Object} DecisionRelay
 * @property {'USER_DECISION_RELAY'} kind Marks this as a relay envelope for a
 *   human decision — it is NOT a grant, approval or permit object and must
 *   never be treated as one by the UI or by anything reading it.
 * @property {true} humanApproval Explicit marker: a real human decided.
 * @property {false} authorityClaimed The UI claims no authority.
 * @property {'APPROVE'|'REFUSE'} decision
 * @property {string} relayedVia Same-origin API path the decision travels over.
 * @property {string} stepId
 * @property {string} stepDigest
 * @property {{ snapshotId: string, digest: string }} caseRef
 * @property {StepOutcomeLike} outcome
 */
/**
 * @typedef {Object} DecisionRefused
 * @property {false} ok
 * @property {string} code
 * @property {string} reason
 * @property {undefined} [relay]
 */
/**
 * @typedef {Object} DecisionOk
 * @property {true} ok
 * @property {DecisionRelay} relay
 */
/** @typedef {DecisionOk|DecisionRefused} DecisionResult */

/**
 * The ONLY path from a click to an effectful action: validate step and user
 * outcome, demand an explicit confirmation flag, and emit a frozen relay
 * envelope for same-origin /api. Forged authority fields anywhere in the
 * outcome, step/decision mismatches, expired steps and unconfirmed clicks
 * are refused. APPROVE is reserved for REVIEW_EFFECT (R2) steps; REFUSE is
 * always available for a current step.
 *
 * @param {{ step: unknown, outcome: unknown, decision: string, confirmed: unknown, nowUnixMs: unknown }} input
 * @returns {DecisionResult}
 */
export function userDecisionRelay({ step, outcome, decision, confirmed, nowUnixMs }) {
  const shape = stepShape(step);
  if (!shape.ok) {
    return { ok: false, code: 'STEP_SPEC_INVALID', reason: shape.reason };
  }
  const spec = /** @type {Record<string, any>} */ (step);
  if (!APPROVED_TEMPLATE_IDS.includes(spec.templateRef.artifactId)) {
    return { ok: false, code: 'TEMPLATE_UNKNOWN', reason: 'Step template is not in the approved catalog.' };
  }
  if (typeof nowUnixMs !== 'number' || !Number.isFinite(nowUnixMs)) {
    return {
      ok: false,
      code: 'CLOCK_UNKNOWN',
      reason: 'The current time could not be established, so nothing can be decided.',
    };
  }
  if (nowUnixMs > spec.validUntilUnixMs) {
    return {
      ok: false,
      code: 'STEP_EXPIRED',
      reason: 'The step window (validUntil) has closed; nothing can be decided on it.',
    };
  }
  if (decision !== 'APPROVE' && decision !== 'REFUSE') {
    return { ok: false, code: 'DECISION_UNKNOWN', reason: `Decision "${String(decision)}" is not decidable.` };
  }
  if (confirmed !== true) {
    return {
      ok: false,
      code: 'EXPLICIT_CONFIRMATION_REQUIRED',
      reason: 'An effectful decision requires an explicit user confirmation; nothing is auto-approved.',
    };
  }
  if (decision === 'APPROVE' && spec.kind !== 'REVIEW_EFFECT') {
    return {
      ok: false,
      code: 'APPROVE_RESERVED_FOR_REVIEW_EFFECT',
      reason: 'Only an effect-reviewing (R2) step can be approved here.',
    };
  }
  const checked = outcomeAgainstStep(outcome, spec);
  if (!checked.ok) return checked;
  const outcomeValue = /** @type {StepOutcomeLike} */ (checked.outcome);
  /** @type {DecisionRelay} */
  const relay = {
    kind: 'USER_DECISION_RELAY',
    humanApproval: true,
    authorityClaimed: false,
    decision,
    relayedVia: '/api',
    stepId: outcomeValue.stepId,
    stepDigest: spec.templateRef.digest,
    caseRef: { snapshotId: outcomeValue.caseRef.snapshotId, digest: outcomeValue.caseRef.digest },
    outcome: freezeDeep(outcomeValue),
  };
  return { ok: true, relay: Object.freeze(relay) };
}

/**
 * Full validation of a claimed StepOutcome against the current StepSpec:
 * schema, identity binding, event/source, declared answer fields, value
 * types and the closed key set (any extra key — grant, approval, permit —
 * is forged authority and refused).
 *
 * @param {unknown} outcome
 * @param {Record<string, any>} spec
 * @returns {{ ok: true, outcome: StepOutcomeLike } | { ok: false, code: string, reason: string }}
 */
function outcomeAgainstStep(outcome, spec) {
  if (!outcome || typeof outcome !== 'object' || Array.isArray(outcome)) {
    return { ok: false, code: 'OUTCOME_INVALID', reason: 'Outcome is not an object.' };
  }
  const record = /** @type {Record<string, unknown>} */ (outcome);
  for (const key of Object.keys(record)) {
    if (!OUTCOME_KEYS.includes(key)) {
      return {
        ok: false,
        code: 'EXTRA_KEYS_REFUSED',
        reason: `Outcome carries the forbidden field "${key}"; the UI never accepts constructed authority.`,
      };
    }
  }
  if (record.schema !== 'shun.guided.step-outcome.v1') {
    return { ok: false, code: 'OUTCOME_INVALID', reason: 'Outcome schema is not shun.guided.step-outcome.v1.' };
  }
  for (const key of ['journeyId', 'taskId', 'stepId']) {
    if (record[key] !== spec[key]) {
      return { ok: false, code: 'OUTCOME_INVALID', reason: `Outcome "${key}" does not match the current step.` };
    }
  }
  const caseRef = /** @type {Record<string, unknown> | undefined} */ (record.caseRef);
  if (
    !caseRef ||
    caseRef.snapshotId !== spec.caseRef.snapshotId ||
    caseRef.digest !== spec.caseRef.digest
  ) {
    return { ok: false, code: 'OUTCOME_INVALID', reason: 'Outcome caseRef does not match the current step.' };
  }
  if (record.event !== 'USER_SUBMIT' || record.source !== 'USER') {
    return { ok: false, code: 'OUTCOME_INVALID', reason: 'A user decision needs event USER_SUBMIT from source USER.' };
  }
  if (typeof record.sourceRef !== 'string' || record.sourceRef.length === 0) {
    return { ok: false, code: 'OUTCOME_INVALID', reason: 'Outcome needs a non-empty sourceRef.' };
  }
  if (typeof record.occurredAtUnixMs !== 'number' || !Number.isFinite(record.occurredAtUnixMs)) {
    return { ok: false, code: 'OUTCOME_INVALID', reason: 'Outcome needs a finite occurredAtUnixMs.' };
  }
  if (!Array.isArray(record.evidenceRefs) || !record.evidenceRefs.every((ref) => typeof ref === 'string')) {
    return { ok: false, code: 'OUTCOME_INVALID', reason: 'Outcome evidenceRefs must be strings.' };
  }
  const declared = new Map(
    spec.formSchema.fields.map((/** @type {any} */ field) => [field.id, field]),
  );
  const answers = record.answers;
  if (!Array.isArray(answers)) {
    return { ok: false, code: 'OUTCOME_INVALID', reason: 'Outcome answers must be an array.' };
  }
  for (const answer of answers) {
    const entry = /** @type {Record<string, unknown> | undefined} */ (answer);
    if (!entry || Object.keys(entry).length !== 2) {
      return { ok: false, code: 'OUTCOME_INVALID', reason: 'Each answer carries exactly fieldId and value.' };
    }
    const field = declared.get(entry.fieldId);
    if (!field) {
      return { ok: false, code: 'ANSWER_FIELD_UNDECLARED', reason: `Field "${String(entry.fieldId)}" is not part of this step.` };
    }
    if (field.type === 'CONFIRM' && typeof entry.value !== 'boolean') {
      return { ok: false, code: 'ANSWER_VALUE_TYPE_REFUSED', reason: `Field "${entry.fieldId}" expects a boolean.` };
    }
    if ((field.type === 'TEXT' || field.type === 'CHOICE') && typeof entry.value !== 'string') {
      return { ok: false, code: 'ANSWER_VALUE_TYPE_REFUSED', reason: `Field "${entry.fieldId}" expects a string.` };
    }
  }
  return { ok: true, outcome: /** @type {StepOutcomeLike} */ (outcome) };
}

/**
 * Stable replay identity of a submitted outcome: stepId + case digest, per
 * the T10 contract.
 *
 * @param {unknown} outcome
 * @returns {{ ok: true, key: string } | { ok: false, code: 'OUTCOME_INVALID', reason: string }}
 */
export function replayKey(outcome) {
  const record = /** @type {Record<string, unknown> | undefined} */ (outcome);
  const stepId = record?.stepId;
  const digest = /** @type {Record<string, unknown> | undefined} */ (record?.caseRef)?.digest;
  if (typeof stepId !== 'string' || stepId.length === 0 || typeof digest !== 'string' || digest.length === 0) {
    return { ok: false, code: 'OUTCOME_INVALID', reason: 'Replay identity needs stepId and a case digest.' };
  }
  return { ok: true, key: `${stepId}|${digest}` };
}

/**
 * Replay fence over an in-memory ledger of already-relayed outcomes. The
 * same StepOutcome identity (stepId + digest) submitted twice is refused as
 * a possible replay, never silently accepted twice.
 *
 * @param {readonly string[]} seenKeys
 * @param {unknown} outcome
 * @returns {{ allowed: true, key: string } | { allowed: false, code: 'POSSIBLE_REPLAY'|'OUTCOME_INVALID', key: string, reason: string }}
 */
export function replayGuard(seenKeys, outcome) {
  const key = replayKey(outcome);
  if (!key.ok) {
    return { allowed: false, code: 'OUTCOME_INVALID', key: '', reason: key.reason };
  }
  if (seenKeys.includes(key.key)) {
    return {
      allowed: false,
      code: 'POSSIBLE_REPLAY',
      key: key.key,
      reason: 'This exact step result was already submitted; refusing a possible replay.',
    };
  }
  return { allowed: true, key: key.key };
}

/**
 * @typedef {Object} StatusView
 * @property {boolean} success True ONLY for an explicitly accepted outcome.
 * @property {'ok'|'bad'|'unknown'} tone
 * @property {string} stringKey Catalog key for the human sentence.
 */
/**
 * Status → display contract for any claimed step status. Only the exact
 * string 'ACCEPTED' is success; REJECTED/BLOCKED render refused, and
 * anything else — including missing or future statuses — renders as an
 * explicit UNKNOWN. REFUSED and UNKNOWN can never render as success.
 *
 * @param {unknown} status
 * @returns {StatusView}
 */
export function outcomeStatusView(status) {
  if (status === 'ACCEPTED') return { success: true, tone: 'ok', stringKey: 'outcome.accepted' };
  if (status === 'REJECTED') return { success: false, tone: 'bad', stringKey: 'outcome.rejected' };
  if (status === 'BLOCKED') return { success: false, tone: 'bad', stringKey: 'outcome.blocked' };
  return { success: false, tone: 'unknown', stringKey: 'outcome.unknown' };
}

/** Refusal codes with dedicated human sentences; everything else stays UNKNOWN. */
/** @type {Readonly<Record<string, string>>} */
const REFUSAL_STRING_KEYS = Object.freeze({
  STEP_EXPIRED: 'error.stepExpired',
  STEP_SPEC_INVALID: 'error.stepInvalid',
  TEMPLATE_UNKNOWN: 'error.stepInvalid',
  POSSIBLE_REPLAY: 'outcome.replay',
  OUTSIDE_SCOPE_REFUSED: 'scope.outsideRefused',
  EXTRA_KEYS_REFUSED: 'error.forgeryRefused',
  EXPLICIT_CONFIRMATION_REQUIRED: 'consent.explicitRequired',
  LOCALE_UNBOUND: 'error.localeUnbound',
  ADVISORY_SCHEMA_REFUSED: 'advisory.notAuthority',
});

/**
 * Localized refusal line for a typed refusal code. Unknown codes render as
 * an explicit UNKNOWN (fail loud), never as success and never as silence.
 *
 * @param {unknown} code
 * @param {string} locale
 * @returns {{ ok: true, text: string, success: false, tone: 'bad'|'unknown' } | { ok: false, code: 'LOCALE_UNBOUND', reason: string }}
 */
export function refusalView(code, locale) {
  const key =
    typeof code === 'string' && REFUSAL_STRING_KEYS[code] ? REFUSAL_STRING_KEYS[code] : 'outcome.unknown';
  const line = t(locale, key);
  if (!line.ok) {
    return { ok: false, code: 'LOCALE_UNBOUND', reason: line.reason };
  }
  return { ok: true, text: line.text, success: false, tone: key === 'outcome.unknown' ? 'unknown' : 'bad' };
}

/**
 * Localized history lines. Refused/unknown entries keep success:false so a
 * past refusal can never be shown as a past success.
 *
 * @param {{ at: string, status: unknown, stepId?: string }[]} entries
 * @param {string} locale
 * @returns {{ ok: true, lines: { at: string, stepId: string, text: string, tone: 'ok'|'bad'|'unknown', success: boolean }[]} | { ok: false, code: 'LOCALE_UNBOUND'|'ENTRIES_INVALID', reason: string }}
 */
export function historyModel(entries, locale) {
  if (!Array.isArray(entries)) {
    return { ok: false, code: 'ENTRIES_INVALID', reason: 'History entries must be an array.' };
  }
  /** @type {{ at: string, stepId: string, text: string, tone: 'ok'|'bad'|'unknown', success: boolean }[]} */
  const lines = [];
  for (const entry of entries) {
    const record = /** @type {Record<string, unknown> | undefined} */ (entry);
    if (!record || typeof record.at !== 'string') {
      return { ok: false, code: 'ENTRIES_INVALID', reason: 'Every history entry needs a timestamp string.' };
    }
    const view = outcomeStatusView(record.status);
    const text = t(locale, view.stringKey);
    if (!text.ok) {
      return { ok: false, code: 'LOCALE_UNBOUND', reason: text.reason };
    }
    lines.push({
      at: record.at,
      stepId: typeof record.stepId === 'string' ? record.stepId : '',
      text: text.text,
      tone: view.tone,
      success: view.success,
    });
  }
  return { ok: true, lines };
}

/**
 * @typedef {Object} ProgressKnown
 * @property {true} known
 * @property {string} text
 * @property {undefined} [code]
 */
/**
 * @typedef {Object} ProgressPositionUnknown
 * @property {false} known
 * @property {string} text The explicit UNKNOWN sentence, never a guess.
 * @property {undefined} [code]
 */
/** @typedef {ProgressKnown|ProgressPositionUnknown} ProgressPosition */
/**
 * @typedef {Object} ProgressModel
 * @property {true} ok
 * @property {'RUNNING'|'PAUSED'|'UNKNOWN'} status PAUSED wins over UNKNOWN;
 *   an unusable paused flag or an unknown position degrades honestly.
 * @property {ProgressPosition} position
 * @property {string | undefined} pausedReason Set only when status is PAUSED.
 */
/**
 * @typedef {Object} ProgressRefused
 * @property {false} ok
 * @property {'LOCALE_UNBOUND'} code
 * @property {string} reason
 */
/** @typedef {ProgressModel|ProgressRefused} ProgressResult */

/**
 * Journey progress / paused panel model. Honesty rules:
 * - position renders only from real numbers (1 ≤ position ≤ total ≥ 1);
 *   anything else is an explicit UNKNOWN, never a fabricated position;
 * - the paused flag must be exactly true/false; any other value renders as
 *   UNKNOWN instead of being coerced into running or paused.
 *
 * @param {{ position?: unknown, total?: unknown, paused?: unknown } | undefined} journey
 * @param {string} locale
 * @returns {ProgressResult}
 */
export function progressModel(journey, locale) {
  const unknownLine = t(locale, 'progress.unknown');
  if (!unknownLine.ok) {
    return { ok: false, code: 'LOCALE_UNBOUND', reason: unknownLine.reason };
  }
  const record = /** @type {Record<string, unknown> | undefined} */ (journey);
  const position = record?.position;
  const total = record?.total;
  const positionValid =
    typeof position === 'number' &&
    Number.isInteger(position) &&
    position >= 1 &&
    typeof total === 'number' &&
    Number.isInteger(total) &&
    total >= 1 &&
    position <= total;
  /** @type {ProgressPosition} */
  let positionView;
  if (positionValid) {
    const stepOf = tf(locale, 'progress.stepOf', [position, total]);
    if (!stepOf.ok) {
      return { ok: false, code: 'LOCALE_UNBOUND', reason: stepOf.reason };
    }
    positionView = { known: true, text: stepOf.text };
  } else {
    positionView = { known: false, text: unknownLine.text };
  }
  const paused = record?.paused;
  if (paused === true) {
    const reason = t(locale, 'paused.reason');
    if (!reason.ok) {
      return { ok: false, code: 'LOCALE_UNBOUND', reason: reason.reason };
    }
    return Object.freeze({ ok: true, status: 'PAUSED', position: positionView, pausedReason: reason.text });
  }
  if (paused === false && positionView.known) {
    return Object.freeze({ ok: true, status: 'RUNNING', position: positionView, pausedReason: undefined });
  }
  return Object.freeze({ ok: true, status: 'UNKNOWN', position: positionView, pausedReason: undefined });
}

/**
 * @typedef {Object} AdvisoryOnly
 * @property {'ADVISORY_ONLY'} status
 * @property {string} reasonCode
 * @property {string} explanation
 * @property {false} authorityRelevant Advisory is text-only; never authority.
 */
/**
 * @typedef {Object} AdvisoryRefused
 * @property {'REFUSED'} status
 * @property {'ADVISORY_SCHEMA_REFUSED'} code
 * @property {string} reason
 */
/** @typedef {AdvisoryOnly|AdvisoryRefused} AdvisoryModel */

/**
 * Advisory fence: a well-formed advisory renders as a suggestion with
 * authorityRelevant:false. An advisory that smuggles authority-shaped or
 * template-shaped fields (grant, approval, permit, templateId, consent…) is
 * refused — a suggestion must never arrive dressed as authority.
 *
 * @param {unknown} advisory
 * @returns {AdvisoryModel}
 */
export function advisoryView(advisory) {
  if (!advisory || typeof advisory !== 'object' || Array.isArray(advisory)) {
    return {
      status: 'REFUSED',
      code: 'ADVISORY_SCHEMA_REFUSED',
      reason: 'Advisory is not an object.',
    };
  }
  const record = /** @type {Record<string, unknown>} */ (advisory);
  for (const key of Object.keys(record)) {
    if (!ADVISORY_KEYS.includes(key)) {
      return {
        status: 'REFUSED',
        code: 'ADVISORY_SCHEMA_REFUSED',
        reason: `Advisory carries the forbidden field "${key}"; suggestions are never authority.`,
      };
    }
  }
  if (record.schema !== 'shun.guided.advisory.v1') {
    return {
      status: 'REFUSED',
      code: 'ADVISORY_SCHEMA_REFUSED',
      reason: 'Advisory schema is not shun.guided.advisory.v1.',
    };
  }
  if (typeof record.reasonCode !== 'string' || record.reasonCode.length === 0) {
    return { status: 'REFUSED', code: 'ADVISORY_SCHEMA_REFUSED', reason: 'Advisory needs a reasonCode.' };
  }
  if (typeof record.explanation !== 'string' || record.explanation.length === 0) {
    return { status: 'REFUSED', code: 'ADVISORY_SCHEMA_REFUSED', reason: 'Advisory needs an explanation.' };
  }
  if (!Array.isArray(record.evidenceRefs) || !record.evidenceRefs.every((ref) => typeof ref === 'string')) {
    return { status: 'REFUSED', code: 'ADVISORY_SCHEMA_REFUSED', reason: 'Advisory evidenceRefs must be strings.' };
  }
  return Object.freeze({
    status: 'ADVISORY_ONLY',
    reasonCode: record.reasonCode,
    explanation: record.explanation,
    authorityRelevant: false,
  });
}
