// Pure view-model for the Shun control surface (T08, L2 §12).
//
// No DOM, no fetch: every function maps API data to what a human should see,
// and every decision path is guarded here so the DOM layer cannot bypass it.
// The fallback table covers every typed control-api error code — the UI never
// leaves a user stuck with a raw machine message (predictable fallback).
// This module is plain ES so the browser loads it without a build step; the
// tests import the same file (type-checked via checkJs).

/** Fixed human-readable fallback per control-api error code (closed taxonomy). */
/** @type {Record<string, string>} */
export const FALLBACK_MESSAGES = {
  INVALID_JSON_BODY: 'The request could not be sent. Please try again.',
  BODY_TOO_LARGE: 'The request was too large. Please try again.',
  NOT_FOUND: 'That item does not exist (it may have been removed).',
  METHOD_NOT_ALLOWED: 'This action is not available.',
  INTERNAL: 'Something went wrong inside the control surface. Nothing was approved.',
  TASK_NOT_FOUND: 'This task no longer exists.',
  TASK_INVALID_BODY: 'The request was not understood. Please check the form and try again.',
  CLARIFICATION_NOT_PENDING: 'This task is not waiting for an answer anymore.',
  PREVIEW_NOT_AVAILABLE: 'There is no plan to preview yet. The task may still be resolving.',
  APPROVAL_NOT_FOUND: 'This approval no longer exists.',
  APPROVAL_ALREADY_DECIDED: 'You already decided this approval.',
  APPROVAL_EXPIRED:
    'The approval window closed. Ask Shun to re-plan, then review the fresh preview.',
  PLAN_HASH_MISMATCH:
    'The plan changed after the preview you saw. Nothing was recorded — review the fresh preview and decide again.',
  POLICY_EXPIRED:
    'The policy snapshot has expired, so approval is refused until Shun re-resolves policy. This cannot be overridden here.',
  POLICY_STATE_UNKNOWN:
    'The current policy cannot be established, so approval is refused. This cannot be overridden here.',
  TRUST_BLOCKED:
    'A provider trust failure is active. Approval cannot make an untrusted provider trusted.',
  CANCEL_UNSUPPORTED: 'This plan declared no cancellable steps.',
  CANCEL_INVALID_STATE: 'There is nothing running that can be cancelled right now.',
  RECOVERY_NOT_APPLICABLE: 'There is nothing to recover for this task.',
  RETRY_BLOCKED_UNCERTAIN:
    'It is not yet known whether the interrupted step took effect. Reconcile first — an uncertain destructive action is never retried blindly.',
  EVIDENCE_REF_INVALID: 'Evidence must be local. This surface never fetches external evidence.',
  EVIDENCE_NOT_FOUND: 'That evidence record does not exist.',
  LOCAL_ONLY_VIOLATION:
    'The control surface is local-only and refused a request that did not come from this computer.',
};

/** Fallback text for an error code; unknown codes still get a predictable sentence. */
/**
 * @param {string} code
 * @returns {string}
 */
export function fallbackFor(code) {
  return FALLBACK_MESSAGES[code] ?? `Unexpected response (${code}). Nothing was changed.`;
}

/** Fixed labels for the 13 reference task states (L2 §5.1). */
/** @type {Record<string, string>} */
export const STATE_LABELS = {
  RECEIVED: 'Received',
  INTERPRETING: 'Understanding the goal',
  CLARIFICATION: 'Needs your answer',
  RESOLVING: 'Finding a way to do it',
  PLANNED: 'Plan ready',
  AWAITING_AUTHORIZATION: 'Waiting for your approval',
  EXECUTING: 'Running',
  VERIFYING: 'Verifying the result',
  LIFECYCLE_RECONCILIATION: 'Reconciling lifecycle state',
  SUCCEEDED: 'Done — verified',
  FAILED: 'Failed',
  CANCELLED: 'Cancelled',
  NEEDS_INTERVENTION: 'Needs your decision',
};

/**
 * @param {string} state
 * @returns {string}
 */
export function stateLabel(state) {
  return STATE_LABELS[state] ?? state;
}

/** @type {Record<string, string>} */
const STATE_TONES = {
  SUCCEEDED: 'ok',
  FAILED: 'bad',
  CANCELLED: 'muted',
  NEEDS_INTERVENTION: 'warn',
  AWAITING_AUTHORIZATION: 'warn',
  CLARIFICATION: 'warn',
};

/**
 * @param {string} state
 * @returns {string}
 */
export function stateTone(state) {
  return STATE_TONES[state] ?? 'neutral';
}

/**
 * @typedef {Object} SnapshotLike
 * @property {string} taskId
 * @property {string} title
 * @property {string} state
 * @property {{ code?: string, message?: string } | undefined} [failure]
 * @property {{ status?: string } | undefined} [approval]
 * @property {{ at: string, state: string, note?: string }[]} progress
 * @property {{ classification: string, detail: string, reconciled: boolean } | undefined} [recovery]
 * @property {{ enforced?: boolean, externalDisclosure?: string } | undefined} [localOnly]
 */

/** Compact list-entry model for one task. */
/**
 * @param {SnapshotLike} snapshot
 * @returns {{ taskId: string, title: string, stateLabel: string, tone: string, detailLine: string }}
 */
export function taskCard(snapshot) {
  const bits = [stateLabel(snapshot.state)];
  if (snapshot.failure?.code) bits.push(snapshot.failure.code);
  if (snapshot.approval?.status === 'PENDING') bits.push('approval pending');
  return {
    taskId: snapshot.taskId,
    title: snapshot.title,
    stateLabel: stateLabel(snapshot.state),
    tone: stateTone(snapshot.state),
    detailLine: bits.join(' · '),
  };
}

/** Preview → readable blocks. The risk statement is shown verbatim and always first. */
/**
 * @typedef {Object} PreviewLike
 * @property {string} taskId
 * @property {string} planHash
 * @property {string} capabilityId
 * @property {string} riskStatement
 * @property {{ description: string }[]} actions
 * @property {{ summary: string }} verification
 * @property {{ summary: string }} recovery
 * @property {string} [expiresAt]
 * @property {boolean} requiresExplicitApproval
 */
/**
 * @param {PreviewLike} preview
 * @returns {{ headline: string, riskStatement: string, planHash: string, requiresExplicitApproval: boolean, bullets: string[] }}
 */
export function previewBlocks(preview) {
  const bullets = [];
  for (const action of preview.actions) {
    bullets.push(action.description);
  }
  bullets.push(preview.verification.summary);
  bullets.push(preview.recovery.summary);
  if (preview.expiresAt) {
    bullets.push(`This approval window closes at ${preview.expiresAt}.`);
  }
  return {
    headline: `Plan for “${preview.capabilityId}” — ${preview.actions.length} step${preview.actions.length === 1 ? '' : 's'}`,
    riskStatement: preview.riskStatement,
    planHash: preview.planHash,
    requiresExplicitApproval: preview.requiresExplicitApproval,
    bullets,
  };
}

/**
 * UI-side misleading-preview prevention: a decision may only be sent when the
 * plan hash the user actually saw equals the hash bound to the approval. The
 * server re-checks this fail-closed; this guard keeps the click honest.
 */
/**
 * @param {{ previewPlanHash: string, approvalPlanHash: string, enteredPlanHash: string }} hashes
 * @returns {{ allowed: boolean, reason: string }}
 */
export function decisionGuard({ previewPlanHash, approvalPlanHash, enteredPlanHash }) {
  if (previewPlanHash !== approvalPlanHash) {
    return {
      allowed: false,
      reason: fallbackFor('PLAN_HASH_MISMATCH'),
    };
  }
  if (enteredPlanHash !== approvalPlanHash) {
    return {
      allowed: false,
      reason: 'The plan changed while you were reviewing. Nothing was sent — reload the preview.',
    };
  }
  return { allowed: true, reason: '' };
}

/** Progress history as readable lines. */
/**
 * @param {SnapshotLike} snapshot
 * @returns {{ at: string, label: string, note: string }[]}
 */
export function progressLines(snapshot) {
  return snapshot.progress.map((step) => ({
    at: step.at,
    label: stateLabel(step.state),
    note: step.note ?? '',
  }));
}

/** Failure block, always human-phrased, with the typed code as a small tag. */
/**
 * @param {SnapshotLike} snapshot
 * @returns {string[]}
 */
export function failureLines(snapshot) {
  if (!snapshot.failure) return [];
  return [`(${snapshot.failure.code}) ${snapshot.failure.message}`];
}

/** Recovery block: classification and what may happen next, in plain words. */
/** @type {Record<string, string>} */
export const RECOVERY_EXPLANATIONS = {
  NOT_STARTED: 'Nothing was executed.',
  FAILED_BEFORE_EFFECT: 'The step did not take effect. A retry is provably safe.',
  MAY_HAVE_EXECUTED_UNCERTAIN:
    'It is unknown whether the step took effect. Shun must reconcile before anything is retried.',
  COMPLETED_VERIFIED: 'The step ran and its result was independently verified.',
};

/**
 * @param {SnapshotLike} snapshot
 * @returns {string[]}
 */
export function recoveryLines(snapshot) {
  if (!snapshot.recovery) return [];
  const explanation = RECOVERY_EXPLANATIONS[snapshot.recovery.classification] ?? '';
  const state = snapshot.recovery.reconciled ? 'Reconciled.' : 'Not reconciled yet.';
  return [`(${snapshot.recovery.classification}) ${explanation} ${state} ${snapshot.recovery.detail}`];
}

/** Residue summary as readable lines; detailed items are opt-in only. */
/**
 * @typedef {Object} ResidueLike
 * @property {string} [taskId]
 * @property {string} [generatedAt]
 * @property {string} headline
 * @property {{ label: string, count: number, readableBytes?: string }[]} groups
 * @property {number} protectedUntouchedCount
 * @property {boolean} [detailAvailable]
 */
/**
 * @param {ResidueLike} residue
 * @returns {string[]}
 */
export function residueLines(residue) {
  const lines = [residue.headline];
  for (const group of residue.groups) {
    lines.push(
      `${group.label}: ${group.count} item${group.count === 1 ? '' : 's'}${group.readableBytes ? ` (${group.readableBytes})` : ''}`,
    );
  }
  if (residue.protectedUntouchedCount > 0) {
    lines.push(
      `${residue.protectedUntouchedCount} protected file${residue.protectedUntouchedCount === 1 ? '' : 's'} detected — protected files are never touched.`,
    );
  }
  return lines;
}

/** Local-only badge text — the surface discloses its own posture. */
/**
 * @param {SnapshotLike} snapshot
 * @returns {string}
 */
export function localOnlyBadge(snapshot) {
  return snapshot.localOnly?.enforced
    ? 'Local only — nothing leaves this computer'
    : `External disclosure: ${snapshot.localOnly?.externalDisclosure ?? 'UNKNOWN'}`;
}
