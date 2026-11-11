import { createHash } from 'node:crypto';

/**
 * T06 — opt-in, allowlist-only feedback projection for future-build Shadow.
 *
 * This module is pure domain code. It does not persist, transmit, train,
 * promote, or activate anything. A trusted Host supplies the current consent
 * and operator/evidence binding, then runs the narrow Shadow-only workflow.
 */

export const META_FEEDBACK_SCHEMA = 'shun.meta-feedback-candidate/1' as const;
export const META_FEEDBACK_SCOPE = 'META_FEEDBACK_SHADOW' as const;

export type MetaFeedbackRating = 'HELPFUL' | 'NOT_HELPFUL';
export type MetaFeedbackCategory =
  | 'INCORRECT_RESULT'
  | 'MISSING_STEP'
  | 'WRONG_TARGET'
  | 'UNSAFE_SUGGESTION'
  | 'TOO_COMPLEX'
  | 'OTHER';
export type MetaFeedbackCorrection =
  | 'WRONG_OBJECT'
  | 'MISSING_CONSTRAINT'
  | 'STALE_CONTEXT'
  | 'POLICY_MISMATCH'
  | 'NO_CORRECTION';

export interface MetaFeedbackSelection {
  readonly selected: true;
  readonly caseRef: string;
  readonly sourceRevision: string;
  readonly rating: MetaFeedbackRating;
  readonly category: MetaFeedbackCategory;
  readonly correction?: MetaFeedbackCorrection;
}

export interface MetaFeedbackAuthorizationRequest {
  readonly scope: typeof META_FEEDBACK_SCOPE;
  readonly caseRef: string;
  readonly sourceRevision: string;
  readonly selection: MetaFeedbackSelection;
}

/**
 * Returned only by the trusted Host after resolving current consent,
 * evidence ownership and operator identity. The Host must recheck this
 * currentness atomically again inside runMetaFeedbackWorkflow before storing.
 */
export interface MetaFeedbackAuthorization {
  readonly status: 'AUTHORIZED';
  readonly scope: typeof META_FEEDBACK_SCOPE;
  readonly candidateId: string;
  readonly caseRef: string;
  readonly sourceRevision: string;
  readonly sourceDigest: string;
  readonly evidenceOwnerRef: string;
  readonly operatorSubjectRef: string;
  readonly operatorId: string;
  readonly consentRef: string;
  readonly consentRevision: string;
  readonly consentExpiresAt: string;
  readonly authorizationRevision: string;
  readonly currentnessRef: string;
  readonly selection: MetaFeedbackSelection;
}

export interface MetaFeedbackShadowCandidate {
  readonly schema: typeof META_FEEDBACK_SCHEMA;
  readonly candidateId: string;
  readonly kind: 'META_FEEDBACK';
  readonly lifecycle: 'FUTURE_BUILD_SHADOW';
  readonly active: false;
  readonly source: Readonly<{
    caseRef: string;
    revision: string;
    sha256: string;
  }>;
  readonly feedback: Readonly<{
    rating: MetaFeedbackRating;
    category: MetaFeedbackCategory;
    correction?: MetaFeedbackCorrection;
  }>;
  readonly provenance: Readonly<{
    operatorId: string;
    operatorSubjectRef: string;
    consentRef: string;
    consentRevision: string;
    consentExpiresAt: string;
    authorizationRevision: string;
    currentnessRef: string;
  }>;
}

export interface MetaFeedbackHostPort {
  /** Verify current, exact-scope consent and resolve source/operator ownership. */
  authorizeCurrentFeedback(input: MetaFeedbackAuthorizationRequest): Promise<unknown>;
  /**
   * Persist only a future-build Shadow candidate. The Host must atomically
   * recheck consentRef/currentnessRef and reject any promotion or activation.
   */
  runMetaFeedbackWorkflow(input: {
    readonly candidate: MetaFeedbackShadowCandidate;
    readonly authorization: MetaFeedbackAuthorization;
  }): Promise<unknown>;
}

export type MetaFeedbackSubmitResult =
  | { readonly status: 'NOT_SELECTED' }
  | { readonly status: 'REFUSED'; readonly code: string }
  | {
      readonly status: 'STORED_SHADOW';
      readonly candidateRef: string;
      readonly candidateDigest: string;
      readonly active: false;
    }
  | {
      readonly status: 'UNKNOWN';
      readonly code: 'HOST_OUTCOME_UNKNOWN' | 'HOST_RESULT_UNVERIFIABLE';
    };

const SAFE_REF = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const RATINGS: readonly string[] = ['HELPFUL', 'NOT_HELPFUL'];
const CATEGORIES: readonly string[] = [
  'INCORRECT_RESULT',
  'MISSING_STEP',
  'WRONG_TARGET',
  'UNSAFE_SUGGESTION',
  'TOO_COMPLEX',
  'OTHER',
];
const CORRECTIONS: readonly string[] = [
  'WRONG_OBJECT',
  'MISSING_CONSTRAINT',
  'STALE_CONTEXT',
  'POLICY_MISMATCH',
  'NO_CORRECTION',
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value).sort();
  const allowed = [...required, ...optional].sort();
  return (
    required.every((key) => Object.hasOwn(value, key)) && keys.every((key) => allowed.includes(key))
  );
}

function isSafeRef(value: unknown): value is string {
  return typeof value === 'string' && SAFE_REF.test(value);
}

function isIsoUtc(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    ISO_UTC.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(Date.parse(value)).toISOString() === value
  );
}

function sameSelection(a: MetaFeedbackSelection, b: unknown): boolean {
  if (!isRecord(b)) return false;
  if (
    !hasExactKeys(
      b,
      ['selected', 'caseRef', 'sourceRevision', 'rating', 'category'],
      ['correction'],
    )
  )
    return false;
  return (
    b.selected === true &&
    b.caseRef === a.caseRef &&
    b.sourceRevision === a.sourceRevision &&
    b.rating === a.rating &&
    b.category === a.category &&
    (a.correction === undefined ? b.correction === undefined : b.correction === a.correction)
  );
}

function parseSelection(raw: unknown): MetaFeedbackSelection | null {
  if (
    !isRecord(raw) ||
    !hasExactKeys(
      raw,
      ['selected', 'caseRef', 'sourceRevision', 'rating', 'category'],
      ['correction'],
    ) ||
    raw.selected !== true ||
    !isSafeRef(raw.caseRef) ||
    !isSafeRef(raw.sourceRevision) ||
    typeof raw.rating !== 'string' ||
    !RATINGS.includes(raw.rating) ||
    typeof raw.category !== 'string' ||
    !CATEGORIES.includes(raw.category) ||
    (raw.correction !== undefined &&
      (typeof raw.correction !== 'string' || !CORRECTIONS.includes(raw.correction)))
  ) {
    return null;
  }

  const selection: MetaFeedbackSelection = {
    selected: true,
    caseRef: raw.caseRef,
    sourceRevision: raw.sourceRevision,
    rating: raw.rating as MetaFeedbackRating,
    category: raw.category as MetaFeedbackCategory,
    ...(raw.correction === undefined
      ? {}
      : { correction: raw.correction as MetaFeedbackCorrection }),
  };
  return Object.freeze(selection);
}

function parseAuthorization(
  raw: unknown,
  selection: MetaFeedbackSelection,
  nowIso: string,
): MetaFeedbackAuthorization | null {
  if (
    !isRecord(raw) ||
    !hasExactKeys(raw, [
      'status',
      'scope',
      'candidateId',
      'caseRef',
      'sourceRevision',
      'sourceDigest',
      'evidenceOwnerRef',
      'operatorSubjectRef',
      'operatorId',
      'consentRef',
      'consentRevision',
      'consentExpiresAt',
      'authorizationRevision',
      'currentnessRef',
      'selection',
    ])
  )
    return null;

  if (
    raw.status !== 'AUTHORIZED' ||
    raw.scope !== META_FEEDBACK_SCOPE ||
    !isSafeRef(raw.candidateId) ||
    raw.caseRef !== selection.caseRef ||
    raw.sourceRevision !== selection.sourceRevision ||
    typeof raw.sourceDigest !== 'string' ||
    !SHA256.test(raw.sourceDigest) ||
    !isSafeRef(raw.evidenceOwnerRef) ||
    !isSafeRef(raw.operatorSubjectRef) ||
    raw.evidenceOwnerRef !== raw.operatorSubjectRef ||
    !isSafeRef(raw.operatorId) ||
    !isSafeRef(raw.consentRef) ||
    !isSafeRef(raw.consentRevision) ||
    !isIsoUtc(raw.consentExpiresAt) ||
    Date.parse(raw.consentExpiresAt) <= Date.parse(nowIso) ||
    !isSafeRef(raw.authorizationRevision) ||
    !isSafeRef(raw.currentnessRef) ||
    !sameSelection(selection, raw.selection)
  )
    return null;

  return Object.freeze({
    status: 'AUTHORIZED',
    scope: META_FEEDBACK_SCOPE,
    candidateId: raw.candidateId,
    caseRef: raw.caseRef,
    sourceRevision: raw.sourceRevision,
    sourceDigest: raw.sourceDigest,
    evidenceOwnerRef: raw.evidenceOwnerRef,
    operatorSubjectRef: raw.operatorSubjectRef,
    operatorId: raw.operatorId,
    consentRef: raw.consentRef,
    consentRevision: raw.consentRevision,
    consentExpiresAt: raw.consentExpiresAt,
    authorizationRevision: raw.authorizationRevision,
    currentnessRef: raw.currentnessRef,
    selection,
  });
}

function buildCandidate(
  selection: MetaFeedbackSelection,
  authorization: MetaFeedbackAuthorization,
): MetaFeedbackShadowCandidate {
  const source = Object.freeze({
    caseRef: selection.caseRef,
    revision: selection.sourceRevision,
    sha256: authorization.sourceDigest,
  });
  const feedback = Object.freeze({
    rating: selection.rating,
    category: selection.category,
    ...(selection.correction === undefined ? {} : { correction: selection.correction }),
  });
  const provenance = Object.freeze({
    operatorId: authorization.operatorId,
    operatorSubjectRef: authorization.operatorSubjectRef,
    consentRef: authorization.consentRef,
    consentRevision: authorization.consentRevision,
    consentExpiresAt: authorization.consentExpiresAt,
    authorizationRevision: authorization.authorizationRevision,
    currentnessRef: authorization.currentnessRef,
  });
  return Object.freeze({
    schema: META_FEEDBACK_SCHEMA,
    candidateId: authorization.candidateId,
    kind: 'META_FEEDBACK',
    lifecycle: 'FUTURE_BUILD_SHADOW',
    active: false,
    source,
    feedback,
    provenance,
  });
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, stableValue(value[key])]),
    );
  }
  return value;
}

/** SHA-256 of canonical candidate JSON; Host must return this exact digest. */
function digestCandidate(candidate: MetaFeedbackShadowCandidate): string {
  return createHash('sha256')
    .update(JSON.stringify(stableValue(candidate)), 'utf8')
    .digest('hex');
}

function validShadowResult(
  raw: unknown,
  expectedDigest: string,
): raw is {
  status: 'SHADOW_STORED';
  candidateRef: string;
  candidateDigest: string;
  active: false;
} {
  return (
    isRecord(raw) &&
    hasExactKeys(raw, ['status', 'candidateRef', 'candidateDigest', 'active']) &&
    raw.status === 'SHADOW_STORED' &&
    isSafeRef(raw.candidateRef) &&
    typeof raw.candidateDigest === 'string' &&
    SHA256.test(raw.candidateDigest) &&
    raw.candidateDigest === expectedDigest &&
    raw.active === false
  );
}

export function createMetaFeedbackAdapter(
  host: MetaFeedbackHostPort,
  now: () => string = () => new Date().toISOString(),
) {
  let authorizeCurrentFeedback: MetaFeedbackHostPort['authorizeCurrentFeedback'];
  let runMetaFeedbackWorkflow: MetaFeedbackHostPort['runMetaFeedbackWorkflow'];
  try {
    if (!isRecord(host)) throw new Error('META_FEEDBACK_HOST_PORT_REQUIRED');
    const authorize = host.authorizeCurrentFeedback;
    const run = host.runMetaFeedbackWorkflow;
    if (typeof authorize !== 'function' || typeof run !== 'function') {
      throw new Error('META_FEEDBACK_HOST_PORT_REQUIRED');
    }
    // Snapshot trusted methods once; a mutable/getter-backed Host object
    // cannot swap the persistence operation between consent and commit.
    authorizeCurrentFeedback = authorize.bind(host);
    runMetaFeedbackWorkflow = run.bind(host);
  } catch {
    throw new TypeError('META_FEEDBACK_HOST_PORT_REQUIRED');
  }

  return Object.freeze({
    async submit(raw: unknown): Promise<MetaFeedbackSubmitResult> {
      // A deselected form is an absolute no-op: no parsing of answer/source
      // material, no consent lookup, no payload construction and no Host call.
      if (isRecord(raw) && raw.selected === false) return { status: 'NOT_SELECTED' };

      let selection: MetaFeedbackSelection | null;
      try {
        selection = parseSelection(raw);
      } catch {
        selection = null;
      }
      if (!selection) return { status: 'REFUSED', code: 'FEEDBACK_INPUT_INVALID' };

      let rawAuthorization: unknown;
      try {
        rawAuthorization = await authorizeCurrentFeedback({
          scope: META_FEEDBACK_SCOPE,
          caseRef: selection.caseRef,
          sourceRevision: selection.sourceRevision,
          selection,
        });
      } catch {
        return { status: 'REFUSED', code: 'FEEDBACK_AUTHORITY_UNAVAILABLE' };
      }

      // Check expiry AFTER the asynchronous Host consent/source resolution;
      // the Host must still recheck atomically when it persists the candidate.
      let currentTime: string;
      try {
        currentTime = now();
      } catch {
        return { status: 'REFUSED', code: 'FEEDBACK_CURRENTNESS_UNRESOLVABLE' };
      }
      if (!isIsoUtc(currentTime)) {
        return { status: 'REFUSED', code: 'FEEDBACK_CURRENTNESS_UNRESOLVABLE' };
      }

      let authorization: MetaFeedbackAuthorization | null;
      try {
        authorization = parseAuthorization(rawAuthorization, selection, currentTime);
      } catch {
        authorization = null;
      }
      if (!authorization) {
        return { status: 'REFUSED', code: 'FEEDBACK_AUTHORIZATION_INVALID' };
      }

      const candidate = buildCandidate(selection, authorization);
      const expectedCandidateDigest = digestCandidate(candidate);
      let rawResult: unknown;
      try {
        rawResult = await runMetaFeedbackWorkflow({ candidate, authorization });
      } catch {
        // The Host may have committed before losing its response. Never retry
        // or claim refusal; the caller must reconcile the stable candidateId.
        return { status: 'UNKNOWN', code: 'HOST_OUTCOME_UNKNOWN' };
      }

      let shadowResult: {
        status: 'SHADOW_STORED';
        candidateRef: string;
        candidateDigest: string;
        active: false;
      } | null = null;
      try {
        if (validShadowResult(rawResult, expectedCandidateDigest)) shadowResult = rawResult;
      } catch {
        shadowResult = null;
      }
      if (!shadowResult || shadowResult.candidateRef !== authorization.candidateId) {
        return { status: 'UNKNOWN', code: 'HOST_RESULT_UNVERIFIABLE' };
      }
      return {
        status: 'STORED_SHADOW',
        candidateRef: shadowResult.candidateRef,
        candidateDigest: shadowResult.candidateDigest,
        active: false,
      };
    },
  });
}
