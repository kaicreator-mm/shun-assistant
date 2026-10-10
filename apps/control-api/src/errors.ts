// Typed control-surface error taxonomy (T08).
//
// The Control Surface is non-authoritative (L2 §12): it never creates
// authorization and never owns failures — it reports and relays. Every code
// here is a closed enum so the UI can map each one to a fixed human-readable
// fallback (DAG T08 validation: "approval readability, override forbidden,
// local-only disclosure, predictable fallback").

export const CONTROL_ERROR_CODES = [
  // transport / parsing
  'INVALID_JSON_BODY',
  'BODY_TOO_LARGE',
  'NOT_FOUND',
  'METHOD_NOT_ALLOWED',
  'INTERNAL',
  // goals / clarification
  'TASK_NOT_FOUND',
  'TASK_INVALID_BODY',
  'CLARIFICATION_NOT_PENDING',
  // preview
  'PREVIEW_NOT_AVAILABLE',
  // approvals — fail-closed ladder
  'APPROVAL_NOT_FOUND',
  'APPROVAL_ALREADY_DECIDED',
  'APPROVAL_EXPIRED',
  'PLAN_HASH_MISMATCH',
  'POLICY_EXPIRED',
  'POLICY_STATE_UNKNOWN',
  'TRUST_BLOCKED',
  // cancellation / recovery
  'CANCEL_UNSUPPORTED',
  'CANCEL_INVALID_STATE',
  'RECOVERY_NOT_APPLICABLE',
  'RETRY_BLOCKED_UNCERTAIN',
  // evidence — local-only disclosure
  'EVIDENCE_REF_INVALID',
  'EVIDENCE_NOT_FOUND',
  'LOCAL_ONLY_VIOLATION',
] as const;

export type ControlErrorCode = (typeof CONTROL_ERROR_CODES)[number];

/** Deterministic HTTP status mapping; fail-closed security states lock (423). */
export function httpStatusForCode(code: ControlErrorCode): number {
  switch (code) {
    case 'INVALID_JSON_BODY':
    case 'TASK_INVALID_BODY':
    case 'EVIDENCE_REF_INVALID':
      return 400;
    case 'BODY_TOO_LARGE':
      return 413;
    case 'TASK_NOT_FOUND':
    case 'APPROVAL_NOT_FOUND':
    case 'EVIDENCE_NOT_FOUND':
    case 'NOT_FOUND':
      return 404;
    case 'METHOD_NOT_ALLOWED':
      return 405;
    case 'LOCAL_ONLY_VIOLATION':
      return 403;
    case 'APPROVAL_EXPIRED':
    case 'POLICY_EXPIRED':
    case 'POLICY_STATE_UNKNOWN':
    case 'TRUST_BLOCKED':
      return 423;
    case 'CLARIFICATION_NOT_PENDING':
    case 'PREVIEW_NOT_AVAILABLE':
    case 'APPROVAL_ALREADY_DECIDED':
    case 'PLAN_HASH_MISMATCH':
    case 'CANCEL_UNSUPPORTED':
    case 'CANCEL_INVALID_STATE':
    case 'RECOVERY_NOT_APPLICABLE':
    case 'RETRY_BLOCKED_UNCERTAIN':
      return 409;
    case 'INTERNAL':
      return 500;
  }
}

export class ControlError extends Error {
  readonly code: ControlErrorCode;

  constructor(code: ControlErrorCode, detail: string, options?: { cause?: unknown }) {
    super(`${code}: ${detail}`, options);
    this.name = 'ControlError';
    this.code = code;
  }

  get status(): number {
    return httpStatusForCode(this.code);
  }
}
