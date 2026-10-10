// Typed Action Controller refusals (L2 §9.1, §13 failure ownership).
//
// Distinct from grant boundary rejections (GRANT_* codes in @shun/contracts):
// controller refusals happen BEFORE any grant exists — plan intake, policy
// routing, bounded approval — or when the controller refuses to proceed under
// a moved/revoked/unresolvable policy. Boundary rejections happen at the
// privileged side of an existing presentation. Both are structured so recovery
// and user explanation never need to infer hidden machine state (L2 §13).

export const CONTROLLER_REFUSAL_CODES = [
  /** Proposed plan failed schema/semantic validation or hash re-derivation at intake. */
  'PLAN_INVALID',
  /** Current authority/policy state is unresolvable — nothing proceeds. */
  'AUTHORIZATION_STATE_UNRESOLVABLE',
  /** Current policy forbids this plan (frozen taxonomy code, reused in the authorization domain). */
  'POLICY_BLOCKED',
  /** Control surface returned approved=false for the bounded approval request. */
  'APPROVAL_REJECTED',
  /** Approval decision does not bind the exact plan/task — bounded approval violated. */
  'APPROVAL_INVALID',
] as const;
export type ControllerRefusalCode = (typeof CONTROLLER_REFUSAL_CODES)[number];

/** Any typed code a controller refusal may carry: local codes plus pass-through contract/grant codes. */
export type RefusalCode = ControllerRefusalCode | import('@shun/contracts').ContractErrorCode;

/** Structured refusal result: the controller returns these instead of throwing for expected denials. */
export type ControllerRefusal = {
  ok: false;
  code: RefusalCode;
  detail: string;
  /** The action ids the refusal applies to (whole plan when omitted). */
  actionIds?: string[];
};

/** Typed error for contexts that prefer exceptions (mirrors ShunContractError ergonomics). */
export class AuthorizationRefusalError extends Error {
  readonly code: RefusalCode;
  readonly detail: string;

  constructor(code: RefusalCode, detail: string) {
    super(`authorization refused: ${code} — ${detail}`);
    this.name = 'AuthorizationRefusalError';
    this.code = code;
    this.detail = detail;
  }
}
