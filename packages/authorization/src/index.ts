// @shun/authorization — T02 trust/policy/action controller for Shun v0.1.
//
// Authority: docs/architecture/L2-v0.1.md §4.6/§4.6.1 (grants + privileged
// currentness), §9.1 (central Action Controller), §9.2 (risk classes),
// §11.2 (identity/currentness), §12 (bounded approval), §13 (failure
// ownership); frozen contract types come from @shun/contracts.
//
// This package owns the AUTHORITY side of authorization: durable policy
// state and its fail-closed currentness resolution, the grant-issuing
// AuthorizationAuthority (integrity applied here, never by callers), and
// the Action Controller routing (effective risk R0-R3, bounded approvals,
// grant-backed AuthorizedActions, per-effect currentness gating).
// Execution itself lives in the executor packages; the privileged boundary
// re-validates every presentation independently (§4.6.1).
export * from './authority.ts';
export * from './controller.ts';
export * from './failures.ts';
export * from './integrity.ts';
export * from './policy.ts';
