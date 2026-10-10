// AuthorizationAuthority / AuthorizationGrant and privileged-boundary grant
// validation (L2 §4.6.1, closing P0-AUTH-01 and P0-AUTH-CURRENTNESS-01).
//
// A self-declared approval JSON attached by the caller is NOT authorization.
// Every AuthorizedAction carries a grant issued by the trusted authority
// regardless of authorizationKind, and the privileged boundary validates the
// grant independently and fail-closed:
//   - authenticity: an integrity envelope must be present AND pass the
//     caller-injected trusted verifier — presence of an envelope is not
//     verification (P1-02);
//   - currentness against CURRENT authority/policy state, never grant
//     self-claims — an authentic, unexpired grant issued under a superseded
//     authority revision or changed/revoked policy revision is void;
//   - unresolvable currentness is refused exactly like negative currentness;
//   - exact planHash binding (re-derived here from the presented plan),
//     declared action-scope containment, and exact identity between the
//     presented action and the action recorded in the hashed plan — a plan
//     whose hash matches but a presented action surface that differs is
//     refused (P1-01);
//   - expiry decided on parsed instants, never lexicographic string order,
//     at grant and action level, with the injected clock itself validated
//     (P1-04).
//
// The concrete integrity/revocation substrate (signing/MAC/trusted local
// channel, revision records) is an L3 implementation freedom; this module is
// pure validation and performs no execution and no I/O.
import { z } from 'zod';
import {
  type ActionPlan,
  ActionPlanSchema,
  type AuthorizedAction,
  AuthorizedActionSchema,
  canonicalJson,
  computePlanHash,
  PrivilegeLevelSchema,
} from './plan.ts';
import {
  type GrantRejectionCode,
  IsoDateTimeSchema,
  Sha256HexSchema,
  ShunContractError,
} from './taxonomy.ts';

export const AuthorizationAuthoritySchema = z.strictObject({
  authorityId: z.string().min(1),
  authorityRevision: z.string().min(1),
});
export type AuthorizationAuthority = z.infer<typeof AuthorizationAuthoritySchema>;

/** Integrity envelope. The mechanism is an L3 freedom; absence is a structural authenticity failure. */
export const GrantIntegritySchema = z.strictObject({
  scheme: z.enum(['HMAC_SHA256', 'SIGNATURE_ED25519', 'TRUSTED_LOCAL_CHANNEL']),
  value: z.string().min(1),
});
export type GrantIntegrity = z.infer<typeof GrantIntegritySchema>;

/**
 * Trusted seam (L2 §4.6.1): the L3 substrate verifies the integrity envelope.
 * Presence of an envelope is NOT verification; this verifier is the only thing
 * that turns a structurally-present envelope into authenticity. Pure and
 * synchronous.
 */
export type GrantIntegrityVerifier = (
  grant: AuthorizationGrant,
  envelope: GrantIntegrity,
) => boolean;

/** The exact action surface a grant covers: actionIds/op plus declared scope plus privilege level. */
export const ActionScopeSchema = z.strictObject({
  actionIds: z.array(z.string().min(1)).min(1),
  privilegeLevel: PrivilegeLevelSchema,
  filesystem: z
    .strictObject({
      read: z.array(z.string().min(1)),
      write: z.array(z.string().min(1)),
    })
    .optional(),
  network: z
    .strictObject({
      allowed: z.boolean(),
      domains: z.array(z.string().min(1)).optional(),
    })
    .optional(),
  registry: z.strictObject({ write: z.array(z.string().min(1)) }).optional(),
});
export type ActionScope = z.infer<typeof ActionScopeSchema>;

/**
 * The issued grant record shape (authority side): integrity always present.
 * Issued grants are durable, integrity-protected records in ShunStore.
 */
export const AuthorizationGrantSchema = z.strictObject({
  grantId: z.string().min(1),
  issuer: z.strictObject({
    authorityId: z.string().min(1),
    authorityRevision: z.string().min(1),
  }),
  taskId: z.string().min(1),
  /** Exact approved plan identity — any plan change voids the grant. */
  planHash: Sha256HexSchema,
  policySnapshotRevision: z.string().min(1),
  actionScope: ActionScopeSchema,
  issuedAt: IsoDateTimeSchema,
  expiresAt: IsoDateTimeSchema,
  /** Durable approval record reference; required for explicit-approval grants. */
  approvalRef: z.string().min(1).optional(),
  integrity: GrantIntegritySchema,
});
export type AuthorizationGrant = z.infer<typeof AuthorizationGrantSchema>;

/**
 * What an untrusted caller may present across the privilege boundary:
 * structurally identical, but the integrity envelope is optional because a
 * forged/self-declared grant is exactly a presentation without one.
 */
export const AuthorizationGrantPresentationSchema = AuthorizationGrantSchema.extend({
  integrity: GrantIntegritySchema.optional(),
});

/**
 * The privileged boundary's view of current authority/policy state,
 * established immediately before any side effect. `UNRESOLVABLE` models a
 * missing, unreadable or corrupt currentness record — the boundary never
 * falls back to "authentic therefore current".
 */
export const CurrentAuthorityStateSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('CURRENT'),
    authorityId: z.string().min(1),
    authorityRevision: z.string().min(1),
    policySnapshotRevision: z.string().min(1),
    policyStatus: z.enum(['ACTIVE', 'SUPERSEDED', 'REVOKED']),
    revokedGrantIds: z.array(z.string().min(1)),
  }),
  z.strictObject({
    kind: z.literal('UNRESOLVABLE'),
    reason: z.string().min(1),
  }),
]);
export type CurrentAuthorityState = z.infer<typeof CurrentAuthorityStateSchema>;

export type GrantValidationInput = {
  /** Untrusted presented grant. */
  grant: unknown;
  /** Untrusted presented plan; its hash is re-derived here, never trusted from the envelope. */
  plan: unknown;
  /** Untrusted presented authorized action. */
  action: unknown;
  /** Current authority/policy state established by the privileged boundary itself. */
  currentAuthority: unknown;
  /** Current time as ISO 8601 UTC; injected so validation stays pure and deterministic. */
  now: string;
  /**
   * Trusted verifier for the integrity envelope, backed by the L3 substrate.
   * Required (not optional with a default) so a caller cannot silently skip
   * authenticity: an envelope being present does not make it verified.
   */
  verifyIntegrity: GrantIntegrityVerifier;
};

export type GrantValidationResult =
  | { ok: true; grant: AuthorizationGrant }
  | { ok: false; code: GrantRejectionCode; detail: string };

/**
 * Windows-style path containment: case-insensitive, separator-normalized
 * prefix match on path-segment boundaries. A prefix must match whole segments
 * (`C:\Users\a` does not contain `C:\Users\ab`). Any `..` segment on either
 * side fails closed: this is a purely lexical containment check and cannot
 * resolve where `..` actually lands (Win32 normalization may move the target
 * outside the prefix, e.g. `C:\out\..\protected` is `C:\protected`). The
 * executor must still independently verify realpaths and reject reparse
 * points before touching the filesystem (L2 §8.2.1); this contract check does
 * not replace that.
 */
export function pathWithin(path: string, prefix: string): boolean {
  const normalize = (p: string) => p.replaceAll('\\', '/').replace(/\/+$/, '').toLowerCase();
  const np = normalize(path);
  const nprefix = normalize(prefix);
  // Fail closed on traversal segments: resolving them is the executor's job
  // (realpath/reparse-point checks), never this lexical contract check.
  if (np.split('/').includes('..') || nprefix.split('/').includes('..')) return false;
  return np === nprefix || np.startsWith(`${nprefix}/`);
}

function isPrefixCovered(
  paths: readonly string[],
  prefixes: readonly string[] | undefined,
): boolean {
  if (paths.length === 0) return true;
  if (!prefixes || prefixes.length === 0) return false;
  return paths.every((p) => prefixes.some((prefix) => pathWithin(p, prefix)));
}

/**
 * Full privileged-boundary presentation check for one AuthorizedAction.
 * Ordered deterministically so every rejection is reproducible and testable;
 * the first failing rule wins. Fails closed on every branch. Rule order:
 * clock well-formedness → grant well-formedness → envelope presence and
 * trusted verification → currentness (authority/policy/revocation) → grant
 * expiry → plan identity (re-derived hash) → action well-formedness and
 * grant consistency → declared scope containment → exact action↔plan
 * binding → action-level expiry.
 */
export function validateGrantPresentation(input: GrantValidationInput): GrantValidationResult {
  const reject = (code: GrantRejectionCode, detail: string): GrantValidationResult => ({
    ok: false,
    code,
    detail,
  });

  // The injected clock is boundary input too: an unparseable `now` is refused
  // instead of silently degrading every expiry comparison (P1-04).
  const now = IsoDateTimeSchema.safeParse(input.now);
  if (!now.success)
    return reject('GRANT_MALFORMED', 'validation clock `now` is not an ISO 8601 UTC datetime');

  const presented = AuthorizationGrantPresentationSchema.safeParse(input.grant);
  if (!presented.success)
    return reject('GRANT_MALFORMED', 'presented grant is not a valid AuthorizationGrant');
  const g = presented.data;

  // Structural authenticity precondition: a self-declared JSON without an
  // integrity envelope is refused before anything else.
  if (!g.integrity) {
    return reject(
      'GRANT_NOT_AUTHENTIC',
      'grant carries no integrity envelope; self-declared grants are not authorization',
    );
  }

  // Presence is not verification (P1-02): only the injected trusted verifier
  // turns the structurally-present envelope into authenticity.
  const verified: AuthorizationGrant = { ...g, integrity: g.integrity };
  if (!input.verifyIntegrity(verified, verified.integrity)) {
    return reject(
      'GRANT_NOT_AUTHENTIC',
      'integrity envelope present but it did not pass trusted verification',
    );
  }

  const current = CurrentAuthorityStateSchema.safeParse(input.currentAuthority);
  if (!current.success)
    return reject('GRANT_CURRENTNESS_UNRESOLVABLE', 'currentness record unreadable');
  if (current.data.kind === 'UNRESOLVABLE') {
    return reject(
      'GRANT_CURRENTNESS_UNRESOLVABLE',
      `currentness record unresolvable: ${current.data.reason}`,
    );
  }
  const cur = current.data;

  if (
    g.issuer.authorityId !== cur.authorityId ||
    g.issuer.authorityRevision !== cur.authorityRevision
  ) {
    return reject(
      'GRANT_AUTHORITY_STALE',
      `issuer ${g.issuer.authorityId}@${g.issuer.authorityRevision} is not the current authority ${cur.authorityId}@${cur.authorityRevision}`,
    );
  }

  if (cur.policyStatus === 'REVOKED')
    return reject('GRANT_POLICY_REVOKED', 'current policy revision is revoked');
  if (cur.policyStatus === 'SUPERSEDED')
    return reject('GRANT_POLICY_STALE', 'current policy revision is superseded');
  if (g.policySnapshotRevision !== cur.policySnapshotRevision) {
    return reject(
      'GRANT_POLICY_STALE',
      `grant policy revision ${g.policySnapshotRevision} != current ${cur.policySnapshotRevision}`,
    );
  }

  if (cur.revokedGrantIds.includes(g.grantId)) {
    return reject('GRANT_REVOKED', `grant ${g.grantId} is on the current revocation list`);
  }

  // Expiry compares parsed instants, never lexicographic string order:
  // equal instants written differently ('08:30:00Z' vs '08:30:00.000Z') are
  // the same moment and count as expired — fail closed (P1-04).
  if (Date.parse(g.expiresAt) <= Date.parse(now.data))
    return reject('GRANT_EXPIRED', `grant expired at ${g.expiresAt}, now ${now.data}`);
  if (Date.parse(g.issuedAt) >= Date.parse(g.expiresAt))
    return reject('GRANT_MALFORMED', 'grant issuedAt is not before expiresAt');

  const plan = ActionPlanSchema.safeParse(input.plan);
  if (!plan.success) return reject('GRANT_MALFORMED', 'presented plan is not a valid ActionPlan');
  const derived = computePlanHash(plan.data);
  if (derived !== plan.data.planHash || derived !== g.planHash) {
    return reject(
      'GRANT_PLAN_MISMATCH',
      `re-derived plan hash ${derived} does not match presented plan (${plan.data.planHash}) and grant (${g.planHash})`,
    );
  }

  const action = AuthorizedActionSchema.safeParse(input.action);
  if (!action.success)
    return reject('GRANT_MALFORMED', 'presented action is not a valid AuthorizedAction');
  const a = action.data;

  if (a.planHash !== g.planHash)
    return reject('GRANT_PLAN_MISMATCH', 'action planHash does not match grant');
  if (a.authorizationRef !== g.grantId) {
    return reject(
      'GRANT_MALFORMED',
      'action authorizationRef does not identify the presented grant',
    );
  }
  if (a.taskId !== g.taskId) {
    return reject(
      'GRANT_SCOPE_MISMATCH',
      `action taskId ${a.taskId} is outside grant task ${g.taskId}`,
    );
  }
  if (a.authorizationKind === 'EXPLICIT_APPROVAL' && !g.approvalRef) {
    return reject(
      'GRANT_APPROVAL_REF_MISSING',
      'explicit-approval grant must reference the durable approval record',
    );
  }

  const scope = g.actionScope;
  if (!scope.actionIds.includes(a.actionId)) {
    return reject('GRANT_SCOPE_MISMATCH', `actionId ${a.actionId} is not covered by grant scope`);
  }
  if (a.action.requiredPrivilege !== scope.privilegeLevel) {
    return reject(
      'GRANT_SCOPE_MISMATCH',
      `action privilege ${a.action.requiredPrivilege} != granted privilege ${scope.privilegeLevel}`,
    );
  }

  const declaredWrite = a.action.filesystemScope?.write ?? [];
  const declaredRead = a.action.filesystemScope?.read ?? [];
  if (!isPrefixCovered(declaredWrite, scope.filesystem?.write)) {
    return reject('GRANT_SCOPE_MISMATCH', 'action declares a filesystem write outside grant scope');
  }
  if (
    !isPrefixCovered(declaredRead, [
      ...(scope.filesystem?.read ?? []),
      ...(scope.filesystem?.write ?? []),
    ])
  ) {
    return reject('GRANT_SCOPE_MISMATCH', 'action declares a filesystem read outside grant scope');
  }

  if (a.action.networkScope?.allowed) {
    if (!scope.network?.allowed) {
      return reject(
        'GRANT_SCOPE_MISMATCH',
        'action requires network access the grant does not cover',
      );
    }
    const domains = scope.network.domains;
    const used = a.action.networkScope.domains ?? [];
    if (domains && !used.every((d) => domains.includes(d))) {
      return reject('GRANT_SCOPE_MISMATCH', 'action uses a network domain outside grant scope');
    }
  }

  const registryWrite = a.action.registryScope?.write ?? [];
  if (!isPrefixCovered(registryWrite, scope.registry?.write)) {
    return reject('GRANT_SCOPE_MISMATCH', 'action declares a registry write outside grant scope');
  }

  // Exact action↔plan binding (P1-01), checked after scope containment so
  // scope violations keep their more specific diagnosis; this identity gate
  // is the final structural authority on what may run. A matching planHash
  // alone is not enough: the presented action surface must be exactly the
  // action the hashed plan committed to.
  if (a.actionId !== a.action.actionId) {
    return reject(
      'GRANT_MALFORMED',
      'action actionId does not match the actionId of its embedded action surface',
    );
  }
  // Resolve by unique identity, never "first match" (R2-02, review
  // 5478548765): ActionPlanSchema already refuses plans with duplicate
  // actionIds, so this explicit ambiguity guard is defense in depth — it
  // fires only if the schema-level uniqueness were ever relaxed, and in that
  // event refuses the presentation instead of executing an arbitrary shadow
  // of the ambiguous identity.
  const planActionMatches = plan.data.actions.filter(
    (candidate) => candidate.actionId === a.actionId,
  );
  const planAction = planActionMatches[0];
  if (!planAction) {
    return reject(
      'GRANT_PLAN_MISMATCH',
      `actionId ${a.actionId} is not present in the hashed plan`,
    );
  }
  if (planActionMatches.length > 1) {
    return reject(
      'GRANT_PLAN_MISMATCH',
      `actionId ${a.actionId} is ambiguous: ${planActionMatches.length} actions of the hashed plan share this identity (L2 §9.4 stable identity)`,
    );
  }
  // Canonical-form deep equality: representation differences (key order) are
  // irrelevant, any content difference voids the presentation.
  if (canonicalJson(planAction) !== canonicalJson(a.action)) {
    return reject(
      'GRANT_PLAN_MISMATCH',
      `presented action ${a.actionId} does not exactly match the action recorded in the hashed plan`,
    );
  }
  if (
    a.policySnapshotRevision !== plan.data.policySnapshotRevision ||
    a.policySnapshotRevision !== g.policySnapshotRevision
  ) {
    return reject(
      'GRANT_PLAN_MISMATCH',
      `action policy revision ${a.policySnapshotRevision} does not match the hashed plan (${plan.data.policySnapshotRevision}) and grant (${g.policySnapshotRevision})`,
    );
  }
  if (a.taskId !== plan.data.taskId) {
    return reject(
      'GRANT_PLAN_MISMATCH',
      `action taskId ${a.taskId} is not the task of the hashed plan (${plan.data.taskId})`,
    );
  }

  // Action-level expiry (P1-04), last so it is only consulted once the
  // presented action is proven to be exactly the hashed plan action; equal
  // instants count as expired, same as the grant-level check.
  if (a.expiresAt && Date.parse(a.expiresAt) <= Date.parse(now.data)) {
    return reject('GRANT_EXPIRED', `action expired at ${a.expiresAt}, now ${now.data}`);
  }

  return { ok: true, grant: verified };
}

/** Convenience wrapper for callers that want a typed throw instead of a result object. */
export function assertGrantPresentation(input: GrantValidationInput): AuthorizationGrant {
  const result = validateGrantPresentation(input);
  if (!result.ok) {
    throw new ShunContractError(result.code, `grant rejected: ${result.code} — ${result.detail}`);
  }
  return result.grant;
}

export type { ActionPlan, AuthorizedAction };
