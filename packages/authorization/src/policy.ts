// Durable policy/authority state for the authorization domain
// (L2 §4.6.1 grant currentness, §9.1 policy/risk classification, §11.2
// identity/currentness).
//
// The concrete revision/revocation substrate (revision records, revocation
// list, trusted local status channel) is an L3 implementation freedom. This
// module freezes:
//   - the durable record shapes (authority record, policy snapshot with
//     automatic-authorization rules and risk guards),
//   - the fail-closed resolution of CURRENT authority/policy state — any
//     missing, unreadable, corrupt or incoherent record resolves to
//     UNRESOLVABLE and never falls back to "last known good",
//   - the bounded durable-policy rule model the Action Controller routes
//     automatic R0-R2 authorization through. R3 is structurally
//     unrepresentable as a durable rule: high-impact effects always require
//     explicit approval (L2 §9.2).
//
// Nothing here performs I/O against a concrete database: the store seam is
// implemented durably by the workflow/store package and as an in-memory
// reference by the test suite.

import {
  type CurrentAuthorityState,
  CurrentAuthorityStateSchema,
  IsoDateTimeSchema,
  type PrivilegeLevel,
  PrivilegeLevelSchema,
  type RiskClass,
  RiskClassSchema,
} from '@shun/contracts';
import { z } from 'zod';

/** Ordered risk ranking (L2 §9.2): R0 read-only … R3 high-impact. */
export const RISK_RANK: Record<RiskClass, number> = { R0: 0, R1: 1, R2: 2, R3: 3 };

/** The higher of two risk classes — used to compute effective classifications. */
export function maxRiskClass(a: RiskClass, b: RiskClass): RiskClass {
  return RISK_RANK[a] >= RISK_RANK[b] ? a : b;
}

/**
 * One durable automatic-authorization rule. "Sufficiently specific" (L2 §9.2
 * R2): the rule pins the capability and the exact op string — wildcards are
 * deliberately unrepresentable — and bounds the highest risk class it may
 * authorize. Scope prefixes, when present, bound what rule-covered actions may
 * declare (validated with the same segment-boundary containment the privilege
 * boundary uses).
 */
export const DurablePolicyRuleSchema = z.strictObject({
  ruleId: z.string().min(1),
  capabilityId: z.string().min(1),
  /** Exact op string; a rule without an exact op is not "sufficiently specific". */
  op: z.string().min(1),
  /** Highest risk class this rule may authorize automatically. R3 excluded by construction. */
  maxRiskClass: z.enum(['R0', 'R1', 'R2']),
  privilegeLevel: PrivilegeLevelSchema,
  filesystem: z
    .strictObject({
      read: z.array(z.string().min(1)),
      write: z.array(z.string().min(1)),
    })
    .optional(),
  network: z
    .strictObject({
      /** A rule can only grant network access; denial is the absence of a rule. */
      allowed: z.literal(true),
      domains: z.array(z.string().min(1)).optional(),
    })
    .optional(),
  registry: z.strictObject({ write: z.array(z.string().min(1)) }).optional(),
});
export type DurablePolicyRule = z.infer<typeof DurablePolicyRuleSchema>;

/**
 * Policy risk guard (L2 §9.1 — policy may RAISE the effective classification
 * of an instantiated action, never lower it). A guard matches by exact op
 * and/or filesystem write prefix; a matching action's effective risk is at
 * least `minRiskClass`.
 */
export const PolicyRiskGuardSchema = z
  .strictObject({
    guardId: z.string().min(1),
    op: z.string().min(1).optional(),
    filesystemWritePrefix: z.string().min(1).optional(),
    minRiskClass: RiskClassSchema,
  })
  .superRefine((guard, ctx) => {
    if (!guard.op && !guard.filesystemWritePrefix) {
      ctx.addIssue({
        code: 'custom',
        message: `risk guard ${guard.guardId} must match by op and/or filesystemWritePrefix`,
      });
    }
  });
export type PolicyRiskGuard = z.infer<typeof PolicyRiskGuardSchema>;

/**
 * The durable authority record (L2 §4.6.1 AuthorizationAuthority). A new
 * revision is a deliberate authority event; grants issued under a previous
 * revision become stale by comparison against the current record.
 */
export const AuthorityRecordSchema = z.strictObject({
  authorityId: z.string().min(1),
  authorityRevision: z.string().min(1),
  updatedAt: IsoDateTimeSchema,
});
export type AuthorityRecord = z.infer<typeof AuthorityRecordSchema>;

/**
 * The durable policy snapshot (L2 §11.1 `policy_snapshot`). `status` is the
 * CURRENT status of this revision: ACTIVE, or SUPERSEDED/REVOKED when the
 * current record itself has been superseded/revoked in place. The snapshot is
 * bound to the authority that owns it — a snapshot paired with a different
 * authority record is incoherent state and fails closed as UNRESOLVABLE.
 */
export const PolicySnapshotRecordSchema = z.strictObject({
  policySnapshotRevision: z.string().min(1),
  status: z.enum(['ACTIVE', 'SUPERSEDED', 'REVOKED']),
  authorityId: z.string().min(1),
  authorityRevision: z.string().min(1),
  /** Grant ids revoked under this policy revision; checked before every effect. */
  revokedGrantIds: z.array(z.string().min(1)),
  rules: z.array(DurablePolicyRuleSchema),
  riskGuards: z.array(PolicyRiskGuardSchema),
  updatedAt: IsoDateTimeSchema,
});
export type PolicySnapshotRecord = z.infer<typeof PolicySnapshotRecordSchema>;

/**
 * Durable state seam behind the authorization authority and the Action
 * Controller (L2 §11.1). Reads return unknown on purpose: every read is
 * schema-validated by `resolveCurrentAuthorityState`, so corrupt or foreign
 * records fail closed instead of being trusted. The workflow/store package
 * provides the durable ShunStore adapter; tests provide an in-memory one.
 */
export interface PolicyStateStore {
  loadAuthorityRecord(): Promise<unknown>;
  loadCurrentPolicy(): Promise<unknown>;
  saveAuthorityRecord(record: AuthorityRecord): Promise<void>;
  savePolicySnapshot(snapshot: PolicySnapshotRecord): Promise<void>;
}

function unresolvable(reason: string) {
  return { kind: 'UNRESOLVABLE', reason } as const;
}

/**
 * Establish the CURRENT authority/policy state exactly as the privileged
 * boundary requires it (L2 §4.6.1): missing, unreadable, corrupt, or
 * incoherent (policy bound to a different authority than the current record)
 * state resolves to UNRESOLVABLE — the boundary never falls back to
 * "authentic therefore current".
 */
export async function resolveCurrentAuthorityState(
  store: PolicyStateStore,
): Promise<CurrentAuthorityState> {
  let authority: unknown;
  let policy: unknown;
  try {
    authority = await store.loadAuthorityRecord();
    policy = await store.loadCurrentPolicy();
  } catch (error) {
    return unresolvable(`currentness read failed: ${(error as Error).message}`);
  }
  const parsedAuthority = AuthorityRecordSchema.safeParse(authority);
  if (!parsedAuthority.success) {
    return unresolvable('authority record missing or corrupt');
  }
  const parsedPolicy = PolicySnapshotRecordSchema.safeParse(policy);
  if (!parsedPolicy.success) {
    return unresolvable('current policy record missing or corrupt');
  }
  const a = parsedAuthority.data;
  const p = parsedPolicy.data;
  if (p.authorityId !== a.authorityId || p.authorityRevision !== a.authorityRevision) {
    return unresolvable(
      `policy ${p.policySnapshotRevision} is bound to authority ${p.authorityId}@${p.authorityRevision} but the current authority record is ${a.authorityId}@${a.authorityRevision}`,
    );
  }
  return CurrentAuthorityStateSchema.parse({
    kind: 'CURRENT',
    authorityId: a.authorityId,
    authorityRevision: a.authorityRevision,
    policySnapshotRevision: p.policySnapshotRevision,
    policyStatus: p.status,
    revokedGrantIds: p.revokedGrantIds,
  });
}

/** True when the action's declared scope is fully covered by the rule's scope prefixes. */
export function ruleCoversScope(
  scope: {
    privilegeLevel: PrivilegeLevel;
    filesystem?: { read: string[]; write: string[] } | undefined;
    network?: { allowed: boolean; domains?: string[] } | undefined;
    registry?: { write: string[] } | undefined;
  },
  rule: DurablePolicyRule,
  pathWithin: (path: string, prefix: string) => boolean,
): boolean {
  if (scope.privilegeLevel !== rule.privilegeLevel) return false;
  const ruleWrite = rule.filesystem?.write;
  const ruleRead = [...(rule.filesystem?.read ?? []), ...(rule.filesystem?.write ?? [])];
  const declaredWrite = scope.filesystem?.write ?? [];
  const declaredRead = scope.filesystem?.read ?? [];
  const covered = (paths: readonly string[], prefixes: readonly string[] | undefined) =>
    paths.length === 0 ||
    (prefixes !== undefined &&
      paths.every((p) => prefixes.some((prefix) => pathWithin(p, prefix))));
  if (!covered(declaredWrite, ruleWrite)) return false;
  if (!covered(declaredRead, ruleRead)) return false;
  if (scope.network?.allowed) {
    if (!rule.network?.allowed) return false;
    const domains = scope.network.domains ?? [];
    const allowed = rule.network.domains;
    if (allowed !== undefined && !domains.every((d) => allowed.includes(d))) return false;
  }
  const registryWrite = scope.registry?.write ?? [];
  if (!covered(registryWrite, rule.registry?.write)) return false;
  return true;
}
