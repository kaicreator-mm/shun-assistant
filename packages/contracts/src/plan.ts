// ActionPlan / AuthorizedAction contracts (L2 §4.5, §4.6) plus the
// canonicalization and plan-hash identity shared by the planning side and the
// privileged boundary (the privileged executor re-derives the hash
// independently, L2 §8.2.1).
//
// This module is pure contract code: no execution of any kind happens here.
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { AuthorizationKindSchema, RiskClassSchema, Sha256HexSchema } from './taxonomy.ts';

/** Ordered R2 gate phases (Product C-002/C-003): plan → preview → checkpoint → approval → execute → verify. */
export const R2_GATE_PHASES = [
  'PLAN',
  'PREVIEW',
  'CHECKPOINT',
  'APPROVAL',
  'EXECUTE',
  'VERIFY',
] as const;
export type R2GatePhase = (typeof R2_GATE_PHASES)[number];

export const R2GateRecordSchema = z
  .strictObject({
    phases: z.array(z.enum(R2_GATE_PHASES)),
    approvedBy: z.enum(['USER_APPROVAL', 'DURABLE_POLICY']).optional(),
  })
  .superRefine((gate, ctx) => {
    const expected = R2_GATE_PHASES.join('>');
    const actual = gate.phases.join('>');
    if (actual !== expected) {
      ctx.addIssue({
        code: 'custom',
        message: `R2 gate phases must be the complete ordered sequence ${expected}`,
      });
    }
  });
export type R2GateRecord = z.infer<typeof R2GateRecordSchema>;

/** Semantic verification plan; a precommitted oracle is declared before execution (Product C-001). */
export const VerificationPlanSchema = z.strictObject({
  verifierId: z.string().min(1),
  verifierRevision: z.string().min(1),
  checks: z
    .array(
      z.strictObject({ checkId: z.string().min(1), description: z.string().min(1).optional() }),
    )
    .min(1),
  oracle: z
    .strictObject({
      precommitted: z.literal(true),
      spec: z.record(z.string(), z.unknown()),
    })
    .optional(),
});
export type VerificationPlan = z.infer<typeof VerificationPlanSchema>;

/**
 * Recovery contract (L2 §9.4): classifications derive from journal + post-state
 * only; destructive actions reconcile before any retry; retry requires proven
 * non-execution or a declared idempotency/currentness guarantee.
 */
export const RecoveryPlanSchema = z.strictObject({
  classificationStrategy: z.literal('JOURNAL_AND_POST_STATE'),
  reconcileBeforeRetry: z.literal(true),
  retryAllowedWhen: z.enum(['PROVEN_NOT_EXECUTED', 'DECLARED_IDEMPOTENT']),
  checkpointRef: z.string().min(1).optional(),
});
export type RecoveryPlan = z.infer<typeof RecoveryPlanSchema>;

/** Filesystem scope declarations are path prefixes; secrets appear as references, never values. */
export const FilesystemScopeSchema = z.strictObject({
  read: z.array(z.string().min(1)),
  write: z.array(z.string().min(1)),
});
export type FilesystemScope = z.infer<typeof FilesystemScopeSchema>;

export const NetworkScopeSchema = z.strictObject({
  allowed: z.boolean(),
  domains: z.array(z.string().min(1)).optional(),
});
export type NetworkScope = z.infer<typeof NetworkScopeSchema>;

export const PrivilegeLevelSchema = z.enum(['NONE', 'USER', 'ELEVATED']);
export type PrivilegeLevel = z.infer<typeof PrivilegeLevelSchema>;

/** One side-effecting step. Every declared dimension feeds policy, authorization and recovery. */
export const PlanActionSchema = z.strictObject({
  actionId: z.string().min(1),
  /** Reference into ActionPlan.bindingRefs — every action names its binding (L2 §4.5). */
  bindingRef: z.string().min(1),
  op: z.string().min(1),
  /** Typed parameters. Secret references only — durable plans never carry secret values (L2 §4.5). */
  parameters: z.record(z.string(), z.unknown()),
  sideEffectClass: RiskClassSchema,
  requiredPrivilege: PrivilegeLevelSchema,
  filesystemScope: FilesystemScopeSchema.optional(),
  networkScope: NetworkScopeSchema.optional(),
  registryScope: z.strictObject({ write: z.array(z.string().min(1)) }).optional(),
  secretRefs: z.array(z.string().min(1)).optional(),
  timeoutMs: z.number().int().positive().optional(),
  cancellation: z
    .strictObject({
      supported: z.boolean(),
      mode: z.enum(['COOPERATIVE', 'FORCED']),
    })
    .optional(),
  /** Verifiable expected state enabling reconcile-first classification of uncertain interruptions (L2 §9.4). */
  expectedState: z.record(z.string(), z.unknown()).optional(),
});
export type PlanAction = z.infer<typeof PlanActionSchema>;

export const ActionPlanSchema = z
  .strictObject({
    taskId: z.string().min(1),
    capabilityId: z.string().min(1),
    /** Bindings this plan may act through. A P0 plan may hold one binding; the model permits many (L2 §4.5). */
    bindingRefs: z.array(z.string().min(1)).min(1),
    recipeRef: z.string().min(1).optional(),
    rankingPolicyRevision: z.string().min(1),
    policySnapshotRevision: z.string().min(1),
    actions: z.array(PlanActionSchema).min(1),
    verificationPlan: VerificationPlanSchema,
    recoveryPlan: RecoveryPlanSchema,
    planHash: Sha256HexSchema,
  })
  .superRefine((plan, ctx) => {
    const known = new Set(plan.bindingRefs);
    plan.actions.forEach((action, index) => {
      if (!known.has(action.bindingRef)) {
        ctx.addIssue({
          code: 'custom',
          message: `actions[${index}] bindingRef "${action.bindingRef}" is not declared in bindingRefs`,
        });
      }
    });
  });
export type ActionPlan = z.infer<typeof ActionPlanSchema>;

/**
 * Deterministic canonical JSON: object keys sorted lexicographically at every
 * depth, arrays ordered, no whitespace. Representation-stable so two sides of
 * a privilege boundary hashing the same plan agree byte-for-byte (U-06 D2-b).
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'number' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`);
    return `{${entries.join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported value ${String(value)}`);
}

/** SHA-256 of the canonical form, excluding the planHash field itself. */
export function computePlanHash(plan: ActionPlan): string {
  const { planHash: _omit, ...rest } = plan;
  return createHash('sha256').update(canonicalJson(rest), 'utf8').digest('hex');
}

/**
 * The only AuthorizedAction an execution backend may accept (L2 §4.6): produced
 * by the central Action Controller, bound to a grant issued by the
 * AuthorizationAuthority (validated separately in authorization.ts).
 */
export const AuthorizedActionSchema = z.strictObject({
  taskId: z.string().min(1),
  actionId: z.string().min(1),
  planHash: Sha256HexSchema,
  policySnapshotRevision: z.string().min(1),
  authorizationKind: AuthorizationKindSchema,
  authorizationRef: z.string().min(1),
  expiresAt: z.iso.datetime().optional(),
  action: PlanActionSchema,
});
export type AuthorizedAction = z.infer<typeof AuthorizedActionSchema>;
