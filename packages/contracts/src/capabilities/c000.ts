// C-000 — Shared Goal / Resolution Contract (docs/product/capability-contracts-v0.1.md).
//
// Resolution itself is read-only; Provider acquisition, configuration or
// execution is a separate step carrying its own risk gate. Failure codes are
// the frozen shared resolution taxonomy.
import { z } from 'zod';
import { ConstraintsSchema } from '../goal.ts';
import { VerificationPlanSchema } from '../plan.ts';
import { InterfaceClassSchema, ResolutionFailureSchema, RiskClassSchema } from '../taxonomy.ts';

/** Hard gates execute before ranking, in this order (L2 §7.2). */
export const HARD_GATES = [
  'CAPABILITY_FIT',
  'TRUST_SUPPLY_CHAIN',
  'PROVIDER_ENVIRONMENT_FEASIBILITY',
  'USER_ORG_POLICY',
  'SAFETY_CONSTRAINTS',
] as const;
export type HardGate = (typeof HARD_GATES)[number];
export const HardGateSchema = z.enum(HARD_GATES);

export const HardGateDispositionSchema = z.strictObject({
  gate: HardGateSchema,
  bindingId: z.string().min(1),
  outcome: z.enum(['PASS', 'REJECT', 'ESCALATION_REQUIRED']),
  reason: z.string().min(1),
});
export type HardGateDisposition = z.infer<typeof HardGateDispositionSchema>;

/** One candidate Provider × Environment pairing surfaced by resolution. */
export const BindingCandidateSchema = z.strictObject({
  bindingId: z.string().min(1),
  providerId: z.string().min(1),
  environmentId: z.string().min(1),
  interfaceClass: InterfaceClassSchema,
});
export type BindingCandidate = z.infer<typeof BindingCandidateSchema>;

/** Resolution planning layer (L2 §6.4): deterministic fast path, deterministic known-capability path, or planner-interpreted. */
export const ExecutionPlanClassSchema = z.enum([
  'RECIPE_FAST_PATH',
  'KNOWN_CAPABILITY_DETERMINISTIC',
  'PLANNER_INTERPRETED',
]);
export type ExecutionPlanClass = z.infer<typeof ExecutionPlanClassSchema>;

/**
 * Semantic invariant the committed JSON Schema artifact cannot express (array
 * membership across two properties): a selected binding must be among the
 * feasible bindings. Exported so consumers of the artifact — which names this
 * function in its `x-semantic-validation` annotation — run the same check the
 * Zod parser enforces.
 */
export function validateResolutionRecordSemantics(record: ResolutionRecord): string[] {
  const issues: string[] = [];
  if (
    record.selectedBindingId !== null &&
    !record.feasibleBindings.includes(record.selectedBindingId)
  ) {
    issues.push('selectedBindingId must be among feasibleBindings');
  }
  return issues;
}

/**
 * C-000 structured resolution record: candidate providers, feasible bindings,
 * per-binding hard-gate dispositions, selected binding with reasons, risk
 * class, verification plan and privacy/disclosure plan — or an explicit
 * failure/fallback disposition when no binding is feasible.
 */
export const ResolutionRecordSchema = z
  .strictObject({
    taskId: z.string().min(1),
    resolvedCapabilityId: z.string().min(1),
    capabilityRevision: z.string().min(1),
    normalizedConstraints: ConstraintsSchema,
    candidates: z.array(BindingCandidateSchema),
    /** bindingIds that passed all hard gates. */
    feasibleBindings: z.array(z.string().min(1)),
    hardGateDispositions: z.array(HardGateDispositionSchema),
    /** null exactly when no binding is feasible and failureDisposition is set. */
    selectedBindingId: z.string().min(1).nullable(),
    selectionReasons: z.array(z.string().min(1)),
    riskClass: RiskClassSchema,
    executionPlanClass: ExecutionPlanClassSchema,
    verificationPlan: VerificationPlanSchema,
    privacyDisclosurePlan: z.strictObject({
      externalDisclosure: z.enum(['ALLOWED', 'FORBIDDEN', 'POLICY_CONTROLLED']),
      notes: z.array(z.string().min(1)),
    }),
    /** Explicit typed failure/fallback disposition; null exactly when a binding was selected. */
    failureDisposition: z
      .strictObject({
        failureCode: ResolutionFailureSchema,
        detail: z.string().min(1),
      })
      .nullable(),
  })
  .superRefine((record, ctx) => {
    const selected = record.selectedBindingId !== null;
    const failed = record.failureDisposition !== null;
    if (selected === failed) {
      ctx.addIssue({
        code: 'custom',
        message: 'exactly one of selectedBindingId / failureDisposition must be set',
      });
    }
    for (const message of validateResolutionRecordSemantics(record)) {
      ctx.addIssue({ code: 'custom', message });
    }
  });
export type ResolutionRecord = z.infer<typeof ResolutionRecordSchema>;
