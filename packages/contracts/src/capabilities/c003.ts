// C-003 — system.storage.diagnose_bounded_action (Loop C reference, Product
// capability contract). Observation is R0; cleanup is R2 with the observable
// gate sequence. Deletion by size alone is structurally impossible: an
// AuthorizedAction requires policy classification and exact plan identity.
// Unknown or user-created data is fail-closed.
import { z } from 'zod';
import { R2GateRecordSchema } from '../plan.ts';
import { ExecutionReceiptSchema } from '../receipts.ts';
import { Sha256HexSchema } from '../taxonomy.ts';
import { ResidueClassificationSchema } from './c002.ts';

/** Policy-eligible disposable categories — the only classes a cleanup may ever target. */
const CLEANUP_ELIGIBLE_CATEGORIES = ['CACHE', 'TEMP'] as const;

/** Production input (L2 §4.2): Product semantic fields only. */
export const StorageDiagnoseInputSchema = z.strictObject({
  taskId: z.string().min(1),
  targetVolume: z.string().min(1),
  /** Protected assets declared up front; integrity is verified after any bounded action. */
  protectedAssets: z.array(z.strictObject({ path: z.string().min(1) })).min(1),
  /** Only policy-eligible disposable categories may be removed automatically. */
  cleanupPolicy: z.strictObject({
    eligibleCategories: z.array(z.enum(CLEANUP_ELIGIBLE_CATEGORIES)).min(1),
  }),
});
export type StorageDiagnoseInput = z.infer<typeof StorageDiagnoseInputSchema>;

/**
 * Benchmark-only envelope (L2 §4.2): the synthetic growth injector and the
 * precommitted protected-asset baseline hashes are hidden harness truth and
 * MUST NOT be required production inputs. The benchmark harness supplies them
 * through this envelope; production consumes StorageDiagnoseInputSchema.
 */
export const StorageBenchmarkInputSchema = StorageDiagnoseInputSchema.extend({
  growthFixture: z.strictObject({
    kind: z.enum(['SYNTHETIC', 'REPRODUCIBLE']),
    /** Harness-side reference; never interpreted by the diagnoser. */
    injectorRef: z.string().min(1).optional(),
  }),
  protectedAssets: z
    .array(
      z.strictObject({
        path: z.string().min(1),
        /** Precommitted canary baseline: integrity is verified against it after any bounded action. */
        baselineSha256: Sha256HexSchema,
      }),
    )
    .min(1),
});
export type StorageBenchmarkInput = z.infer<typeof StorageBenchmarkInputSchema>;

/**
 * Semantic invariants the committed JSON Schema artifact cannot express
 * (identity/uniqueness across array elements): each protected asset is
 * verified at most once. Exported so consumers of the artifact — which names
 * this function in its `x-semantic-validation` annotation — run the same
 * check the Zod parser enforces.
 */
export function validateC003OutputSemantics(output: StorageDiagnoseOutput): string[] {
  const issues: string[] = [];
  const seen = new Set<string>();
  for (const asset of output.protectedAssetVerification) {
    if (seen.has(asset.path)) {
      issues.push(`duplicate protected asset verification for ${asset.path}`);
    }
    seen.add(asset.path);
  }
  return issues;
}

/**
 * VerifierPort boundary invariant (L2 §4.7/§13): coverage equality between
 * the protected assets declared in the input and the verifications recorded
 * in the output. Nonemptiness alone is not asset-set proof: every declared
 * asset must be verified (exactly once — the duplicate rule lives in
 * validateC003OutputSemantics), and no verification may name a path the
 * input never declared.
 *
 * This is a contract-level consistency check over declared vs. recorded
 * verifications. It does NOT observe the filesystem and does not prove the
 * assets were actually untouched — interpreting the `unchanged` flags and any
 * hashing is the executor/verifier adapters' responsibility (L2 §8.2.1); no
 * executor-level guarantee may be claimed from this helper. Path identity is
 * exact string equality; adapters needing case-insensitive or normalized
 * matching must canonicalize paths before calling.
 */
export function validateProtectedAssetCoverage(
  input: StorageDiagnoseInput,
  output: StorageDiagnoseOutput,
): string[] {
  const declared = new Set(input.protectedAssets.map((asset) => asset.path));
  const verified = new Set(output.protectedAssetVerification.map((asset) => asset.path));
  const issues: string[] = [];
  for (const path of declared) {
    if (!verified.has(path)) {
      issues.push(`protected asset ${path} declared in the input was not verified in the output`);
    }
  }
  for (const path of verified) {
    if (!declared.has(path)) {
      issues.push(`protected asset verification names ${path}, which the input never declared`);
    }
  }
  return issues;
}

export const StorageDiagnoseOutputSchema = z
  .strictObject({
    taskId: z.string().min(1),
    attribution: z.strictObject({
      growthSourcePath: z.string().min(1),
      classifiedAs: ResidueClassificationSchema,
      evidenceRefs: z.array(z.string().min(1)).min(1),
    }),
    /** null when attribution failed or nothing was policy-eligible. */
    cleanupPlan: z
      .strictObject({
        bounded: z.literal(true),
        targets: z.array(
          z.strictObject({
            path: z.string().min(1),
            /** Only policy-eligible disposable data; user-created/unknown/protected is fail-closed. */
            classification: z.enum(CLEANUP_ELIGIBLE_CATEGORIES),
            expectedReclaimBytes: z.number().int().nonnegative(),
          }),
        ),
        r2Gate: R2GateRecordSchema,
      })
      .nullable(),
    /** Present only after the bounded action executed. */
    executionEvidence: ExecutionReceiptSchema.optional(),
    reclaimed: z
      .strictObject({
        /** Gross reclaimed bytes attributable to the bounded action. */
        grossBytes: z.number().int().nonnegative(),
        /** Current post-action state — records regrowth honestly instead of claiming permanent recovery. */
        postActionStateBytes: z.number().int().nonnegative(),
      })
      .optional(),
    protectedAssetVerification: z.array(
      z.strictObject({
        path: z.string().min(1),
        unchanged: z.boolean(),
      }),
    ),
  })
  .superRefine((output, ctx) => {
    // executionEvidence is present only after the bounded action executed
    // (field contract): a record carrying the receipt cannot claim "nothing
    // was policy-eligible" (cleanupPlan null) to dodge the executed-cleanup
    // invariants below (R3-01, review 5478735287).
    if (output.executionEvidence && output.cleanupPlan === null) {
      ctx.addIssue({
        code: 'custom',
        message: 'executionEvidence records an executed bounded action; cleanupPlan cannot be null',
      });
    }
    if (output.cleanupPlan && !output.executionEvidence) {
      ctx.addIssue({
        code: 'custom',
        message: 'an executed cleanup plan requires executionEvidence',
      });
    }
    if (output.cleanupPlan && output.reclaimed === undefined) {
      ctx.addIssue({
        code: 'custom',
        message: 'an executed cleanup plan requires reclaimed measurement',
      });
    }
    // Frozen C-003: protected assets are verified after any bounded action.
    // An executed cleanup that verifies nothing must not pass (R2-03, review
    // 5478548765); full input→output coverage equality is additionally
    // available via validateProtectedAssetCoverage at the VerifierPort
    // boundary.
    if (output.cleanupPlan && output.protectedAssetVerification.length === 0) {
      ctx.addIssue({
        code: 'custom',
        message: 'an executed cleanup requires at least one protected-asset verification',
      });
    }
    for (const message of validateC003OutputSemantics(output)) {
      ctx.addIssue({ code: 'custom', message });
    }
  });
export type StorageDiagnoseOutput = z.infer<typeof StorageDiagnoseOutputSchema>;
