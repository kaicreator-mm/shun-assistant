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

/** Growth fixtures are known to the benchmark harness and hidden from the resolver/diagnoser (Product C-003 precondition). */
export const StorageDiagnoseInputSchema = z.strictObject({
  taskId: z.string().min(1),
  targetVolume: z.string().min(1),
  growthFixture: z.strictObject({
    kind: z.enum(['SYNTHETIC', 'REPRODUCIBLE']),
    /** Harness-side reference; never interpreted by the diagnoser. */
    injectorRef: z.string().min(1).optional(),
  }),
  /** Protected baseline: integrity is verified after any bounded action. */
  protectedAssets: z
    .array(
      z.strictObject({
        path: z.string().min(1),
        baselineSha256: Sha256HexSchema,
      }),
    )
    .min(1),
  /** Only policy-eligible disposable categories may be removed automatically. */
  cleanupPolicy: z.strictObject({
    eligibleCategories: z.array(z.enum(['CACHE', 'TEMP'])).min(1),
  }),
});
export type StorageDiagnoseInput = z.infer<typeof StorageDiagnoseInputSchema>;

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
            classification: ResidueClassificationSchema,
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
    const protectedPaths = new Set<string>();
    for (const asset of output.protectedAssetVerification) {
      if (protectedPaths.has(asset.path)) {
        ctx.addIssue({
          code: 'custom',
          message: `duplicate protected asset verification for ${asset.path}`,
        });
      }
      protectedPaths.add(asset.path);
    }
  });
export type StorageDiagnoseOutput = z.infer<typeof StorageDiagnoseOutputSchema>;
