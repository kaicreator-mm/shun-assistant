// C-001 — image.batch_process (Loop A reference, Product capability contract).
// Side effects: creates new output files only; must never overwrite or delete
// source files in the reference journey. Quality oracle is precommitted before
// execution (SSIM ≥ 0.95 against a lossless reference resize).
import { z } from 'zod';
import { VerificationReceiptSchema } from '../receipts.ts';
import { ImageBatchFailureSchema } from '../taxonomy.ts';

export const ImageBatchProcessInputSchema = z.strictObject({
  taskId: z.string().min(1),
  /** Reference benchmark accepts JPG/PNG; anything else is UNSUPPORTED_INPUT. */
  inputFiles: z
    .array(
      z.strictObject({
        path: z.string().min(1),
        format: z.enum(['JPG', 'PNG']),
      }),
    )
    .min(1),
  operation: z.strictObject({
    kind: z.literal('RESIZE'),
    maxLongEdgePx: z.number().int().positive(),
  }),
  /** Frozen reference journey: capture date is preserved when present. */
  metadataPolicy: z.strictObject({
    preserveCaptureDate: z.literal(true),
  }),
  /** Must differ from the input directory; collisions are detected before write. */
  outputDirectory: z.string().min(1),
  qualityPolicy: z.strictObject({
    oracle: z.literal('NO_OBVIOUS_DEGRADATION_V1'),
    /** Frozen bar for the reference journey. */
    ssimThreshold: z.number().min(0.95).max(1),
  }),
  /** No cloud upload is allowed for the reference journey. */
  networkUsage: z.literal('LOCAL_ONLY'),
});
export type ImageBatchProcessInput = z.infer<typeof ImageBatchProcessInputSchema>;

export const ImageBatchProcessOutputSchema = z
  .strictObject({
    taskId: z.string().min(1),
    /** Exactly one record per input: an output or an explicit rejection. */
    records: z.array(
      z.strictObject({
        inputPath: z.string().min(1),
        status: z.enum(['WRITTEN', 'REJECTED']),
        outputPath: z.string().min(1).optional(),
        rejectionCode: ImageBatchFailureSchema.optional(),
      }),
    ),
    selectedBindingId: z.string().min(1),
    rankingEvidence: z.strictObject({
      rankingPolicyRevision: z.string().min(1),
      reasons: z.array(z.string().min(1)),
    }),
    verification: VerificationReceiptSchema,
  })
  .superRefine((output, ctx) => {
    output.records.forEach((record, index) => {
      if (record.status === 'WRITTEN' && !record.outputPath) {
        ctx.addIssue({ code: 'custom', message: `records[${index}] WRITTEN requires outputPath` });
      }
      if (record.status === 'REJECTED' && !record.rejectionCode) {
        ctx.addIssue({
          code: 'custom',
          message: `records[${index}] REJECTED requires rejectionCode`,
        });
      }
    });
  });
export type ImageBatchProcessOutput = z.infer<typeof ImageBatchProcessOutputSchema>;
