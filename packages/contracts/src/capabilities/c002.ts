// C-002 — software.jit_capability_lifecycle (Loop B reference, Product
// capability contract). Any uninstall/removal or residue deletion is R2 and
// must pass the observable gate plan → preview → checkpoint → approval →
// execute → verify. User confirmation alone cannot override failed/unknown
// provenance, and user-created/unknown/protected data is never automatically
// deleted.
import { z } from 'zod';
import { R2GateRecordSchema } from '../plan.ts';
import { VerificationReceiptSchema } from '../receipts.ts';

export const RESIDUE_CLASSIFICATIONS = [
  'PROGRAM_OWNED',
  'CACHE',
  'CONFIGURATION',
  'USER_CREATED_UNKNOWN',
  'PROTECTED',
] as const;
export type ResidueClassification = (typeof RESIDUE_CLASSIFICATIONS)[number];
export const ResidueClassificationSchema = z.enum(RESIDUE_CLASSIFICATIONS);

export const JitLifecycleInputSchema = z.strictObject({
  taskId: z.string().min(1),
  capabilityRequirement: z.strictObject({
    capabilityId: z.string().min(1),
    revision: z.string().min(1).optional(),
  }),
  providerConstraints: z.strictObject({
    /** Frozen: trusted provenance is mandatory for JIT acquisition. */
    trustedProvenanceRequired: z.literal(true),
    supportedPlatform: z.literal('WINDOWS'),
    licensing: z.string().min(1).optional(),
  }),
  /** Declared BEFORE acquisition/use (Product C-002 precondition). */
  lifecyclePolicy: z.strictObject({
    retention: z.enum(['RETAIN', 'JIT_REMOVE_AFTER_VERIFIED_USE']),
  }),
  targetTask: z.strictObject({
    fixtureRef: z.string().min(1).optional(),
    parameters: z.record(z.string(), z.unknown()).optional(),
  }),
  /** User assets placed where residue classification could discover them. */
  preExistingUserAssets: z.array(z.strictObject({ path: z.string().min(1) })),
});
export type JitLifecycleInput = z.infer<typeof JitLifecycleInputSchema>;

export const JitLifecycleOutputSchema = z
  .strictObject({
    taskId: z.string().min(1),
    selectedBindingId: z.string().min(1),
    provenance: z.strictObject({
      source: z.string().min(1),
      official: z.boolean(),
      version: z.string().min(1),
      hash: z.string().min(1).optional(),
      signature: z.string().min(1).optional(),
      licenseDisposition: z.string().min(1),
    }),
    taskResult: z.strictObject({
      status: z.enum(['SUCCEEDED', 'FAILED']),
      verification: VerificationReceiptSchema,
    }),
    lifecycleState: z.strictObject({
      providerId: z.string().min(1),
      version: z.string().min(1),
      state: z.enum(['INSTALLED', 'RETAINED', 'REMOVED', 'REMOVE_FAILED']),
    }),
    residueReport: z.strictObject({
      candidates: z.array(
        z.strictObject({
          path: z.string().min(1),
          classification: ResidueClassificationSchema,
          disposition: z.enum(['DELETE', 'RETAIN']),
        }),
      ),
      /** Frozen fail-closed invariant: unknown/user-created/protected data is never auto-deleted. */
      unknownOrProtectedDeleted: z.literal(false),
    }),
    /** Required when lifecycle policy was JIT_REMOVE_AFTER_VERIFIED_USE and removal was gated. */
    r2Gate: R2GateRecordSchema.optional(),
    finalState: z.enum(['RETAINED', 'REMOVED']),
  })
  .superRefine((output, ctx) => {
    if (output.finalState === 'REMOVED' && !output.r2Gate) {
      ctx.addIssue({
        code: 'custom',
        message: 'REMOVED finalState requires the completed R2 gate record',
      });
    }
  });
export type JitLifecycleOutput = z.infer<typeof JitLifecycleOutputSchema>;
