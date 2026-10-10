// ExecutionReceipt / VerificationReceipt (L2 §4.7).
// Execution success without required semantic verification can never become
// Task PASS. Recovery classifications derive ONLY from the privileged phase
// journal plus independent post-state verification — never from transport or
// exit-code optimism (L2 §9.4).
import { z } from 'zod';
import {
  ExecutionTerminalSchema,
  IsoDateTimeSchema,
  RecoveryClassificationSchema,
  RiskClassSchema,
  VerificationStatusSchema,
} from './taxonomy.ts';

export const ExecutionReceiptSchema = z
  .strictObject({
    actionId: z.string().min(1),
    environmentId: z.string().min(1),
    providerId: z.string().min(1),
    /** Exact installed provider version — durable identity input (L2 §11.2). */
    providerVersion: z.string().min(1),
    startedAt: IsoDateTimeSchema,
    finishedAt: IsoDateTimeSchema,
    terminal: ExecutionTerminalSchema,
    exitCode: z.number().int().optional(),
    outputRefs: z.array(z.string().min(1)),
    stdoutRef: z.string().min(1).optional(),
    stderrRef: z.string().min(1).optional(),
    sideEffectEvidence: z.strictObject({
      sideEffectClass: RiskClassSchema,
      recoveryClassification: RecoveryClassificationSchema,
      postStateVerified: z.boolean(),
      journalRef: z.string().min(1).optional(),
    }),
  })
  .superRefine((receipt, ctx) => {
    if (receipt.startedAt > receipt.finishedAt) {
      ctx.addIssue({ code: 'custom', message: 'startedAt must not be after finishedAt' });
    }
  });
export type ExecutionReceipt = z.infer<typeof ExecutionReceiptSchema>;

export const VerificationReceiptSchema = z.strictObject({
  taskId: z.string().min(1),
  verifierId: z.string().min(1),
  verifierRevision: z.string().min(1),
  status: VerificationStatusSchema,
  checks: z
    .array(
      z.strictObject({
        checkId: z.string().min(1),
        status: z.enum(['PASS', 'FAIL', 'NOT_RUN', 'SKIPPED']),
        detail: z.string().min(1).optional(),
      }),
    )
    .min(1),
  /** Committed oracle inputs, proving the oracle was fixed before execution (Product C-001). */
  oracleInputs: z.record(z.string(), z.unknown()),
  evidenceRefs: z.array(z.string().min(1)),
});
export type VerificationReceipt = z.infer<typeof VerificationReceiptSchema>;
