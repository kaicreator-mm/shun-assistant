// The AuthorizedAction envelope crossing the privilege boundary (L2 §8.2.1).
//
// Typed JSON on disk — never command text; no LLM prompt, no arbitrary
// provider object. The envelope carries the three untrusted presentation
// surfaces (action, grant, plan) plus the untrusted I/O channel paths. The
// helper re-validates all of it independently inside the privileged boundary;
// nothing here is trusted on the launcher's say-so. Trusted inputs (authority
// store, currentness, HMAC key) are resolved by the helper from its
// build-time constant and deliberately absent from this schema.
import { readFileSync, writeFileSync } from 'node:fs';
import type { AuthorizationGrantPresentationInput } from '@shun/contracts';
import {
  type ActionPlan,
  ActionPlanSchema,
  AuthorizationGrantPresentationSchema,
  type AuthorizedAction,
  AuthorizedActionSchema,
} from '@shun/contracts';
import { z } from 'zod';

export const ENVELOPE_SCHEMA_VERSION = 'shun.executor-windows.envelope/1';

/** Exit codes of the one-shot helper (stable launcher↔helper contract). */
export const HELPER_EXIT_CODES = {
  OK: 0,
  REFUSED: 2,
  FAILED: 3,
  TIMED_OUT: 4,
  CANCELLED: 5,
  RECEIPT_LOST: 6,
} as const;

export const EnvelopeSchema = z.strictObject({
  schemaVersion: z.literal(ENVELOPE_SCHEMA_VERSION),
  action: AuthorizedActionSchema,
  grant: AuthorizationGrantPresentationSchema,
  plan: ActionPlanSchema,
  io: z.strictObject({
    journalFile: z.string().min(1),
    receiptFile: z.string().min(1),
    /** Cancel sentinel polled between phases; absent = cancellation unsupported. */
    cancelFile: z.string().min(1).optional(),
    /** Directory for captured proc.exec stdio artifacts. */
    evidenceDir: z.string().min(1),
  }),
});
export type Envelope = z.infer<typeof EnvelopeSchema>;

export interface EnvelopeInput {
  action: AuthorizedAction;
  grant: AuthorizationGrantPresentationInput;
  plan: ActionPlan;
  io: Envelope['io'];
}

export function writeEnvelopeFile(file: string, envelope: EnvelopeInput): void {
  const parsed = EnvelopeSchema.parse({ schemaVersion: ENVELOPE_SCHEMA_VERSION, ...envelope });
  // UTF-8 without BOM; the helper parses with the same strict schema.
  writeFileSync(file, `${JSON.stringify(parsed, null, 2)}\n`, 'utf8');
}

/** Strict parse of an envelope file; BOM-tolerant, any deviation throws. */
export function readEnvelopeFile(file: string): Envelope {
  const raw = readFileSync(file, 'utf8');
  return EnvelopeSchema.parse(JSON.parse(raw.replace(/^\uFEFF/, '')));
}

/** The strict contracts receipt, plus launcher diagnostics kept OFF the frozen schema. */
export const HelperReceiptFileSchema = z.strictObject({
  schemaVersion: z.literal(ENVELOPE_SCHEMA_VERSION),
  actionId: z.string().min(1),
  environmentId: z.string().min(1),
  providerId: z.string().min(1),
  providerVersion: z.string().min(1),
  startedAt: z.string().min(1),
  finishedAt: z.string().min(1),
  terminal: z.enum(['SUCCEEDED', 'FAILED', 'REFUSED', 'CANCELLED', 'TIMED_OUT']),
  exitCode: z.number().int(),
  outputRefs: z.array(z.string().min(1)),
  stdoutRef: z.string().min(1).optional(),
  stderrRef: z.string().min(1).optional(),
  sideEffectEvidence: z.strictObject({
    sideEffectClass: z.enum(['R0', 'R1', 'R2', 'R3']),
    recoveryClassification: z.enum([
      'NOT_STARTED',
      'FAILED_BEFORE_EFFECT',
      'MAY_HAVE_EXECUTED_UNCERTAIN',
      'COMPLETED_VERIFIED',
    ]),
    postStateVerified: z.boolean(),
    journalRef: z.string().min(1).optional(),
  }),
  // Helper-local diagnostic extension — stripped before the contracts
  // ExecutionReceipt is returned to callers.
  detail: z
    .strictObject({
      reason: z.string().min(1),
      rejectionCode: z.string().min(1).optional(),
      isElevated: z.boolean(),
      planHash: z.string().min(1).optional(),
    })
    .optional(),
});
export type HelperReceiptFile = z.infer<typeof HelperReceiptFileSchema>;
