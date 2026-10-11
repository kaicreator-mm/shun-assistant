// ShunAnchorWriter job layer (L2 v0.2 delta §6).
import { createHmac } from 'node:crypto';
import {
  type AuthorizationGrant,
  AuthorizationGrantSchema,
  type CurrentAuthorityState,
  CurrentAuthorityStateSchema,
  canonicalJson,
  PrivilegeLevelSchema,
  RiskClassSchema,
} from '@shun/contracts';
import { z } from 'zod';

const WINDOWS_RESERVED_STEM = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;

/**
 * Anchor filenames must have one canonical spelling on Windows. Reject path
 * separators/traversal, case aliases, trailing-dot/space normalization and
 * reserved device names before any path is constructed.
 */
export function isSafeAnchorId(value: string): boolean {
  if (value.length < 1 || value.length > 128) return false;
  if (value !== value.toLowerCase()) return false;
  if (!/^[a-z0-9][a-z0-9._-]*$/.test(value)) return false;
  if (value.includes('..') || value.endsWith('.') || value.endsWith(' ')) return false;
  const stem = value.split('.')[0] ?? value;
  if (WINDOWS_RESERVED_STEM.test(stem)) return false;
  return true;
}

export const AnchorIdSchema = z
  .string()
  .min(1)
  .max(128)
  .refine(isSafeAnchorId, 'anchor identifier is not canonical/path-safe');

export const PolicyWindowScopeBudgetSchema = z.strictObject({
  /** Maximum side-effect classes whose grants may be minted in this window. */
  riskClasses: z.array(RiskClassSchema).min(1),
  /** Privilege levels the window is allowed to issue. */
  privilegeLevels: z.array(PrivilegeLevelSchema).min(1),
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
  /** Bound grant lifetime even when the policy window itself is longer. */
  maxGrantTtlMs: z.number().int().positive(),
});
export type PolicyWindowScopeBudget = z.infer<typeof PolicyWindowScopeBudgetSchema>;

export const PolicyWindowSchema = z.strictObject({
  windowId: AnchorIdSchema,
  notBefore: z.iso.datetime(),
  notAfter: z.iso.datetime(),
  policySnapshotRevision: z.string().min(1),
  authorityRevision: z.string().min(1),
  /** Issuance budget: max grants this window may mint. */
  maxGrants: z.number().int().positive(),
  scopeBudget: PolicyWindowScopeBudgetSchema,
});
export type PolicyWindow = z.infer<typeof PolicyWindowSchema>;

export const WriterJobIntegritySchema = z.strictObject({
  scheme: z.literal('HMAC_SHA256'),
  value: z.string().min(1),
});

export const AuthorizationGrantProposalSchema = AuthorizationGrantSchema.omit({
  integrity: true,
});
export type AuthorizationGrantProposal = z.infer<typeof AuthorizationGrantProposalSchema>;

export const WriterJobProposalSchema = z.discriminatedUnion('jobType', [
  z.strictObject({
    jobId: AnchorIdSchema,
    jobType: z.literal('issue-grant'),
    policyWindowRef: AnchorIdSchema,
    riskClass: RiskClassSchema,
    payload: AuthorizationGrantProposalSchema,
  }),
  z.strictObject({
    jobId: AnchorIdSchema,
    jobType: z.literal('write-currentness'),
    policyWindowRef: AnchorIdSchema,
    payload: CurrentAuthorityStateSchema,
  }),
]);
export type WriterJobProposal = z.infer<typeof WriterJobProposalSchema>;

export const WriterJobSchema = z
  .strictObject({
    jobId: AnchorIdSchema,
    jobType: z.enum(['issue-grant', 'write-currentness']),
    policyWindowRef: AnchorIdSchema,
    /**
     * Required for issue-grant: AuthorizationGrant itself does not carry the
     * PlanAction sideEffectClass, so the approved writer job commits it and
     * the window can enforce its risk budget before issuance.
     */
    riskClass: RiskClassSchema.optional(),
    /** Frozen contract record: grant or currentness. */
    payload: z.unknown(),
    integrity: WriterJobIntegritySchema,
  })
  .superRefine((job, ctx) => {
    if (job.jobType === 'issue-grant' && job.riskClass === undefined) {
      ctx.addIssue({ code: 'custom', message: 'issue-grant writer job requires riskClass' });
    }
  });
export type WriterJob = z.infer<typeof WriterJobSchema>;
export type WriterJobInput = Omit<WriterJob, 'integrity'>;

function jobHmac(keyBase64: string, job: WriterJobInput): string {
  return createHmac('sha256', Buffer.from(keyBase64, 'base64'))
    .update(canonicalJson(job), 'utf8')
    .digest('base64');
}

/** Authority-side: seal a job under the protected anchor key. */
export function signWriterJob(keyBase64: string, job: WriterJobInput): WriterJob {
  return { ...job, integrity: { scheme: 'HMAC_SHA256', value: jobHmac(keyBase64, job) } };
}

/** Writer-side verification: structure and HMAC both fail closed. */
export function verifyWriterJob(
  keyBase64: string,
  job: unknown,
): { ok: true; job: WriterJob } | { ok: false; reason: string } {
  const parsed = WriterJobSchema.safeParse(job);
  if (!parsed.success) {
    return { ok: false, reason: `job structure rejected: ${parsed.error.message}` };
  }
  const expected = jobHmac(keyBase64, {
    jobId: parsed.data.jobId,
    jobType: parsed.data.jobType,
    policyWindowRef: parsed.data.policyWindowRef,
    ...(parsed.data.riskClass ? { riskClass: parsed.data.riskClass } : {}),
    payload: parsed.data.payload,
  });
  if (expected !== parsed.data.integrity.value) {
    return {
      ok: false,
      reason: `job integrity mismatch (forged or corrupted order): ${parsed.data.jobId}`,
    };
  }
  return { ok: true, job: parsed.data };
}

/** Frozen payload schemas are parsed here, never asserted by type-cast. */
export function jobPayloadAsGrant(job: WriterJob): AuthorizationGrant | undefined {
  if (job.jobType !== 'issue-grant') return undefined;
  const parsed = AuthorizationGrantSchema.safeParse(job.payload);
  return parsed.success ? parsed.data : undefined;
}
export function jobPayloadAsCurrentness(job: WriterJob): CurrentAuthorityState | undefined {
  if (job.jobType !== 'write-currentness') return undefined;
  const parsed = CurrentAuthorityStateSchema.safeParse(job.payload);
  return parsed.success ? parsed.data : undefined;
}
