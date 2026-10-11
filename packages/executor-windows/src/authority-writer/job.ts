// ShunAnchorWriter job layer (L2 v0.2 delta §6) — the issuance-order shape
// between an approved policy window and the one-shot privileged writer.
//
// A policy window is an ISSUANCE LICENSE, not a grant: nothing executes on a
// window alone. A writer job is one issuance order whose payload is a FROZEN
// contract record (AuthorizationGrant / CurrentAuthorityState — L2 v0.1
// §4.6.1 shapes, byte-compatible with the trusted-store module). Jobs are
// integrity-protected with the anchor key, which under the v0.2 deployment is
// never readable by the runtime user — the writer (elevated) is the signer.
import { createHmac } from 'node:crypto';
import {
  type AuthorizationGrant,
  type CurrentAuthorityState,
  canonicalJson,
} from '@shun/contracts';
import { z } from 'zod';

export const PolicyWindowSchema = z.strictObject({
  windowId: z.string().min(1),
  notBefore: z.string().min(1), // ISO 8601
  notAfter: z.string().min(1), // ISO 8601
  policySnapshotRevision: z.string().min(1),
  authorityRevision: z.string().min(1),
  /** Issuance budget: max grants this window may mint (integrity, not DoS, bound). */
  maxGrants: z.number().int().positive(),
});
export type PolicyWindow = z.infer<typeof PolicyWindowSchema>;

export const WriterJobIntegritySchema = z.strictObject({
  scheme: z.literal('HMAC_SHA256'),
  value: z.string().min(1),
});

export const WriterJobSchema = z.strictObject({
  jobId: z.string().min(1),
  jobType: z.enum(['issue-grant', 'write-currentness']),
  policyWindowRef: z.string().min(1),
  /** Frozen contract record: grant (issue-grant) or currentness (write-currentness). */
  payload: z.unknown(),
  integrity: WriterJobIntegritySchema,
});
export type WriterJob = z.infer<typeof WriterJobSchema>;
export type WriterJobInput = Omit<WriterJob, 'integrity'>;

export class WriterJobIntegrityError extends Error {}

function jobHmac(keyBase64: string, job: WriterJobInput): string {
  return createHmac('sha256', Buffer.from(keyBase64, 'base64'))
    .update(canonicalJson(job), 'utf8')
    .digest('base64');
}

/** Authority-side (writer): seal a job under the anchor key. */
export function signWriterJob(keyBase64: string, job: WriterJobInput): WriterJob {
  return { ...job, integrity: { scheme: 'HMAC_SHA256', value: jobHmac(keyBase64, job) } };
}

/**
 * Writer-side verification: fail closed on ANY structural or integrity
 * problem — an unverifiable job is an unauthentic order, never "apply anyway".
 */
export function verifyWriterJob(
  keyBase64: string,
  job: unknown,
): { ok: true; job: WriterJob } | { ok: false; reason: string } {
  const parsed = WriterJobSchema.safeParse(job);
  if (!parsed.success)
    return { ok: false, reason: `job structure rejected: ${parsed.error.message}` };
  const expected = jobHmac(keyBase64, {
    jobId: parsed.data.jobId,
    jobType: parsed.data.jobType,
    policyWindowRef: parsed.data.policyWindowRef,
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

/** Typed payload accessor — a job of the wrong type for its payload is refused. */
export function jobPayloadAsGrant(job: WriterJob): AuthorizationGrant | undefined {
  return job.jobType === 'issue-grant' ? (job.payload as AuthorizationGrant) : undefined;
}
export function jobPayloadAsCurrentness(job: WriterJob): CurrentAuthorityState | undefined {
  return job.jobType === 'write-currentness' ? (job.payload as CurrentAuthorityState) : undefined;
}
