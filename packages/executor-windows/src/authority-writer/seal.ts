// Elevated-only production sealing for one-shot ShunAnchorWriter proposals.
// The runtime submits an UNSIGNED bounded proposal. Only the pinned elevated
// writer, after UAC, can read the protected HMAC key and mint both the inner
// AuthorizationGrant envelope and the outer exact WriterJob envelope.
import type { AuthorizationGrant } from '@shun/contracts';
import { signGrantWithHmac } from '../trusted-store.ts';
import {
  signWriterJob,
  type WriterJob,
  type WriterJobInput,
  WriterJobProposalSchema,
} from './job.ts';

export type SealWriterJobResult =
  | { ok: true; job: WriterJob }
  | { ok: false; reason: string };

export function sealWriterJobProposal(
  keyBase64: string,
  proposal: unknown,
): SealWriterJobResult {
  const parsed = WriterJobProposalSchema.safeParse(proposal);
  if (!parsed.success) {
    return { ok: false, reason: `writer proposal rejected: ${parsed.error.message}` };
  }

  let input: WriterJobInput;
  if (parsed.data.jobType === 'issue-grant') {
    // Construct the frozen grant from a schema-normalized PRIVATE proposal.
    // The placeholder is never persisted or exposed; signGrantWithHmac omits
    // integrity from its canonical payload before computing the HMAC.
    const grantForSigning: AuthorizationGrant = {
      ...parsed.data.payload,
      integrity: { scheme: 'HMAC_SHA256', value: 'pending-elevated-seal' },
    };
    const grant: AuthorizationGrant = {
      ...parsed.data.payload,
      integrity: signGrantWithHmac(keyBase64, grantForSigning),
    };
    input = {
      jobId: parsed.data.jobId,
      jobType: 'issue-grant',
      policyWindowRef: parsed.data.policyWindowRef,
      riskClass: parsed.data.riskClass,
      payload: grant,
    };
  } else {
    input = {
      jobId: parsed.data.jobId,
      jobType: 'write-currentness',
      policyWindowRef: parsed.data.policyWindowRef,
      payload: parsed.data.payload,
    };
  }

  return { ok: true, job: signWriterJob(keyBase64, input) };
}
