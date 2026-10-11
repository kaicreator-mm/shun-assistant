// R6 production provenance: the runtime proposes; only the elevated writer seals.
// These controls prove the protected key never needs to cross into the runtime
// and a caller-supplied already-signed artifact is NOT accepted as a proposal.
import { describe, expect, it } from 'vitest';
import {
  jobPayloadAsGrant,
  verifyWriterJob,
  WriterJobProposalSchema,
} from '../src/authority-writer/job.ts';
import { sealWriterJobProposal } from '../src/authority-writer/seal.ts';
import { generateGrantHmacKey, verifyGrantWithHmac } from '../src/trusted-store.ts';

describe('C06 R6 protected WriterJob production sealing', () => {
  it('elevated sealer binds both inner grant and outer job to the exact proposal', () => {
    const key = generateGrantHmacKey();
    const proposal = {
      jobId: 'job-production-seal-1',
      jobType: 'issue-grant' as const,
      policyWindowRef: 'win-1',
      riskClass: 'R2' as const,
      payload: {
        grantId: 'grant-production-seal-1',
        issuer: {
          authorityId: 'shun.action-controller.test',
          authorityRevision: 'auth-rev-1',
        },
        taskId: 'task-1',
        planHash: 'a'.repeat(64),
        policySnapshotRevision: 'policy-rev-1',
        actionScope: {
          actionIds: ['act-1'],
          privilegeLevel: 'ELEVATED' as const,
        },
        issuedAt: '2026-10-11T00:00:00.000Z',
        expiresAt: '2026-10-12T00:00:00.000Z',
      },
    };

    expect(WriterJobProposalSchema.safeParse(proposal).success).toBe(true);
    const sealed = sealWriterJobProposal(key, proposal);
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;

    const outer = verifyWriterJob(key, sealed.job);
    expect(outer.ok).toBe(true);
    const grant = jobPayloadAsGrant(sealed.job);
    expect(grant).toBeDefined();
    expect(grant && verifyGrantWithHmac(key, grant)).toBe(true);
    expect(grant?.grantId).toBe(proposal.payload.grantId);

    // Production launcher accepts proposals only. An attacker cannot bypass
    // the elevated sealing boundary by supplying a self-signed job envelope.
    expect(WriterJobProposalSchema.safeParse(sealed.job).success).toBe(false);
  });

  it('proposal schema rejects caller-provided inner grant integrity', () => {
    const raw = {
      jobId: 'job-production-seal-2',
      jobType: 'issue-grant',
      policyWindowRef: 'win-1',
      riskClass: 'R2',
      payload: {
        grantId: 'grant-production-seal-2',
        issuer: {
          authorityId: 'shun.action-controller.test',
          authorityRevision: 'auth-rev-1',
        },
        taskId: 'task-1',
        planHash: 'b'.repeat(64),
        policySnapshotRevision: 'policy-rev-1',
        actionScope: { actionIds: ['act-2'], privilegeLevel: 'ELEVATED' },
        issuedAt: '2026-10-11T00:00:00.000Z',
        expiresAt: '2026-10-12T00:00:00.000Z',
        integrity: { scheme: 'HMAC_SHA256', value: 'caller-forged' },
      },
    };
    expect(WriterJobProposalSchema.safeParse(raw).success).toBe(false);
  });
});
