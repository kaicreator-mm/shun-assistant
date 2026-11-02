import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createMetaFeedbackAdapter } from '../../../../packages/domain-computer/src/feedback/meta-feedback.ts';
import { HostMetaShadowStore } from '../../../../packages/domain-host/src/meta/host-meta-shadow-store.ts';

const sha256 = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

const EXPERIENCE = {
  capabilityId: 'system.storage.diagnose_bounded_action',
  taskClass: 'filesystem.repair',
  patternId: 'bounded-folder-repair',
  outcome: 'COMPLETED_VERIFIED' as const,
  tags: ['folder-selection', 'manifest-preview'],
  constraints: ['selected-root-only', 'poststate-verified'],
};

function consent(input: {
  caseRef: string;
  revision: string;
  digest: string;
  consentRef?: string;
  optIn?: boolean;
}) {
  return {
    consentRef: input.consentRef ?? `consent-${input.caseRef}-${input.revision}`,
    revision: 'consent-rev-1',
    caseRef: input.caseRef,
    sourceRevision: input.revision,
    sourceDigest: input.digest,
    operatorId: 'operator-owner',
    operatorSubjectRef: 'subject-owner',
    authorizationRevision: 'authorization-rev-1',
    currentnessRef: `currentness-${input.caseRef}-${input.revision}`,
    optIn: input.optIn ?? true,
    expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
  };
}

describe('R03C shared Meta experience in the existing Host SQLite store', () => {
  it('Case B retrieves eligible verified experience and feedback from Case A; restart preserves it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r03c-meta-cross-case-'));
    const file = join(dir, 'meta.sqlite');
    const digest = sha256('case-a-verified-outcome-r1');
    const first = new HostMetaShadowStore(file);
    const second = new HostMetaShadowStore(file);
    try {
      first.recordOutcomeReceipt({
        caseRef: 'case-a',
        revision: 'outcome-r1',
        sha256: digest,
        experience: EXPERIENCE,
      });
      first.recordOptInConsent(consent({ caseRef: 'case-a', revision: 'outcome-r1', digest }));

      const adapterA = createMetaFeedbackAdapter(first);
      const adapterB = createMetaFeedbackAdapter(second);
      const selection = {
        selected: true,
        caseRef: 'case-a',
        sourceRevision: 'outcome-r1',
        rating: 'HELPFUL',
        category: 'OTHER',
        correction: 'NO_CORRECTION',
      };
      const [a, b] = await Promise.all([adapterA.submit(selection), adapterB.submit(selection)]);
      expect(a.status).toBe('STORED_SHADOW');
      expect(b.status).toBe('STORED_SHADOW');
      expect(first.listShadowCandidates()).toHaveLength(2);
      expect(first.listShadowCandidates().every((candidate) =>
        candidate.lifecycle === 'FUTURE_BUILD_SHADOW' && candidate.active === false,
      )).toBe(true);

      const crossCase = first.querySharedExperiences({
        targetCaseRef: 'case-b',
        capabilityId: EXPERIENCE.capabilityId,
        taskClass: EXPERIENCE.taskClass,
        tags: ['folder-selection'],
        limit: 5,
      });
      expect(crossCase).toHaveLength(1);
      expect(crossCase[0]).toMatchObject({
        sourceCaseRef: 'case-a',
        sourceRevision: 'outcome-r1',
        sourceDigest: digest,
        experience: EXPERIENCE,
        feedback: { rating: 'HELPFUL', category: 'OTHER', correction: 'NO_CORRECTION' },
        crossCase: true,
        advisoryOnly: true,
      });
      expect(crossCase[0]).not.toHaveProperty('permit');
      expect(crossCase[0]).not.toHaveProperty('grant');
      expect(crossCase[0]).not.toHaveProperty('action');

      const sameCase = first.querySharedExperiences({
        targetCaseRef: 'case-a',
        capabilityId: EXPERIENCE.capabilityId,
        taskClass: EXPERIENCE.taskClass,
      });
      expect(sameCase).toHaveLength(1);
      expect(sameCase[0]?.crossCase).toBe(false);

      first.close();
      second.close();
      const reopened = new HostMetaShadowStore(file);
      try {
        expect(reopened.querySharedExperiences({
          targetCaseRef: 'case-b',
          capabilityId: EXPERIENCE.capabilityId,
          taskClass: EXPERIENCE.taskClass,
        })).toEqual(crossCase);
      } finally {
        reopened.close();
      }
    } finally {
      try { first.close(); } catch { /* already closed for restart check */ }
      try { second.close(); } catch { /* already closed for restart check */ }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('excludes stale source revisions and explicitly revoked experiences', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r03c-meta-currentness-'));
    const store = new HostMetaShadowStore(join(dir, 'meta.sqlite'));
    try {
      const digest1 = sha256('case-a-r1');
      store.recordOutcomeReceipt({
        caseRef: 'case-a',
        revision: 'outcome-r1',
        sha256: digest1,
        experience: EXPERIENCE,
      });
      store.recordOptInConsent(consent({ caseRef: 'case-a', revision: 'outcome-r1', digest: digest1 }));
      const query = {
        targetCaseRef: 'case-b',
        capabilityId: EXPERIENCE.capabilityId,
        taskClass: EXPERIENCE.taskClass,
      };
      expect(store.querySharedExperiences(query)).toHaveLength(1);

      expect(store.revokeSharedExperience({
        caseRef: 'case-a',
        revision: 'outcome-r1',
        sourceDigest: digest1,
      })).toBe(true);
      expect(store.querySharedExperiences(query)).toHaveLength(0);

      const digest2 = sha256('case-a-r2');
      store.recordOutcomeReceipt({
        caseRef: 'case-a',
        revision: 'outcome-r2',
        sha256: digest2,
        experience: EXPERIENCE,
      });
      store.recordOptInConsent(consent({ caseRef: 'case-a', revision: 'outcome-r2', digest: digest2 }));
      expect(store.querySharedExperiences(query)).toHaveLength(1);

      store.recordOutcomeReceipt({
        caseRef: 'case-a',
        revision: 'outcome-r3',
        sha256: sha256('case-a-r3'),
      });
      expect(store.querySharedExperiences(query)).toHaveLength(0);
    } finally {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('revoking current opt-in prevents both cross-Case retrieval and new feedback writes', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r03c-meta-consent-revoke-'));
    const store = new HostMetaShadowStore(join(dir, 'meta.sqlite'));
    try {
      const digest = sha256('case-a-consent');
      store.recordOutcomeReceipt({
        caseRef: 'case-a',
        revision: 'outcome-r1',
        sha256: digest,
        experience: EXPERIENCE,
      });
      store.recordOptInConsent(consent({ caseRef: 'case-a', revision: 'outcome-r1', digest }));
      store.recordOptInConsent(consent({
        caseRef: 'case-a',
        revision: 'outcome-r1',
        digest,
        consentRef: 'consent-case-a-revoked',
        optIn: false,
      }));
      expect(store.querySharedExperiences({
        targetCaseRef: 'case-b',
        capabilityId: EXPERIENCE.capabilityId,
      })).toHaveLength(0);
      const adapter = createMetaFeedbackAdapter(store);
      expect(await adapter.submit({
        selected: true,
        caseRef: 'case-a',
        sourceRevision: 'outcome-r1',
        rating: 'HELPFUL',
        category: 'OTHER',
      })).toMatchObject({ status: 'REFUSED' });
      expect(store.listShadowCandidates()).toHaveLength(0);
    } finally {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects raw, path-shaped, secret-shaped, duplicate and oversized experience inputs', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r03c-meta-invalid-'));
    const store = new HostMetaShadowStore(join(dir, 'meta.sqlite'));
    const base = {
      caseRef: 'case-a',
      revision: 'outcome-r1',
      sha256: sha256('case-a-invalid'),
    };
    try {
      const invalid = [
        { ...EXPERIENCE, patternId: 'C:Usersprivate' },
        { ...EXPERIENCE, patternId: 'private-prompt-text' },
        { ...EXPERIENCE, tags: ['folder-selection', 'folder-selection'] },
        { ...EXPERIENCE, tags: Array.from({ length: 17 }, (_, index) => `tag-${index}`) },
        { ...EXPERIENCE, extraRawPrompt: 'private content' },
      ];
      for (const experience of invalid) {
        expect(() => store.recordOutcomeReceipt({ ...base, experience: experience as never }))
          .toThrow('META_EXPERIENCE_INVALID');
      }
      expect(() => store.querySharedExperiences({
        targetCaseRef: 'case-b',
        capabilityId: EXPERIENCE.capabilityId,
        tags: ['C:Usersprivate'],
      })).toThrow('META_EXPERIENCE_QUERY_INVALID');
    } finally {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
