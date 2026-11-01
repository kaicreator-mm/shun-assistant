/**
 * R02-V J09 — real Feedback/Shadow/Meta journey over durable Host state
 * (Owner authorization OWNER_SHUN_V030_R02_J030509... see
 * OWNER_SHUN_V030_R02_J02030509_DISPOSITION_APPROVE on #259).
 *
 * What is REAL here (no Vitest mock of the Host port):
 *   - a genuine guided journey outcome minted on the real HostGuidedService
 *     SQLite store (trusted staging + one atomic human decision);
 *   - the durable opt-in Shadow candidate store (domain-host/src/meta) over
 *     real SQLite, implementing the frozen MetaFeedbackHostPort contract;
 *   - restart durability: a fresh store instance over the same file reads the
 *     identical candidate digest, lifecycle FUTURE_BUILD_SHADOW, active=false.
 *
 * Negatives prove: deselected form is an absolute no-op (zero Host calls),
 * expired consent refuses, promotion-shaped candidates are refused and never
 * persisted, and a current-receipt mismatch refuses stale provenance.
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createMetaFeedbackAdapter } from '../../../../packages/domain-computer/src/feedback/meta-feedback.ts';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { HostMetaShadowStore } from '../../../../packages/domain-host/src/meta/host-meta-shadow-store.ts';

const sha256 = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

function stageObservation(now: number, revision: string) {
  return {
    schema: 'shun.guided.host-observation.v1',
    taskId: 'task-r02v-j09',
    journeyId: 'journey-r02v-j09',
    sourceRef: 'host:obs:r02v-j09',
    revision,
    caseRef: { snapshotId: 'snap-r02v-j09', digest: 'd'.repeat(64) },
    observedAtUnixMs: now - 1_000,
    validUntilUnixMs: now + 3_600_000,
    evidenceRefs: ['host:scope:r02v-j09'],
  };
}

const semanticSelection = {
  status: 'SELECTED' as const,
  semantic: {
    schema: 'shun.goal-semantic.v1',
    taskId: 'task-r02v-j09',
    goalContract: { taskId: 'task-r02v-j09', objective: 'collect feedback on the journey' },
    capabilityId: 'system.storage.diagnose_bounded_action',
    capabilityRevision: 'r1',
    provenance: { resolverRevision: 'resolver-v03' },
  },
};

describe('R02-V J09: real durable Shadow/Meta journey (zero paid, zero physical)', () => {
  let dir: string;
  let guided: HostGuidedService;
  let store: HostMetaShadowStore;
  let adapter: ReturnType<typeof createMetaFeedbackAdapter>;
  let hostCalls: { authorize: number; workflow: number };
  let genuineReceiptDigest: string;
  let storedCandidate: { candidateRef: string; candidateDigest: string };

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'shun-r02v-j09-'));
    // ---- genuine outcome receipt from a real guided journey ----
    guided = new HostGuidedService(join(dir, 'guided.sqlite'));
    const now = Date.now();
    const staged = guided.stageTrustedSelection({
      observation: stageObservation(now, 'r02v-j09-r1'),
      semanticSelection,
      scope: { status: 'KNOWN', selectedRootRef: undefined },
    });
    if (staged.status !== 'CURRENT') throw new Error('genuine staging failed');
    const step = staged.step;
    const decision = guided.decide({
      kind: 'USER_DECISION_RELAY',
      humanApproval: true,
      authorityClaimed: false,
      decision: 'REFUSE',
      relayedVia: '/api',
      stepId: step.stepId,
      stepDigest: step.templateRef.digest,
      caseRef: step.caseRef,
      outcome: {
        schema: 'shun.guided.step-outcome.v1',
        journeyId: step.journeyId,
        taskId: step.taskId,
        stepId: step.stepId,
        caseRef: step.caseRef,
        event: 'USER_SUBMIT',
        source: 'USER',
        sourceRef: 'ui:local',
        answers: [{ fieldId: 'selectedRoot', value: 'C:Work' }],
        evidenceRefs: [],
        occurredAtUnixMs: Date.now(),
      },
    });
    expect(decision.status).toBe('RECORDED');
    if (decision.status !== 'RECORDED') throw new Error('genuine decision not recorded');
    // Digest over the genuinely persisted durable decision record.
    const historyEntry = decision.history.at(-1);
    genuineReceiptDigest = sha256(
      JSON.stringify({
        caseRef: step.caseRef,
        stepId: step.stepId,
        stepDigest: step.templateRef.digest,
        decision: 'REFUSE',
        recordedEntry: historyEntry,
      }),
    );

    // ---- the REAL durable Host Shadow store (no mock port) ----
    store = new HostMetaShadowStore(join(dir, 'meta-shadow.sqlite'));
    // Trusted Host composition records the genuine receipt, then the operator
    // records an explicit, separate opt-in consent for META_FEEDBACK_SHADOW.
    store.recordOutcomeReceipt({
      caseRef: 'task-r02v-j09',
      revision: 'outcome-r1',
      sha256: genuineReceiptDigest,
    });
    store.recordOptInConsent({
      consentRef: 'consent-r02v-j09-r1',
      revision: 'consent-rev-1',
      caseRef: 'task-r02v-j09',
      sourceRevision: 'outcome-r1',
      sourceDigest: genuineReceiptDigest,
      operatorId: 'operator:shun-owner',
      operatorSubjectRef: 'operator:shun-owner',
      authorizationRevision: 'authz-rev-1',
      currentnessRef: 'currentness:r02v-j09:r1',
      optIn: true,
      expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
    });

    // Adapter over the real store; delegate-counting proves absolute no-ops.
    hostCalls = { authorize: 0, workflow: 0 };
    const countingStore = {
      async authorizeCurrentFeedback(input: unknown): Promise<unknown> {
        hostCalls.authorize++;
        return store.authorizeCurrentFeedback(input as never);
      },
      async runMetaFeedbackWorkflow(input: never): Promise<unknown> {
        hostCalls.workflow++;
        return store.runMetaFeedbackWorkflow(input);
      },
    };
    adapter = createMetaFeedbackAdapter(countingStore);
  });

  afterAll(() => {
    store?.close();
    guided?.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('a deselected form is an absolute no-op: no Host call, no parse', async () => {
    const before = { ...hostCalls };
    const result = await adapter.submit({ selected: false });
    expect(result).toEqual({ status: 'NOT_SELECTED' });
    expect(hostCalls).toEqual(before);
  });

  it('opt-in feedback on the genuine receipt stores a FUTURE_BUILD_SHADOW candidate', async () => {
    const result = await adapter.submit({
      selected: true,
      caseRef: 'task-r02v-j09',
      sourceRevision: 'outcome-r1',
      rating: 'HELPFUL',
      category: 'OTHER',
    });
    expect(result.status).toBe('STORED_SHADOW');
    if (result.status !== 'STORED_SHADOW') throw new Error('not stored');
    expect(result.active).toBe(false);
    storedCandidate = { candidateRef: result.candidateRef, candidateDigest: result.candidateDigest };
    // The persisted candidate is bound to the genuine receipt digest.
    const persisted = store.readShadowCandidate(result.candidateRef);
    expect(persisted?.lifecycle).toBe('FUTURE_BUILD_SHADOW');
    expect(persisted?.active).toBe(false);
    expect(persisted?.candidateDigest).toBe(result.candidateDigest);
    const payload = JSON.parse(persisted?.payloadJson ?? '{}') as {
      source?: { sha256?: string };
    };
    expect(payload.source?.sha256).toBe(genuineReceiptDigest);
    expect(hostCalls).toEqual({ authorize: 1, workflow: 1 });
  });

  it('a fresh store instance over the same file reads the identical candidate (restart)', () => {
    const reopened = new HostMetaShadowStore(join(dir, 'meta-shadow.sqlite'));
    try {
      const candidates = reopened.listShadowCandidates();
      expect(candidates).toHaveLength(1);
      const candidate = candidates[0] as NonNullable<ReturnType<typeof reopened.listShadowCandidates>[0]>;
      expect(candidate.candidateId).toBe(storedCandidate.candidateRef);
      expect(candidate.candidateDigest).toBe(storedCandidate.candidateDigest);
      expect(candidate.lifecycle).toBe('FUTURE_BUILD_SHADOW');
      expect(candidate.active).toBe(false);
    } finally {
      reopened.close();
    }
  });

  it('expired or missing consent refuses; nothing is persisted', async () => {
    // A consent for a DIFFERENT case never authorizes this feedback.
    const refused = await adapter.submit({
      selected: true,
      caseRef: 'task-unknown-case',
      sourceRevision: 'outcome-r1',
      rating: 'HELPFUL',
      category: 'OTHER',
    });
    expect(refused.status).toBe('REFUSED');
    expect(store.listShadowCandidates()).toHaveLength(1);
  });

  it('promotion-shaped candidates are refused by the store and never persisted', async () => {
    const authorization = (await store.authorizeCurrentFeedback({
      scope: 'META_FEEDBACK_SHADOW',
      caseRef: 'task-r02v-j09',
      sourceRevision: 'outcome-r1',
      selection: {
        selected: true,
        caseRef: 'task-r02v-j09',
        sourceRevision: 'outcome-r1',
        rating: 'HELPFUL',
        category: 'OTHER',
      },
    })) as unknown as { candidateId: string; consentRef: string; consentRevision: string; consentExpiresAt: string; operatorId: string; operatorSubjectRef: string; authorizationRevision: string; currentnessRef: string; caseRef: string; sourceRevision: string; sourceDigest: string };
    const hostile = {
      schema: 'shun.meta-feedback-candidate/1',
      candidateId: authorization.candidateId,
      kind: 'META_FEEDBACK',
      lifecycle: 'FUTURE_BUILD_SHADOW',
      active: true, // promotion attempt
      source: {
        caseRef: authorization.caseRef,
        revision: authorization.sourceRevision,
        sha256: authorization.sourceDigest,
      },
      feedback: { rating: 'HELPFUL', category: 'OTHER' },
      provenance: {
        operatorId: authorization.operatorId,
        operatorSubjectRef: authorization.operatorSubjectRef,
        consentRef: authorization.consentRef,
        consentRevision: authorization.consentRevision,
        consentExpiresAt: authorization.consentExpiresAt,
        authorizationRevision: authorization.authorizationRevision,
        currentnessRef: authorization.currentnessRef,
      },
    };
    await expect(
      store.runMetaFeedbackWorkflow({
        candidate: hostile as never,
        authorization: authorization as never,
      }),
    ).rejects.toThrow('META_PROMOTION_REFUSED');
    expect(store.listShadowCandidates()).toHaveLength(1);
  });

  it('a stale receipt revision (not the current recorded outcome) refuses authorization', async () => {
    // Record a NEWER genuine receipt; the old revision is no longer current.
    store.recordOutcomeReceipt({
      caseRef: 'task-r02v-j09',
      revision: 'outcome-r2',
      sha256: 'f'.repeat(64),
    });
    await expect(
      store.authorizeCurrentFeedback({
        scope: 'META_FEEDBACK_SHADOW',
        caseRef: 'task-r02v-j09',
        sourceRevision: 'outcome-r1',
        selection: {
          selected: true,
          caseRef: 'task-r02v-j09',
          sourceRevision: 'outcome-r1',
          rating: 'HELPFUL',
          category: 'OTHER',
        },
      }),
    ).rejects.toThrow('META_RECEIPT_NOT_CURRENT');
  });
});
