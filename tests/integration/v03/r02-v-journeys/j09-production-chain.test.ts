/**
 * R03-INT J09 — FULL production meta-feedback chain through the selected
 * v0.3 DomainApp (R03-F02 repair, OWNER_SHUN_V030_R03_F01F02Q01_REPAIR_APPROVE).
 * Ungated (no OS effect, no paid call): runs on every platform including CI.
 *
 * The chain is the REAL production topology: Control API HTTP →
 * reference-authenticated journey gateway → selected public v0.10.3 Kernel
 * (live K-minted Effect Permit) → trusted shun-meta-host binding over the
 * REAL durable HostMetaShadowStore. The genuine outcome receipt comes from a
 * real guided journey decision on the real HostGuidedService SQLite store;
 * the opt-in consent is recorded by trusted composition only. Promotion of a
 * candidate remains impossible (no promote API; active stays false).
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { HostMetaShadowStore } from '../../../../packages/domain-host/src/meta/host-meta-shadow-store.ts';
import { bootLiveStack, json, type LiveStack } from './stack-harness.ts';

const disabledInterpreter = {
  status: () => ({
    enabled: false,
    provider: 'deepseek' as const,
    model: 'deepseek-flash' as const,
    osConsentRequired: true as const,
  }),
  interpretGoal: async () => ({ ok: false, code: 'CLOUD_UNAVAILABLE' }),
};

describe('R03-INT J09: production meta-feedback chain over the selected K (CI-safe)', () => {
  let dir: string;
  let guided: HostGuidedService;
  let store: HostMetaShadowStore;
  let stack: LiveStack;
  let genuineReceiptDigest: string;
  let stored: { candidateRef: string; candidateDigest: string } | undefined;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'shun-r03int-j09-'));
    // Genuine outcome receipt: one real guided decision on the real store.
    guided = new HostGuidedService(join(dir, 'guided-source.sqlite'));
    const now = Date.now();
    const staged = guided.stageTrustedSelection({
      observation: {
        schema: 'shun.guided.host-observation.v1',
        taskId: 'task-r03int-j09-src',
        journeyId: 'journey-r03int-j09',
        sourceRef: 'host:obs:r03int-j09',
        revision: 'r03int-j09-r1',
        caseRef: { snapshotId: 'snap-r03int-j09', digest: 'e'.repeat(64) },
        observedAtUnixMs: now - 1_000,
        validUntilUnixMs: now + 3_600_000,
        evidenceRefs: ['host:scope:r03int-j09'],
      },
      semanticSelection: {
        status: 'SELECTED',
        semantic: {
          schema: 'shun.goal-semantic.v1',
          taskId: 'task-r03int-j09-src',
          goalContract: { taskId: 'task-r03int-j09-src', objective: 'source journey' },
          capabilityId: 'system.storage.diagnose_bounded_action',
          capabilityRevision: 'r1',
          provenance: { resolverRevision: 'resolver-v03' },
        },
      },
      scope: { status: 'KNOWN', selectedRootRef: undefined },
    });
    if (staged.status !== 'CURRENT') throw new Error('source staging failed');
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
    if (decision.status !== 'RECORDED') throw new Error('genuine decision not recorded');
    const entry = decision.history.at(-1);
    genuineReceiptDigest = createHash('sha256')
      .update(
        JSON.stringify({
          caseRef: step.caseRef,
          stepId: step.stepId,
          stepDigest: step.templateRef.digest,
          decision: 'REFUSE',
          recordedEntry: entry,
        }),
      )
      .digest('hex');

    // Trusted composition records the genuine receipt + explicit opt-in.
    store = new HostMetaShadowStore(join(dir, 'meta-shadow.sqlite'));
    store.recordOutcomeReceipt({
      caseRef: 'task-r03int-j09-src',
      revision: 'outcome-r1',
      sha256: genuineReceiptDigest,
    });
    store.recordOptInConsent({
      consentRef: 'consent-r03int-j09-r1',
      revision: 'consent-rev-1',
      caseRef: 'task-r03int-j09-src',
      sourceRevision: 'outcome-r1',
      sourceDigest: genuineReceiptDigest,
      operatorId: 'operator:shun-owner',
      operatorSubjectRef: 'operator:shun-owner',
      authorizationRevision: 'authz-rev-1',
      currentnessRef: 'currentness:r03int-j09:r1',
      optIn: true,
      expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
    });

    stack = await bootLiveStack({
      interpreter: disabledInterpreter,
      prefix: 'shun-r03int-j09-stack-',
      journeys: { manifest: { meta: true }, bindings: { meta: { store } } },
    });
  });

  afterAll(async () => {
    if (stack) await stack.close();
    store?.close();
    guided?.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('boots with the meta journey manifest and the real durable store', () => {
    expect(stack.production.journeys).toBeTruthy();
  });

  it('REAL chain: HTTP feedback → K permit → durable FUTURE_BUILD_SHADOW candidate', async () => {
    const refs = stack.submitRefs();
    const result = await json(stack.port, 'POST', '/api/v03/meta/feedback', {
      caseId: stack.caseId,
      caseRef: 'task-r03int-j09-src',
      sourceRevision: 'outcome-r1',
      rating: 'HELPFUL',
      category: 'OTHER',
      correction: 'NO_CORRECTION',
      currentnessRef: refs.currentnessRef,
      approvalRef: refs.approvalRef,
    });
    expect(result.status).toBe(200);
    expect((result.body as { status: string }).status).toBe('COMPLETED');
    const output = (
      (
        (result.body as { result: { admitted?: { effects?: { output?: { outcome?: { output?: {
          status?: string;
          candidateRef?: string;
          candidateDigest?: string;
          active?: boolean;
        } } } }[] } } }).result ?? {}
      ).admitted?.effects?.[0]?.output?.outcome?.output ?? {}
    );
    expect(output.status).toBe('STORED_SHADOW');
    expect(output.active).toBe(false);
    stored = { candidateRef: output.candidateRef ?? '', candidateDigest: output.candidateDigest ?? '' };
    // Durable: read back through a FRESH store instance over the same file.
    const reopened = new HostMetaShadowStore(join(dir, 'meta-shadow.sqlite'));
    try {
      const candidate = reopened.readShadowCandidate(stored.candidateRef);
      expect(candidate?.lifecycle).toBe('FUTURE_BUILD_SHADOW');
      expect(candidate?.active).toBe(false);
      expect(candidate?.candidateDigest).toBe(stored.candidateDigest);
    } finally {
      reopened.close();
    }
    console.log(
      '[J09-production] real feedback receipt:',
      JSON.stringify({ candidateRef: stored.candidateRef, digestHead: stored.candidateDigest.slice(0, 16) }),
    );
  });

  it('NEGATIVE: feedback for an unknown Case refuses (nothing persisted)', async () => {
    const refs = stack.submitRefs();
    const result = await json(stack.port, 'POST', '/api/v03/meta/feedback', {
      caseId: stack.caseId,
      caseRef: 'task-never-existed',
      sourceRevision: 'outcome-r1',
      rating: 'HELPFUL',
      category: 'OTHER',
      correction: 'NO_CORRECTION',
      currentnessRef: refs.currentnessRef,
      approvalRef: refs.approvalRef,
    });
    expect(result.status).toBe(422);
    expect((result.body as { status: string }).status).toBe('KERNEL_REFUSED');
    const reopened = new HostMetaShadowStore(join(dir, 'meta-shadow.sqlite'));
    try {
      expect(reopened.listShadowCandidates()).toHaveLength(1);
    } finally {
      reopened.close();
    }
  });

  it('NEGATIVE: a forged reference pair refuses pre-send', async () => {
    const result = await json(stack.port, 'POST', '/api/v03/meta/feedback', {
      caseId: stack.caseId,
      caseRef: 'task-r03int-j09-src',
      sourceRevision: 'outcome-r1',
      rating: 'HELPFUL',
      category: 'OTHER',
      correction: 'NO_CORRECTION',
      currentnessRef: `forged-${'a'.repeat(32)}`,
      approvalRef: `forged-${'b'.repeat(32)}`,
    });
    expect(result.status).toBe(422);
    expect((result.body as { status: string }).status).toBe('REFUSED');
  });

  it('fail-closed boot: meta routes without the trusted binding refuse activation', async () => {
    await expect(
      bootLiveStack({
        interpreter: disabledInterpreter,
        prefix: 'shun-r03int-j09-failclosed-',
        journeys: { manifest: { meta: true } },
      }),
    ).rejects.toThrow('V03_PRODUCTION_COMPOSITION_REFUSED');
  });
});
