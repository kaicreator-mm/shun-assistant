/**
 * R03B composite journey proof — ONE selected DomainApp carrying the goal,
 * windows-effect, provider first-use and meta-feedback route families, each
 * backed by its real trusted Host binding, with a REAL submit per family
 * through the same reference-authenticated Control API surface and
 * per-family K-minted permit evidence in the durable k-docs store.
 * Separate FILE on purpose: vitest isolates module globals per file, so this
 * composite boot owns its own journey binding installs
 * (OWNER_SHUN_V030_R03B_CROSSCASE_UI_COMPOSITE_APPROVE).
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { HostMetaShadowStore } from '../../../../packages/domain-host/src/meta/host-meta-shadow-store.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  ON_WINDOWS,
  type TestAuthority,
} from '../../../../packages/executor-windows/test/helpers.ts';
import {
  ARTIFACT_SHA256,
  DESCRIPTOR,
  RG_BYTES,
  ROOT_KEY_ID,
  ROOT_PEM,
  SCOPE,
} from '../t08-provider/material.ts';
import { bootLiveStack, json, type LiveStack } from './stack-harness.ts';

const RUN_PHYSICAL =
  process.env.SHUN_R02V_PHYSICAL === '1' && process.platform === 'win32' && ON_WINDOWS;

const disabledInterpreter = {
  status: () => ({
    enabled: false,
    provider: 'deepseek' as const,
    model: 'deepseek-flash' as const,
    osConsentRequired: true as const,
  }),
  interpretGoal: async () => ({ ok: false, code: 'CLOUD_UNAVAILABLE' }),
};

function seedProviderCache(cacheRoot: string): void {
  const artifacts = join(cacheRoot, 'artifacts');
  mkdirSync(artifacts, { recursive: true });
  writeFileSync(join(artifacts, ARTIFACT_SHA256), RG_BYTES);
}

describe.skipIf(!RUN_PHYSICAL)(
  'R03B composite: ALL journey families in ONE selected App with real submits + per-family permits (physical)',
  () => {
    let dir: string;
    let authority: TestAuthority;
    let workspace: string;
    let sourceGuided: HostGuidedService;
    let store: HostMetaShadowStore;
    let stack: LiveStack;
    let canaryText: string;
    let canaryFile: string;

    beforeAll(async () => {
      dir = mkdtempSync(join(tmpdir(), 'shun-r03b-comp-'));
      authority = await createTestAuthority('shun-r03b-comp-');
      workspace = mkdtempSync(join(tmpdir(), 'shun-r03b-comp-ws-'));

      // Genuine outcome receipt for the meta family: one real guided decision
      // on a real HostGuidedService store (independent source Case).
      sourceGuided = new HostGuidedService(join(dir, 'guided-source.sqlite'));
      const now = Date.now();
      const staged = sourceGuided.stageTrustedSelection({
        observation: {
          schema: 'shun.guided.host-observation.v1',
          taskId: 'task-r03b-comp-src',
          journeyId: 'journey-r03b-comp',
          sourceRef: 'host:obs:r03b-comp',
          revision: 'r03b-comp-r1',
          caseRef: { snapshotId: 'snap-r03b-comp', digest: 'a'.repeat(64) },
          observedAtUnixMs: now - 1_000,
          validUntilUnixMs: now + 3_600_000,
          evidenceRefs: ['host:scope:r03b-comp'],
        },
        semanticSelection: {
          status: 'SELECTED',
          semantic: {
            schema: 'shun.goal-semantic.v1',
            taskId: 'task-r03b-comp-src',
            goalContract: { taskId: 'task-r03b-comp-src', objective: 'composite source journey' },
            capabilityId: 'system.storage.diagnose_bounded_action',
            capabilityRevision: 'r1',
            provenance: { resolverRevision: 'resolver-v03' },
          },
        },
        scope: { status: 'KNOWN', selectedRootRef: undefined },
      });
      if (staged.status !== 'CURRENT') throw new Error('source staging failed');
      const step = staged.step;
      const decision = sourceGuided.decide({
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
      if (decision.status !== 'RECORDED') throw new Error('source decision not recorded');
      const receiptDigest = createHash('sha256')
        .update(
          JSON.stringify({
            caseRef: step.caseRef,
            stepId: step.stepId,
            stepDigest: step.templateRef.digest,
            decision: 'REFUSE',
            recordedEntry: decision.history.at(-1),
          }),
        )
        .digest('hex');

      store = new HostMetaShadowStore(join(dir, 'meta-shadow.sqlite'));
      store.recordOutcomeReceipt({
        caseRef: 'task-r03b-comp-src',
        revision: 'outcome-r1',
        sha256: receiptDigest,
      });
      store.recordOptInConsent({
        consentRef: 'consent-r03b-comp-r1',
        revision: 'consent-rev-1',
        caseRef: 'task-r03b-comp-src',
        sourceRevision: 'outcome-r1',
        sourceDigest: receiptDigest,
        operatorId: 'operator:shun-owner',
        operatorSubjectRef: 'operator:shun-owner',
        authorizationRevision: 'authz-rev-1',
        currentnessRef: 'currentness:r03b-comp:r1',
        optIn: true,
        expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      });

      const cacheRoot = join(dir, 'provider-cache');
      seedProviderCache(cacheRoot);
      stack = await bootLiveStack({
        interpreter: disabledInterpreter,
        prefix: 'shun-r03b-comp-stack-',
        journeys: {
          manifest: { windows: true, provider: true, meta: true },
          bindings: {
            windows: { authorityDir: authority.authorityDir, workspaceRoot: workspace },
            provider: {
              cacheRoot,
              roots: [{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM }],
              scopes: [SCOPE],
              descriptor: DESCRIPTOR,
              taskId: 'task-r03b-comp-provider',
              revocationEpoch: 1,
            },
            meta: { store },
          },
        },
      });
    });

    afterAll(async () => {
      if (stack) await stack.close();
      store?.close();
      sourceGuided?.close();
      disposeTestAuthority(authority);
      if (workspace) rmSync(workspace, { recursive: true, force: true });
      if (dir) rmSync(dir, { recursive: true, force: true });
    });

    it('family windows: one REAL scoped effect through the K (caseId-bound authority)', async () => {
      canaryText = `r03b-composite-canary-${Date.now()}`;
      canaryFile = join(workspace, 'composite-write.txt');
      const { action, plan, grant } = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: canaryFile, content: canaryText },
        requiredPrivilege: 'USER',
        sideEffectClass: 'R1',
        filesystemScope: { read: [], write: [workspace] },
        expectedState: { path: canaryFile, exists: true, content: canaryText },
        taskId: stack.caseId,
      });
      const refs = stack.submitRefs();
      const result = await json(stack.port, 'POST', '/api/v03/effect/submit', {
        caseId: stack.caseId,
        actionRef: action.actionId,
        planRef: plan.planHash,
        grantRef: grant.grantId,
        currentnessRef: refs.currentnessRef,
        approvalRef: refs.approvalRef,
      });
      expect(result.status).toBe(200);
      expect((result.body as { status: string }).status).toBe('COMPLETED');
      expect(existsSync(canaryFile)).toBe(true);
      expect(readFileSync(canaryFile, 'utf8')).toBe(canaryText);
    });

    it('family provider: one REAL signed first-use execution through the K', async () => {
      const refs = stack.submitRefs();
      const result = await json(stack.port, 'POST', '/api/v03/provider/first-use', {
        caseId: stack.caseId,
        taskId: 'task-r03b-comp-provider',
        currentnessRef: refs.currentnessRef,
        approvalRef: refs.approvalRef,
      });
      expect(result.status).toBe(200);
      expect((result.body as { status: string }).status).toBe('COMPLETED');
      const output = (
        (
          (result.body as { result: { admitted?: { effects?: { output?: { outcome?: { output?: {
            stdout?: string;
          } } } }[] } } }).result ?? {}
        ).admitted?.effects?.[0]?.output?.outcome?.output ?? {}
      );
      expect((output.stdout ?? '').toLowerCase()).toContain('ripgrep 14.1.1');
    });

    it('family meta: one REAL durable Shadow candidate through the K', async () => {
      const refs = stack.submitRefs();
      const result = await json(stack.port, 'POST', '/api/v03/meta/feedback', {
        caseId: stack.caseId,
        caseRef: 'task-r03b-comp-src',
        sourceRevision: 'outcome-r1',
        rating: 'HELPFUL',
        category: 'OTHER',
        correction: 'NO_CORRECTION',
        currentnessRef: refs.currentnessRef,
        approvalRef: refs.approvalRef,
      });
      expect(result.status).toBe(200);
      expect((result.body as { status: string }).status).toBe('COMPLETED');
      const candidates = store.listShadowCandidates();
      expect(candidates).toHaveLength(1);
      expect(candidates[0]?.lifecycle).toBe('FUTURE_BUILD_SHADOW');
      expect(candidates[0]?.active).toBe(false);
    });

    it('cross-Case negative: authority minted for another task refuses with zero effect', async () => {
      const crossTarget = join(workspace, 'composite-cross-never.txt');
      const { action, plan, grant } = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: crossTarget, content: 'never' },
        requiredPrivilege: 'USER',
        sideEffectClass: 'R1',
        filesystemScope: { read: [], write: [workspace] },
        taskId: 'task-not-this-case',
      });
      const refs = stack.submitRefs();
      const result = await json(stack.port, 'POST', '/api/v03/effect/submit', {
        caseId: stack.caseId,
        actionRef: action.actionId,
        planRef: plan.planHash,
        grantRef: grant.grantId,
        currentnessRef: refs.currentnessRef,
        approvalRef: refs.approvalRef,
      });
      expect(result.status).toBe(422);
      expect(existsSync(crossTarget)).toBe(false);
    });

    it('per-family K-minted permit evidence in the durable k-docs store', () => {
      const kDocs = new DatabaseSync(join(stack.dir, 'k-docs.sqlite'));
      try {
        const keys = (
          kDocs.prepare('SELECT doc_key FROM k_v10_docs').all() as { doc_key: string }[]
        ).map((row) => decodeURIComponent(row.doc_key));
        for (const workflow of ['windows-journey', 'shun-provider', 'shun-meta']) {
          const permits = keys.filter(
            (key) => key.includes('effect-permit') && key.includes(`turn:${workflow}:`),
          );
          expect(permits.length).toBeGreaterThanOrEqual(1);
        }
      } finally {
        kDocs.close();
      }
    });
  },
);
