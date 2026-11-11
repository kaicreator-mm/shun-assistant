/**
 * R03B — REAL CN/EN UI→API→K→Host user loop over the shipped v03 UI
 * (OWNER_SHUN_V030_R03B_CROSSCASE_UI_COMPOSITE_APPROVE).
 * Runs ONLY when SHUN_R02V_PHYSICAL=1 on a real Windows host.
 *
 * What is REAL here (no product doubles):
 *   - the SHIPPED UI code: app.js + view-model.js + strings.js are imported
 *     from apps/control-ui/public/v03 and executed unmodified — the only
 *     substituted layer is the minimal DOM shim (browser infrastructure);
 *   - the REAL loopback Control API → selected public v0.10.3 Kernel
 *     (K-minted permits) → trusted Host bindings → REAL scoped effect /
 *     REAL signed provider execution / REAL durable Shadow candidate;
 *   - the UI's fetch is the real global fetch; relative same-origin paths
 *     resolve against the live origin exactly as a served browser page's.
 * Both locales (en, zh) drive the same loop end to end.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
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
import { ARTIFACT_SHA256, DESCRIPTOR, RG_BYTES, ROOT_KEY_ID, ROOT_PEM, SCOPE } from '../t08-provider/material.ts';
import { bootLiveStack, type LiveStack } from './stack-harness.ts';
import { installDom, type InstalledDom } from './ui-dom-shim.ts';

const here = dirname(fileURLToPath(import.meta.url));
const uiDir = resolve(here, '../../../../apps/control-ui/public/v03');

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

async function until(condition: () => boolean, timeoutMs = 10_000): Promise<void> {
  const started = Date.now();
  while (!condition()) {
    if (Date.now() - started > timeoutMs) throw new Error('UI condition timeout');
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

type MetaCandidateReader = Pick<HostMetaShadowStore, 'listShadowCandidates' | 'readShadowCandidate'>;

/** Shared assertion used by the physical UI loop and a CI-runnable pure test. */
function assertSingleNewMetaCandidate(
  reader: MetaCandidateReader,
  candidateIdsBeforeSubmit: ReadonlySet<string>,
): void {
  const newCandidates = reader
    .listShadowCandidates()
    .filter((candidate) => !candidateIdsBeforeSubmit.has(candidate.candidateId));
  expect(newCandidates).toHaveLength(1);
  const newCandidate = newCandidates[0];
  if (!newCandidate) throw new Error('expected one new Meta Shadow candidate');
  const persisted = reader.readShadowCandidate(newCandidate.candidateId);
  expect(persisted).toBeDefined();
  const payload = JSON.parse(persisted!.payloadJson) as {
    kind: string;
    lifecycle: string;
    active: boolean;
    source: { caseRef: string; revision: string };
    feedback: { rating: string; category: string; correction?: string };
  };
  expect(payload).toMatchObject({
    kind: 'META_FEEDBACK',
    lifecycle: 'FUTURE_BUILD_SHADOW',
    active: false,
    source: { caseRef: 'task-r03b-ui-src', revision: 'outcome-r1' },
    feedback: {
      rating: 'HELPFUL',
      category: 'OTHER',
      correction: 'NO_CORRECTION',
    },
  });
  expect(persisted!.lifecycle).toBe('FUTURE_BUILD_SHADOW');
  expect(persisted!.active).toBe(false);
}

describe('R03B UI Meta candidate correlation assertion (CI-runnable)', () => {
  it('accepts exactly one newly persisted candidate with the expected provenance', () => {
    const candidate = {
      candidateId: 'candidate-new',
      payloadJson: JSON.stringify({
        kind: 'META_FEEDBACK',
        lifecycle: 'FUTURE_BUILD_SHADOW',
        active: false,
        source: { caseRef: 'task-r03b-ui-src', revision: 'outcome-r1' },
        feedback: { rating: 'HELPFUL', category: 'OTHER', correction: 'NO_CORRECTION' },
      }),
      lifecycle: 'FUTURE_BUILD_SHADOW',
      active: false,
    };
    const reader = {
      listShadowCandidates: () => [{ candidateId: 'candidate-old' }, candidate],
      readShadowCandidate: (id: string) => id === candidate.candidateId ? candidate : undefined,
    } as unknown as MetaCandidateReader;
    assertSingleNewMetaCandidate(reader, new Set(['candidate-old']));
  });

  it('rejects zero, multiple, missing-payload and mismatched-provenance candidates', () => {
    const empty = {
      listShadowCandidates: () => [{ candidateId: 'candidate-old' }],
      readShadowCandidate: () => undefined,
    } as unknown as MetaCandidateReader;
    expect(() => assertSingleNewMetaCandidate(empty, new Set(['candidate-old']))).toThrow();

    const multiple = {
      listShadowCandidates: () => [
        { candidateId: 'candidate-old' },
        { candidateId: 'candidate-a' },
        { candidateId: 'candidate-b' },
      ],
      readShadowCandidate: () => undefined,
    } as unknown as MetaCandidateReader;
    expect(() => assertSingleNewMetaCandidate(multiple, new Set(['candidate-old']))).toThrow();

    const missingPayload = {
      listShadowCandidates: () => [{ candidateId: 'candidate-new' }],
      readShadowCandidate: () => undefined,
    } as unknown as MetaCandidateReader;
    expect(() => assertSingleNewMetaCandidate(missingPayload, new Set())).toThrow();

    const mismatch = {
      candidateId: 'candidate-new',
      payloadJson: JSON.stringify({
        kind: 'META_FEEDBACK',
        lifecycle: 'FUTURE_BUILD_SHADOW',
        active: false,
        source: { caseRef: 'another-case', revision: 'outcome-r1' },
        feedback: { rating: 'HELPFUL', category: 'OTHER', correction: 'NO_CORRECTION' },
      }),
      lifecycle: 'FUTURE_BUILD_SHADOW',
      active: false,
    };
    const wrongSource = {
      listShadowCandidates: () => [mismatch],
      readShadowCandidate: () => mismatch,
    } as unknown as MetaCandidateReader;
    expect(() => assertSingleNewMetaCandidate(wrongSource, new Set())).toThrow();
  });
});

describe.skipIf(!RUN_PHYSICAL)(
  'R03B UI loop: real shipped CN/EN UI → API → K → Host (physical)',
  () => {
    let dir: string;
    let authority: TestAuthority;
    let workspace: string;
    let sourceGuided: HostGuidedService;
    let store: HostMetaShadowStore;
    let stack: LiveStack;
    let originalFetch: typeof fetch;
    let strings: typeof import('../../../../apps/control-ui/public/v03/strings.js');

    beforeAll(async () => {
      dir = mkdtempSync(join(tmpdir(), 'shun-r03b-ui-'));
      authority = await createTestAuthority('shun-r03b-ui-');
      workspace = mkdtempSync(join(tmpdir(), 'shun-r03b-ui-ws-'));

      // Genuine outcome receipt (independent source Case) for the meta family.
      sourceGuided = new HostGuidedService(join(dir, 'guided-source.sqlite'));
      const now = Date.now();
      const staged = sourceGuided.stageTrustedSelection({
        observation: {
          schema: 'shun.guided.host-observation.v1',
          taskId: 'task-r03b-ui-src',
          journeyId: 'journey-r03b-ui',
          sourceRef: 'host:obs:r03b-ui',
          revision: 'r03b-ui-r1',
          caseRef: { snapshotId: 'snap-r03b-ui', digest: 'b'.repeat(64) },
          observedAtUnixMs: now - 1_000,
          validUntilUnixMs: now + 3_600_000,
          evidenceRefs: ['host:scope:r03b-ui'],
        },
        semanticSelection: {
          status: 'SELECTED',
          semantic: {
            schema: 'shun.goal-semantic.v1',
            taskId: 'task-r03b-ui-src',
            goalContract: { taskId: 'task-r03b-ui-src', objective: 'ui source journey' },
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
        caseRef: 'task-r03b-ui-src',
        revision: 'outcome-r1',
        sha256: receiptDigest,
      });
      store.recordOptInConsent({
        consentRef: 'consent-r03b-ui-r1',
        revision: 'consent-rev-1',
        caseRef: 'task-r03b-ui-src',
        sourceRevision: 'outcome-r1',
        sourceDigest: receiptDigest,
        operatorId: 'operator:shun-owner',
        operatorSubjectRef: 'operator:shun-owner',
        authorizationRevision: 'authz-rev-1',
        currentnessRef: 'currentness:r03b-ui:r1',
        optIn: true,
        expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
      });

      const cacheRoot = join(dir, 'provider-cache');
      mkdirSync(join(cacheRoot, 'artifacts'), { recursive: true });
      writeFileSync(join(cacheRoot, 'artifacts', ARTIFACT_SHA256), RG_BYTES);
      stack = await bootLiveStack({
        interpreter: disabledInterpreter,
        prefix: 'shun-r03b-ui-stack-',
        journeys: {
          manifest: { windows: true, provider: true, meta: true },
          bindings: {
            windows: { authorityDir: authority.authorityDir, workspaceRoot: workspace },
            provider: {
              cacheRoot,
              roots: [{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM }],
              scopes: [SCOPE],
              descriptor: DESCRIPTOR,
              taskId: 'task-r03b-ui-provider',
              revocationEpoch: 1,
            },
            meta: { store },
          },
        },
      });

      strings = (await import(
        pathToFileURL(join(uiDir, 'strings.js')).href
      )) as typeof import('../../../../apps/control-ui/public/v03/strings.js');

      // Resolve the UI's relative same-origin fetches against the live
      // loopback origin (what the serving browser does); the fetch is REAL.
      originalFetch = globalThis.fetch;
      const origin = `http://127.0.0.1:${stack.port}`;
      globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const target =
          typeof input === 'string' && input.startsWith('/')
            ? `${origin}${input}`
            : input;
        return originalFetch(target as Parameters<typeof fetch>[0], init);
      }) as typeof fetch;
    });

    afterAll(async () => {
      globalThis.fetch = originalFetch;
      if (stack) await stack.close();
      store?.close();
      sourceGuided?.close();
      disposeTestAuthority(authority);
      if (workspace) rmSync(workspace, { recursive: true, force: true });
      if (dir) rmSync(dir, { recursive: true, force: true });
    });

    for (const locale of ['en', 'zh'] as const) {
      it(`locale ${locale}: the shipped UI completes effect → provider → meta through the real K`, async () => {
        const dom: InstalledDom = installDom(locale);
        try {
          // Execute the REAL shipped UI module (fresh instance per locale).
          await import(`${pathToFileURL(join(uiDir, 'app.js')).href}?l=${locale}`);
          // Initial refresh renders the live guided state.
          await until(() => (dom.byId('v03-step')?.textContent ?? '').length > 0);
          expect(dom.byId('v03-title')?.textContent).toContain(
            (strings.t(locale, 'app.title') as { ok: true; text: string }).text,
          );

          // Operator pastes the Host-issued reference pair (boot console).
          const refs = stack.submitRefs();
          dom.byId('v03-j-currentness')!.value = refs.currentnessRef;
          dom.byId('v03-j-approval')!.value = refs.approvalRef;

          // --- effect family: user submits the caseId-bound plan/grant refs
          const canary = `r03b-ui-${locale}-canary-${Date.now()}`;
          const target = join(workspace, `ui-${locale}-write.txt`);
          const { action, plan, grant } = buildAuthorizedAction(authority, {
            op: 'windows.fs.write',
            parameters: { path: target, content: canary },
            requiredPrivilege: 'USER',
            sideEffectClass: 'R1',
            filesystemScope: { read: [], write: [workspace] },
            expectedState: { path: target, exists: true, content: canary },
            taskId: stack.caseId,
          });
          dom.byId('v03-j-action')!.value = action.actionId;
          dom.byId('v03-j-plan')!.value = plan.planHash;
          dom.byId('v03-j-grant')!.value = grant.grantId;
          dom.byId('v03-j-effect-run')!.click();
          await until(() => (dom.byId('v03-j-effect-status')?.textContent ?? '').length > 0);
          const completed = strings.t(locale, 'journeys.status.completed') as {
            ok: boolean;
            text?: string;
          };
          expect(completed.ok).toBe(true);
          expect(dom.byId('v03-j-effect-status')?.textContent).toContain(completed.text ?? '');
          // The REAL effect landed with the exact canary bytes.
          expect(existsSync(target)).toBe(true);
          expect(readFileSync(target, 'utf8')).toBe(canary);

          // --- provider family: Host-global first use through the UI
          // (R03C/#403 migration: one click runs prepare → confirm; the
          // closed-world receipt surfaces outcome facts, never stdout.)
          dom.byId('v03-j-provider-run')!.click();
          await until(() => (dom.byId('v03-j-provider-status')?.textContent ?? '').length > 0);
          expect(dom.byId('v03-j-provider-status')?.textContent).toContain(completed.text ?? '');
          expect(dom.byId('v03-j-provider-status')?.textContent).toContain(
            'PROVIDER_FIRST_USE_EXECUTED',
          );
          expect(dom.byId('v03-j-provider-status')?.textContent).toContain('canary MATCHED');
          // Closed-world honesty: the artifact identity never surfaces here.
          expect(dom.byId('v03-j-provider-status')?.textContent).not.toContain('ripgrep');

          // --- meta family: real durable Shadow candidate through the UI
          dom.byId('v03-j-meta-case')!.value = 'task-r03b-ui-src';
          dom.byId('v03-j-meta-revision')!.value = 'outcome-r1';
          dom.byId('v03-j-meta-rating')!.value = 'HELPFUL';
          dom.byId('v03-j-meta-category')!.value = 'OTHER';
          dom.byId('v03-j-meta-correction')!.value = 'NO_CORRECTION';
          const candidateIdsBeforeSubmit = new Set(
            store.listShadowCandidates().map((candidate) => candidate.candidateId),
          );
          dom.byId('v03-j-meta-run')!.click();
          await until(() => (dom.byId('v03-j-meta-status')?.textContent ?? '').length > 0);
          expect(dom.byId('v03-j-meta-status')?.textContent).toContain(completed.text ?? '');
          assertSingleNewMetaCandidate(store, candidateIdsBeforeSubmit);
        } finally {
          dom.restore();
        }
      });
    }

    it('locale zh strings are a strict parity catalog for every journeys key', () => {
      // The loop above already exercised both locales end to end; this guard
      // pins the catalog parity the UI contract requires.
      for (const key of [
        'journeys.title',
        'journeys.note',
        'journeys.refsNeeded',
        'journeys.status.completed',
        'journeys.status.refused',
        'journeys.status.unknown',
      ]) {
        for (const locale of ['en', 'zh'] as const) {
          const line = strings.t(locale, key) as { ok: boolean; text?: string };
          expect(line.ok, `${locale}:${key}`).toBe(true);
          expect((line.text ?? '').length).toBeGreaterThan(0);
        }
      }
    });
  },
);
