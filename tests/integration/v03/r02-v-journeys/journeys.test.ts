/**
 * R02-V zero-paid / zero-physical-effect user journeys over the REAL
 * product surfaces, executed on this actual Windows Node>=24 host.
 *
 * What is REAL here:
 *   - the shipping `createControlServer` HTTP surface on loopback;
 *   - the durable Guided Case (SQLite) and the production v0.3 gateway over
 *     the installed public v0.10.3 SDK consumer (real Kernel bytes);
 *   - J01: the REAL read-only B-040 Windows collector (no egress, no writes);
 *   - restart/replay fences on real SQLite files.
 *
 * The ONLY controlled double is the trusted T04 cloud interpreter port
 * (zero paid calls). J02 physical effects and J03 paid DeepSeek stay
 * OWNER_DEFERRED and are never claimed PASS here.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectWindowsSupportContext } from '@shun/vertical-support';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DemoShunBackend } from '../../../../apps/control-api/src/demo/backend.ts';
import { createControlServer } from '../../../../apps/control-api/src/server.ts';
import { createProductionV03Gateway } from '../../../../apps/control-api/src/v03/composition-production.ts';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { consumerDir } from '../r02-a-build/ensure-consumer.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const t11Fixtures = resolve(repoRoot, 'tests/integration/v03/t11-runtime/fixtures');
const shunModules = resolve(repoRoot, 'packages/domain-app/src/activation/modules');

const sha256Hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

function readPinned(name: string): string {
  return readFileSync(join(t11Fixtures, name), 'utf8');
}

function standardBundle(): string {
  const sdk = readPinned('standard-sdk-v1.mjs');
  const router = readPinned('workflow-router.mjs');
  const routerBody = router.replace(/^export /gm, '');
  return `${sdk}
const __dhv10RouterBundle = (() => {
${routerBody}
return { routeWorkflowIntent };
})();
export const routeWorkflowIntent = __dhv10RouterBundle.routeWorkflowIntent;
`;
}

function assembleBuild(dir: string): { buildFile: string; buildFileSha256: string } {
  const kernel = readPinned('kernel-mechanism-v1.mjs');
  const standard = standardBundle();
  const business = readFileSync(join(shunModules, 'business-goal.mjs'), 'utf8');
  const capability = readFileSync(join(shunModules, 'capability-llm.mjs'), 'utf8');
  const kernelFile = join(dir, 'kernel.mjs');
  const standardFile = join(dir, 'standard-bundle.mjs');
  writeFileSync(kernelFile, kernel);
  writeFileSync(standardFile, standard);
  const spec = {
    appId: 'shun-v03-goal',
    audience: 'operator-local',
    buildId: 'shun-v0.3-r02v-qualification',
    targetProfile: 'node24-esm/1',
    routes: [
      {
        intentId: 'goal-interpret',
        operationId: 'interpretGoal',
        capabilityId: 'llm',
        handlerId: 'interpretGoal',
      },
    ],
    hardBudget: { maxStepsPerTurn: 8, maxWorkUnitsPerTurn: 64 },
    modules: [
      {
        provenance: 'PUBLIC_DOMAIN_PACKAGE_V0103',
        sourceFile: kernelFile,
        sourceSha256: sha256Hex(kernel),
        module: {
          packageId: 'v08-kernel-mechanism@1.0.0',
          role: 'kernel-primary',
          abiVersion: 'v08-kernel-abi/1',
          endpoint: 'occurrence-runtime',
          dependencies: [],
          provides: ['kernel:occurrence-runtime/1'],
          requires: [],
        },
      },
      {
        provenance: 'PUBLIC_DOMAIN_PACKAGE_V0103',
        sourceFile: standardFile,
        sourceSha256: sha256Hex(standard),
        module: {
          packageId: 'standard-sdk@v08.1.0.0',
          role: 'standard-primary',
          abiVersion: 'v08-standard-sdk-abi/1',
          endpoint: 'rule-interpreter',
          dependencies: [],
          provides: ['standard:interpret/1', 'standard:route/1'],
          requires: [],
        },
      },
      {
        provenance: 'SHUN_TRUSTED_DOMAIN_PACKAGE',
        sourceFile: join(shunModules, 'business-goal.mjs'),
        sourceSha256: sha256Hex(business),
        module: {
          packageId: 'shun.business.goal@v0.3.0',
          role: 'business',
          abiVersion: 'v08-business-abi/1',
          endpoint: 'business-policy',
          dependencies: [],
          provides: ['intent:goal-interpret'],
          requires: [],
        },
      },
      {
        provenance: 'SHUN_TRUSTED_DOMAIN_PACKAGE',
        sourceFile: join(shunModules, 'capability-llm.mjs'),
        sourceSha256: sha256Hex(capability),
        module: {
          packageId: 'shun.capability.llm-openai-compatible@v0.3.0',
          role: 'capability',
          abiVersion: 'v08-capability-abi/1',
          endpoint: 'capability-endpoint',
          dependencies: [],
          externalImports: { node: [], npm: ['domain-harness-openai-host'], native: [] },
          provides: ['capability:llm/1'],
          requires: [],
          capabilityId: 'llm',
          externalEffect: true,
          handlers: [{ operationId: 'interpretGoal', handler: 'interpretGoal' }],
        },
      },
    ],
  };
  const specFile = join(dir, 'spec.json');
  const buildFile = join(dir, 'build.json');
  writeFileSync(specFile, JSON.stringify(spec, null, 2));
  const assembler = spawnSync(
    process.execPath,
    [join(repoRoot, 'scripts/v03-ci/assemble-trusted-build.mjs'), specFile, buildFile],
    { encoding: 'utf8' },
  );
  expect(assembler.status, `assembler failed: ${assembler.stderr?.slice(0, 2000)}`).toBe(0);
  return {
    buildFile,
    buildFileSha256: (JSON.parse(assembler.stdout) as { sha256: string }).sha256,
  };
}

function submission(caseId: string, goal: string): Record<string, unknown> {
  return {
    caseId,
    request: {
      taskId: caseId,
      goal,
      objects: [],
      constraints: {},
      policyContext: {
        privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
        environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
      },
    },
    currentnessRef: 'shun.currentness.v1/goal-r02v',
    approvalRef: 'shun.approval.v1/goal-r02v',
  };
}

async function json(
  port: number,
  method: string,
  path: string,
  body?: unknown,
): Promise<{
  status: number;
  body: unknown;
}> {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text === '' ? undefined : JSON.parse(text) };
}

describe('R02-V real-product journeys (zero paid, zero physical effects)', () => {
  let dir: string;
  let guided: HostGuidedService;
  let production: Awaited<ReturnType<typeof createProductionV03Gateway>>;
  let server: ReturnType<typeof createControlServer>;
  let bareServer: ReturnType<typeof createControlServer>;
  let port: number;
  let barePort: number;
  let caseId: string;
  let interpreterCalls = 0;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'shun-r02v-'));
    const now = Date.now();
    guided = new HostGuidedService(join(dir, 'guided.sqlite'));
    const staged = guided.stageTrustedSelection({
      observation: {
        schema: 'shun.guided.host-observation.v1',
        taskId: 'task-r02v-goal',
        journeyId: 'journey-r02v',
        sourceRef: 'host:obs:r02v',
        revision: 'r02v',
        caseRef: { snapshotId: 'snap-r02v', digest: 'c'.repeat(64) },
        observedAtUnixMs: now - 1_000,
        validUntilUnixMs: now + 3_600_000,
        evidenceRefs: ['host:scope:r02v'],
      },
      semanticSelection: {
        status: 'SELECTED',
        semantic: {
          schema: 'shun.goal-semantic.v1',
          taskId: 'task-r02v-goal',
          goalContract: { taskId: 'task-r02v-goal', objective: 'summarize selected folder' },
          capabilityId: 'system.storage.diagnose_bounded_action',
          capabilityRevision: 'r1',
          provenance: { resolverRevision: 'resolver-v03' },
        },
      },
      scope: { status: 'KNOWN', selectedRootRef: undefined },
    });
    expect(staged.status).toBe('CURRENT');
    if (staged.status !== 'CURRENT') throw new Error('staging failed');
    caseId = staged.step.taskId;

    const { buildFile, buildFileSha256 } = assembleBuild(dir);
    production = await createProductionV03Gateway({
      buildFile,
      buildFileSha256,
      sdkConsumerDir: consumerDir,
      kDocDatabaseFile: join(dir, 'k-docs.sqlite'),
      deploymentRoot: consumerDir,
      tenantId: 'tenant:shun-v03',
      deployedAppId: 'deployment:shun-v03-r02v',
      selectedCase: guided,
      llm: {
        interpreter: {
          status: () => ({
            enabled: true,
            provider: 'deepseek' as const,
            model: 'deepseek-flash' as const,
            osConsentRequired: true as const,
          }),
          interpretGoal: async (input: { goalText: string }) => {
            interpreterCalls++;
            return {
              ok: true,
              taskId: 'cloud-task-r02v',
              status: 'UNTRUSTED_REMOTE_PROPOSAL',
              proposalText: '{"proposalId":"r02v-proposal"}',
              model: 'deepseek-flash',
              costState: 'UNKNOWN_COST',
              executed: false,
              goalEcho: input.goalText,
            };
          },
        },
        journalFile: join(dir, 'cloud-journal.sqlite'),
        configuredMaxOutputTokens: 256,
      },
    });
    server = createControlServer({
      backend: new DemoShunBackend(),
      uiDir: resolve(repoRoot, 'apps/control-ui/public'),
      port: 0,
      v03Guided: guided,
      v03Gateway: production.gateway,
    });
    port = await server.start();
    // A second, gateway-less instance proves the truthful fail-closed boot.
    bareServer = createControlServer({ backend: new DemoShunBackend(), port: 0 });
    barePort = await bareServer.start();
  });

  afterAll(async () => {
    await server?.close();
    await bareServer?.close();
    try {
      production?.dispose();
    } catch {
      /* already disposed */
    }
    try {
      guided?.close();
    } catch {
      /* closed by the J06 restart journey */
    }
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        rmSync(dir, { recursive: true, force: true });
        break;
      } catch {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
      }
    }
  });

  it('J01: real Windows read-only B-040 collection, localOnly, zero egress', async () => {
    if (process.platform !== 'win32') {
      throw new Error('J01 journey requires the real Windows host');
    }
    const collected = await collectWindowsSupportContext();
    expect(collected.localOnly).toBe(true);
    expect(collected.externalDisclosures).toEqual([]);
    expect(collected.report.schema).toBe('shun.support-context.v1');
    // Truthful environment record (no fabricated locale/caption claims).
    const record = {
      platform: process.platform,
      node: process.version,
      osCaption: collected.report.os?.name ?? null,
      collectedAt: new Date().toISOString(),
    };
    console.log('[J01] real read-only host record:', JSON.stringify(record));
    expect(typeof collected.report.os?.name).toBe('string');
  });

  it('J07: the real HTTP surface serves the UI and guided state truthfully', async () => {
    const ui = await fetch(`http://127.0.0.1:${port}/v03/index.html`);
    expect(ui.status).toBe(200);
    expect((await ui.text()).includes('v03')).toBe(true);
    const state = await json(port, 'GET', '/api/v03/guided/state');
    expect(state.status).toBe(200);
    const body = state.body as { currentStep?: { taskId: string }; journey: { paused: boolean } };
    expect(body.currentStep?.taskId).toBe(caseId);
    expect(body.journey.paused).toBe(false);
  });

  it('J07/J03-shape: gateway submit over real HTTP completes the trusted proposal', async () => {
    const result = await json(
      port,
      'POST',
      '/api/v03/gateway/submit',
      submission(caseId, 'Summarize the selected folder.'),
    );
    expect(result.status).toBe(200);
    expect((result.body as { status: string }).status).toBe('COMPLETED');
    expect(interpreterCalls).toBe(1);
  });

  it('J04: identical resubmission is fenced by the K gate (no re-send)', async () => {
    const result = await json(
      port,
      'POST',
      '/api/v03/gateway/submit',
      submission(caseId, 'Summarize the selected folder.'),
    );
    expect(result.status).toBe(422);
    expect((result.body as { status: string }).status).toBe('KERNEL_REFUSED');
    expect(interpreterCalls).toBe(1);
  });

  it('J08: one atomic guided decision, 409 replay, and the consumed Case gates submits', async () => {
    const state = (await json(port, 'GET', '/api/v03/guided/state')).body as {
      currentStep?: {
        stepId: string;
        journeyId: string;
        taskId: string;
        templateRef: { digest: string };
        caseRef: unknown;
      };
    };
    const step = state.currentStep;
    expect(step).toBeTruthy();
    if (!step) return;
    const outcome = {
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
    };
    const relay = {
      kind: 'USER_DECISION_RELAY',
      humanApproval: true,
      authorityClaimed: false,
      decision: 'REFUSE',
      relayedVia: '/api',
      stepId: step.stepId,
      stepDigest: step.templateRef.digest,
      caseRef: step.caseRef,
      outcome,
    };
    const first = await json(port, 'POST', '/api/v03/guided/decision', relay);
    expect(first.status).toBe(200);
    expect(first.body).toMatchObject({
      status: 'RECORDED',
      humanGrantIssued: false,
      effectSent: false,
    });
    const replay = await json(port, 'POST', '/api/v03/guided/decision', relay);
    expect(replay.status).toBe(409);
    expect((replay.body as { status: string }).status).toBe('STALE');
    // The consumed Case can no longer authorize any K send.
    const gated = await json(
      port,
      'POST',
      '/api/v03/gateway/submit',
      submission(caseId, 'After consumption.'),
    );
    expect(gated.status).toBe(422);
    expect((gated.body as { status: string }).status).toBe('KERNEL_REFUSED');
    expect(interpreterCalls).toBe(1);
  });

  it('J06: guided/K durable state survives a process restart and keeps refusing replay', async () => {
    // Restart the trusted Host Guided service over the SAME SQLite file.
    guided.close();
    const reopened = new HostGuidedService(join(dir, 'guided.sqlite'));
    try {
      expect(reopened.state().currentStep).toBeUndefined();
      expect(reopened.state().history).toHaveLength(1);
      const again = reopened.stageTrustedSelection({
        observation: {
          schema: 'shun.guided.host-observation.v1',
          taskId: 'task-r02v-goal',
          journeyId: 'journey-r02v',
          sourceRef: 'host:obs:r02v',
          revision: 'r02v-2',
          caseRef: { snapshotId: 'snap-r02v', digest: 'c'.repeat(64) },
          observedAtUnixMs: Date.now() - 1_000,
          validUntilUnixMs: Date.now() + 3_600_000,
          evidenceRefs: ['host:scope:r02v'],
        },
        semanticSelection: {
          status: 'SELECTED',
          semantic: {
            schema: 'shun.goal-semantic.v1',
            taskId: 'task-r02v-goal',
            goalContract: { taskId: 'task-r02v-goal', objective: 'summarize selected folder' },
            capabilityId: 'system.storage.diagnose_bounded_action',
            capabilityRevision: 'r1',
            provenance: { resolverRevision: 'resolver-v03' },
          },
        },
        scope: { status: 'KNOWN', selectedRootRef: undefined },
      });
      // A genuinely NEW Host observation revision may stage a next step.
      expect(again.status).toBe('CURRENT');
    } finally {
      reopened.close();
      // Reopen the service handle the running server was built with is not
      // possible after close; the remaining assertions are HTTP-free.
    }
  });

  it('J07 truth: a gateway-less boot answers 503, never a fake success', async () => {
    const result = await json(barePort, 'POST', '/api/v03/gateway/submit', submission(caseId, 'x'));
    expect(result.status).toBe(503);
    expect(result.body).toMatchObject({ ok: false, code: 'V03_GATEWAY_UNAVAILABLE' });
    const guidedToo = await json(barePort, 'GET', '/api/v03/guided/state');
    expect(guidedToo.status).toBe(503);
  });

  it('J07 truth: hostile input is refused pre-send with 422', async () => {
    const hostile = { ...submission(caseId, 'x'), approvalObject: { grant: true } };
    const extraKey = { ...submission(caseId, 'x'), extra: 1 };
    for (const body of [hostile, extraKey]) {
      const result = await json(port, 'POST', '/api/v03/gateway/submit', body);
      expect(result.status).toBe(422);
      expect((result.body as { status: string }).status).toBe('REFUSED');
    }
    expect(interpreterCalls).toBe(1);
  });
});
