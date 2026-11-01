/**
 * Shared R02-V production-stack harness. Extracted from journeys.test.ts
 * (same lane write set) so the authorized live journeys (J03 real cloud) can
 * boot the IDENTICAL real stack — trusted Guided Case (SQLite), the trusted
 * BUILD assembled from the pinned public v0.10.3 fixtures, the production
 * v0.3 gateway over the installed SDK consumer and the real loopback HTTP
 * control server — with only the T04 interpreter port differing.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DemoShunBackend } from '../../../../apps/control-api/src/demo/backend.ts';
import { createControlServer } from '../../../../apps/control-api/src/server.ts';
import { createProductionV03Gateway } from '../../../../apps/control-api/src/v03/composition-production.ts';
import type { TrustedLlmInterpreterPort } from '../../../../apps/control-api/src/v03/composition-production.ts';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { consumerDir } from '../r02-a-build/ensure-consumer.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const t11Fixtures = resolve(repoRoot, 'tests/integration/v03/t11-runtime/fixtures');
const shunModules = resolve(repoRoot, 'packages/domain-app/src/activation/modules');

export const sha256Hex = (value: string): string =>
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

function trustedModule(
  provenance: string,
  sourceFile: string,
  bytes: string,
  module: Record<string, unknown>,
): { provenance: string; sourceFile: string; sourceSha256: string; module: Record<string, unknown> } {
  return { provenance, sourceFile, sourceSha256: sha256Hex(bytes), module };
}

/**
 * R03-INT journey modules: the windows effect, provider first-use and meta
 * feedback Business/Capability Domain Packages, wired exactly like the goal
 * pair over the same pinned public SDK bytes.
 */
function journeyModules(wanted: {
  windows?: boolean;
  provider?: boolean;
  meta?: boolean;
}): {
  modules: ReturnType<typeof trustedModule>[];
  routes: Record<string, string>[];
} {
  const read = (name: string): string => readFileSync(join(shunModules, name), 'utf8');
  const windowsBusiness = read('business-windows.mjs');
  const windowsCapability = read('capability-windows-effect.mjs');
  const providerBusiness = read('business-provider.mjs');
  const providerCapability = read('capability-provider.mjs');
  const metaBusiness = read('business-meta.mjs');
  const metaCapability = read('capability-meta.mjs');
  const modules: ReturnType<typeof trustedModule>[] = [];
  const routes: Record<string, string>[] = [];
  if (wanted.windows) {
    modules.push(
      trustedModule('SHUN_TRUSTED_DOMAIN_PACKAGE', join(shunModules, 'business-windows.mjs'), windowsBusiness, {
        packageId: 'shun.business.windows@v0.3.0',
        role: 'business',
        abiVersion: 'v08-business-abi/1',
        endpoint: 'business-policy',
        dependencies: [],
        provides: ['intent:submitWindowsAction', 'intent:submitUnpermittedWindowsProbe'],
        requires: [],
      }),
    );
    modules.push(
      trustedModule('SHUN_TRUSTED_DOMAIN_PACKAGE', join(shunModules, 'capability-windows-effect.mjs'), windowsCapability, {
        packageId: 'shun.capability.windows-executor@v0.3.0',
        role: 'capability',
        abiVersion: 'v08-capability-abi/1',
        endpoint: 'capability-endpoint',
        dependencies: [],
        externalImports: { node: [], npm: ['shun-windows-effect-host'], native: [] },
        provides: ['capability:windows/1'],
        requires: [],
        capabilityId: 'windows',
        externalEffect: true,
        handlers: [{ operationId: 'windows.execute', handler: 'windowsExecute' }],
      }),
    );
    routes.push(
      { intentId: 'submitWindowsAction', operationId: 'windows.execute', capabilityId: 'windows', handlerId: 'windowsExecute' },
      { intentId: 'submitUnpermittedWindowsProbe', operationId: 'windows.execute', capabilityId: 'windows', handlerId: 'windowsExecute' },
    );
  }
  if (wanted.provider) {
    modules.push(
      trustedModule('SHUN_TRUSTED_DOMAIN_PACKAGE', join(shunModules, 'business-provider.mjs'), providerBusiness, {
        packageId: 'shun.business.provider@v0.3.0',
        role: 'business',
        abiVersion: 'v08-business-abi/1',
        endpoint: 'business-policy',
        dependencies: [],
        provides: ['intent:submitProviderFirstUse'],
        requires: [],
      }),
    );
    modules.push(
      trustedModule('SHUN_TRUSTED_DOMAIN_PACKAGE', join(shunModules, 'capability-provider.mjs'), providerCapability, {
        packageId: 'shun.capability.provider-first-use@v0.3.0',
        role: 'capability',
        abiVersion: 'v08-capability-abi/1',
        endpoint: 'capability-endpoint',
        dependencies: [],
        externalImports: { node: [], npm: ['shun-provider-host'], native: [] },
        provides: ['capability:provider/1'],
        requires: [],
        capabilityId: 'provider',
        externalEffect: true,
        handlers: [{ operationId: 'provider.firstUse', handler: 'providerFirstUse' }],
      }),
    );
    routes.push(
      { intentId: 'submitProviderFirstUse', operationId: 'provider.firstUse', capabilityId: 'provider', handlerId: 'providerFirstUse' },
    );
  }
  if (wanted.meta) {
    modules.push(
      trustedModule('SHUN_TRUSTED_DOMAIN_PACKAGE', join(shunModules, 'business-meta.mjs'), metaBusiness, {
        packageId: 'shun.business.meta@v0.3.0',
        role: 'business',
        abiVersion: 'v08-business-abi/1',
        endpoint: 'business-policy',
        dependencies: [],
        provides: ['intent:submitMetaFeedback'],
        requires: [],
      }),
    );
    modules.push(
      trustedModule('SHUN_TRUSTED_DOMAIN_PACKAGE', join(shunModules, 'capability-meta.mjs'), metaCapability, {
        packageId: 'shun.capability.meta-feedback@v0.3.0',
        role: 'capability',
        abiVersion: 'v08-capability-abi/1',
        endpoint: 'capability-endpoint',
        dependencies: [],
        externalImports: { node: [], npm: ['shun-meta-host'], native: [] },
        provides: ['capability:meta/1'],
        requires: [],
        capabilityId: 'meta',
        externalEffect: true,
        handlers: [{ operationId: 'meta.submitFeedback', handler: 'submitMetaFeedback' }],
      }),
    );
    routes.push(
      { intentId: 'submitMetaFeedback', operationId: 'meta.submitFeedback', capabilityId: 'meta', handlerId: 'submitMetaFeedback' },
    );
  }
  return { modules, routes };
}

export function assembleBuild(
  dir: string,
  options?: { readonly journeys?: { windows?: boolean; provider?: boolean; meta?: boolean } },
): { buildFile: string; buildFileSha256: string } {
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
  if (options?.journeys) {
    const journey = journeyModules(options.journeys);
    (spec.modules as unknown[]).push(...journey.modules);
    (spec.routes as unknown[]).push(...journey.routes);
  }
  const specFile = join(dir, 'spec.json');
  const buildFile = join(dir, 'build.json');
  writeFileSync(specFile, JSON.stringify(spec, null, 2));
  const assembler = spawnSync(
    process.execPath,
    [join(repoRoot, 'scripts/v03-ci/assemble-trusted-build.mjs'), specFile, buildFile],
    { encoding: 'utf8' },
  );
  if (assembler.status !== 0) {
    throw new Error(`assembler failed: ${assembler.stderr?.slice(0, 2000)}`);
  }
  return {
    buildFile,
    buildFileSha256: (JSON.parse(assembler.stdout) as { sha256: string }).sha256,
  };
}

export interface LiveStack {
  dir: string;
  guided: HostGuidedService;
  production: Awaited<ReturnType<typeof createProductionV03Gateway>>;
  server: ReturnType<typeof createControlServer>;
  port: number;
  caseId: string;
  submitRefs(): { currentnessRef: string; approvalRef: string };
  close(): Promise<void>;
}

/** Boot the identical real stack; only the interpreter port is injected. */
export async function bootLiveStack(options: {
  interpreter: TrustedLlmInterpreterPort;
  prefix: string;
  journeys?: {
    manifest?: { windows?: boolean; provider?: boolean; meta?: boolean };
    bindings?: import('../../../../apps/control-api/src/v03/composition-journeys.ts').JourneyBindingsConfig;
  };
}): Promise<LiveStack> {
  const dir = mkdtempSync(join(tmpdir(), options.prefix));
  const guided = new HostGuidedService(join(dir, 'guided.sqlite'));
  const now = Date.now();
  const staged = guided.stageTrustedSelection({
    observation: {
      schema: 'shun.guided.host-observation.v1',
      taskId: 'task-r02v-live',
      journeyId: 'journey-r02v-live',
      sourceRef: 'host:obs:r02v-live',
      revision: 'r02v-live',
      caseRef: { snapshotId: 'snap-r02v-live', digest: 'c'.repeat(64) },
      observedAtUnixMs: now - 1_000,
      validUntilUnixMs: now + 3_600_000,
      evidenceRefs: ['host:scope:r02v-live'],
    },
    semanticSelection: {
      status: 'SELECTED',
      semantic: {
        schema: 'shun.goal-semantic.v1',
        taskId: 'task-r02v-live',
        goalContract: { taskId: 'task-r02v-live', objective: 'summarize selected folder' },
        capabilityId: 'system.storage.diagnose_bounded_action',
        capabilityRevision: 'r1',
        provenance: { resolverRevision: 'resolver-v03' },
      },
    },
    scope: { status: 'KNOWN', selectedRootRef: undefined },
  });
  if (staged.status !== 'CURRENT') throw new Error('live stack staging failed');
  const caseId = staged.step.taskId;
  const { buildFile, buildFileSha256 } = assembleBuild(dir, { journeys: options.journeys?.manifest });
  const production = await createProductionV03Gateway({
    buildFile,
    buildFileSha256,
    sdkConsumerDir: consumerDir,
    kDocDatabaseFile: join(dir, 'k-docs.sqlite'),
    deploymentRoot: consumerDir,
    tenantId: 'tenant:shun-v03',
    deployedAppId: 'deployment:shun-v03-r02v-live',
    selectedCase: guided,
    llm: {
      interpreter: options.interpreter,
      journalFile: join(dir, 'cloud-journal.sqlite'),
      configuredMaxOutputTokens: 1024,
    },
    approvalLedgerFile: join(dir, 'submit-references.sqlite'),
    journeys: options.journeys?.bindings,
  });
  const server = createControlServer({
    backend: new DemoShunBackend(),
    uiDir: resolve(repoRoot, 'apps/control-ui/public'),
    port: 0,
    v03Guided: guided,
    v03Gateway: production.gateway,
    v03Journeys: production.journeys,
  });
  const port = await server.start();
  return {
    dir,
    guided,
    production,
    server,
    port,
    caseId,
    // Each submission uses a FRESH Host-issued pair (old pairs are superseded).
    submitRefs() {
      const issued = production.issueSubmitReferences();
      if (issued.status !== 'ISSUED') throw new Error(`reference issuance refused: ${issued.status}`);
      return { currentnessRef: issued.currentnessRef, approvalRef: issued.approvalRef };
    },
    async close() {
      await server.close();
      try {
        production.dispose();
      } catch {
        /* already disposed */
      }
      try {
        guided.close();
      } catch {
        /* already closed */
      }
    },
  };
}

export function submission(
  caseId: string,
  goal: string,
  refs: { currentnessRef: string; approvalRef: string },
): Record<string, unknown> {
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
    currentnessRef: refs.currentnessRef,
    approvalRef: refs.approvalRef,
  };
}

export async function json(
  port: number,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: unknown }> {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text === '' ? undefined : JSON.parse(text) };
}
