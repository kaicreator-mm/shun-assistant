/**
 * R03C-PROVIDER-GLOBAL-ROUTE — Host-global Provider prepare/confirm over the
 * REAL production composition and the REAL loopback HTTP control surface
 * (Issue #288, LOCAL_BUILDER generation 1).
 *
 * Proves the R03C contract end-to-end through HTTP → trusted composition →
 * selected public v0.10.3 K (live external Effect Permit) → staged
 * shun-provider-host binding over the real signed-descriptor chain with
 * injected artifact/spawn seams (zero real child processes, zero UAC):
 *   - prepare succeeds with NO Guided Case, no Case ID, no currentnessRef and
 *     no approvalRef, and returns the exact closed preview;
 *   - confirm consumes the one-time Host requestRef and submits the FIXED
 *     Business Intent (instanceKey provider-global, payload exactly
 *     {requestRef}) — the HTTP surface exposes no intent/instance/path/args/
 *     privilege input at all;
 *   - malformed/replayed/unknown requestRefs refuse with zero activations;
 *   - queryAuthority is never consulted for send authorization (no Case is
 *     even selected while reference issuance refuses);
 *   - receipts stay closed-world: no raw provider stdout/stderr anywhere.
 */
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DemoShunBackend } from '../../../../apps/control-api/src/demo/backend.ts';
import { createControlServer } from '../../../../apps/control-api/src/server.ts';
import {
  createProductionV03Gateway,
  type TrustedLlmInterpreterPort,
} from '../../../../apps/control-api/src/v03/composition-production.ts';
import { canonicalJson } from '../../../../packages/contracts/src/plan.ts';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import type { ActivationRunSpec } from '../../../../packages/provider-loader/src/activation.ts';
import { consumerDir, ensureV03SdkConsumer } from '../r02-a-build/ensure-consumer.mjs';

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

const ARTIFACT_BYTES = Buffer.from('pinned trusted rg fixture bytes', 'utf8');
const keyPair = generateKeyPairSync('ed25519');

function providerScope(artifactSha256: string): Record<string, unknown> {
  return {
    providerId: 'rg',
    capabilityId: 'file.search',
    version: '14.1.1',
    catalogRevision: 'catalog-v1',
    bindingId: 'rg-binding',
    scopedVerifierId: 'safe-verifier',
    catalogManifestSha256: 'a'.repeat(64),
    bindingEvidenceSha256: 'b'.repeat(64),
    artifactSha256,
    origin: 'https://trusted.invalid/rg.exe',
    platform: 'windows-x64',
    artifactKind: 'CLI',
  };
}

function makeDescriptor(trust: Record<string, unknown>): Record<string, unknown> {
  const unsigned = {
    ...trust,
    entrypoint: 'rg.exe',
    signerKeyId: 'key-1',
    dependencySha256: [] as string[],
  };
  return {
    ...unsigned,
    curatorSignature: sign(null, Buffer.from(canonicalJson(unsigned)), keyPair.privateKey).toString(
      'base64',
    ),
  };
}

interface CapturedRun {
  readonly specs: ActivationRunSpec[];
  readonly port: unknown;
}

/** Capturing spawn port: the real chain runs, no real child process starts. */
function capturePort(): CapturedRun {
  const specs: ActivationRunSpec[] = [];
  const port = {
    specs,
    async run(spec: ActivationRunSpec): Promise<{
      exitCode: number;
      stdout: string;
      stderr: string;
      timedOut: boolean;
      stdoutTruncated: boolean;
      stderrTruncated: boolean;
    }> {
      specs.push(spec);
      return {
        exitCode: 0,
        stdout: spec.args.includes('SHUN-PROVIDER-FIRST-USE')
          ? 'noise\nSHUN-PROVIDER-FIRST-USE matched\n'
          : 'ripgrep 14.1.1',
        stderr: '',
        timedOut: false,
        stdoutTruncated: false,
        stderrTruncated: false,
      };
    },
  };
  return { specs, port };
}

function assembleBuild(dir: string): { buildFile: string; buildFileSha256: string } {
  const kernel = readPinned('kernel-mechanism-v1.mjs');
  const standard = standardBundle();
  const business = readFileSync(join(shunModules, 'business-goal.mjs'), 'utf8');
  const capability = readFileSync(join(shunModules, 'capability-llm.mjs'), 'utf8');
  const providerBusiness = readFileSync(join(shunModules, 'business-provider.mjs'), 'utf8');
  const providerCapability = readFileSync(join(shunModules, 'capability-provider.mjs'), 'utf8');
  const kernelFile = join(dir, 'kernel.mjs');
  const standardFile = join(dir, 'standard-bundle.mjs');
  writeFileSync(kernelFile, kernel);
  writeFileSync(standardFile, standard);
  const spec = {
    appId: 'shun-v03-goal',
    audience: 'operator-local',
    buildId: 'shun-v0.3-r03c-provider-global-route',
    targetProfile: 'node24-esm/1',
    routes: [
      { intentId: 'goal-interpret', operationId: 'interpretGoal', capabilityId: 'llm', handlerId: 'interpretGoal' },
      { intentId: 'submitProviderFirstUse', operationId: 'provider.firstUse', capabilityId: 'provider', handlerId: 'providerFirstUse' },
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
      {
        provenance: 'SHUN_TRUSTED_DOMAIN_PACKAGE',
        sourceFile: join(shunModules, 'business-provider.mjs'),
        sourceSha256: sha256Hex(providerBusiness),
        module: {
          packageId: 'shun.business.provider@v0.3.0',
          role: 'business',
          abiVersion: 'v08-business-abi/1',
          endpoint: 'business-policy',
          dependencies: [],
          provides: ['intent:submitProviderFirstUse'],
          requires: [],
        },
      },
      {
        provenance: 'SHUN_TRUSTED_DOMAIN_PACKAGE',
        sourceFile: join(shunModules, 'capability-provider.mjs'),
        sourceSha256: sha256Hex(providerCapability),
        module: {
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
  if (assembler.status !== 0) {
    throw new Error(`assembler failed: ${assembler.stderr?.slice(0, 2000)}`);
  }
  return {
    buildFile,
    buildFileSha256: (JSON.parse(assembler.stdout) as { sha256: string }).sha256,
  };
}

const disabledInterpreter: TrustedLlmInterpreterPort = {
  status: () => ({
    enabled: false,
    provider: 'deepseek' as const,
    model: 'deepseek-flash' as const,
    osConsentRequired: true as const,
  }),
  interpretGoal: async () => ({ ok: false, code: 'CLOUD_UNAVAILABLE' }),
};

async function json(
  port: number,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text === '' ? {} : (JSON.parse(text) as Record<string, unknown>),
  };
}

function receiptOutput(body: Record<string, unknown>): Record<string, unknown> {
  const result = body.result as {
    admitted?: { effects?: { output?: { outcome?: { output?: unknown } } }[] };
  };
  return (result?.admitted?.effects?.[0]?.output?.outcome?.output ?? {}) as Record<string, unknown>;
}

describe('R03C: Host-global Provider prepare/confirm route (production composition + HTTP)', () => {
  let dir: string;
  let guided: HostGuidedService;
  let production: Awaited<ReturnType<typeof createProductionV03Gateway>>;
  let server: ReturnType<typeof createControlServer>;
  let port: number;
  let specs: ActivationRunSpec[];
  let firstRequestRef = '';

  beforeAll(async () => {
    ensureV03SdkConsumer();
    dir = mkdtempSync(join(tmpdir(), 'shun-r03c-provider-global-route-'));
    const { buildFile, buildFileSha256 } = assembleBuild(dir);
    guided = new HostGuidedService(join(dir, 'guided.sqlite'));
    const capture = capturePort();
    specs = capture.specs;
    const artifactSha256 = sha256Hex(ARTIFACT_BYTES.toString('utf8'));
    const trust = providerScope(artifactSha256);
    production = await createProductionV03Gateway({
      buildFile,
      buildFileSha256,
      sdkConsumerDir: consumerDir,
      kDocDatabaseFile: join(dir, 'k-docs.sqlite'),
      deploymentRoot: consumerDir,
      tenantId: 'tenant:shun-v03',
      deployedAppId: 'deployment:shun-v03-r03c-provider-global',
      selectedCase: guided,
      llm: {
        interpreter: disabledInterpreter,
        journalFile: join(dir, 'cloud-journal.sqlite'),
        configuredMaxOutputTokens: 1024,
      },
      approvalLedgerFile: join(dir, 'submit-references.sqlite'),
      journeys: {
        provider: {
          cacheRoot: join(dir, 'provider-cache'),
          roots: [
            {
              keyId: 'key-1',
              publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
            },
          ],
          scopes: [trust],
          descriptor: makeDescriptor(trust),
          taskId: 'provider-global',
          revocationEpoch: 1,
          hostFacts: { platform: 'win32', architecture: 'x64', nodeAbi: '137' },
          fetchArtifact: (async () => new Response(ARTIFACT_BYTES, { status: 200 })) as typeof fetch,
          process: capture.port,
        },
      },
    });
    expect(production.providerGlobal).toBeTruthy();
    server = createControlServer({
      backend: new DemoShunBackend(),
      uiDir: resolve(repoRoot, 'apps/control-ui/public'),
      port: 0,
      v03Guided: guided,
      v03Journeys: production.journeys,
      v03ProviderGlobal: production.providerGlobal,
    });
    port = await server.start();
  }, 120_000);

  afterAll(async () => {
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
    // Release the module-global trusted binding singleton for this process.
    const shim = (await import(
      pathToFileURL(join(consumerDir, 'node_modules/shun-provider-host/index.mjs')).href
    )) as { closeTrustedProviderBinding?: () => void };
    try {
      shim.closeTrustedProviderBinding?.();
    } catch {
      /* already released */
    }
    // A durable handle may still be releasing the file; retry briefly.
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        rmSync(dir, { recursive: true, force: true });
        break;
      } catch {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
      }
    }
  });

  it('no Guided Case is selected — the Host-global route needs none', () => {
    const state = guided.state() as { currentStep?: unknown };
    expect(state.currentStep ?? null).toBeNull();
    // Host reference issuance refuses: no live step exists at all. The
    // provider flow below still succeeds — queryAuthority/Case admission is
    // never consulted for this send.
    expect(production.issueSubmitReferences().status).toBe('REFUSED');
  });

  it('POST /api/v03/provider/prepare issues a Host requestRef + exact closed preview', async () => {
    const { status, body } = await json(port, 'POST', '/api/v03/provider/prepare');
    expect(status).toBe(200);
    expect(body.status).toBe('PREPARED');
    firstRequestRef = body.requestRef as string;
    expect(firstRequestRef).toMatch(/^provider-request-[0-9a-f-]{36}$/);
    expect(typeof body.expiresAtUnixMs).toBe('number');
    const preview = body.preview as Record<string, unknown>;
    // Closed-world preview: identity + privilege scope only, no stdout/secrets.
    expect(preview.privilegeScope).toBe('USER');
    expect(preview.elevatedAction).toBeUndefined();
    expect(preview.artifactSha256).toBe(sha256Hex(ARTIFACT_BYTES.toString('utf8')));
    expect(JSON.stringify(body)).not.toContain('stdout');
    expect(JSON.stringify(body)).not.toContain('stderr');
  });

  it('a second prepare while one request is pending refuses (one pending request)', async () => {
    const { status, body } = await json(port, 'POST', '/api/v03/provider/prepare');
    expect(status).toBe(422);
    expect(body.code).toBe('PROVIDER_FIRST_USE_ALREADY_PENDING');
  });

  it('confirm refuses caller-shaped bodies with zero K sends and zero executions', async () => {
    const attempts: unknown[] = [
      {},
      { requestRef: 42 },
      { requestRef: 'provider-request-' + '0'.repeat(36), intentType: 'goal-interpret' },
      { requestRef: 'provider-request-' + '0'.repeat(36), instanceKey: 'other-instance' },
      { requestRef: 'provider-request-' + '0'.repeat(36), privilege: 'ELEVATED' },
      { requestRef: 'provider-request-' + '0'.repeat(36), path: 'C:\\evil.exe' },
    ];
    for (const body of attempts) {
      const result = await json(port, 'POST', '/api/v03/provider/confirm', body);
      expect(result.status).toBe(422);
      expect((result.body as { status?: string }).status).toBe('REFUSED');
      expect((result.body as { code?: string }).code).toBe('GATEWAY_INPUT_INVALID');
    }
    expect(specs.length).toBe(0);
  });

  it('POST /api/v03/provider/confirm consumes the one-time requestRef and completes the real chain', async () => {
    const { status, body } = await json(port, 'POST', '/api/v03/provider/confirm', {
      requestRef: firstRequestRef,
    });
    expect(status).toBe(200);
    expect(body.status).toBe('COMPLETED');
    const output = receiptOutput(body);
    expect(output.outcome).toBe('EXECUTED');
    expect(output.code).toBe('PROVIDER_FIRST_USE_EXECUTED');
    expect(output.exitCode).toBe(0);
    expect(output.canaryResult).toBe('MATCHED');
    expect(output.bindingId).toBe('rg-binding');
    // Closed-world receipt: raw provider stdout/stderr never surface.
    expect(output.stdout).toBeUndefined();
    expect(output.stderr).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain('ripgrep 14.1.1');
    // The real chain ran exactly the probe + canary activations.
    expect(specs.length).toBe(2);
    expect(specs.some((spec) => spec.args.includes('SHUN-PROVIDER-FIRST-USE'))).toBe(true);
  });

  it('replayed requestRef refuses with zero new executions', async () => {
    const { status, body } = await json(port, 'POST', '/api/v03/provider/confirm', {
      requestRef: firstRequestRef,
    });
    expect(status).toBe(422);
    expect(body.code).toBe('PROVIDER_REQUEST_NOT_PREPARED');
    expect(specs.length).toBe(2);
  });

  it('unknown requestRef refuses before any activation', async () => {
    const { status, body } = await json(port, 'POST', '/api/v03/provider/confirm', {
      requestRef: 'provider-request-' + '1'.repeat(36),
    });
    expect(status).toBe(422);
    expect(body.code).toBe('PROVIDER_REQUEST_NOT_PREPARED');
    expect(specs.length).toBe(2);
  });

  it('a fresh prepare/confirm cycle works again after completion (durable ledger)', async () => {
    const prepared = await json(port, 'POST', '/api/v03/provider/prepare');
    expect(prepared.status).toBe(200);
    const { status, body } = await json(port, 'POST', '/api/v03/provider/confirm', {
      requestRef: prepared.body.requestRef,
    });
    expect(status).toBe(200);
    expect(body.status).toBe('COMPLETED');
    expect(specs.length).toBe(4);
  });
});
