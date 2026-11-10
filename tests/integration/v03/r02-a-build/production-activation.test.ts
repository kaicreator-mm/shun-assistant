/**
 * R02-A production activation closure — the REAL public v0.10.3 SDK closure.
 *
 * Chain proven here (zero paid calls, zero physical effects):
 *   operator manifest assembly (scripts/v03-ci/assemble-trusted-build.mjs)
 *     → composeTrustedRuntimeBuild (admission boundary)
 *     → REAL buildV10App + activateV10App installed from the pinned v0.10.3
 *       tag tarballs (node_modules/.v03-sdk-consumer)
 *     → REAL selected K bytes (kernel-mechanism-v1.mjs, SHA-pinned) with the
 *       REAL Shun B (business-goal.mjs) and C (capability-llm.mjs) modules
 *     → facade.send(goal-interpret) → kernel-minted external Effect Permit
 *     → the C's single ordinary import resolves the trusted
 *       domain-harness-openai-host binding → REAL T04 static generate entry
 *       (controlled interpreter double + memory journal: no network, no key).
 *
 * The selected C enforces the exact dh.llm.generate/1 contract; consent
 * decline and unknown remote outcomes keep their truthful terminal receipts
 * with exactly one interpreter entry (no second sender, no blind retry).
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { activatePublicShunDomainApp } from '../../../../packages/domain-app/src/activation/public-sdk.ts';
import { composeTrustedRuntimeBuild } from '../../../../packages/domain-app/src/activation/trusted-build.ts';
import { buildNeutralGoalRequest } from '../../../../packages/domain-computer/src/cloud/goal-request.ts';
import type { ShunLlmGenerateRequestV1 } from '../../../../packages/domain-computer/src/contracts/llm-generate-v1.ts';
import { SqliteKernelDocStore } from '../../../../packages/domain-host/src/state/kernel-doc-store.ts';
import { consumerDir } from './ensure-consumer.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const t11Fixtures = resolve(repoRoot, 'tests/integration/v03/t11-runtime/fixtures');
const shunModules = resolve(repoRoot, 'packages/domain-app/src/activation/modules');

const KERNEL_PACKAGE_ID = 'v08-kernel-mechanism@1.0.0';
const STANDARD_PACKAGE_ID = 'standard-sdk@v08.1.0.0';
const BUSINESS_PACKAGE_ID = 'shun.business.goal@v0.3.0';
const CAPABILITY_PACKAGE_ID = 'shun.capability.llm-openai-compatible@v0.3.0';
const TENANT = 'tenant:shun-v03';
const NOW = Date.UTC(2026, 10, 1, 0, 0, 0);

function sha256Hex(value: string): Buffer | string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function readPinned(name: string): { source: string; sha256: string } {
  const source = readFileSync(join(t11Fixtures, name), 'utf8');
  const receipts = new Map<string, string>();
  for (const line of readFileSync(join(t11Fixtures, 'SHA256SUMS.txt'), 'utf8').split(/\r?\n/)) {
    const match = line.match(/^([0-9a-f]{64})\s+\*?(.+)$/);
    const [, digest, fileName] = match ?? [];
    if (typeof digest === 'string' && typeof fileName === 'string') {
      receipts.set(fileName.trim(), digest);
    }
  }
  const expected = receipts.get(name);
  if (!expected) throw new Error(`missing receipt for ${name}`);
  expect(sha256Hex(source)).toBe(expected);
  return { source, sha256: expected };
}

/** The upstream BUILD-style vendored Standard bundle (SDK + WorkflowRouter). */
function standardBundle(): string {
  const sdk = readPinned('standard-sdk-v1.mjs').source;
  const router = readPinned('workflow-router.mjs').source;
  const routerBody = router.replace(/^export /gm, '');
  return `${sdk}
// R02-A BUILD-style vendored bundle: the pure Standard WorkflowRouter.
const __dhv10RouterBundle = (() => {
${routerBody}
return { routeWorkflowIntent };
})();
export const routeWorkflowIntent = __dhv10RouterBundle.routeWorkflowIntent;
`;
}

interface InterpreterDouble {
  calls: { goalText: string; deadlineUnixMs: number }[];
  nextResult: 'proposal' | 'consent-declined' | 'remote-refused';
}

function interpreterDouble(): InterpreterDouble {
  const state: InterpreterDouble = { calls: [], nextResult: 'proposal' };
  return state;
}

/** The trusted T04 host sees only the frozen port; no key, no network.
 * The install MUST go through the SAME module instance the capability's
 * domain-harness-openai-host import resolves to, or the module-global
 * installed binding would stay empty in that instance. */
async function installTrustedBinding(state: InterpreterDouble, now: () => number): Promise<void> {
  const rows = new Map<
    string,
    { requestSha256: string; result?: ShunLlmGenerateRequestV1 | unknown }
  >();
  const binding = (await import('domain-harness-openai-host')) as {
    installTrustedCloudHostBinding: (config: unknown) => void;
  };
  binding.installTrustedCloudHostBinding({
    interpreter: {
      status: () => ({
        enabled: true,
        provider: 'deepseek',
        model: 'deepseek-flash',
        osConsentRequired: true,
      }),
      interpretGoal: async (input: { goalText: string; deadlineUnixMs: number }) => {
        state.calls.push({ goalText: input.goalText, deadlineUnixMs: input.deadlineUnixMs });
        if (state.nextResult === 'consent-declined') {
          return { ok: false, code: 'CONSENT_DECLINED' };
        }
        if (state.nextResult === 'remote-refused') {
          return { ok: false, code: 'REMOTE_REFUSED' };
        }
        return {
          ok: true,
          taskId: 'cloud-task-r02a',
          status: 'UNTRUSTED_REMOTE_PROPOSAL',
          proposalText: '{"proposalId":"untrusted-proposal","summary":"r02a"}',
          model: 'deepseek-flash',
          costState: 'UNKNOWN_COST',
          executed: false,
        };
      },
    },
    journal: {
      durability: 'DURABLE_SHUN_STORE',
      reserve: async (input: { requestId: string; requestSha256: string }) => {
        const prior = rows.get(input.requestId);
        if (!prior) {
          rows.set(input.requestId, { requestSha256: input.requestSha256 });
          return { status: 'RESERVED' };
        }
        if (prior.requestSha256 !== input.requestSha256) return { status: 'CONFLICT' };
        return prior.result ? { status: 'REPLAY', result: prior.result } : { status: 'IN_FLIGHT' };
      },
      complete: async (input: { requestId: string; requestSha256: string; result: unknown }) => {
        const prior = rows.get(input.requestId);
        if (!prior || prior.requestSha256 !== input.requestSha256 || prior.result) return false;
        prior.result = input.result;
        return true;
      },
    },
    configuredMaxOutputTokens: 256,
    now,
  });
}

interface Activated {
  facade: { send(payload: unknown): Promise<Record<string, unknown>> };
  dispose(): void;
  subjectDigest: string;
  store: SqliteKernelDocStore;
}

function assembleTrustedBuild(dir: string): { buildFile: string; buildFileSha256: string } {
  const kernel = readPinned('kernel-mechanism-v1.mjs');
  const standard = { source: standardBundle(), sha256: '' };
  standard.sha256 = sha256Hex(standard.source) as string;
  const business = readFileSync(join(shunModules, 'business-goal.mjs'), 'utf8');
  const capability = readFileSync(join(shunModules, 'capability-llm.mjs'), 'utf8');
  const kernelFile = join(dir, 'kernel.mjs');
  const standardFile = join(dir, 'standard-bundle.mjs');
  const businessFile = join(shunModules, 'business-goal.mjs');
  const capabilityFile = join(shunModules, 'capability-llm.mjs');
  writeFileSync(kernelFile, kernel.source);
  writeFileSync(standardFile, standard.source);
  const kernelSha = kernel.sha256;
  const standardSha = standard.sha256;
  const businessSha = sha256Hex(business) as string;
  const capabilitySha = sha256Hex(capability) as string;
  const spec = {
    appId: 'shun-v03-goal',
    audience: 'operator-local',
    buildId: 'shun-v0.3-r02a-production',
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
        sourceSha256: kernelSha,
        module: {
          packageId: KERNEL_PACKAGE_ID,
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
        sourceSha256: standardSha,
        module: {
          packageId: STANDARD_PACKAGE_ID,
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
        sourceFile: businessFile,
        sourceSha256: businessSha,
        module: {
          packageId: BUSINESS_PACKAGE_ID,
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
        sourceFile: capabilityFile,
        sourceSha256: capabilitySha,
        module: {
          packageId: CAPABILITY_PACKAGE_ID,
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
  const receipt = JSON.parse(assembler.stdout) as { sha256: string };
  return { buildFile, buildFileSha256: receipt.sha256 };
}

function goalInput(
  requestId: string,
  overrides: Partial<Record<string, unknown>> = {},
): Record<string, unknown> {
  const llmRequest = buildNeutralGoalRequest({
    requestId,
    goalText: 'Please summarize the selected folder contents.',
    deadlineUnixMs: Date.now() + 600_000,
    maxOutputTokens: 256,
  });
  expect(llmRequest).not.toBeNull();
  return {
    llmRequest,
    idempotencyToken: requestId,
    currentnessRef: 'shun.currentness.v1/goal-r02a',
    approvalRef: 'shun.approval.v1/goal-r02a',
    ...overrides,
  };
}

describe('R02-A real v0.10.3 SDK closure activation (production BUILD, no fixtures)', () => {
  let dir: string;
  let interpreter: InterpreterDouble;
  let activated: Activated;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'shun-r02a-'));
    const clock = { now: Date.now };
    interpreter = interpreterDouble();
    await installTrustedBinding(interpreter, clock.now);
    const { buildFile } = assembleTrustedBuild(dir);
    const prepared = composeTrustedRuntimeBuild(JSON.parse(readFileSync(buildFile, 'utf8')));
    expect(prepared.status).toBe('READY_FOR_PUBLIC_SDK_BUILD');
    if (prepared.status !== 'READY_FOR_PUBLIC_SDK_BUILD') throw new Error('not ready');
    const store = new SqliteKernelDocStore(join(dir, 'k-docs.sqlite'));
    // The REAL public SDK functions resolved from the installed consumer
    // layout via its pinned exports map (same rule as the production root:
    // the SDK exports expose only the ESM import condition).
    const resolveInstalledSdk = (id: string): string => {
      const [scope = '', pkgName = '', ...subpathParts] = id.split('/');
      const pkgDir = join(consumerDir, 'node_modules', scope, pkgName);
      const manifest = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8')) as {
        name?: string;
        exports?: Record<string, { import?: string }>;
      };
      if (manifest.name !== `${scope}/${pkgName}`) {
        throw new Error('consumer package identity mismatch');
      }
      const subpath = subpathParts.length > 0 ? `./${subpathParts.join('/')}` : '.';
      const entry = manifest.exports?.[subpath]?.import;
      if (typeof entry !== 'string' || !entry.startsWith('./dist/')) {
        throw new Error('consumer exports entry refused');
      }
      return join(pkgDir, entry);
    };
    const buildPath = resolveInstalledSdk('@kaicreator/domain-harness-build');
    const kernelPath = resolveInstalledSdk('@kaicreator/domain-harness-microkernel/host-seam');
    type InstalledBuildSdk = { buildV10App: (options: unknown) => unknown };
    type InstalledKernelSdk = {
      activateV10App: (build: unknown, options: unknown) => Promise<unknown>;
    };
    const installedBuild = (await import(pathToFileURL(buildPath).href)) as InstalledBuildSdk;
    const installedKernel = (await import(pathToFileURL(kernelPath).href)) as InstalledKernelSdk;
    expect(typeof installedBuild.buildV10App).toBe('function');
    expect(typeof installedKernel.activateV10App).toBe('function');
    const app = await activatePublicShunDomainApp({
      sdk: {
        buildV10App: installedBuild.buildV10App,
        activateV10App: installedKernel.activateV10App,
      },
      buildOptions: prepared.options,
      host: {
        store,
        tenantId: TENANT,
        now: clock.now,
        deploymentIdentity: {
          deployedAppId: 'deployment:shun-v03-r02a',
          tenantId: TENANT,
          appId: prepared.options.appId,
        },
        queryAuthority: {
          principal: { role: 'local-host' },
          authorize: (_principal: unknown, target: { instanceKey: string }) =>
            target.instanceKey.startsWith('goal-case-'),
        },
        deploymentRoot: consumerDir,
      },
    });
    activated = {
      facade: app.facade as unknown as Activated['facade'],
      dispose: app.dispose,
      subjectDigest: app.subjectDigest,
      store,
    };
  });

  afterAll(() => {
    try {
      activated?.dispose();
    } catch {
      /* already disposed */
    }
    // Windows may briefly hold SQLite WAL handles; retry the temp cleanup.
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        rmSync(dir, { recursive: true, force: true });
        break;
      } catch {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
      }
    }
  });

  it('activates the real installed SDK closure over the same trusted BUILD', () => {
    expect(activated.subjectDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it('positive: kernel-minted permit drives the real K gate to a verified terminal proposal', async () => {
    const receipt = await activated.facade.send({
      intentType: 'goal-interpret',
      instanceKey: 'goal-case-1',
      messageId: 'msg-r02a-1',
      input: goalInput('r02a-req-1'),
    });
    expect(receipt.status).toBe('admitted');
    const effect = (receipt.admitted as { effects: Array<Record<string, unknown>> }).effects[0];
    expect(effect?.disposition).toBe('executed');
    expect(effect?.output).toMatchObject({
      phase: 'terminal',
      outcome: { ok: true },
    });
    const llm = (effect?.output as { outcome: { output: ShunLlmGenerateRequestV1 } }).outcome
      .output;
    expect(llm).toMatchObject({
      status: 'completed',
      requestId: 'r02a-req-1',
      text: '{"proposalId":"untrusted-proposal","summary":"r02a"}',
    });
    // Exactly one trusted interpreter entry: no second sender, no retry.
    expect(interpreter.calls).toHaveLength(1);
    expect(interpreter.calls[0]?.goalText).toBe('Please summarize the selected folder contents.');
  });

  it('consent decline keeps a truthful refused terminal result (no fake success)', async () => {
    interpreter.nextResult = 'consent-declined';
    interpreter.calls.length = 0;
    const receipt = await activated.facade.send({
      intentType: 'goal-interpret',
      instanceKey: 'goal-case-2',
      messageId: 'msg-r02a-2',
      input: goalInput('r02a-req-2'),
    });
    expect(receipt.status).toBe('admitted');
    const effect = (receipt.admitted as { effects: Array<Record<string, unknown>> }).effects[0];
    const outcome = (
      effect?.output as { outcome: { ok: unknown; output: ShunLlmGenerateRequestV1 } }
    )?.outcome;
    const llm = outcome?.output;
    expect(llm).toMatchObject({
      status: 'refused',
      errorCategory: 'CANCELLED',
      reasonCode: 'CONSENT_DECLINED',
    });
    expect(interpreter.calls).toHaveLength(1);
  });

  it('an unresolved remote outcome stays unknown with no blind retry', async () => {
    interpreter.nextResult = 'remote-refused';
    interpreter.calls.length = 0;
    // The sealed C refuses to mint a terminal receipt for an unresolved
    // outcome: it throws so the existing K Journal/fence owns UNKNOWN.
    await expect(
      activated.facade.send({
        intentType: 'goal-interpret',
        instanceKey: 'goal-case-3',
        messageId: 'msg-r02a-3',
        input: goalInput('r02a-req-3'),
      }),
    ).rejects.toThrow('OpenAI external outcome requires reconciliation');
    expect(interpreter.calls).toHaveLength(1);
  });

  it('a malformed LLM request is refused by the sealed C before any sender entry', async () => {
    interpreter.nextResult = 'proposal';
    interpreter.calls.length = 0;
    const bad = goalInput('r02a-req-4', { llmRequest: { contractVersion: 'dh.llm.generate/2' } });
    await expect(
      activated.facade.send({
        intentType: 'goal-interpret',
        instanceKey: 'goal-case-4',
        messageId: 'msg-r02a-4',
        input: bad,
      }),
    ).rejects.toThrow('SHUN_LLM_REQUEST_CONTRACT_REFUSED');
    expect(interpreter.calls).toHaveLength(0);
  });
});
