/**
 * R02-E production shipping composition journey — the REAL production entry
 * (`createProductionV03Gateway`) over the installed public v0.10.3 SDK
 * consumer, the real operator manifest, the durable Guided Case, the SQLite
 * K doc store and the durable cloud request journal.
 *
 * Zero paid calls / zero physical effects: the trusted T04 binding is
 * installed with a controlled interpreter double whose status/interpretGoal
 * follow the real frozen port; the single-sender/replay/no-retry invariants
 * are asserted against the REAL Kernel gate.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
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
  if (expected !== undefined) expect(sha256Hex(source)).toBe(expected);
  return source;
}

function standardBundle(): string {
  const sdk = readPinned('standard-sdk-v1.mjs');
  const router = readPinned('workflow-router.mjs');
  const routerBody = router.replace(/^export /gm, '');
  return `${sdk}
// R02-E BUILD-style vendored bundle: the pure Standard WorkflowRouter.
const __dhv10RouterBundle = (() => {
${routerBody}
return { routeWorkflowIntent };
})();
export const routeWorkflowIntent = __dhv10RouterBundle.routeWorkflowIntent;
`;
}

/** Assemble the SHUN_V03_BUILD_FILE through the REAL operator script. */
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
    buildId: 'shun-v0.3-r02e-production',
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

interface InterpreterState {
  calls: { goalText: string; deadlineUnixMs: number }[];
  nextResult: 'proposal' | 'consent-declined';
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
    currentnessRef: 'shun.currentness.v1/goal-r02e',
    approvalRef: 'shun.approval.v1/goal-r02e',
  };
}

describe('R02-E shipping production gateway over the real SDK consumer', () => {
  let dir: string;
  let guided: HostGuidedService;
  let interpreter: InterpreterState;
  let gateway: Awaited<ReturnType<typeof createProductionV03Gateway>>;
  let caseId: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'shun-r02e-'));
    const now = Date.now();
    // The trusted Host stages a CURRENT Guided Case; the production gateway
    // binds every submit to exactly this live step identity.
    guided = new HostGuidedService(join(dir, 'guided.sqlite'));
    const staged = guided.stageTrustedSelection({
      observation: {
        schema: 'shun.guided.host-observation.v1',
        taskId: 'task-r02e-goal',
        journeyId: 'journey-r02e',
        sourceRef: 'host:obs:r02e',
        revision: 'r02e',
        caseRef: { snapshotId: 'snap-r02e', digest: 'b'.repeat(64) },
        observedAtUnixMs: now - 1_000,
        validUntilUnixMs: now + 3_600_000,
        evidenceRefs: ['host:scope:r02e'],
        selectedRootRef: 'host:root:r02e',
      },
      semanticSelection: {
        status: 'SELECTED',
        semantic: {
          schema: 'shun.goal-semantic.v1',
          taskId: 'task-r02e-goal',
          goalContract: { taskId: 'task-r02e-goal', objective: 'summarize selected folder' },
          capabilityId: 'system.storage.diagnose_bounded_action',
          capabilityRevision: 'r1',
          provenance: { resolverRevision: 'resolver-v03' },
        },
      },
      scope: { status: 'KNOWN', selectedRootRef: 'host:root:r02e' },
    });
    expect(staged.status).toBe('CURRENT');
    if (staged.status !== 'CURRENT') throw new Error('staging failed');
    caseId = staged.step.taskId;

    interpreter = { calls: [], nextResult: 'proposal' };
    const { buildFile, buildFileSha256 } = assembleBuild(dir);
    gateway = await createProductionV03Gateway({
      buildFile,
      buildFileSha256,
      sdkConsumerDir: consumerDir,
      kDocDatabaseFile: join(dir, 'k-docs.sqlite'),
      deploymentRoot: consumerDir,
      tenantId: 'tenant:shun-v03',
      deployedAppId: 'deployment:shun-v03-r02e',
      selectedCase: guided,
      llm: {
        interpreter: {
          status: () => ({
            enabled: true,
            provider: 'deepseek' as const,
            model: 'deepseek-flash' as const,
            osConsentRequired: true as const,
          }),
          interpretGoal: async (input: { goalText: string; deadlineUnixMs: number }) => {
            interpreter.calls.push({
              goalText: input.goalText,
              deadlineUnixMs: input.deadlineUnixMs,
            });
            if (interpreter.nextResult === 'consent-declined') {
              return { ok: false, code: 'CONSENT_DECLINED' };
            }
            return {
              ok: true,
              taskId: 'cloud-task-r02e',
              status: 'UNTRUSTED_REMOTE_PROPOSAL',
              proposalText: '{"proposalId":"r02e-proposal"}',
              model: 'deepseek-flash',
              costState: 'UNKNOWN_COST',
              executed: false,
            };
          },
        },
        journalFile: join(dir, 'cloud-journal.sqlite'),
        configuredMaxOutputTokens: 256,
      },
    });
  });

  afterAll(() => {
    try {
      gateway?.dispose();
    } catch {
      /* already disposed */
    }
    guided?.close();
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        rmSync(dir, { recursive: true, force: true });
        break;
      } catch {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
      }
    }
  });

  it('boots the production composition with the real SDK closure', () => {
    expect(gateway.subjectDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it('positive: live Case submit reaches COMPLETED with the trusted proposal', async () => {
    const receipt = await gateway.gateway.submit(
      submission(caseId, 'Summarize the selected folder.'),
    );
    expect(receipt.status).toBe('COMPLETED');
    if (receipt.status !== 'COMPLETED') return;
    const effect = (receipt.result as { admitted: { effects: Array<Record<string, unknown>> } })
      .admitted.effects[0];
    const llm = (effect?.output as { outcome: { output: { status: string; text: string } } })
      .outcome.output;
    expect(llm.status).toBe('completed');
    expect(llm.text).toBe('{"proposalId":"r02e-proposal"}');
    expect(interpreter.calls).toHaveLength(1);
    // The exact Host-minted disclosure reached the only sender entry.
    expect(interpreter.calls[0]?.goalText).toBe('Summarize the selected folder.');
  });

  it('re-submitting identical content is refused by the K non-idempotency fence, never re-sent', async () => {
    const receipt = await gateway.gateway.submit(
      submission(caseId, 'Summarize the selected folder.'),
    );
    // The real Kernel refuses re-entry of the same content-derived effect
    // idempotency key; the journaled result is never re-sent or re-minted.
    expect(receipt.status).toBe('KERNEL_REFUSED');
    expect(interpreter.calls).toHaveLength(1);
  });

  it('a submit for a foreign/stale Case is refused before any K send', async () => {
    const receipt = await gateway.gateway.submit(
      submission('case-not-staged', 'Read something else.'),
    );
    expect(receipt).toMatchObject({ status: 'KERNEL_REFUSED', sendCalls: 1 });
    expect(interpreter.calls).toHaveLength(1);
  });

  it('consent decline surfaces as a truthful non-success receipt, no retry', async () => {
    interpreter.nextResult = 'consent-declined';
    // A DIFFERENT goal mints a fresh requestId so the journal reserves anew.
    const receipt = await gateway.gateway.submit(
      submission(caseId, 'Summarize again with decline.'),
    );
    expect(receipt.status).toBe('KERNEL_REFUSED');
    expect(interpreter.calls).toHaveLength(2);
    expect(interpreter.calls[1]?.goalText).toBe('Summarize again with decline.');
  });

  it('hostile submission shape is refused pre-send with zero journal risk', async () => {
    const receipt = await gateway.gateway.submit({ ...submission(caseId, 'x'), extra: true });
    expect(receipt).toMatchObject({ status: 'REFUSED', sendCalls: 0, journalEntries: 0 });
    expect(interpreter.calls).toHaveLength(2);
  });
});
