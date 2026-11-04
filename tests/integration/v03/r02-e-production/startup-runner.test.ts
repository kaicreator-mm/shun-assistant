/**
 * R02-E Generation-3 startup-runner regression (Issue #269): the default
 * control-api dev entry must boot the REAL import graph under Node 24's
 * strip-only TypeScript mode without ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX
 * (native/index.ts constructor parameter properties), must stay truthful
 * (no hidden DEMO fallback for a requested real mode), must bind loopback
 * only, and must shut down deterministically. On Windows it additionally
 * boots the full real-storage production composition (operator-pinned BUILD,
 * durable Guided Case, SQLite K docs, cloud journal, Host reference ledger)
 * through the same entry and reads back production BUILD activation plus a
 * truthful Guided state and gateway over HTTP.
 *
 * Zero paid calls / zero physical effects: no cloud interpreter is
 * configured (every LLM effect fails closed CLOUD_UNAVAILABLE), no Provider
 * install, no UAC, no persistent Windows effect beyond temp fixture files.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { get as httpGet } from 'node:http';
import { createConnection, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { consumerDir } from '../r02-a-build/ensure-consumer.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const apiDir = join(repoRoot, 'apps/control-api');
const tsxCli = join(apiDir, 'node_modules/tsx/dist/cli.mjs');
const isWindows = process.platform === 'win32';
const PNPM = isWindows ? 'pnpm.cmd' : 'pnpm';

const sha256Hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

/** One free loopback port, obtained the same way the product probes do. */
async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((ready) => probe.listen(0, '127.0.0.1', ready));
  const address = probe.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  await new Promise<void>((closed) => probe.close(() => closed()));
  return port;
}

function collect(child: ReturnType<typeof spawn>): { text: () => string } {
  let out = '';
  child.stdout?.on('data', (chunk: Buffer) => (out += chunk.toString('utf8')));
  child.stderr?.on('data', (chunk: Buffer) => (out += chunk.toString('utf8')));
  return { text: () => out };
}

/** Boot main.ts through the pinned tsx runner exactly as the dev script does. */
function startViaTsx(port: number, env: NodeJS.ProcessEnv) {
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/main.ts'], {
    cwd: apiDir,
    env: { ...process.env, ...env, SHUN_CONTROL_PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return { child, output: collect(child) };
}

async function waitForHttp(port: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`);
      if (response.status === 200) return true;
    } catch {
      /* not listening yet */
    }
    await delay(400);
  }
  return false;
}

function portRefusesConnection(port: number): Promise<boolean> {
  return new Promise((resolveRefused) => {
    const conn = createConnection({ port, host: '127.0.0.1' });
    conn.once('connect', () => {
      conn.destroy();
      resolveRefused(false);
    });
    conn.once('error', () => resolveRefused(true));
  });
}

async function portRefusesConnectionEventually(port: number, timeoutMs = 5_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await portRefusesConnection(port)) return true;
    await delay(150);
  }
  return false;
}

async function waitForExit(
  child: ReturnType<typeof spawn>,
  timeoutMs: number,
): Promise<{ code: number | null; signal: NodeJS.Signals | null } | 'TIMEOUT'> {
  return new Promise((resolved) => {
    const timer = setTimeout(() => resolved('TIMEOUT'), timeoutMs);
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      resolved({ code, signal });
    });
  });
}

/** Deterministic shutdown expectation, honest per platform signal semantics. */
function expectCleanShutdown(
  exit: { code: number | null; signal: NodeJS.Signals | null } | 'TIMEOUT',
) {
  expect(exit, 'server must exit within the shutdown bound').not.toBe('TIMEOUT');
  if (exit === 'TIMEOUT') return;
  if (isWindows) {
    // Windows cannot deliver POSIX signals cross-process (TerminateProcess);
    // determinism here means: signal death, no hang, no orphan listener.
    expect(exit.signal ?? exit.code).not.toBeNull();
  } else {
    // POSIX delivers SIGTERM to the handler: graceful close, natural exit 0.
    expect(exit.code).toBe(0);
  }
}

function rawGet(
  port: number,
  path: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  return new Promise((resolveResponse, rejectResponse) => {
    const request = httpGet({ host: '127.0.0.1', port, path, headers }, (response) => {
      let body = '';
      response.on('data', (chunk: Buffer) => (body += chunk.toString('utf8')));
      response.on('end', () => resolveResponse({ status: response.statusCode ?? 0, body }));
    });
    request.once('error', rejectResponse);
  });
}

/** Kill the whole spawned process tree (pnpm wrapper smoke test cleanup). */
function killTree(child: ReturnType<typeof spawn>): void {
  if (isWindows && child.pid) {
    spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
  } else if (child.pid) {
    // POSIX: the dev server is a grandchild (pnpm → tsx → node); killing only
    // the direct child would orphan the listener. The child was spawned
    // detached, so a group kill takes the whole tree.
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch {
      child.kill('SIGKILL');
    }
  }
}

describe('R02-E default dev startup runner (Node 24 strip-mode repair)', () => {
  it('default pnpm --filter @shun/control-api dev boots the real graph with no TypeScript syntax error', async () => {
    const port = await freePort();
    // The exact operator default command; on Windows .cmd requires a shell.
    // POSIX detaches so killTree can take the whole pnpm → tsx → node group.
    const child = spawn(PNPM, ['--filter', '@shun/control-api', 'dev'], {
      cwd: repoRoot,
      env: { ...process.env, SHUN_CONTROL_PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: isWindows,
      detached: !isWindows,
    });
    const output = collect(child);
    const up = await waitForHttp(port, 60_000);
    const text = output.text();
    expect(up, `server did not come up; output:\n${text}`).toBe(true);
    expect(text).not.toContain('ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX');
    expect(text).toContain('Shun control surface (T08 DEMO ONLY)');
    killTree(child);
    await waitForExit(child, 15_000);
    expect(await portRefusesConnectionEventually(port)).toBe(true);
  });

  it('tsx entry boots DEMO on loopback, refuses hostile Host, reports Guided truthfully, shuts down deterministically', async () => {
    const port = await freePort();
    const { child, output } = startViaTsx(port, {});
    const up = await waitForHttp(port, 60_000);
    const text = output.text();
    expect(up, `server did not come up; output:\n${text}`).toBe(true);
    expect(text).not.toContain('ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX');
    expect(text).toContain('T08 DEMO ONLY');
    expect(text).toContain('v0.3 production BUILD inactive');

    const hostile = await rawGet(port, '/', { host: 'attacker.example' });
    expect(hostile.status).toBe(403);
    expect(hostile.body).toContain('LOCAL_ONLY_VIOLATION');

    const guided = await rawGet(port, '/api/v03/guided/state', { host: `127.0.0.1:${port}` });
    expect(guided.status).toBe(503);
    expect(guided.body).toContain('V03_GUIDED_UNAVAILABLE');

    child.kill('SIGTERM');
    expectCleanShutdown(await waitForExit(child, 20_000));
    expect(await portRefusesConnectionEventually(port)).toBe(true);
  });

  it('unknown SHUN_CONTROL_MODE fails closed — never a silent DEMO fallback', async () => {
    const port = await freePort();
    const { child, output } = startViaTsx(port, { SHUN_CONTROL_MODE: 'bogus' });
    const exit = await waitForExit(child, 30_000);
    expect(exit, 'boot must refuse and exit').not.toBe('TIMEOUT');
    expect(output.text()).toContain('Unknown SHUN_CONTROL_MODE: refusing to start');
    if (exit !== 'TIMEOUT') expect(exit.code).not.toBe(0);
    expect(await portRefusesConnectionEventually(port)).toBe(true);
  });

  it('real-storage mode without trusted config fails closed with the exact missing gate', async () => {
    const port = await freePort();
    const { child, output } = startViaTsx(port, { SHUN_CONTROL_MODE: 'real-storage' });
    const exit = await waitForExit(child, 30_000);
    expect(exit, 'boot must refuse and exit').not.toBe('TIMEOUT');
    expect(output.text()).toContain(
      'Missing trusted local configuration SHUN_REAL_STORAGE_ROOT; refusing real mode',
    );
    if (exit !== 'TIMEOUT') expect(exit.code).not.toBe(0);
    expect(await portRefusesConnectionEventually(port)).toBe(true);
  });
});

describe.skipIf(!isWindows)(
  'R02-E production real-storage boot through the same dev runner',
  () => {
    const t11Fixtures = resolve(repoRoot, 'tests/integration/v03/t11-runtime/fixtures');
    const shunModules = resolve(repoRoot, 'packages/domain-app/src/activation/modules');
    let dir: string;
    let port: number;
    let env: NodeJS.ProcessEnv;
    let caseId: string;

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
const __dhv10RouterBundle = (() => {
${routerBody}
return { routeWorkflowIntent };
})();
export const routeWorkflowIntent = __dhv10RouterBundle.routeWorkflowIntent;
`;
    }

    /** Assemble SHUN_V03_BUILD_FILE through the REAL operator script. */
    function assembleBuild(): { buildFile: string; buildFileSha256: string } {
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
        buildId: 'shun-v0.3-r02e-startup',
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

    beforeAll(async () => {
      dir = mkdtempSync(join(tmpdir(), 'shun-r02e-startup-'));
      const workspace = resolve(join(dir, 'workspace'));
      const protectedDir = join(workspace, 'protected');
      mkdirSync(protectedDir, { recursive: true });
      const evidenceDir = resolve(join(dir, 'evidence'));
      mkdirSync(evidenceDir, { recursive: true });

      // Independent Ed25519 registry authority, issued by the REAL operator
      // issuer script against this exact workspace (60s short-lived proof).
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
      const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
      const publicKeyFile = resolve(join(dir, 'registry-public.pem'));
      const privateKeyFile = resolve(join(dir, 'registry-private.pem'));
      const currentnessFile = resolve(join(dir, 'registry-currentness.json'));
      writeFileSync(publicKeyFile, publicKeyPem);
      writeFileSync(privateKeyFile, privateKeyPem);
      const spkiSha256 = createHash('sha256')
        .update(publicKey.export({ type: 'spki', format: 'der' }))
        .digest('hex');
      const whoami = spawnSync(
        'C:\\Windows\\System32\\whoami.exe',
        ['/groups', '/fo', 'csv', '/nh'],
        {
          encoding: 'utf8',
        },
      );
      const privilegeMode = /S-1-16-12288/i.test(whoami.stdout)
        ? 'ELEVATED_ADMIN'
        : /S-1-5-32-544/i.test(whoami.stdout)
          ? 'FILTERED_ADMIN'
          : 'STANDARD_USER';
      const issuer = spawnSync(
        process.execPath,
        [tsxCli, 'apps/control-api/scripts/issue-registry-currentness.ts'],
        {
          cwd: repoRoot,
          encoding: 'utf8',
          env: {
            ...process.env,
            SHUN_ISSUER_WORKSPACE: workspace,
            SHUN_REGISTRY_CURRENTNESS_FILE: currentnessFile,
            SHUN_REGISTRY_PUBLIC_KEY_FILE: publicKeyFile,
            SHUN_ISSUER_PRIVATE_KEY_FILE: privateKeyFile,
            SHUN_ISSUER_TARGET_PRIVILEGE_MODE: privilegeMode,
          },
        },
      );
      expect(issuer.status, `issuer failed: ${issuer.stderr?.slice(0, 2000)}`).toBe(0);

      // Operator-pinned Guided Case file (SHA256-pinned like production).
      caseId = 'task-r02e-startup-goal';
      const now = Date.now();
      const guidedCase = {
        observation: {
          schema: 'shun.guided.host-observation.v1',
          taskId: caseId,
          journeyId: 'journey-r02e-startup',
          sourceRef: 'host:obs:r02e-startup',
          revision: 'r02e-startup',
          caseRef: { snapshotId: 'snap-r02e-startup', digest: 'e'.repeat(64) },
          observedAtUnixMs: now - 1_000,
          validUntilUnixMs: now + 3_600_000,
          evidenceRefs: ['host:scope:r02e-startup'],
          selectedRootRef: 'host:root:r02e-startup',
        },
        semanticSelection: {
          status: 'SELECTED',
          semantic: {
            schema: 'shun.goal-semantic.v1',
            taskId: caseId,
            goalContract: { taskId: caseId, objective: 'summarize selected folder' },
            capabilityId: 'system.storage.diagnose_bounded_action',
            capabilityRevision: 'r1',
            provenance: { resolverRevision: 'resolver-v03' },
          },
        },
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:r02e-startup' },
      };
      const caseFile = resolve(join(dir, 'guided-case.json'));
      const caseJson = JSON.stringify(guidedCase);
      writeFileSync(caseFile, caseJson);

      const { buildFile, buildFileSha256 } = assembleBuild();
      env = {
        SHUN_CONTROL_MODE: 'real-storage',
        SHUN_REAL_STORAGE_ROOT: workspace,
        SHUN_REAL_STORAGE_PROTECTED: JSON.stringify([protectedDir]),
        SHUN_REAL_STORAGE_DATABASE: resolve(join(dir, 'real.sqlite')),
        SHUN_REGISTRY_CURRENTNESS_FILE: currentnessFile,
        SHUN_REGISTRY_PUBLIC_KEY_FILE: publicKeyFile,
        SHUN_REGISTRY_PUBLIC_KEY_SPKI_SHA256: spkiSha256,
        SHUN_REAL_STORAGE_EVIDENCE_DIR: evidenceDir,
        SHUN_CONTROLLER_ISSUANCE_SECRET: 'issuance-secret-r02e-startup',
        SHUN_GRANT_INTEGRITY_SECRET: 'integrity-secret-r02e-startup',
        SHUN_V03_GUIDED_DATABASE: resolve(join(dir, 'guided.sqlite')),
        SHUN_V03_GUIDED_CASE_FILE: caseFile,
        SHUN_V03_GUIDED_CASE_SHA256: sha256Hex(caseJson),
        SHUN_V03_BUILD_FILE: buildFile,
        SHUN_V03_BUILD_SHA256: buildFileSha256,
        SHUN_V03_SDK_CONSUMER_DIR: consumerDir,
        SHUN_V03_KERNEL_DOC_DATABASE: resolve(join(dir, 'k-docs.sqlite')),
        SHUN_V03_DEPLOYMENT_ROOT: consumerDir,
        SHUN_V03_TENANT_ID: 'tenant:shun-v03',
        SHUN_V03_DEPLOYED_APP_ID: 'deployment:shun-v03-r02e-startup',
        SHUN_V03_CLOUD_JOURNAL: resolve(join(dir, 'cloud-journal.sqlite')),
        SHUN_V03_APPROVAL_LEDGER: resolve(join(dir, 'submit-references.sqlite')),
      };
      port = await freePort();
    }, 120_000);

    afterAll(() => {
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          rmSync(dir, { recursive: true, force: true });
          break;
        } catch {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
        }
      }
    });

    it('boots production: real BUILD activated, same selected K/Host, truthful Guided and gateway, deterministic shutdown', async () => {
      const { child, output } = startViaTsx(port, env);
      const up = await waitForHttp(port, 90_000);
      const text = output.text();
      expect(up, `production surface did not come up; output:\n${text}`).toBe(true);
      expect(text).not.toContain('ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX');
      expect(text).toContain('Shun control surface (REAL bounded C-003)');
      expect(text).not.toContain('T08 DEMO ONLY');
      expect(text).not.toContain('v0.3 production BUILD inactive');
      // The production DomainHarness is activated and the issued reference log
      // binds the gateway to the exact selected Guided Case (same K/Host).
      expect(text).toMatch(/v0\.3 public DomainHarness activated: subjectDigest=[0-9a-f]{64}/);
      expect(text).toContain(`v0.3 submit references issued (case ${caseId}, step `);

      const guided = await rawGet(port, '/api/v03/guided/state', { host: `127.0.0.1:${port}` });
      expect(guided.status, guided.body).toBe(200);
      const state = JSON.parse(guided.body) as { currentStep?: { taskId?: string } };
      expect(state.currentStep?.taskId).toBe(caseId);

      // Unauthenticated submit (valid-shaped forged references) is refused
      // truthfully pre-Kernel: 422 KERNEL_REFUSED, never a fake success.
      const forged = await fetch(`http://127.0.0.1:${port}/api/v03/gateway/submit`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          host: `127.0.0.1:${port}`,
        },
        body: JSON.stringify({
          caseId,
          request: {
            taskId: caseId,
            goal: 'Summarize the selected folder.',
            objects: [],
            constraints: {},
            policyContext: {
              privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
              environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
            },
          },
          currentnessRef: `shun.currentness.v1/${'a'.repeat(48)}`,
          approvalRef: `shun.approval.v1/${'b'.repeat(48)}`,
        }),
      });
      const receipt = (await forged.json()) as { status?: string };
      expect(forged.status).toBe(422);
      expect(receipt.status).toBe('KERNEL_REFUSED');

      child.kill('SIGTERM');
      expectCleanShutdown(await waitForExit(child, 20_000));
      expect(await portRefusesConnectionEventually(port)).toBe(true);
    }, 180_000);
  },
);
