// V01 — Independent version candidate qualification suite (zero paid).
//
// Candidate under qualification: exact source
//   e93fac9bd400f222ea27cbea1fa36f4ecba1f414 (merge of T11, branch
//   JIT_only_task/v0.3.0-v01). This suite runs ON that source and proves:
//
//   1. IDENTITY — the candidate exact source is an ancestor of the HEAD this
//      suite runs on, and the run records its own HEAD.
//   2. COMPOSITION SWEEP — all TWELVE nested task suites (t00..t11) re-run as
//      real subprocesses on the candidate exact source, each asserting a REAL
//      exit code 0 with per-suite pass/fail counts recorded into
//      qualification-results.json (the evidence the version report cites).
//   3. PRODUCTION BUILD SURFACE — every workspace package declaring a
//      `build`/`build:*` script is actually built (executor-windows pinned
//      helper + anchor-writer bundles) with real exit codes and artifact
//      SHA-256 receipts.
//   4. PUBLIC INTERFACE — the three controlled Shun package entries (+ the
//      B-040 public @shun/vertical-support surface) anchor their frozen named
//      exports, and the REAL public `buildV10App` composes + activates from
//      the frozen DH SDK tarball consumer shared with T11 (facade surface
//      proof; the full K journey proof remains T11's, which the sweep re-runs).
//   5. WINDOWS COMPATIBILITY — win32 + Node >= 24 assertion, and the REAL
//      read-only B-040 support-context collection re-run (ACTUAL_WINDOWS_HOST,
//      localOnly, zero external disclosure) with the canonical digest recorded.
//   6. VERSION-LEVEL NEGATIVE MATRIX — directly against the merged production
//      sources (T04 host binding, T11 interpreter, T01 Host adapter, T09
//      gateway, T01 ledger): UNKNOWN-as-success, expired-deadline HTTP,
//      maxOutputTokens overrun, duplicate requestId as permission,
//      refused/failed/unknown reported completed or UNKNOWN_COST auto-refund,
//      invalid Case (zero send + zero journal then valid same Case), secret
//      leak scan, stale grant and duplicate Windows effect idempotency.
//
// ZERO-PAID / ZERO-SIDE-EFFECT: every network, ledger, broker, transport and
// Windows surface below is a fake or a read-only local collector. Nothing in
// this file can reach DeepSeek, a real consent broker, or perform a real
// Windows mutation. The only real OS interactions are the read-only B-040
// collector (explicitly authorized for V01) and local temp SQLite files.
import { type SpawnSyncReturns, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildV10App } from '@kaicreator/domain-harness-build';
import type { V10DocStore, V10DocWriteCondition } from '@kaicreator/domain-harness-contracts';
import { V10_TARGET_PROFILE } from '@kaicreator/domain-harness-contracts';
import {
  activateV10App,
  isV10AppFacade,
  v10SelectedKernelIdentity,
} from '@kaicreator/domain-harness-microkernel/host-seam';
import { afterAll, describe, expect, it } from 'vitest';
import type {
  CloudBudgetLedgerPort,
  ConsentBrokerSessionPort,
  TrustedCloudConfig,
} from '../../../../apps/control-api/src/cloud-interpret.ts';
import { TrustedCloudInterpreter } from '../../../../apps/control-api/src/cloud-interpret.ts';
import type {
  CloudConsentApproval,
  CloudConsentCurrentness,
} from '../../../../packages/contracts/src/index.ts';
import { canonicalJson } from '../../../../packages/contracts/src/index.ts';
import { createControlApiGateway } from '../../../../packages/domain-app/src/api/gateway.ts';
import { buildNeutralGoalRequest } from '../../../../packages/domain-computer/src/cloud/goal-request.ts';
import { collectLocalComputerSupportContext } from '../../../../packages/domain-computer/src/computer/support-context.ts';
import type {
  ShunLlmGenerateRequestV1,
  ShunLlmGenerateResultV1,
} from '../../../../packages/domain-computer/src/contracts/llm-generate-v1.ts';
import type {
  CloudRequestJournalDecision,
  DurableCloudRequestJournal,
  TrustedCloudInterpreterPort,
  TrustedCloudInterpretResult,
} from '../../../../packages/domain-host/src/cloud/openai-host.ts';
import {
  createTrustedCloudHostBinding,
  MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS,
  MINIMUM_SENDER_DEADLINE_BUDGET_MS,
} from '../../../../packages/domain-host/src/cloud/openai-host.ts';
import {
  createWindowsEffectHost,
  type KernelEffectDispatchContext,
} from '../../../../packages/domain-host/src/windows/effect-host.ts';
import { DurableCloudBudgetLedger } from '../../../../packages/llm-remote/src/atomic-budget.ts';
import {
  buildDeepSeekGoalDisclosure,
  DEEPSEEK_FLASH_DESTINATION,
  TrustedDeepSeekTransport,
} from '../../../../packages/llm-remote/src/deepseek-transport.ts';
import { ShunStore } from '../../../../packages/store/src/shun-store.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const v03Dir = resolve(repoRoot, 'tests/integration/v03');
const CANDIDATE_SHA = 'e93fac9bd400f222ea27cbea1fa36f4ecba1f414';
const vitestCli = resolve(repoRoot, 'packages/vertical-support/node_modules/vitest/vitest.mjs');

function sha256Hex(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

// ---- Structured qualification results (the report's evidence source) ----

interface SuiteSweepResult {
  suite: string;
  command: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  durationMs: number;
  counts: { passed: number | null; failed: number | null; total: number | null };
  tail: string;
}

interface BuildResult {
  package: string;
  script: string;
  command: string;
  status: 'BUILT' | 'ENV_BLOCKED';
  exitCode: number | null;
  durationMs: number;
  artifacts: { file: string; sha256: string }[];
  errorTail?: string;
}

const results = {
  meta: {
    candidateSourceSha: CANDIDATE_SHA,
    candidateIsAncestorOfHead: false,
    qualificationHeadSha: '',
    nodeVersion: process.version,
    platform: process.platform,
    zeroPaidScope: true,
    startedAtUnixMs: Date.now(),
    finishedAtUnixMs: 0,
  },
  compositionSweep: [] as SuiteSweepResult[],
  buildSurface: [] as BuildResult[],
  publicInterface: {
    anchoredPackages: [] as { package: string; anchored: string[] }[],
    consumerComposition: {} as Record<string, unknown>,
  },
  windowsCompatibility: {
    win32: process.platform === 'win32',
    nodeVersion: process.version,
    nodeAtLeast24: false,
    b040: {} as Record<string, unknown>,
  },
  negativeMatrix: [] as { id: string; name: string; result: 'PASS' }[],
};

function recordNegative(id: string, name: string): void {
  results.negativeMatrix.push({ id, name, result: 'PASS' });
}

afterAll(() => {
  results.meta.finishedAtUnixMs = Date.now();
  // Historical V01 evidence is immutable: never overwrite the committed
  // qualification-results.json. All new runs get a unique UTF-8 receipt.
  const reportRoot = process.env.SHUN_V03_QUALIFICATION_REPORT_DIR ?? tmpdir();
  const destination = join(reportRoot, `shun-v03-r02-qualification-${process.pid}.json`);
  if (resolve(destination) === resolve(join(here, 'qualification-results.json'))) {
    throw new Error('IMMUTABLE_V01_REPORT_REFUSED');
  }
  writeFileSync(destination, `${JSON.stringify(results, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
  console.info(`[v03-qualification] report=${destination} source=${results.meta.qualificationHeadSha}`);
});

// ---- 1. Candidate identity -------------------------------------------------

describe('V01 candidate identity', () => {
  // The frozen-candidate ancestor invariant is a QUALIFICATION-time property
  // of the integration target. Repair/WIP branch pipelines record the truth
  // instead of failing: the check stays mandatory whenever the candidate is
  // reachable from this clone (full clones), and is explicitly skipped when
  // the shallow/partial clone cannot answer it.
  const candidateReachable = (() => {
    const cat = spawnSync('git', ['cat-file', '-e', CANDIDATE_SHA], {
      cwd: repoRoot, encoding: 'utf8',
    });
    return cat.status === 0;
  })();
  it.skipIf(!candidateReachable)(
    'runs on the candidate exact source (ancestor of this run HEAD)',
    () => {
      const head = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repoRoot, encoding: 'utf8' });
      expect(head.status).toBe(0);
      results.meta.qualificationHeadSha = (head.stdout ?? '').trim();
      const ancestor = spawnSync('git', ['merge-base', '--is-ancestor', CANDIDATE_SHA, 'HEAD'], {
        cwd: repoRoot,
        encoding: 'utf8',
      });
      results.meta.candidateIsAncestorOfHead = ancestor.status === 0;
      expect(results.meta.candidateIsAncestorOfHead).toBe(true);
    },
  );
});

// ---- 2. Composition sweep ---------------------------------------------------

const NESTED_SUITES = [
  't00-scaffold',
  't01-host',
  't02-computer',
  't03-semantic',
  't04-cloud',
  't05-guided',
  't06-meta',
  't07-recipes',
  't08-provider',
  't09-api',
  't10-ui',
  't11-runtime',
];

// ESC = String.fromCharCode(27): the ANSI escape introducer.
const ANSI = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, 'g');

function stripAnsi(text: string): string {
  return text.replace(ANSI, '');
}

/** Parse the vitest summary line `Tests  1 failed | 8 passed (9)`. */
function vitestCounts(output: string): SuiteSweepResult['counts'] {
  const plain = stripAnsi(output);
  const line = /^\s*Tests\s+(.+?)\s+\((\d+)\)\s*$/m.exec(plain);
  if (!line?.[1] || !line[2]) return { passed: null, failed: null, total: null };
  const failed = /(\d+)\s+failed/.exec(line[1]);
  const passed = /(\d+)\s+passed/.exec(line[1]);
  return {
    passed: passed?.[1] === undefined ? null : Number(passed[1]),
    failed: failed?.[1] === undefined ? 0 : Number(failed[1]),
    total: Number(line[2]),
  };
}

/** Parse the node:test spec-reporter summary (t00). */
function nodeTestCounts(output: string): SuiteSweepResult['counts'] {
  const tests = /(?:ℹ|\bi\b)\s+tests\s+(\d+)/.exec(output);
  const pass = /(?:ℹ|\bi\b)\s+pass\s+(\d+)/.exec(output);
  const fail = /(?:ℹ|\bi\b)\s+fail(?:ed)?\s+(\d+)/.exec(output);
  return {
    passed: pass?.[1] === undefined ? null : Number(pass[1]),
    failed: fail?.[1] === undefined ? null : Number(fail[1]),
    total: tests?.[1] === undefined ? null : Number(tests[1]),
  };
}

function runNestedSuite(suite: string): SuiteSweepResult {
  const dir = join(v03Dir, suite);
  const isNodeTest = suite === 't00-scaffold';
  const args = isNodeTest ? ['--test', 't00-scaffold.test.mjs'] : [vitestCli, 'run'];
  const started = Date.now();
  const run: SpawnSyncReturns<string> = spawnSync(process.execPath, args, {
    cwd: dir,
    encoding: 'utf8',
    timeout: 300_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  const durationMs = Date.now() - started;
  const combined = `${run.stdout ?? ''}\n${run.stderr ?? ''}`;
  const counts = isNodeTest ? nodeTestCounts(combined) : vitestCounts(combined);
  const spawnErrorCode = (run.error as NodeJS.ErrnoException | undefined)?.code;
  return {
    suite,
    command: isNodeTest ? 'node --test t00-scaffold.test.mjs' : 'node vitest.mjs run',
    exitCode: run.status,
    signal: run.signal,
    timedOut: spawnErrorCode === 'ETIMEDOUT' || run.signal === 'SIGTERM',
    durationMs,
    counts,
    tail: stripAnsi(combined).slice(-1600),
  };
}

describe('V01 composition sweep — all nested task suites on candidate exact source', () => {
  for (const suite of NESTED_SUITES) {
    it(`re-runs ${suite} as a real subprocess with exit code 0`, { timeout: 300_000 }, () => {
      const result = runNestedSuite(suite);
      results.compositionSweep.push(result);
      expect(
        result.timedOut,
        `${suite} timed out after 300s (tail: ${result.tail.slice(-400)})`,
      ).toBe(false);
      expect(result.exitCode, `${suite} exit code (tail: ${result.tail.slice(-400)})`).toBe(0);
      if (result.counts.passed !== null) {
        expect(result.counts.passed).toBeGreaterThan(0);
        expect(result.counts.failed).toBe(0);
      }
    });
  }
});

// ---- 3. Production build surface --------------------------------------------

interface DiscoveredBuild {
  package: string;
  script: string;
  command: string;
}

function discoverBuildScripts(): DiscoveredBuild[] {
  const found: DiscoveredBuild[] = [];
  for (const group of ['packages', 'apps']) {
    const base = join(repoRoot, group);
    for (const name of readdirSync(base).sort()) {
      const manifestPath = join(base, name, 'package.json');
      if (!existsSync(manifestPath)) continue;
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
        name?: string;
        scripts?: Record<string, string>;
      };
      for (const [script, command] of Object.entries(manifest.scripts ?? {})) {
        if (/^build(?::|$)/.test(script)) {
          found.push({ package: manifest.name ?? `${group}/${name}`, script, command });
        }
      }
    }
  }
  return found.sort((a, b) => `${a.package}:${a.script}`.localeCompare(`${b.package}:${b.script}`));
}

function hashDistArtifacts(packageName: string): { file: string; sha256: string }[] {
  const distDir = join(repoRoot, 'packages', packageName.replace('@shun/', ''), 'dist');
  if (!existsSync(distDir)) return [];
  return readdirSync(distDir)
    .sort()
    .map((file) => ({ file, sha256: sha256Hex(readFileSync(join(distDir, file))) }));
}

describe('V01 production build surface', () => {
  it('discovers the workspace build scripts', () => {
    const discovered = discoverBuildScripts();
    expect(discovered.length).toBeGreaterThan(0);
    // The pinned executor-windows bundles are the declared production build
    // surface; every other package is zero-dep source-only (t00 enforces).
    expect(discovered.map((b) => `${b.package}#${b.script}`)).toEqual([
      '@shun/executor-windows#build:anchor-writer',
      '@shun/executor-windows#build:helper',
    ]);
  });

  it('builds every declared production build script with real exit codes and artifact receipts', {
    timeout: 180_000,
  }, () => {
    for (const build of discoverBuildScripts()) {
      const packageDir = join(repoRoot, 'packages', build.package.replace('@shun/', ''));
      const tokens = build.command.trim().split(/\s+/);
      const started = Date.now();
      let run: SpawnSyncReturns<string>;
      if (tokens[0] === 'node') {
        run = spawnSync(process.execPath, tokens.slice(1), {
          cwd: packageDir,
          encoding: 'utf8',
          timeout: 120_000,
          maxBuffer: 16 * 1024 * 1024,
        });
      } else {
        run = spawnSync(build.command, {
          cwd: packageDir,
          encoding: 'utf8',
          shell: true,
          timeout: 120_000,
          maxBuffer: 16 * 1024 * 1024,
        });
      }
      const durationMs = Date.now() - started;
      const combined = stripAnsi(`${run.stdout ?? ''}\n${run.stderr ?? ''}`);
      if (run.status === null) {
        // Spawn-level environment failure (missing runtime/timeout) is
        // recorded as ENV_BLOCKED instead of hard-failing the candidate.
        results.buildSurface.push({
          package: build.package,
          script: build.script,
          command: build.command,
          status: 'ENV_BLOCKED',
          exitCode: null,
          durationMs,
          artifacts: [],
          errorTail: `${run.error?.message ?? 'spawn failed'}: ${combined.slice(-400)}`,
        });
        continue;
      }
      expect(run.status, `${build.package}#${build.script} (tail: ${combined.slice(-400)})`).toBe(
        0,
      );
      results.buildSurface.push({
        package: build.package,
        script: build.script,
        command: build.command,
        status: 'BUILT',
        exitCode: run.status,
        durationMs,
        artifacts: hashDistArtifacts(build.package),
      });
    }
    expect(results.buildSurface.length).toBeGreaterThan(0);
    expect(results.buildSurface.every((b) => b.status === 'BUILT')).toBe(true);
    expect(
      results.buildSurface.every((b) => b.artifacts.every((a) => /^[0-9a-f]{64}$/.test(a.sha256))),
    ).toBe(true);
  });
});

// ---- 4. Public interface ------------------------------------------------------

describe('V01 public interface anchoring and real consumer composition', () => {
  it('anchors the three controlled Shun package entries plus the B-040 public surface', async () => {
    const app = await import('../../../../packages/domain-app/src/index.ts');
    expect(typeof app.composeDomainBuild).toBe('function');
    expect(typeof app.createControlApiGateway).toBe('function');
    expect(app.V03_TRUSTED_CLOUD_INTERPRETER_PORT).toBe('shun.trusted-cloud-interpreter.v03');
    expect(app.V03_EXTERNAL_IMPORT_BINDINGS).toEqual({
      'domain-harness-openai-host': 'shun.trusted-cloud-interpreter.v03',
    });

    const computer = await import('../../../../packages/domain-computer/src/index.ts');
    for (const name of [
      'selectGoalSemantic',
      'createNextGuidedStep',
      'validateGuidedStepOutcome',
      'validateGuidedAdvisory',
      'APPROVED_STEP_TEMPLATES',
      'createMetaFeedbackAdapter',
      'createProviderJitBusinessAdapter',
      'DomainComputerRecipeReplayAdapter',
      'createComputerFolderObservationAdapter',
      'collectLocalComputerSupportContext',
      'buildNeutralGoalRequest',
      'selectedCAdapterSeam',
    ]) {
      expect(typeof (computer as Record<string, unknown>)[name]).toBe(
        name === 'APPROVED_STEP_TEMPLATES' ? 'object' : 'function',
      );
    }

    const host = await import('../../../../packages/domain-host/src/index.ts');
    for (const name of [
      'createTrustedCloudHostBinding',
      'installTrustedCloudHostBinding',
      'MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS',
      'createWindowsEffectHost',
      'readKernelEffectPermit',
      'createShunStoreStateAdapter',
      'createTrustedProviderHost',
    ]) {
      expect(typeof (host as Record<string, unknown>)[name]).toBe(
        name === 'MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS' ? 'number' : 'function',
      );
    }
    expect(host.MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS).toBe(20_000);

    const support = await import('@shun/vertical-support');
    expect(typeof support.minimizeSupportContext).toBe('function');
    expect(typeof support.collectWindowsSupportContext).toBe('function');
    expect(typeof support.SupportContextResultSchema.safeParse).toBe('function');

    results.publicInterface.anchoredPackages = [
      { package: '@shun/domain-app', anchored: ['composeDomainBuild', 'createControlApiGateway'] },
      { package: '@shun/domain-computer', anchored: ['13 merged task adapter factories'] },
      { package: '@shun/domain-host', anchored: ['T01/T04/T08 Host seams'] },
      { package: '@shun/vertical-support', anchored: ['B-040 minimize/collect/schema'] },
    ];
  });

  it('re-composes the REAL public buildV10App from the frozen SDK tarball consumer (facade proof)', {
    timeout: 180_000,
  }, async () => {
    const fixturesDir = resolve(repoRoot, 'tests/integration/v03/t11-runtime/fixtures');
    const consumerDir = resolve(repoRoot, 'node_modules/.t11-dh-consumer');
    const readFixture = (name: string): string => readFileSync(join(fixturesDir, name), 'utf8');
    const fileSha = (name: string): string => sha256Hex(readFileSync(join(fixturesDir, name)));

    // Frozen payload receipts (same identity chain T11 proves end-to-end).
    const receipts = new Map<string, string>();
    for (const line of readFileSync(join(fixturesDir, 'SHA256SUMS.txt'), 'utf8').split(/\r?\n/)) {
      const match = line.match(/^([0-9a-f]{64})\s+\*?(.+)$/);
      if (match?.[1] !== undefined && match?.[2] !== undefined) {
        receipts.set(match[2].trim(), match[1]);
      }
    }
    for (const name of ['kernel-mechanism-v1.mjs', 'standard-sdk-v1.mjs', 'workflow-router.mjs']) {
      expect(receipts.get(name)).toBe(fileSha(name));
    }
    expect(readFixture('SOURCE-IDENTITY.txt')).toMatch(
      /sdk_tag_commit=061376f4a023070f215f9feffad5c24d96d503cb/,
    );

    const routerBody = readFixture('workflow-router.mjs').replace(/^export /gm, '');
    const sdk = `${readFixture('standard-sdk-v1.mjs')}
// V01 BUILD-style vendored bundle: the pure Standard WorkflowRouter.
const __dhv10RouterBundle = (() => {
${routerBody}
return { routeWorkflowIntent };
})();
export const routeWorkflowIntent = __dhv10RouterBundle.routeWorkflowIntent;
`;
    const kernel = readFixture('kernel-mechanism-v1.mjs');
    const business = readFixture('business-windows-journey.mjs');
    const capability = readFixture('capability-windows-effect.mjs');

    const app = buildV10App({
      appId: 'shun-v03-qualification',
      audience: 'operator-local',
      buildId: 'shun-v0.3-v01-qualification',
      targetProfile: V10_TARGET_PROFILE,
      modules: [
        {
          packageId: 'v08-kernel-mechanism@1.0.0',
          role: 'kernel-primary',
          abiVersion: 'v08-kernel-abi/1',
          moduleSource: kernel,
          moduleSha256: sha256Hex(kernel),
          endpoint: 'occurrence-runtime',
          dependencies: [],
          provides: ['kernel:occurrence-runtime/1'],
          requires: [],
        },
        {
          packageId: 'standard-sdk@v08.1.0.0',
          role: 'standard-primary',
          abiVersion: 'v08-standard-sdk-abi/1',
          moduleSource: sdk,
          moduleSha256: sha256Hex(sdk),
          endpoint: 'rule-interpreter',
          dependencies: [],
          provides: ['standard:interpret/1', 'standard:route/1'],
          requires: [],
        },
        {
          packageId: 'business-windows-journey@v030.1.0.0',
          role: 'business',
          abiVersion: 'v08-business-abi/1',
          moduleSource: business,
          moduleSha256: sha256Hex(business),
          endpoint: 'business-policy',
          dependencies: [],
          provides: ['business:policy/1', 'intent:submitWindowsAction'],
          requires: [],
        },
        {
          packageId: 'capability-windows-effect@v030.1.0.0',
          role: 'capability',
          abiVersion: 'v08-capability-abi/1',
          moduleSource: capability,
          moduleSha256: sha256Hex(capability),
          endpoint: 'capability-endpoint',
          dependencies: [],
          externalImports: { node: [], npm: ['shun-windows-effect-host'], native: [] },
          provides: ['capability:windows/1'],
          requires: [],
          capabilityId: 'windows',
          externalEffect: true,
          handlers: [{ operationId: 'windows.execute', handler: 'windowsExecute' }],
        },
      ],
      routes: [
        {
          intentId: 'submitWindowsAction',
          operationId: 'windows.execute',
          capabilityId: 'windows',
          handlerId: 'windowsExecute',
        },
      ],
      hardBudget: { maxStepsPerTurn: 8, maxWorkUnitsPerTurn: 64 },
    });
    expect(app.appId).toBe('shun-v03-qualification');

    class PlainV10DocStore implements V10DocStore {
      readonly #documents = new Map<string, { value: unknown; revision: number }>();

      async get(key: string): Promise<{ value: unknown; revision: number } | null> {
        const doc = this.#documents.get(key);
        return doc === undefined
          ? null
          : { value: structuredClone(doc.value), revision: doc.revision };
      }

      async put(
        key: string,
        value: unknown,
        condition: V10DocWriteCondition,
      ): Promise<{ revision: number }> {
        if (condition.kind === 'create') {
          if (this.#documents.has(key)) throw new Error(`CAS conflict on ${key}: exists`);
          this.#documents.set(key, { value: structuredClone(value), revision: 0 });
          return { revision: 0 };
        }
        const existing = this.#documents.get(key);
        if (existing === undefined || existing.revision !== condition.revision) {
          throw new Error(`CAS conflict on ${key}: revision moved`);
        }
        this.#documents.set(key, {
          value: structuredClone(value),
          revision: condition.revision + 1,
        });
        return { revision: condition.revision + 1 };
      }

      async remove(key: string, condition: V10DocWriteCondition): Promise<void> {
        if (condition.kind === 'create') {
          if (this.#documents.has(key)) throw new Error(`CAS conflict on ${key}: exists`);
          this.#documents.delete(key);
          return;
        }
        const existing = this.#documents.get(key);
        if (existing === undefined || existing.revision !== condition.revision) {
          throw new Error(`CAS conflict on ${key}: revision moved`);
        }
        this.#documents.delete(key);
      }

      keys(): readonly string[] {
        return [...this.#documents.keys()].sort();
      }
    }

    let tick = 0;
    const store = new PlainV10DocStore();
    const activation = await activateV10App(app, {
      store,
      tenantId: 'tenant:shun-v03',
      now: () => {
        tick += 1;
        return Date.UTC(2026, 9, 31, 0, 0, 0) + tick * 1000;
      },
      deploymentIdentity: {
        deployedAppId: 'deployment:shun-v03-v01',
        tenantId: 'tenant:shun-v03',
        appId: app.appId,
      },
      queryAuthority: { principal: { role: 'reader' }, authorize: () => true },
      deploymentRoot: consumerDir,
    });
    const facade: unknown = activation.facade;
    // The authoritative Host-seam brand check plus the frozen public
    // facade surface (send/subscribe/isClosed per the SDK activation.d.ts).
    expect(isV10AppFacade(facade)).toBe(true);
    const facadeRecord = facade as Record<string, unknown>;
    for (const method of ['send', 'subscribe', 'queryScopedSnapshot', 'isClosed']) {
      expect(typeof facadeRecord[method], `facade.${method}`).toBe('function');
    }
    expect((facadeRecord.isClosed as () => boolean)()).toBe(false);
    const kernelIdentity = v10SelectedKernelIdentity(activation.facade);
    expect(kernelIdentity !== null && typeof kernelIdentity === 'object').toBe(true);
    activation.dispose();
    expect((facadeRecord.isClosed as () => boolean)()).toBe(true);

    results.publicInterface.consumerComposition = {
      appId: app.appId,
      moduleCount: 4,
      isV10AppFacade: true,
      facadeSurface: ['send', 'subscribe', 'queryScopedSnapshot', 'isClosed', 'dispose'],
      sdkTagCommit: '061376f4a023070f215f9feffad5c24d96d503cb',
      payloadReceiptsVerified: true,
      fullKJourneyProof: 'T11 suite (re-run by the composition sweep)',
    };
  });
});

// ---- 5. Windows compatibility + real B-040 -----------------------------------

describe('V01 Windows compatibility and real B-040 evidence', () => {
  // The Windows legs are real-host qualification evidence: they run (and
  // stay mandatory) only on a Windows host. The Linux CI agent skips them;
  // recorded Windows evidence lives in the qualification report / R02-V
  // validation receipt, never in the Linux pipeline.
  it.skipIf(process.platform !== 'win32')('runs on real Windows with Node >= 24', () => {
    expect(process.platform).toBe('win32');
    const major = Number(/^v(\d+)/.exec(process.version)?.[1] ?? 0);
    expect(major).toBeGreaterThanOrEqual(24);
    results.windowsCompatibility.nodeAtLeast24 = major >= 24;
  });

  it.skipIf(process.platform !== 'win32')(
    're-runs the REAL read-only B-040 support-context collection',
    { timeout: 120_000 },
    async () => {
    const context = await collectLocalComputerSupportContext();
    expect(context.schema).toBe('shun.computer.support-context.v03');
    expect(context.source).toBe('ACTUAL_WINDOWS_HOST');
    expect(context.result.localOnly).toBe(true);
    expect(context.result.externalDisclosures).toEqual([]);
    expect(context.result.report.schema).toBe('shun.support-context.v1');
    const digest = sha256Hex(canonicalJson(context.result));
    results.windowsCompatibility.b040 = {
      source: context.source,
      localOnly: context.result.localOnly,
      externalDisclosures: context.result.externalDisclosures.length,
      reportSchema: context.result.report.schema,
      osName: context.result.report.os.name,
      osBuild: context.result.report.os.build,
      canonicalReportSha256: digest,
    };
    // The sealed report is frozen and carries no absolute collector paths.
    expect(Object.isFrozen(context.result.report)).toBe(true);
    expect(canonicalJson(context.result)).not.toMatch(/[A-Z]:\\\\Users\\\\/);
    },
  );
});

// ---- Shared zero-paid fakes for the negative matrix ---------------------------

const HOST_NOW = Date.parse('2026-10-31T00:00:00.000Z');
const GOAL = 'Please inspect the selected folder and summarize its contents.';
const CANARY = 'SHUN_V01_CANARY_SECRET_DO_NOT_EXPORT';

interface FakeLedgerCounters {
  reserveCalls: number;
  mayHaveSentCalls: number;
  unknownCostCalls: number;
}

type FakeLedger = CloudBudgetLedgerPort & FakeLedgerCounters;

function fakeLedger(): FakeLedger {
  const counters = { reserveCalls: 0, mayHaveSentCalls: 0, unknownCostCalls: 0 };
  return {
    get reserveCalls(): number {
      return counters.reserveCalls;
    },
    get mayHaveSentCalls(): number {
      return counters.mayHaveSentCalls;
    },
    get unknownCostCalls(): number {
      return counters.unknownCostCalls;
    },
    reserve: () => {
      counters.reserveCalls += 1;
      return {
        ok: true as const,
        attemptId: 'attempt-t12',
        requestBytesSha256: 'b'.repeat(64),
        reservedCostMicros: 1,
      };
    },
    markMayHaveSent: () => {
      counters.mayHaveSentCalls += 1;
      return true;
    },
    markUnknownCost: () => {
      counters.unknownCostCalls += 1;
      return true;
    },
  };
}

function countersOf(ledger: FakeLedger): FakeLedgerCounters {
  return {
    reserveCalls: ledger.reserveCalls,
    mayHaveSentCalls: ledger.mayHaveSentCalls,
    unknownCostCalls: ledger.unknownCostCalls,
  };
}

function fakeBrokerSession(overrides: { consentOutcome?: string }): ConsentBrokerSessionPort {
  return {
    facts: { principalUserSid: 'principal-t12', logonSid: 'session-t12' },
    requestConsent(request) {
      if (overrides.consentOutcome !== undefined) return { outcome: overrides.consentOutcome };
      const scope = request;
      return {
        outcome: 'APPROVED',
        approval: {
          consentId: 'consent-t12',
          confirmationNonce: 'nonce-t12',
          displayedProjectionSha256: scope.approvedProjectionSha256,
          displayedDisclosureCategories: ['GOAL_TEXT'],
          issuer: {
            brokerId: 'fake-shun-broker',
            brokerRevision: 'broker-t12',
            assertionId: 'assertion-t12',
            channel: 'AUTHENTICATED_PRIVATE_IPC',
            proof: 'fake-session-zero-paid-only',
          },
          scope: {
            taskId: scope.taskId,
            principalId: scope.principalId,
            sessionId: scope.sessionId,
            providerId: 'deepseek',
            modelId: 'deepseek-flash',
            destination: DEEPSEEK_FLASH_DESTINATION,
            approvedProjectionSha256: scope.approvedProjectionSha256,
            scopeRevision: scope.scopeRevision,
            disclosureCategories: ['GOAL_TEXT'],
            registryRevision: scope.registryRevision,
            policyRevision: scope.policyRevision,
            pricingRevision: scope.pricingRevision,
            revocationEpoch: scope.revocationEpoch,
            maxCalls: scope.maxCalls,
            maxInputTokens: scope.maxInputTokens,
            maxOutputTokens: scope.maxOutputTokens,
            maxCostMicros: scope.maxCostMicros,
            issuedAt: scope.issuedAt,
            expiresAt: scope.expiresAt,
          },
        } satisfies CloudConsentApproval,
      };
    },
    checkNonce: () => true,
    verifyApproval: () => ({ valid: true, reason: 'fake-session' }),
    shutdown: () => ({ exitCode: 0, timedOut: false }),
  };
}

function t12InterpreterConfig(options: {
  ledger: FakeLedger;
  broker: ConsentBrokerSessionPort;
  fetchTransport: typeof fetch;
}): TrustedCloudConfig {
  return {
    ledgerFile: join(tmpdir(), 't12-zero-paid-unused.sqlite'),
    registryRevision: 'registry-t12',
    policyRevision: 'policy-t12',
    scopeRevision: 'scope-t12',
    pricingRevision: 'pricing-t12',
    revocationEpoch: 1,
    inputMicrosPerToken: 1,
    outputMicrosPerToken: 2,
    maxInputTokens: 4096,
    maxOutputTokens: 256,
    maxCostMicros: 100_000,
    isCurrent: () => true,
    isOffline: () => false,
    readApiKey: () => 't12-local-test-key-never-a-real-credential',
    consentHostAvailable: () => true,
    openConsentSession: () => options.broker,
    createLedger: () => options.ledger,
    fetchTransport: options.fetchTransport,
    now: () => HOST_NOW,
  };
}

function countingFetch(respond: () => Response): typeof fetch & { calls: () => number } {
  let calls = 0;
  const transport = (async (
    _input: Parameters<typeof fetch>[0],
    init?: RequestInit,
  ): Promise<Response> => {
    calls += 1;
    void init?.body;
    return respond();
  }) as typeof fetch & { calls: () => number };
  transport.calls = () => calls;
  return transport;
}

// ---- 6. Version-level negative matrix -----------------------------------------

describe('V01 version-level negative matrix', () => {
  it('N1 UNKNOWN-as-success: a forged remote outcome never renders completed', async () => {
    // The T04 production mapping admits ONLY the exact frozen
    // UNTRUSTED_REMOTE_PROPOSAL shape. A hostile interpreter claiming a
    // completed/executed outcome is remapped to UNKNOWN and the journal
    // records UNKNOWN — never the forged completion.
    const journal = memoryJournal();
    let interpreterCalls = 0;
    const forged = {
      ok: true,
      taskId: 'cloud-forged',
      status: 'completed',
      proposalText: 'untrusted proposal text',
      model: 'deepseek-flash',
      costState: 'SETTLED_ZERO',
      executed: true,
    };
    const binding = createTrustedCloudHostBinding({
      interpreter: {
        status: () => ({
          enabled: true,
          provider: 'deepseek' as const,
          model: 'deepseek-flash' as const,
          osConsentRequired: true as const,
        }),
        interpretGoal: (async () => {
          interpreterCalls += 1;
          return forged;
        }) as unknown as TrustedCloudInterpreterPort['interpretGoal'],
      },
      journal: journal.journal,
      configuredMaxOutputTokens: 256,
      now: () => HOST_NOW,
    });
    const mapped = await binding.generate(validGenerateRequest());
    expect(mapped).toMatchObject({
      status: 'unknown',
      errorCategory: 'OUTCOME_UNKNOWN',
      reasonCode: 'REMOTE_OUTCOME_UNRESOLVED',
    });
    expect(JSON.stringify(mapped)).not.toContain('"status":"completed"');
    expect(journal.rows.get('request-t12-01')?.result).toMatchObject({ status: 'unknown' });
    expect(interpreterCalls).toBe(1);

    // A cost-ambiguous refusal (REMOTE_REFUSED — the send may have happened)
    // maps to UNKNOWN too, never to completed:
    const refused = await createTrustedCloudHostBinding({
      interpreter: {
        status: () => ({
          enabled: true,
          provider: 'deepseek' as const,
          model: 'deepseek-flash' as const,
          osConsentRequired: true as const,
        }),
        interpretGoal: async () => ({ ok: false, code: 'REMOTE_REFUSED' }),
      },
      journal: memoryJournal().journal,
      configuredMaxOutputTokens: 256,
      now: () => HOST_NOW,
    }).generate(validGenerateRequest());
    expect(refused).toMatchObject({ status: 'unknown', errorCategory: 'OUTCOME_UNKNOWN' });

    // The production interpreter on an unparseable remote body stays
    // conservative: REMOTE_REFUSED, never a rendered completion.
    const ledger = fakeLedger();
    const interpreter = new TrustedCloudInterpreter(
      t12InterpreterConfig({
        ledger,
        broker: fakeBrokerSession({}),
        fetchTransport: countingFetch(
          () =>
            new Response('<html>unparseable gateway noise</html>', {
              status: 200,
              headers: { 'content-type': 'text/html' },
            }),
        ),
      }),
    );
    const deadline = HOST_NOW + MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS;
    const result = await interpreter.interpretGoal({ goalText: GOAL, deadlineUnixMs: deadline });
    expect(result).toEqual({ ok: false, code: 'REMOTE_REFUSED' });
    expect(JSON.stringify(result)).not.toContain('completed');

    recordNegative(
      'N1',
      'UNKNOWN-as-success: forged completed/unparseable outcomes stay unknown/refused',
    );
  });

  it('N2 expired deadline sends zero HTTP through the production interpreter', async () => {
    const ledger = fakeLedger();
    const transport = countingFetch(() => new Response('{}', { status: 200 }));
    const interpreter = new TrustedCloudInterpreter(
      t12InterpreterConfig({
        ledger,
        broker: fakeBrokerSession({}),
        fetchTransport: transport,
      }),
    );
    const result = await interpreter.interpretGoal({
      goalText: GOAL,
      deadlineUnixMs: HOST_NOW - 1000,
    });
    expect(result).toEqual({ ok: false, code: 'DEADLINE_EXPIRED' });
    expect(transport.calls()).toBe(0);
    expect(countersOf(ledger)).toEqual({
      reserveCalls: 0,
      mayHaveSentCalls: 0,
      unknownCostCalls: 0,
    });
    recordNegative('N2', 'expired deadline: zero fetch, zero ledger (documented zero-send)');
  });

  it('N3 maxOutputTokens overrun refuses at the host binding and the transport with zero fetch', async () => {
    // (a) T04 host binding: a request DTO ceiling above the configured
    // ceiling refuses BEFORE journal reserve, consent or interpreter.
    const journal = memoryJournal();
    let interpreterCalls = 0;
    const binding = createTrustedCloudHostBinding({
      interpreter: {
        status: () => ({
          enabled: true,
          provider: 'deepseek' as const,
          model: 'deepseek-flash' as const,
          osConsentRequired: true as const,
        }),
        interpretGoal: (async () => {
          interpreterCalls += 1;
          return { ok: false, code: 'CLOUD_UNAVAILABLE' };
        }) as TrustedCloudInterpreterPort['interpretGoal'],
      },
      journal: journal.journal,
      configuredMaxOutputTokens: 256,
      now: () => HOST_NOW,
    });
    const overrun = await binding.generate(validGenerateRequest({ maxOutputTokens: 257 }));
    expect(overrun).toMatchObject({
      status: 'refused',
      errorCategory: 'UNSUPPORTED_FEATURE',
      reasonCode: 'OUTPUT_TOKEN_CEILING_UNSUPPORTED',
    });
    expect(journal.reserveCalls()).toBe(0);
    expect(interpreterCalls).toBe(0);

    // (b) The single existing transport: a request ceiling above the approved
    // consent scope is DISCLOSURE_SCOPE_DRIFT with zero reserve and zero HTTP.
    const goalText = 'Summarize the selected folder contents.';
    const ledger = fakeLedger();
    const fetch = countingFetch(() => new Response('{}', { status: 200 }));
    const approval = transportApproval(goalText);
    const transport = new TrustedDeepSeekTransport({
      ledger,
      currentnessFor: () => ledgerCurrentness(approval),
      isOffline: () => false,
      isLocalOnly: () => false,
      readApiKey: () => 't12-local-test-key-never-a-real-credential',
      fetchTransport: fetch,
    });
    const outcome = await transport.invoke({
      goalText,
      attemptId: 'attempt-overrun',
      approval,
      maxOutputTokens: 999,
    });
    expect(outcome).toEqual({ ok: false, code: 'DISCLOSURE_SCOPE_DRIFT' });
    expect(countersOf(ledger).reserveCalls).toBe(0);
    expect(fetch.calls()).toBe(0);
    recordNegative(
      'N3',
      'maxOutputTokens overrun: refused at binding and transport, zero fetch/reserve',
    );
  });

  it('N4 duplicate requestId never mints new permission (journal replay/conflict + ledger idempotency)', async () => {
    // (a) K request journal: the same requestId replays the RECORDED result
    // without a second interpreter/attempt; a different digest under the same
    // requestId is a CONFLICT refusal — never a fresh mint.
    const journal = memoryJournal();
    let interpreterCalls = 0;
    const binding = createTrustedCloudHostBinding({
      interpreter: {
        status: () => ({
          enabled: true,
          provider: 'deepseek' as const,
          model: 'deepseek-flash' as const,
          osConsentRequired: true as const,
        }),
        interpretGoal: (async () => {
          interpreterCalls += 1;
          return {
            ok: true,
            taskId: 'cloud-t12',
            status: 'UNTRUSTED_REMOTE_PROPOSAL',
            proposalText: 'untrusted proposal text',
            model: 'deepseek-flash',
            costState: 'UNKNOWN_COST',
            executed: false,
          } satisfies Extract<TrustedCloudInterpretResult, { ok: true }>;
        }) as unknown as TrustedCloudInterpreterPort['interpretGoal'],
      },
      journal: journal.journal,
      configuredMaxOutputTokens: 256,
      now: () => HOST_NOW,
    });
    const first = await binding.generate(validGenerateRequest());
    expect(first.status).toBe('completed');
    const replay = await binding.generate(validGenerateRequest());
    expect(replay).toEqual(first);
    expect(interpreterCalls).toBe(1);
    const conflict = await binding.generate(
      validGenerateRequest({ requestId: 'request-t12-01', goalText: 'A different goal text.' }),
    );
    expect(conflict).toMatchObject({
      status: 'refused',
      errorCategory: 'AUTH_DENIED',
      reasonCode: 'REQUEST_ID_CONFLICT',
    });
    expect(interpreterCalls).toBe(1);

    // (b) The durable cloud budget ledger: the same attemptId is an
    // IDEMPOTENCY_REPLAY; a second attemptId under the exhausted maxCalls=1
    // consent is BUDGET_EXHAUSTED — no new permission is minted.
    const { ledger, cleanup } = tempLedger();
    try {
      const firstReserve = ledger.reserve(ledgerRequest('attempt-a'));
      expect(firstReserve.ok).toBe(true);
      expect(ledger.reserve(ledgerRequest('attempt-a'))).toEqual({
        ok: false,
        code: 'IDEMPOTENCY_REPLAY',
      });
      expect(ledger.reserve(ledgerRequest('attempt-b'))).toEqual({
        ok: false,
        code: 'BUDGET_EXHAUSTED',
      });
    } finally {
      cleanup();
    }
    recordNegative(
      'N4',
      'duplicate requestId: journal REPLAY/CONFLICT + ledger IDEMPOTENCY_REPLAY/BUDGET_EXHAUSTED',
    );
  });

  it('N5 refused/failed/unknown never complete and UNKNOWN_COST never auto-refunds', async () => {
    // (a) The durable ledger class exposes NO refund/release surface at all:
    const { ledger: probe, cleanup: probeCleanup } = tempLedger();
    const prototypeMethods = Object.getOwnPropertyNames(Object.getPrototypeOf(probe));
    probeCleanup();
    expect(prototypeMethods.filter((m) => /refund|release|credit/i.test(m))).toEqual([]);

    // (b) UNKNOWN_COST is terminal and never releases the burned budget:
    const { ledger: realLedger, cleanup } = tempLedger();
    try {
      const reserved = realLedger.reserve(ledgerRequest('attempt-unknown'));
      expect(reserved.ok).toBe(true);
      expect(realLedger.markMayHaveSent(mayHaveSentRequest('attempt-unknown'))).toBe(true);
      expect(realLedger.markUnknownCost('attempt-unknown')).toBe(true);
      expect(realLedger.inspect('attempt-unknown')?.status).toBe('UNKNOWN_COST');
      expect(realLedger.markUnknownCost('attempt-unknown')).toBe(false);
      expect(realLedger.reserve(ledgerRequest('attempt-unknown'))).toEqual({
        ok: false,
        code: 'IDEMPOTENCY_REPLAY',
      });
    } finally {
      cleanup();
    }

    // (c) Production interpreter on a 500: REMOTE_REFUSED + UNKNOWN_COST
    // fence (markUnknownCost), zero refund, zero second send.
    const ledger = fakeLedger();
    const transport = countingFetch(
      () =>
        new Response(JSON.stringify({ error: 'remote refusal body' }), {
          status: 500,
          headers: { 'content-type': 'application/json' },
        }),
    );
    const interpreter = new TrustedCloudInterpreter(
      t12InterpreterConfig({
        ledger,
        broker: fakeBrokerSession({}),
        fetchTransport: transport,
      }),
    );
    const deadline = HOST_NOW + MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS;
    const result = await interpreter.interpretGoal({ goalText: GOAL, deadlineUnixMs: deadline });
    expect(result).toEqual({ ok: false, code: 'REMOTE_REFUSED' });
    expect(transport.calls()).toBe(1);
    expect(countersOf(ledger)).toEqual({
      reserveCalls: 1,
      mayHaveSentCalls: 1,
      unknownCostCalls: 1,
    });
    recordNegative(
      'N5',
      'refused/failed/unknown stay non-completed; UNKNOWN_COST has no refund path',
    );
  });

  it('N6 invalid Case: zero send, zero journal, then a valid same-Case submission succeeds', async () => {
    const payloads: unknown[] = [];
    let calls = 0;
    const facade = {
      async send(payload: unknown) {
        calls += 1;
        payloads.push(payload);
        return { accepted: true, receipt: 'k-receipt-t12' };
      },
    };
    const gateway = createControlApiGateway({ domainApp: facade, now: () => HOST_NOW });
    const valid = validSubmission('case-t12-01');
    for (const invalid of [
      { ...valid, extra: 1 },
      { ...valid, caseId: 'mismatched-case' },
      { ...valid, approvalRef: { forged: CANARY } },
      { ...valid, currentnessRef: 'not-a-trusted-reference' },
    ]) {
      const receipt = await gateway.submit(invalid);
      expect(receipt.status).toBe('REFUSED');
      if (receipt.status !== 'REFUSED') return;
      expect(receipt.sendCalls).toBe(0);
      expect(receipt.journalEntries).toBe(0);
    }
    expect(calls).toBe(0);

    // The SAME stable Case stays admissible after the refusals:
    const sent = await gateway.submit(valid);
    expect(sent.status).toBe('UNKNOWN');
    if (sent.status !== 'UNKNOWN') return;
    expect(sent.sendCalls).toBe(1);
    expect(calls).toBe(1);
    expect(payloads[0]).toEqual(valid);
    recordNegative('N6', 'invalid Case: zero send + zero journal, then valid same Case succeeds');
  });

  it('N7 secret leak scan: refusal details, receipts and failure results carry no secrets', async () => {
    const canaries = [CANARY, 'BEGIN FAKE PRIVATE KEY', 'password=hunter2-canary'];
    const sensitive =
      /SHUN_V01_CANARY|BEGIN [A-Z ]*PRIVATE KEY|password\s*=|api[_-]?key\s*=|PRIVATE_KEY/i;
    const collected: string[] = [];

    const payloads: unknown[] = [];
    const facade = {
      async send(payload: unknown) {
        payloads.push(payload);
        return { accepted: true };
      },
    };
    const gateway = createControlApiGateway({ domainApp: facade, now: () => HOST_NOW });
    const valid = validSubmission('case-t12-02', `Summarize the folder. ${CANARY}`);
    for (const hostile of [
      { ...valid, approvalRef: { token: canaries[0] }, extra: canaries[1] },
      { ...valid, currentnessRef: { secret: canaries[2] } },
      { ...valid, caseId: 'case/../traversal', request: { ...valid.request, goal: canaries[0] } },
      { ...valid, password: canaries[2], apiKey: canaries[1] },
    ]) {
      const receipt = await gateway.submit(hostile);
      collected.push(JSON.stringify(receipt));
      expect(receipt.status).toBe('REFUSED');
    }
    const sent = await gateway.submit(valid);
    collected.push(JSON.stringify(sent));
    expect(sent.status).toBe('UNKNOWN');
    // The UNKNOWN receipt keeps may-have-sent truth and must not include raw secrets.
    for (const text of collected) {
      expect(sensitive.test(text), text.slice(0, 200)).toBe(false);
    }

    // Interpreter failure paths never reflect OS/HTTP/model error content:
    const ledger = fakeLedger();
    const throwingBroker = fakeBrokerSession({});
    throwingBroker.requestConsent = () => {
      throw new Error(`broker exploded: ${canaries[0]}`);
    };
    const interpreter = new TrustedCloudInterpreter(
      t12InterpreterConfig({
        ledger,
        broker: throwingBroker,
        fetchTransport: countingFetch(() => new Response('{}', { status: 200 })),
      }),
    );
    const deadline = HOST_NOW + MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS;
    const brokerCrash = await interpreter.interpretGoal({
      goalText: GOAL,
      deadlineUnixMs: deadline,
    });
    expect(brokerCrash).toEqual({ ok: false, code: 'REMOTE_REFUSED' });
    collected.push(JSON.stringify(brokerCrash));
    const declined = await new TrustedCloudInterpreter(
      t12InterpreterConfig({
        ledger: fakeLedger(),
        broker: fakeBrokerSession({ consentOutcome: 'DECLINED' }),
        fetchTransport: countingFetch(() => new Response('{}', { status: 200 })),
      }),
    ).interpretGoal({ goalText: GOAL, deadlineUnixMs: deadline });
    expect(declined).toEqual({ ok: false, code: 'CONSENT_DECLINED' });
    collected.push(JSON.stringify(declined));
    for (const text of collected) {
      expect(text.includes(CANARY)).toBe(false);
    }
    expect(countersOf(ledger).reserveCalls).toBe(0);
    recordNegative('N7', 'no secret leak in refusal details, receipts or failure results');
  });

  it('N8 stale grant and duplicate Windows effect are idempotently refused', async () => {
    // (a) Stale/expired grant: the REAL T01 adapter refuses before the effect
    // port with zero physical execution.
    const planHash = 'a'.repeat(64);
    const executeCalls: string[] = [];
    const host = createWindowsEffectHost({
      binding: { capabilityId: 'cap.windows', operationId: 'windows.execute' },
      authorization: {
        async resolve(input) {
          return {
            effectId: input.effectId,
            plan: { taskId: 'task-t12', planHash: input.planRef },
            action: {
              taskId: 'task-t12',
              actionId: input.actionRef,
              planHash: input.planRef,
              authorizationRef: input.grantRef,
            },
            grant: { grantId: 'grant-t12', planHash, taskId: 'task-t12' },
          };
        },
      },
      osAuthority: {
        async recheck() {
          return { ok: true };
        },
      },
      actionController: {
        async authorizeEffect() {
          return { ok: false, code: 'GRANT_EXPIRED' };
        },
      },
      windows: {
        async execute(input) {
          executeCalls.push(input.effectId);
          const action = input.action as { actionId?: string } | null;
          return {
            actionId: action?.actionId ?? null,
            terminal: 'SUCCEEDED',
            sideEffectEvidence: {
              recoveryClassification: 'COMPLETED_VERIFIED',
              postStateVerified: true,
            },
          };
        },
      },
    });
    const dispatchContext: KernelEffectDispatchContext = {
      capabilityId: 'cap.windows',
      operationId: 'windows.execute',
      effectPermit: { effectId: 'effect-t12-01', durableControlTurnId: 'turn-t12', attempt: 1 },
    };
    const stale = await host.dispatch(
      { actionRef: 'action-t12', planRef: planHash, grantRef: 'grant-t12' },
      dispatchContext,
    );
    expect(stale).toMatchObject({
      phase: 'terminal',
      outcome: { ok: false, error: { code: 'SHUN_AUTHORIZATION_REFUSED' } },
    });
    expect(executeCalls).toEqual([]);

    // (b) Duplicate Windows effect on the durable ShunStore: the retry with
    // the SAME intended mutation replays the recorded receipt (applied:false);
    // the same effectId with a DIFFERENT mutation is an identity conflict —
    // never a second application.
    const storeDir = mkdtempSync(join(tmpdir(), 't12-duplicate-effect-'));
    try {
      const store = new ShunStore({ file: join(storeDir, 'store.sqlite') });
      try {
        const mutation = {
          recordKind: 'lifecycle_record' as const,
          recordId: 'rec-t12-01',
          payload: { note: 'v01-duplicate-effect-probe' },
        };
        const first = await store.apply('turn-t12/effect/1', mutation);
        expect(first.applied).toBe(true);
        const replay = await store.apply('turn-t12/effect/1', { ...mutation });
        expect(replay).toEqual({
          effectId: 'turn-t12/effect/1',
          applied: false,
          receiptRef: first.receiptRef,
        });
        expect(await store.getEffectReceipt('turn-t12/effect/1')).toMatchObject({
          effectId: 'turn-t12/effect/1',
          applied: true,
        });
        await expect(
          store.apply('turn-t12/effect/1', {
            recordKind: 'lifecycle_record' as const,
            recordId: 'rec-t12-01',
            payload: { note: 'a DIFFERENT mutation under the same effectId' },
          }),
        ).rejects.toThrow('effect identity conflict');
        const effectRows = store.database
          .prepare('SELECT COUNT(*) AS n FROM effects WHERE effect_id = ?')
          .get('turn-t12/effect/1') as { n: number };
        expect(effectRows.n).toBe(1);
      } finally {
        await store.close();
      }
    } finally {
      rmSync(storeDir, { recursive: true, force: true });
    }
    recordNegative('N8', 'stale grant refused pre-effect; duplicate effect idempotently rejected');
  });
});

// ---- Negative-matrix helpers (types + fixtures) -------------------------------

function validSubmission(
  caseId: string,
  goal = '整理下载目录里的报告文件',
): {
  caseId: string;
  request: Record<string, unknown>;
  currentnessRef: string;
  approvalRef: string;
} {
  return {
    caseId,
    request: {
      taskId: caseId,
      goal,
      objects: [{ kind: 'DIRECTORY', ref: 'downloads/reports' }],
      constraints: { format: '保持原文件名' },
      policyContext: {
        privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
        environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
      },
      verificationIntent: { successConditions: ['报告文件已按规则归档'] },
    },
    currentnessRef: 'shun.currentness.v1/registry-t12',
    approvalRef: 'shun.approval.v1/appr-t12',
  };
}

function validGenerateRequest(
  overrides: Partial<{
    requestId: string;
    goalText: string;
    deadlineUnixMs: number;
    maxOutputTokens: number;
  }> = {},
): ShunLlmGenerateRequestV1 {
  const request = buildNeutralGoalRequest({
    requestId: overrides.requestId ?? 'request-t12-01',
    goalText: overrides.goalText ?? GOAL,
    deadlineUnixMs:
      overrides.deadlineUnixMs ?? HOST_NOW + MINIMUM_SENDER_DEADLINE_BUDGET_MS + 60_000,
    maxOutputTokens: overrides.maxOutputTokens ?? 256,
  });
  if (!request) throw new Error('BAD_T12_REQUEST_FIXTURE');
  return request;
}

type JournalRow = { requestSha256: string; result?: ShunLlmGenerateResultV1 };

/** Deterministic durable-journal double (production injects the ShunStore journal). */
function memoryJournal(): {
  journal: DurableCloudRequestJournal;
  rows: Map<string, JournalRow>;
  reserveCalls: () => number;
} {
  const rows = new Map<string, JournalRow>();
  let reserveCount = 0;
  const journal: DurableCloudRequestJournal = {
    durability: 'DURABLE_SHUN_STORE',
    reserve: async (input): Promise<CloudRequestJournalDecision> => {
      reserveCount += 1;
      const prior = rows.get(input.requestId);
      if (!prior) {
        rows.set(input.requestId, { requestSha256: input.requestSha256 });
        return { status: 'RESERVED' };
      }
      if (prior.requestSha256 !== input.requestSha256) return { status: 'CONFLICT' };
      return prior.result ? { status: 'REPLAY', result: prior.result } : { status: 'IN_FLIGHT' };
    },
    complete: async (input) => {
      const prior = rows.get(input.requestId);
      if (!prior || prior.requestSha256 !== input.requestSha256 || prior.result) return false;
      prior.result = input.result;
      return true;
    },
  };
  return { journal, rows, reserveCalls: () => reserveCount };
}

const LEDGER_BODY = Buffer.from(
  '{"model":"deepseek-flash","messages":[{"role":"user","content":"Hello"}]}',
  'utf8',
);
const LEDGER_PROJECTION = Buffer.from('{"provider":"deepseek","user":"Hello"}', 'utf8');

function ledgerApproval(): CloudConsentApproval {
  const projectionSha = sha256Hex(LEDGER_PROJECTION);
  return {
    consentId: 'consent-t12-ledger',
    confirmationNonce: 'nonce-t12-ledger',
    displayedProjectionSha256: projectionSha,
    displayedDisclosureCategories: ['GOAL_TEXT'],
    issuer: {
      brokerId: 'shun-private-broker',
      brokerRevision: 'broker-t12',
      assertionId: 'assertion-t12-ledger',
      channel: 'AUTHENTICATED_PRIVATE_IPC',
      proof: 'opaque-external-trust-proof',
    },
    scope: {
      taskId: 'task-t12-ledger',
      principalId: 'principal-t12',
      sessionId: 'session-t12',
      providerId: 'deepseek',
      modelId: 'deepseek-flash',
      destination: DEEPSEEK_FLASH_DESTINATION,
      approvedProjectionSha256: projectionSha,
      scopeRevision: 'scope-t12',
      disclosureCategories: ['GOAL_TEXT'],
      registryRevision: 'registry-t12',
      policyRevision: 'policy-t12',
      pricingRevision: 'pricing-t12',
      revocationEpoch: 1,
      maxCalls: 1,
      maxInputTokens: 1000,
      maxOutputTokens: 100,
      maxCostMicros: 10_000,
      issuedAt: '2026-10-30T23:00:00.000Z',
      expiresAt: '2026-10-31T01:00:00.000Z',
    },
  };
}

function ledgerCurrentness(approval: CloudConsentApproval): CloudConsentCurrentness {
  const scope = approval.scope;
  return {
    kind: 'CURRENT',
    taskId: scope.taskId,
    principalId: scope.principalId,
    sessionId: scope.sessionId,
    policyRevision: scope.policyRevision,
    registryRevision: scope.registryRevision,
    pricingRevision: scope.pricingRevision,
    scopeRevision: scope.scopeRevision,
    revocationEpoch: scope.revocationEpoch,
    nonceIsUnused: true,
  };
}

function ledgerRequest(attemptId: string) {
  const approval = ledgerApproval();
  return {
    attemptId,
    approval,
    currentness: ledgerCurrentness(approval),
    now: '2026-10-31T00:00:00.000Z',
    requestBytes: LEDGER_BODY,
    disclosureProjectionBytes: LEDGER_PROJECTION,
    outputTokenCeiling: 20,
  };
}

function mayHaveSentRequest(attemptId: string) {
  const approval = ledgerApproval();
  return {
    attemptId,
    actualRequestBytes: LEDGER_BODY,
    approval,
    currentness: ledgerCurrentness(approval),
    now: '2026-10-31T00:00:00.000Z',
  };
}

/**
 * Scope-consistent approval for the transport overrun negative: the approved
 * projection hash matches the real goal disclosure, but the approved output
 * ceiling (100) is BELOW the requested one (999).
 */
function transportApproval(goalText: string): CloudConsentApproval {
  const disclosure = buildDeepSeekGoalDisclosure(goalText);
  if (!disclosure) throw new Error('BAD_T12_DISCLOSURE_FIXTURE');
  return {
    consentId: 'consent-t12-transport',
    confirmationNonce: 'nonce-t12-transport',
    displayedProjectionSha256: disclosure.sha256,
    displayedDisclosureCategories: ['GOAL_TEXT'],
    issuer: {
      brokerId: 'private-shun-broker',
      brokerRevision: 'broker-t12',
      assertionId: 'assertion-t12-transport',
      channel: 'AUTHENTICATED_PRIVATE_IPC',
      proof: 'fixture-only-not-production',
    },
    scope: {
      taskId: 'task-t12-transport',
      principalId: 'principal-t12',
      sessionId: 'session-t12',
      providerId: 'deepseek',
      modelId: 'deepseek-flash',
      destination: DEEPSEEK_FLASH_DESTINATION,
      approvedProjectionSha256: disclosure.sha256,
      scopeRevision: 'scope-t12',
      disclosureCategories: ['GOAL_TEXT'],
      registryRevision: 'registry-t12',
      policyRevision: 'policy-t12',
      pricingRevision: 'pricing-t12',
      revocationEpoch: 1,
      maxCalls: 1,
      maxInputTokens: 4096,
      maxOutputTokens: 100,
      maxCostMicros: 100_000,
      issuedAt: '2026-10-30T23:00:00.000Z',
      expiresAt: '2026-10-31T01:00:00.000Z',
    },
  };
}

function tempLedger(): { ledger: DurableCloudBudgetLedger; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 't12-ledger-'));
  const ledger = new DurableCloudBudgetLedger({
    file: join(dir, 'ledger.sqlite'),
    verifyBroker: () => true,
    pricing: { revision: 'pricing-t12', inputMicrosPerToken: 1, outputMicrosPerToken: 2 },
  });
  return {
    ledger,
    cleanup: () => {
      ledger.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
