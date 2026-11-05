/**
 * R02-E Generation-3 startup-runner regression (Issue #269), hardened in
 * Generation-4 (PR #328 R1 findings): the default control-api dev entry must
 * boot the REAL import graph under Node 24's strip-only TypeScript mode
 * without ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX (native/index.ts constructor
 * parameter properties), must stay truthful (no hidden DEMO fallback for a
 * requested real mode), must bind loopback only, and must shut down
 * deterministically. On Windows it additionally boots the full real-storage
 * production composition (operator-pinned BUILD, durable Guided Case, SQLite
 * K docs, cloud journal, Host reference ledger) through the EXACT operator
 * command `pnpm --filter @shun/control-api dev` and reads back production
 * BUILD activation plus a truthful Guided state and gateway over HTTP.
 *
 * G4 test-safety hardening: every spawned Control API process runs in a
 * sanitized environment that forces SHUN_CLOUD_ENABLED=0 and strips
 * DEEPSEEK_API_KEY plus all SHUN_CLOUD_* authority/ledger variables, so a
 * regression at the forged-reference seam can never reach paid egress;
 * fixture digest receipts in SHA256SUMS.txt are mandatory, unique per
 * fixture and lowercase 64-hex (fail closed when missing).
 *
 * G5 bounded cleanup (PR #330 R1 P2 repair): Windows taskkill tree
 * termination is asynchronous with a hard timeout and an explicit
 * fallback, never the G4 unbounded synchronous spawnSync; every spawned
 * server is stopped in a finally so a failed assertion can never leak
 * the child process tree or its loopback listener.
 *
 * G6 cleanup confirmation (PR #332 R1 P2 repair): the taskkill helper
 * handle is retained and, when the timeout wins, the helper is terminated
 * and reaped within a hard bound — no helper child may be left running.
 * Timeout/nonzero fallback no longer pretends that killing the direct
 * pnpm.cmd/shell wrapper proves the descendant tree stopped: killTree
 * reports an explicit result, every finally path inspects the bounded
 * child-exit outcome AND verifies eventual loopback port refusal, and a
 * cleanup failure is surfaced as a secondary diagnostic (preserving the
 * original assertion failure). Deterministic negative coverage forces
 * taskkill timeout and non-zero exit and exercises a wrapper/descendant
 * listener so an orphan can never survive silently.
 *
 * Zero paid calls / zero physical effects: no cloud interpreter is
 * configured (every LLM effect fails closed CLOUD_UNAVAILABLE), no Provider
 * install, no UAC, no persistent Windows effect beyond temp fixture files.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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

/**
 * G4 P1 hardening: variables that must never reach a spawned Control API
 * process. SHUN_CLOUD_ENABLED is forced to '0'; the rest are deleted so a
 * host shell cannot arm the real cloud interpreter (paid egress) even if the
 * security boundary under test regresses. Applied AFTER caller overrides so
 * no override can re-enable the cloud lane.
 */
const STRIPPED_CLOUD_KEYS = [
  'DEEPSEEK_API_KEY',
  'SHUN_CLOUD_LEDGER_FILE',
  'SHUN_CLOUD_AUTHORITY_FILE',
  'SHUN_CLOUD_PUBLIC_KEY_FILE',
  'SHUN_CLOUD_PUBLIC_KEY_SPKI_SHA256',
] as const;

function sanitizedEnv(overrides: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, ...overrides };
  env.SHUN_CLOUD_ENABLED = '0';
  for (const key of STRIPPED_CLOUD_KEYS) delete env[key];
  return env;
}

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

/**
 * Boot main.ts through the pinned tsx runner (the resolved dev script target).
 * The child always receives a cloud-sanitized environment (G4 P1).
 */
function startViaTsx(port: number, env: NodeJS.ProcessEnv) {
  const child = spawn(process.execPath, ['--import', 'tsx', 'src/main.ts'], {
    cwd: apiDir,
    env: { ...sanitizedEnv(env), SHUN_CONTROL_PORT: String(port) },
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
  // Idempotent: a child that already exited (e.g. reaped by a finally
  // cleanup after the success path did its bounded wait) has no second
  // 'exit' event to await, so report the recorded outcome directly.
  if (child.exitCode !== null || child.signalCode !== null) {
    return { code: child.exitCode, signal: child.signalCode };
  }
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

/**
 * Hard bound for the Windows taskkill tree termination below. taskkill
 * normally completes in well under a second; anything past this bound is
 * treated as failure and bounded retry/fallback paths take over.
 */
const TASKKILL_TIMEOUT_MS = 10_000;

/**
 * Hard bound for reaping a taskkill helper that lost its own timeout race:
 * the helper must die to SIGKILL well inside this bound, or cleanup is
 * reported as failed (helperReaped=false).
 */
const TASKKILL_REAP_TIMEOUT_MS = 5_000;

/** Bounded wait for a cleaned-up child to actually exit in cleanupChild. */
const CHILD_EXIT_BOUND_MS = 20_000;

/** Windows exact tree-kill proof persists across later finally cleanup calls. */
const windowsTreeKillHistory = new WeakMap<ReturnType<typeof spawn>, KillTreeResult>();
/** Shell wrappers may orphan silent descendants that no longer own a port. */
const wrapperProcessTrees = new WeakSet<ReturnType<typeof spawn>>();

interface KillTreeResult {
  /**
   * True only when a taskkill attempt exited 0, i.e. the OS confirmed the
   * tree termination. A wrapper-only fallback NEVER sets this: killing the
   * direct pnpm.cmd/shell child is not proof that descendants stopped.
   */
  treeKillConfirmed: boolean;
  /** No taskkill helper survived: every timed-out helper was terminated and reaped within its bound. */
  helperReaped: boolean;
  /** Per-attempt outcomes and fallback notes, for secondary diagnostics. */
  detail: string;
}

/**
 * Negative-test injection points (never used by production cleanup paths):
 * replace the taskkill executable and/or supply verbatim arguments so a
 * deterministic timeout (never-exiting helper) or non-zero exit (bogus
 * PID) can be forced without touching the real taskkill binary.
 */
interface KillTreeOptions {
  timeoutMs?: number;
  taskkillCommand?: string;
  taskkillArgs?: string[];
}

/**
 * Kill the whole spawned process tree and REPORT what could be proven.
 *
 * G6 P2 repair of the G5 killTree:
 * - The taskkill helper child handle is retained for the whole attempt; when
 *   the timeout wins the helper is terminated (SIGKILL / TerminateProcess)
 *   and reaped within TASKKILL_REAP_TIMEOUT_MS — no helper child may be left
 *   running, and a helper that survives is reported (helperReaped=false).
 * - Timeout or non-zero exit triggers ONE bounded retry with the real tree
 *   kill; only if that also fails is the direct wrapper child SIGKILLed as a
 *   last resort, and that fallback is explicitly recorded as "descendant
 *   termination unconfirmed" rather than treated as tree cleanup.
 * - The POSIX group kill is immediate and stays synchronous.
 *
 * Idempotent: a child that already exited is a no-op (the caller's
 * port-refusal verification is what surfaces a leaked descendant), so
 * finally blocks may call this unconditionally. Never throws: cleanup must
 * not mask a test's original assertion failure — cleanupChild aggregates an
 * honest result and guaranteeCleanup surfaces it.
 */
async function killTree(
  child: ReturnType<typeof spawn>,
  options: KillTreeOptions = {},
): Promise<KillTreeResult> {
  const pid = child.pid;
  const alreadyExited = !pid || child.exitCode !== null || child.signalCode !== null;
  if (!isWindows) {
    if (!alreadyExited) {
      try {
        process.kill(-pid, 'SIGKILL');
      } catch {
        child.kill('SIGKILL');
      }
    }
    return {
      treeKillConfirmed: true,
      helperReaped: true,
      detail: alreadyExited ? 'posix: child already exited' : 'posix: process-group SIGKILL',
    };
  }
  if (alreadyExited) {
    // Never erase the proof (or failure) of a previous taskkill attempt.
    return windowsTreeKillHistory.get(child) ?? {
      treeKillConfirmed: false,
      helperReaped: true,
      detail: 'windows: child already exited without an attempted tree kill',
    };
  }
  const timeoutMs = options.timeoutMs ?? TASKKILL_TIMEOUT_MS;
  const detail: string[] = [];
  let helperReaped = true;
  let treeKillConfirmed = false;

  const attempt = async (): Promise<'OK' | 'FAILED' | 'TIMEOUT'> => {
    const killer = spawn(
      options.taskkillCommand ?? 'taskkill',
      options.taskkillArgs ?? ['/PID', String(pid), '/T', '/F'],
      { stdio: 'ignore' },
    );
    const outcome = new Promise<number | null>((resolved) => {
      killer.once('exit', (code) => resolved(code));
      killer.once('error', () => resolved(null));
    });
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<'TIMEOUT'>((resolved) => {
      timer = setTimeout(() => resolved('TIMEOUT'), timeoutMs);
      timer.unref();
    });
    const result = await Promise.race([
      outcome.then((code) => (code === 0 ? ('OK' as const) : ('FAILED' as const))),
      timeout,
    ]);
    clearTimeout(timer);
    if (result !== 'TIMEOUT') return result;
    // G6 P2: the timeout won — terminate the retained helper handle and
    // reap it within a hard bound; a helper that survives is reported.
    killer.kill('SIGKILL');
    const reaped = await waitForExit(killer, TASKKILL_REAP_TIMEOUT_MS);
    if (reaped === 'TIMEOUT') {
      helperReaped = false;
      detail.push('taskkill helper survived SIGKILL and the reap bound');
    } else {
      detail.push('timed-out taskkill helper terminated and reaped');
    }
    return 'TIMEOUT';
  };

  const first = await attempt();
  detail.push(`attempt 1: ${first}`);
  if (first === 'OK') {
    treeKillConfirmed = true;
  } else {
    // G6 P2: one bounded retry of the real tree kill before any
    // wrapper-only fallback; the injection (negative tests) applies to
    // every attempt, production callers retry the real taskkill.
    const second = await attempt();
    detail.push(`attempt 2: ${second}`);
    if (second === 'OK') treeKillConfirmed = true;
  }
  if (!treeKillConfirmed && child.exitCode === null && child.signalCode === null) {
    // Last-resort direct-child kill. Explicitly NOT proof that descendants
    // stopped: cleanupChild must still verify port refusal and report
    // cleanup failure when the listener outlives the wrapper.
    child.kill('SIGKILL');
    detail.push('fell back to direct-child SIGKILL; descendant termination unconfirmed');
  }
  const result = { treeKillConfirmed, helperReaped, detail: detail.join('; ') };
  windowsTreeKillHistory.set(child, result);
  return result;
}

interface CleanupResult {
  ok: boolean;
  detail: string;
  childExit: { code: number | null; signal: NodeJS.Signals | null } | 'TIMEOUT';
  portRefused: boolean;
  kill: KillTreeResult;
}

/**
 * Bounded, verified cleanup: kill the tree, wait for the child exit inside
 * a hard bound, and verify that the loopback port eventually refuses
 * connections. ok requires all three — helper reaped, child exited, port
 * refused — so a leaked descendant listener makes cleanup failure explicit
 * instead of silent. Idempotent; never throws.
 */
async function cleanupChild(
  child: ReturnType<typeof spawn>,
  port: number,
  options: KillTreeOptions = {},
): Promise<CleanupResult> {
  const kill = await killTree(child, options);
  const childExit = await waitForExit(child, CHILD_EXIT_BOUND_MS);
  const portRefused = await portRefusesConnectionEventually(port);
  // A closed loopback listener is not a proof that OTHER descendants
  // stopped. Any attempted-but-unconfirmed Windows tree kill is a failure,
  // including if the wrapper exited after direct-child SIGKILL. Only a
  // direct leaf process that exited without a kill attempt is exempt.
  const treeTerminationProven =
    !isWindows ||
    kill.treeKillConfirmed ||
    (!wrapperProcessTrees.has(child) && !windowsTreeKillHistory.has(child));
  const ok =
    kill.helperReaped && childExit !== 'TIMEOUT' && portRefused && treeTerminationProven;
  const parts = [
    `childExit=${childExit === 'TIMEOUT' ? 'TIMEOUT' : `code ${childExit.code} signal ${childExit.signal}`}`,
    `portRefused=${portRefused}`,
    `taskkillTreeConfirmed=${kill.treeKillConfirmed}`,
    `treeTerminationProven=${treeTerminationProven}`,
    kill.detail,
  ];
  if (!ok) parts.unshift('CLEANUP FAILURE');
  return { ok, detail: parts.join('; '), childExit, portRefused, kill };
}

/**
 * G6 P2 finally-path contract: run bounded verified cleanup and surface its
 * result. When the test body already failed, the original assertion failure
 * must win — the cleanup diagnostic goes to stderr. When the body passed, a
 * cleanup failure throws and fails the test. Cleanup itself never throws.
 */
async function guaranteeCleanup(
  child: ReturnType<typeof spawn>,
  port: number,
  bodyFailed: boolean,
  options: KillTreeOptions = {},
): Promise<void> {
  const cleanup = await cleanupChild(child, port, options);
  if (cleanup.ok) return;
  const diagnostic = `[startup-runner] cleanup failure: ${cleanup.detail}`;
  if (bodyFailed) console.error(diagnostic);
  else throw new Error(diagnostic);
}

describe('R02-E default dev startup runner (Node 24 strip-mode repair)', () => {
  it('default pnpm --filter @shun/control-api dev boots the real graph with no TypeScript syntax error', async () => {
    const port = await freePort();
    // The exact operator default command; on Windows .cmd requires a shell.
    // POSIX detaches so killTree can take the whole pnpm → tsx → node group.
    const child = spawn(PNPM, ['--filter', '@shun/control-api', 'dev'], {
      cwd: repoRoot,
      env: { ...sanitizedEnv({}), SHUN_CONTROL_PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: isWindows,
      detached: !isWindows,
    });
    wrapperProcessTrees.add(child);
    let bodyFailed = false;
    try {
      const output = collect(child);
      const up = await waitForHttp(port, 60_000);
      const text = output.text();
      expect(up, `server did not come up; output:\n${text}`).toBe(true);
      expect(text).not.toContain('ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX');
      expect(text).toContain('Shun control surface (T08 DEMO ONLY)');
      // G5/G6: bounded tree kill, bounded exit wait, then verify the
      // loopback listener is actually gone.
      await killTree(child);
      await waitForExit(child, 15_000);
      expect(await portRefusesConnectionEventually(port)).toBe(true);
    } catch (error) {
      bodyFailed = true;
      throw error;
    } finally {
      // G6 P2: a failed assertion above must never leak the child process
      // tree or its loopback listener into the rest of the run. The
      // bounded cleanup result is inspected: failure is surfaced as a
      // secondary diagnostic when the body already failed, and fails the
      // test when the body passed.
      await guaranteeCleanup(child, port, bodyFailed);
    }
  });

  it('tsx entry boots DEMO on loopback, refuses hostile Host, reports Guided truthfully, shuts down deterministically', async () => {
    const port = await freePort();
    const { child, output } = startViaTsx(port, {});
    let bodyFailed = false;
    try {
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
    } catch (error) {
      bodyFailed = true;
      throw error;
    } finally {
      // G6 P2: verified cleanup on every path; failure surfaced, never
      // silent, never masking the original assertion failure.
      await guaranteeCleanup(child, port, bodyFailed);
    }
  });

  it('unknown SHUN_CONTROL_MODE fails closed — never a silent DEMO fallback', async () => {
    const port = await freePort();
    const { child, output } = startViaTsx(port, { SHUN_CONTROL_MODE: 'bogus' });
    let bodyFailed = false;
    try {
      const exit = await waitForExit(child, 30_000);
      expect(exit, 'boot must refuse and exit').not.toBe('TIMEOUT');
      expect(output.text()).toContain('Unknown SHUN_CONTROL_MODE: refusing to start');
      if (exit !== 'TIMEOUT') expect(exit.code).not.toBe(0);
      expect(await portRefusesConnectionEventually(port)).toBe(true);
    } catch (error) {
      bodyFailed = true;
      throw error;
    } finally {
      // G6 P2: a stuck boot refusal (TIMEOUT) must not survive the test,
      // and cleanup failure must be surfaced, not silent.
      await guaranteeCleanup(child, port, bodyFailed);
    }
  });

  it('real-storage mode without trusted config fails closed with the exact missing gate', async () => {
    const port = await freePort();
    const { child, output } = startViaTsx(port, { SHUN_CONTROL_MODE: 'real-storage' });
    let bodyFailed = false;
    try {
      const exit = await waitForExit(child, 30_000);
      expect(exit, 'boot must refuse and exit').not.toBe('TIMEOUT');
      expect(output.text()).toContain(
        'Missing trusted local configuration SHUN_REAL_STORAGE_ROOT; refusing real mode',
      );
      if (exit !== 'TIMEOUT') expect(exit.code).not.toBe(0);
      expect(await portRefusesConnectionEventually(port)).toBe(true);
    } catch (error) {
      bodyFailed = true;
      throw error;
    } finally {
      // G6 P2: a stuck boot refusal (TIMEOUT) must not survive the test,
      // and cleanup failure must be surfaced, not silent.
      await guaranteeCleanup(child, port, bodyFailed);
    }
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

    /**
     * G4 P2 hardening: fail closed. Every required fixture MUST have exactly
     * one SHA256SUMS.txt receipt, the receipt MUST be lowercase 64-hex, and
     * the computed digest MUST match. A missing or duplicated receipt fails
     * the test instead of silently accepting unpinned content.
     */
    function readPinned(name: string): string {
      const source = readFileSync(join(t11Fixtures, name), 'utf8');
      const receipts = new Map<string, string[]>();
      for (const line of readFileSync(join(t11Fixtures, 'SHA256SUMS.txt'), 'utf8').split(/\r?\n/)) {
        const match = line.match(/^([0-9a-f]{64})\s+\*?(.+)$/);
        const [, digest, fileName] = match ?? [];
        if (typeof digest === 'string' && typeof fileName === 'string') {
          const key = fileName.trim();
          receipts.set(key, [...(receipts.get(key) ?? []), digest]);
        }
      }
      const entries = receipts.get(name);
      expect(
        entries,
        `fixture ${name} must have exactly one SHA256SUMS receipt (found ${entries?.length ?? 0})`,
      ).toHaveLength(1);
      const expected = entries![0];
      expect(expected).toMatch(/^[0-9a-f]{64}$/);
      expect(sha256Hex(source)).toBe(expected);
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
          env: sanitizedEnv({
            SHUN_ISSUER_WORKSPACE: workspace,
            SHUN_REGISTRY_CURRENTNESS_FILE: currentnessFile,
            SHUN_REGISTRY_PUBLIC_KEY_FILE: publicKeyFile,
            SHUN_ISSUER_PRIVATE_KEY_FILE: privateKeyFile,
            SHUN_ISSUER_TARGET_PRIVILEGE_MODE: privilegeMode,
          }),
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
      // G4 P1: prove the cloud egress lane is disabled in the exact
      // environment the production child will receive, BEFORE any gateway
      // POST. A regression at the forged-reference seam can then never
      // reach paid cloud egress.
      const childEnv = sanitizedEnv(env);
      expect(childEnv.SHUN_CLOUD_ENABLED).toBe('0');
      for (const key of STRIPPED_CLOUD_KEYS) expect(childEnv).not.toHaveProperty(key);

      // G4 P2: the EXACT operator command, not a direct node/tsx invocation.
      // On Windows .cmd requires a shell; the whole pnpm → tsx → node tree
      // is terminated with taskkill /T (hard-bounded by the G5 killTree).
      const child = spawn(PNPM, ['--filter', '@shun/control-api', 'dev'], {
        cwd: repoRoot,
        env: { ...childEnv, SHUN_CONTROL_PORT: String(port) },
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: isWindows,
        detached: !isWindows,
      });
      wrapperProcessTrees.add(child);
      let bodyFailed = false;
      try {
        const output = collect(child);
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
                environmentPolicy: {
                  allowedBackendKinds: ['LOCAL_WINDOWS'],
                  allowElevation: false,
                },
              },
            },
            currentnessRef: `shun.currentness.v1/${'a'.repeat(48)}`,
            approvalRef: `shun.approval.v1/${'b'.repeat(48)}`,
          }),
        });
        const receipt = (await forged.json()) as { status?: string };
        expect(forged.status).toBe(422);
        expect(receipt.status).toBe('KERNEL_REFUSED');

        // Windows cannot signal through the pnpm → tsx wrapper chain; the
        // bounded tree kill is the deterministic shutdown path here.
        await killTree(child);
        expectCleanShutdown(await waitForExit(child, 20_000));
        expect(await portRefusesConnectionEventually(port)).toBe(true);
      } catch (error) {
        bodyFailed = true;
        throw error;
      } finally {
        // G6 P2: a failed production assertion must never leak the server
        // child or its loopback listener; the bounded cleanup result is
        // inspected and any cleanup failure is surfaced, never silent.
        await guaranteeCleanup(child, port, bodyFailed);
      }
    }, 180_000);
  },
);

describe.skipIf(!isWindows)(
  'R02-E G6 bounded cleanup — deterministic negative coverage (taskkill timeout / nonzero / orphan listener)',
  () => {
    let dir: string;

    beforeAll(() => {
      dir = mkdtempSync(join(tmpdir(), 'shun-r02e-g6-cleanup-'));
    });

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

    /** node -e one-liner: a minimal loopback HTTP listener on `port`. */
    const listenerOn = (port: number): string =>
      `require('node:http').createServer((q,s)=>s.end('ok')).listen(${port})`;

    /**
     * A real two-level tree: wrapper node process → grandchild node HTTP
     * listener. The wrapper publishes the grandchild PID so tests can prove
     * (via process existence and port refusal) whether any orphan survives.
     */
    function startWrapperTree(port: number): {
      child: ReturnType<typeof spawn>;
      pidFile: string;
    } {
      const pidFile = join(dir, `grandchild-${port}.pid`);
      const wrapperScript = [
        "const { spawn } = require('node:child_process');",
        "const { writeFileSync } = require('node:fs');",
        `const kid = spawn(process.execPath, ['-e', ${JSON.stringify(listenerOn(port))}], { stdio: 'ignore' });`,
        `writeFileSync(${JSON.stringify(pidFile)}, String(kid.pid));`,
        'setInterval(() => {}, 1e9);',
      ].join('\n');
      const child = spawn(process.execPath, ['-e', wrapperScript], { stdio: 'ignore' });
      wrapperProcessTrees.add(child);
      return { child, pidFile };
    }

    async function publishedPid(pidFile: string): Promise<number> {
      const deadline = Date.now() + 15_000;
      while (Date.now() < deadline) {
        if (existsSync(pidFile)) {
          const pid = Number(readFileSync(pidFile, 'utf8').trim());
          if (pid > 0) return pid;
        }
        await delay(100);
      }
      return 0;
    }

    /** Test-local teardown for an orphan PID the production fallback could not reach. */
    async function killPublishedPid(pid: number): Promise<void> {
      const killer = spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' });
      await waitForExit(killer, TASKKILL_TIMEOUT_MS);
    }

    it('taskkill timeout: the helper is terminated and reaped, fallback runs, and the listener still dies', async () => {
      const port = await freePort();
      const child = spawn(process.execPath, ['-e', listenerOn(port)], { stdio: 'ignore' });
      let bodyFailed = false;
      try {
        expect(await waitForHttp(port, 15_000)).toBe(true);
        // Fake taskkill: a node process that never exits, so each bounded
        // attempt (first + retry) must hit the timeout and force
        // terminate-and-reap of the retained helper handle.
        const kill = await killTree(child, {
          taskkillCommand: process.execPath,
          taskkillArgs: ['-e', 'setInterval(() => {}, 1e9)'],
          timeoutMs: 2_000,
        });
        expect(kill.treeKillConfirmed).toBe(false);
        expect(kill.helperReaped).toBe(true);
        expect(kill.detail).toContain('terminated and reaped');
        // The wrapper-only fallback still killed the direct listener. The
        // honest report: port free again, but the taskkill tree kill was
        // never confirmed.
        const cleanup = await cleanupChild(child, port);
        expect(cleanup.portRefused).toBe(true);
        expect(cleanup.ok).toBe(false);
        expect(cleanup.detail).toContain('CLEANUP FAILURE');
        expect(cleanup.detail).toContain('treeTerminationProven=false');
        expect(cleanup.kill.treeKillConfirmed).toBe(false);
      } catch (error) {
        bodyFailed = true;
        throw error;
      } finally {
        // Deliberately failed taskkill cannot be retroactively certified.
        await guaranteeCleanup(child, port, true);
      }
    }, 60_000);

    it('taskkill nonzero exit: fallback is not tree cleanup, and a port that outlives the child is an explicit cleanup failure', async () => {
      const port = await freePort();
      const { child, pidFile } = startWrapperTree(port);
      let grandchildPid = 0;
      try {
        grandchildPid = await publishedPid(pidFile);
        expect(grandchildPid).toBeGreaterThan(0);
        expect(await waitForHttp(port, 15_000)).toBe(true);

        // Real taskkill binary but pointed at a PID that does not exist:
        // both bounded attempts exit non-zero. The fallback SIGKILL of the
        // wrapper is recorded honestly: it is NOT reported as a confirmed
        // tree kill.
        const kill = await killTree(child, { taskkillArgs: ['/PID', '999999', '/T', '/F'] });
        expect(kill.treeKillConfirmed).toBe(false);
        expect(kill.helperReaped).toBe(true);
        expect(kill.detail).toContain('descendant termination unconfirmed');

        // Inspect the REAL wrapper/grandchild tree rather than an unrelated
        // port. Even if the listener happens to stop, an unconfirmed tree
        // kill cannot claim that the grandchild was reaped.
        const cleanup = await cleanupChild(child, port);
        expect(cleanup.childExit).not.toBe('TIMEOUT');
        expect(cleanup.ok).toBe(false);
        expect(cleanup.detail).toContain('CLEANUP FAILURE');
        expect(cleanup.detail).toContain('treeTerminationProven=false');
        await expect(guaranteeCleanup(child, port, true)).resolves.toBeUndefined();
        await expect(guaranteeCleanup(child, port, false)).rejects.toThrow(
          /cleanup failure/,
        );
      } finally {
        if (grandchildPid > 0) await killPublishedPid(grandchildPid);
        // Explicit teardown does not convert the failed kill into proof.
        await guaranteeCleanup(child, port, true);
      }
    }, 90_000);

    it('non-listening grandchild cannot be certified by a closed port after wrapper-only kill', async () => {
      const port = await freePort();
      const pidFile = join(dir, `silent-${port}.pid`);
      const wrapperScript = [
        "const { spawn } = require('node:child_process');",
        "const { writeFileSync } = require('node:fs');",
        "const kid = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1e9)'], { stdio: 'ignore' });",
        `writeFileSync(${JSON.stringify(pidFile)}, String(kid.pid));`,
        'setInterval(() => {}, 1e9);',
      ].join('\\n');
      const child = spawn(process.execPath, ['-e', wrapperScript], { stdio: 'ignore' });
      wrapperProcessTrees.add(child);
      let silentPid = 0;
      try {
        silentPid = await publishedPid(pidFile);
        expect(silentPid).toBeGreaterThan(0);
        expect(await portRefusesConnection(port)).toBe(true);
        const kill = await killTree(child, { taskkillArgs: ['/PID', '999999', '/T', '/F'] });
        expect(kill.treeKillConfirmed).toBe(false);
        const cleanup = await cleanupChild(child, port);
        expect(cleanup.portRefused).toBe(true);
        expect(cleanup.childExit).not.toBe('TIMEOUT');
        expect(cleanup.ok).toBe(false);
        expect(cleanup.detail).toContain('treeTerminationProven=false');
        expect(() => process.kill(silentPid, 0)).not.toThrow();
      } finally {
        if (silentPid > 0) await killPublishedPid(silentPid);
        await guaranteeCleanup(child, port, true);
      }
    }, 60_000);

    it('real taskkill tree termination on a wrapper/descendant listener leaves no orphan', async () => {
      const port = await freePort();
      const { child, pidFile } = startWrapperTree(port);
      let bodyFailed = false;
      let grandchildPid = 0;
      try {
        grandchildPid = await publishedPid(pidFile);
        expect(grandchildPid).toBeGreaterThan(0);
        expect(await waitForHttp(port, 15_000)).toBe(true);

        const cleanup = await cleanupChild(child, port);
        expect(cleanup.ok).toBe(true);
        expect(cleanup.kill.treeKillConfirmed).toBe(true);
        expect(cleanup.portRefused).toBe(true);
        // The descendant process itself is gone, not just its listener.
        expect(() => process.kill(grandchildPid, 0)).toThrow();
      } catch (error) {
        bodyFailed = true;
        throw error;
      } finally {
        if (grandchildPid > 0) await killPublishedPid(grandchildPid);
        await guaranteeCleanup(child, port, bodyFailed);
      }
    }, 60_000);
  },
);
