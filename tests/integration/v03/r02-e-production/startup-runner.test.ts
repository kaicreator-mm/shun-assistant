/**
 * R02-E Generation-3 startup-runner regression (Issue #269), hardened in
 * Generation-4 (PR #328 R1 findings): the default control-api dev entry must
 * boot the REAL import graph through a TypeScript-aware runner without
 * ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX (native/index.ts constructor
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
 * G10-R2 production trust gate (Issue #269, pack PR #367; R04 #404 per-user
 * amendment): the production real-storage boot now constructs the Guided
 * service exclusively through the external verify-only provenance authority
 * (per-interactive-user LocalAppData trust pin, anchor, exact database
 * receipt, per-user ACL/ancestor policy). Without matching per-user trust
 * material the exact operator command must fail closed BEFORE any listener
 * exists — non-zero exit, the truthful SETUP_REQUIRED refusal plus the
 * one-time bootstrap guidance in the output, no REAL banner, no DEMO
 * fallback and no Guided database created. A DEMO banner or a 503-only
 * Guided surface is never accepted as production success. The R04 positive
 * lane proves the full native chain inside a DISPOSABLE isolated profile:
 * plan-only bootstrap (no writes) → one consented bootstrap → real
 * production boot with positive Guided state, served desktop.js bytes and
 * activated DomainHarness → re-run bootstrap is a byte-stable NO-OP.
 *
 * G11 pinned-runner amendment (Issue #371, pack PR #373): Node 26 removed
 * `--experimental-transform-types` entirely, and Node 26 strip-only mode
 * still refuses the real import graph's parameter properties, so the G10-R2
 * dev entry (`node --experimental-transform-types src/main.ts`) cannot boot
 * on Node 26.13.0. The dev script now runs the exact pinned TypeScript-aware
 * runner `tsx@4.23.15` declared in `apps/control-api/package.json`
 * (`dev: "tsx src/main.ts"`; reproducible lockfile, frozen install). Every
 * test-side boot through "the dev runner mode" resolves that same pinned
 * local CLI — never a floating pnpm dlx, network-time resolution, or
 * global/transitive loader — and the removed flag must not reappear in any
 * dev-command output. Production composition, trust gates, and cleanup
 * contracts are unchanged.
 *
 * Zero paid calls / zero physical effects: no cloud interpreter is
 * configured (every LLM effect fails closed CLOUD_UNAVAILABLE), no Provider
 * install, no UAC, no persistent Windows effect beyond temp fixture files.
 */
import { execFileSync, spawn, spawnSync } from 'node:child_process';
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
/**
 * G11: the exact pinned TypeScript-aware dev runner (`tsx@4.23.15`, the
 * declared devDependency of @shun/control-api), resolved from the workspace
 * install — never a floating pnpm dlx, network-time resolution, or
 * global/transitive loader.
 */
const PINNED_TSX_CLI = join(apiDir, 'node_modules', 'tsx', 'dist', 'cli.mjs');
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
 * Boot main.ts through the exact dev runner mode of the current entrypoint
 * (`tsx src/main.ts`, the G11 pinned-runner dev script target: Node 26
 * removed `--experimental-transform-types` and strip-only mode cannot
 * transform the real import graph's parameter properties). The pinned
 * runner must be present from the declared devDependency; the child always
 * receives a cloud-sanitized environment (G4 P1).
 */
function startViaPinnedRunner(port: number, env: NodeJS.ProcessEnv) {
  expect(
    existsSync(PINNED_TSX_CLI),
    'pinned tsx runner must be installed from the declared devDependency',
  ).toBe(true);
  const child = spawn(process.execPath, [PINNED_TSX_CLI, 'src/main.ts'], {
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
    return (
      windowsTreeKillHistory.get(child) ?? {
        treeKillConfirmed: false,
        helperReaped: true,
        detail: 'windows: child already exited without an attempted tree kill',
      }
    );
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
  const ok = kill.helperReaped && childExit !== 'TIMEOUT' && portRefused && treeTerminationProven;
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

describe('R02-E default dev startup runner (G11 pinned TypeScript-aware runner)', () => {
  it('default pnpm --filter @shun/control-api dev boots the real graph with no TypeScript syntax error', async () => {
    const port = await freePort();
    // The exact operator default command; on Windows .cmd requires a shell.
    // POSIX detaches so killTree can take the whole pnpm → node group.
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
      // G11: the Node-26-removed transform flag must never reappear in the
      // exact operator command's output (no `node: bad option` regression).
      expect(text).not.toContain('--experimental-transform-types');
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

  it('dev runner entry boots DEMO on loopback, refuses hostile Host, reports Guided truthfully, shuts down deterministically', async () => {
    const port = await freePort();
    const { child, output } = startViaPinnedRunner(port, {});
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
    const { child, output } = startViaPinnedRunner(port, { SHUN_CONTROL_MODE: 'bogus' });
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
    const { child, output } = startViaPinnedRunner(port, { SHUN_CONTROL_MODE: 'real-storage' });
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
      const expected = entries?.[0];
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
        [PINNED_TSX_CLI, 'apps/control-api/scripts/issue-registry-currentness.ts'],
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

    /** R04: one disposable isolated Windows profile under the OS temp dir. */
    function isolatedProfile(): {
      root: string;
      localAppData: string;
      env: NodeJS.ProcessEnv;
    } {
      const root = mkdtempSync(join(tmpdir(), 'shun-r04-win-profile-'));
      const localAppData = join(root, 'AppData', 'Local');
      mkdirSync(localAppData, { recursive: true });
      // Harden to the REAL per-user profile ACL shape: explicit
      // user/SYSTEM/Administrators full control, shared-temp inherited ACEs
      // removed (a genuine %LOCALAPPDATA% tree carries no foreign write
      // ACEs; the shared OS temp dir on some machines does).
      if (process.platform === 'win32') {
        const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
        const icacls = resolve(systemRoot, 'System32', 'icacls.exe');
        const grants = [
          '*S-1-5-18:(OI)(CI)F',
          '*S-1-5-32-544:(OI)(CI)F',
          `*${whoamiUserSid() ?? 'S-1-5-18'}:(OI)(CI)F`,
        ];
        execFileSync(icacls, [root, '/grant', ...grants], {
          windowsHide: true,
          timeout: 30_000,
        });
        execFileSync(icacls, [root, '/inheritance:r'], { windowsHide: true, timeout: 30_000 });
      }
      return {
        root,
        localAppData,
        env: { USERPROFILE: root, LOCALAPPDATA: localAppData },
      };
    }

    /** Current process user SID via the System32 whoami (PATH-independent). */
    function whoamiUserSid(): string | undefined {
      try {
        const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
        const out = execFileSync(resolve(systemRoot, 'System32', 'whoami.exe'), [
          '/user',
          '/fo',
          'csv',
          '/nh',
        ]);
        for (const line of String(out).split(/\r?\n/)) {
          const fields = line
            .trim()
            .split(',')
            .map((field) => field.replace(/^"|"$/g, '').trim());
          const sid = fields[fields.length - 1] ?? '';
          if (/^S-1-\d+(-\d+)+$/.test(sid)) return sid;
        }
      } catch {
        // fall through
      }
      return undefined;
    }

    it('fails closed with no listener when this Windows user has no per-user trust (first run)', async () => {
      // R04: isolated disposable profile — the real per-user resolution finds
      // NO trust material for that profile and the boot must refuse before
      // any listener with the truthful SETUP_REQUIRED guidance. The REAL
      // interactive profile of this machine is never touched.
      const profile = isolatedProfile();
      try {
        // G4 P1: prove the cloud egress lane is disabled in the exact
        // environment the production child will receive, BEFORE any boot step.
        const childEnv = sanitizedEnv({ ...env, ...profile.env });
        expect(childEnv.SHUN_CLOUD_ENABLED).toBe('0');
        for (const key of STRIPPED_CLOUD_KEYS) expect(childEnv).not.toHaveProperty(key);

        // G4 P2: the EXACT operator command, not a direct node invocation.
        // On Windows .cmd requires a shell. G10-R2: this child is a
        // self-terminating boot refusal, not a killed live server tree — the
        // trust gate exits the process before any listener or descendant
        // exists. It is therefore NOT registered in wrapperProcessTrees:
        // cleanup proves the honest outcome via the recorded exit code and
        // eventual port refusal (the same direct-leaf exemption the G6
        // cleanup contract grants self-exiting refusals).
        const child = spawn(PNPM, ['--filter', '@shun/control-api', 'dev'], {
          cwd: repoRoot,
          env: { ...childEnv, SHUN_CONTROL_PORT: String(port) },
          stdio: ['ignore', 'pipe', 'pipe'],
          shell: isWindows,
          detached: !isWindows,
        });
        let bodyFailed = false;
        try {
          const output = collect(child);
          // G10-R2 + R04: every other production input is valid (registry,
          // BUILD, Guided Case, ledgers), so the first missing input is the
          // per-user LocalAppData trust material. The dev entry must refuse
          // to start instead of opening a listener or degrading to DEMO, and
          // must print the one-time consented bootstrap path.
          const exit = await waitForExit(child, 60_000);
          const text = output.text();
          expect(exit, `boot must refuse and exit; output:\n${text}`).not.toBe('TIMEOUT');
          if (exit !== 'TIMEOUT') expect(exit.code).not.toBe(0);
          expect(text).not.toContain('ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX');
          // G11: the refusal must come from the trust gate, not from a dev
          // runner regression (Node 26 removed --experimental-transform-types).
          expect(text).not.toContain('--experimental-transform-types');
          expect(text).toMatch(
            /GUIDED_TRUST_SETUP_REQUIRED|GUIDED_TRUST_PIN_UNTRUSTED|GUIDED_TRUST_|GUIDED_PROVENANCE_/,
          );
          // Truthful first-run guidance: the exact one-time bootstrap command.
          expect(text).toContain('bootstrap-guided-localappdata.ts');
          expect(text).toContain('--consent');
          // No listener, no REAL banner, no DEMO fallback, no Guided database:
          // the trust gate fires before service construction and before the
          // HTTP surface exists, so neither a production nor a DEMO boot may
          // be observable.
          expect(text).not.toContain('Shun control surface (REAL bounded C-003)');
          expect(text).not.toContain('T08 DEMO ONLY');
          expect(await portRefusesConnectionEventually(port)).toBe(true);
          expect(existsSync(env.SHUN_V03_GUIDED_DATABASE as string)).toBe(false);
        } catch (error) {
          bodyFailed = true;
          throw error;
        } finally {
          // G6 P2: a failed production assertion must never leak the server
          // child or its loopback listener; the bounded cleanup result is
          // inspected and any cleanup failure is surfaced, never silent.
          await guaranteeCleanup(child, port, bodyFailed);
        }
      } finally {
        rmSync(profile.root, { recursive: true, force: true });
      }
    }, 120_000);

    it('R04 native no-effect E2E: plan-only → consented per-user bootstrap → positive real-storage boot → stable NO-OP restart', async () => {
      const profile = isolatedProfile();
      try {
        const guidedDb = env.SHUN_V03_GUIDED_DATABASE as string;
        const bootstrapEnv = () =>
          sanitizedEnv({ ...env, ...profile.env, SHUN_CLOUD_ENABLED: '0' });
        // 1. Plan-only bootstrap: explicit consent gate — prints the plan,
        //    exits 3 and writes NOTHING into the isolated profile.
        const plan = spawnSync(
          process.execPath,
          [
            PINNED_TSX_CLI,
            'apps/control-api/scripts/bootstrap-guided-localappdata.ts',
            '--database',
            guidedDb,
          ],
          { cwd: repoRoot, encoding: 'utf8', env: bootstrapEnv(), timeout: 120_000 },
        );
        expect(plan.status, `plan output:\n${plan.stdout}\n${plan.stderr}`).toBe(3);
        expect(plan.stdout).toContain('BOOTSTRAP_PLAN_ONLY');
        expect(plan.stdout).toContain('BOOTSTRAP_STATUS=FRESH');
        expect(existsSync(join(profile.localAppData, 'Shun'))).toBe(false);

        // 2. One consented bootstrap operation for this Windows user.
        const created = spawnSync(
          process.execPath,
          [
            PINNED_TSX_CLI,
            'apps/control-api/scripts/bootstrap-guided-localappdata.ts',
            '--database',
            guidedDb,
            '--consent',
          ],
          { cwd: repoRoot, encoding: 'utf8', env: bootstrapEnv(), timeout: 120_000 },
        );
        expect(created.status, `bootstrap output:\n${created.stdout}\n${created.stderr}`).toBe(0);
        expect(created.stdout).toContain('BOOTSTRAP_RESULT=BOOTSTRAP_CREATED');
        expect(created.stdout).not.toContain('PRIVATE KEY');
        const trustDir = join(profile.localAppData, 'Shun', 'authority', 'guided-provenance');
        const anchorPath = join(trustDir, 'trust-anchor.json');
        const pinPath = join(profile.localAppData, 'Shun', 'authority', 'guided-provenance-trust-pin.json');
        const receiptsDir = join(trustDir, 'receipts');
        for (const path of [anchorPath, pinPath, receiptsDir]) expect(existsSync(path)).toBe(true);

        // 3. Full production boot through the real main.ts composition with
        //    the per-user trust: REAL banner, positive Guided state over
        //    HTTP, the REAL desktop.js bytes, activated DomainHarness.
        const bootPort = await freePort();
        const { child, output } = startViaPinnedRunner(bootPort, { ...env, ...profile.env });
        let bodyFailed = false;
        try {
          const up = await waitForHttp(bootPort, 90_000);
          const text = output.text();
          expect(up, `production boot output:\n${text}`).toBe(true);
          expect(text).toContain('Shun control surface (REAL bounded C-003)');
          expect(text).toContain('v0.3 public DomainHarness activated');

          const guidedState = await rawGet(bootPort, '/api/v03/guided/state', {
            host: `127.0.0.1:${bootPort}`,
          });
          expect(guidedState.status).toBe(200);
          const state = JSON.parse(guidedState.body) as {
            currentStep?: { templateRef?: { artifactId?: string } };
            journey?: { paused?: boolean };
          };
          // Positive Guided StepSpec: the operator-pinned Case is staged and
          // its live step is exposed (selected-K entrypoint ready, no-effect).
          expect(state.currentStep?.templateRef?.artifactId).toBeTruthy();
          expect(state.journey).toBeDefined();

          // The REAL desktop.js is served byte-identical (not a fixture copy).
          const desktop = await fetch(`http://127.0.0.1:${bootPort}/v03/desktop.js`);
          expect(desktop.status).toBe(200);
          const served = Buffer.from(await desktop.arrayBuffer());
          const onDisk = readFileSync(join(repoRoot, 'apps/control-ui/public/v03/desktop.js'));
          expect(served.equals(onDisk)).toBe(true);
        } catch (error) {
          bodyFailed = true;
          throw error;
        } finally {
          await guaranteeCleanup(child, bootPort, bodyFailed);
        }

        // 4. Restart stability: a second bootstrap is a byte-stable NO-OP —
        //    the anchor/pin/receipt/secret never rotate or re-sign.
        const anchorBefore = readFileSync(anchorPath);
        const pinBefore = readFileSync(pinPath);
        const secretPath = join(
          profile.localAppData,
          'Shun',
          'secrets',
          'guided-issuer',
          'issuer-private.pem',
        );
        const secretBefore = existsSync(secretPath) ? readFileSync(secretPath) : undefined;
        const again = spawnSync(
          process.execPath,
          [
            PINNED_TSX_CLI,
            'apps/control-api/scripts/bootstrap-guided-localappdata.ts',
            '--database',
            guidedDb,
            '--consent',
          ],
          { cwd: repoRoot, encoding: 'utf8', env: bootstrapEnv(), timeout: 120_000 },
        );
        expect(again.status, `re-run output:\n${again.stdout}\n${again.stderr}`).toBe(0);
        expect(again.stdout).toContain('BOOTSTRAP_RESULT=ALREADY_COMPLETE');
        expect(readFileSync(anchorPath).equals(anchorBefore)).toBe(true);
        expect(readFileSync(pinPath).equals(pinBefore)).toBe(true);
        if (secretBefore) expect(readFileSync(secretPath).equals(secretBefore)).toBe(true);
      } finally {
        rmSync(profile.root, { recursive: true, force: true });
      }
    }, 300_000);
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
      // The grandchild must be DETACHED: this Windows host (build 26300,
      // verified 2026-11-05 on Node 24.21.0 and 26.13.0) auto-terminates
      // non-detached children together with their parent — even on a NATURAL
      // parent exit — so only a detached grandchild deterministically survives
      // a wrapper-only kill and can serve as the "orphan witness". A real
      // `taskkill /T /F` on the wrapper still reaches a detached descendant
      // through the parent-PID chain (proven by the positive tree-kill test).
      const wrapperScript = [
        "const { spawn } = require('node:child_process');",
        "const { writeFileSync } = require('node:fs');",
        `const kid = spawn(process.execPath, ['-e', ${JSON.stringify(listenerOn(port))}], { stdio: 'ignore', detached: true });`,
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

    /** PID existence probe: ESRCH means gone; EPERM means it still exists. */
    function isPidAlive(pid: number): boolean {
      try {
        process.kill(pid, 0);
        return true;
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === 'ESRCH') return false;
        if (code === 'EPERM') return true;
        throw new Error(`cannot verify process PID ${pid}: ${String(error)}`);
      }
    }

    /** Bounded proof that the exact published PID has exited. */
    async function waitForPidExit(pid: number, timeoutMs: number): Promise<boolean> {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (!isPidAlive(pid)) return true;
        await delay(100);
      }
      return !isPidAlive(pid);
    }

    /**
     * Test-local teardown for a published leaf PID. taskkill status is
     * observed; timeout helpers are killed and reaped; failed taskkill uses
     * a bounded direct-PID SIGKILL fallback; success requires target PID exit.
     * If the test body already failed, cleanup errors are reported without
     * replacing the original assertion failure.
     */
    async function killPublishedPid(
      pid: number,
      options: KillTreeOptions = {},
      bodyFailed = false,
    ): Promise<void> {
      try {
        if (!Number.isSafeInteger(pid) || pid <= 0) {
          throw new Error(`invalid published target PID: ${pid}`);
        }
        if (!isPidAlive(pid)) return;

        const killer = spawn(
          options.taskkillCommand ?? 'taskkill',
          options.taskkillArgs ?? ['/PID', String(pid), '/T', '/F'],
          { stdio: 'ignore' },
        );
        type TaskkillOutcome = { kind: 'EXIT'; code: number | null } | 'TIMEOUT' | 'SPAWN_ERROR';
        let timer: NodeJS.Timeout | undefined;
        const outcome = await new Promise<TaskkillOutcome>((resolveOutcome) => {
          const finish = (result: TaskkillOutcome) => {
            clearTimeout(timer);
            resolveOutcome(result);
          };
          killer.once('error', () => finish('SPAWN_ERROR'));
          killer.once('exit', (code) => finish({ kind: 'EXIT', code }));
          timer = setTimeout(() => finish('TIMEOUT'), options.timeoutMs ?? TASKKILL_TIMEOUT_MS);
          timer.unref();
        });

        let helperReaped = true;
        if (outcome === 'TIMEOUT' || outcome === 'SPAWN_ERROR') {
          if (killer.pid && killer.exitCode === null && killer.signalCode === null) {
            killer.kill('SIGKILL');
            helperReaped = (await waitForExit(killer, TASKKILL_REAP_TIMEOUT_MS)) !== 'TIMEOUT';
          }
        }

        const taskkillSucceeded =
          outcome !== 'TIMEOUT' && outcome !== 'SPAWN_ERROR' && outcome.code === 0;
        let targetExited =
          taskkillSucceeded && (await waitForPidExit(pid, TASKKILL_REAP_TIMEOUT_MS));

        if (!targetExited) {
          // The target is a test-owned leaf process, so direct-PID fallback
          // cannot orphan its descendants. ESRCH is an acceptable race.
          try {
            process.kill(pid, 'SIGKILL');
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ESRCH') {
              throw new Error(`direct-PID fallback failed for ${pid}: ${String(error)}`);
            }
          }
          targetExited = await waitForPidExit(pid, TASKKILL_REAP_TIMEOUT_MS);
        }

        if (!helperReaped) {
          throw new Error('taskkill helper did not exit within TASKKILL_REAP_TIMEOUT_MS');
        }
        if (!targetExited) {
          throw new Error(`published target PID ${pid} survived taskkill and direct-PID fallback`);
        }
      } catch (error) {
        const diagnostic = `[startup-runner] published PID cleanup failure: ${String(error)}`;
        if (bodyFailed) console.error(diagnostic);
        else throw new Error(diagnostic, { cause: error });
      }
    }

    it('taskkill timeout: the helper is terminated and reaped, fallback runs, and the listener still dies', async () => {
      const port = await freePort();
      const child = spawn(process.execPath, ['-e', listenerOn(port)], { stdio: 'ignore' });
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
      } finally {
        // Deliberately failed taskkill cannot be retroactively certified.
        await guaranteeCleanup(child, port, true);
      }
    }, 60_000);

    it('taskkill nonzero exit: fallback is not tree cleanup, and a port that outlives the child is an explicit cleanup failure', async () => {
      const port = await freePort();
      const { child, pidFile } = startWrapperTree(port);
      let bodyFailed = false;
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
        await expect(guaranteeCleanup(child, port, false)).rejects.toThrow(/cleanup failure/);
      } catch (error) {
        bodyFailed = true;
        throw error;
      } finally {
        if (grandchildPid > 0) await killPublishedPid(grandchildPid, {}, bodyFailed);
        // Explicit teardown does not convert the failed kill into proof.
        await guaranteeCleanup(child, port, true);
      }
    }, 90_000);

    it('non-listening grandchild cannot be certified by a closed port after wrapper-only kill', async () => {
      const port = await freePort();
      const pidFile = join(dir, `silent-${port}.pid`);
      // Detached for the same host reason as startWrapperTree: a non-detached
      // grandchild is auto-reaped with the wrapper on this host (even on a
      // natural exit), which would silently defeat the "silent grandchild
      // outlives a wrapper-only kill" premise this negative case exists to
      // prove. See the wrapper-script comment in startWrapperTree.
      const wrapperScript = [
        "const { spawn } = require('node:child_process');",
        "const { writeFileSync } = require('node:fs');",
        `const kid = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1e9)'], { stdio: 'ignore', detached: true });`,
        `writeFileSync(${JSON.stringify(pidFile)}, String(kid.pid));`,
        'setInterval(() => {}, 1e9);',
      ].join('\n');
      const child = spawn(process.execPath, ['-e', wrapperScript], { stdio: 'ignore' });
      wrapperProcessTrees.add(child);
      let bodyFailed = false;
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
      } catch (error) {
        bodyFailed = true;
        throw error;
      } finally {
        if (silentPid > 0) await killPublishedPid(silentPid, {}, bodyFailed);
        await guaranteeCleanup(child, port, true);
      }
    }, 60_000);

    it('published PID teardown handles spawn error, nonzero exit and timeout with verified fallback', async () => {
      const cases: Array<{ label: string; options: KillTreeOptions }> = [
        {
          label: 'spawn error',
          options: {
            taskkillCommand: join(dir, 'missing-taskkill.exe'),
            timeoutMs: 1_000,
          },
        },
        {
          label: 'nonzero exit',
          options: {
            taskkillCommand: process.execPath,
            taskkillArgs: ['-e', 'process.exit(23)'],
            timeoutMs: 2_000,
          },
        },
        {
          label: 'timeout and helper reap',
          options: {
            taskkillCommand: process.execPath,
            taskkillArgs: ['-e', 'setInterval(() => {}, 1e9)'],
            timeoutMs: 250,
          },
        },
      ];
      for (const scenario of cases) {
        const target = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1e9)'], {
          stdio: 'ignore',
        });
        const targetPid = target.pid;
        expect(targetPid).toBeDefined();
        if (!targetPid) throw new Error('test target did not receive a PID');
        try {
          expect(isPidAlive(targetPid)).toBe(true);
          await killPublishedPid(targetPid, scenario.options);
          expect(isPidAlive(targetPid), scenario.label).toBe(false);
          expect(await waitForExit(target, 1_000)).not.toBe('TIMEOUT');
        } finally {
          if (isPidAlive(targetPid)) await killPublishedPid(targetPid);
        }
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
        if (grandchildPid > 0) await killPublishedPid(grandchildPid, {}, bodyFailed);
        await guaranteeCleanup(child, port, bodyFailed);
      }
    }, 60_000);
  },
);
