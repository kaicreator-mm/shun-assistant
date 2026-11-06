/**
 * R02-V generation-2 (post-R02-E integration) targeted J07 requalification.
 *
 * The nine-path R02-E integration (#375, WIP 47ecf345) changed the default
 * production entrypoint/Node runner (G11 pinned `tsx@4.23.15` dev script) and
 * the trusted Guided authority injection, so J07's production startup and
 * loopback HTTP surface are requalified on the EXACT integrated tree through
 * the shipping operator command `pnpm --filter @shun/control-api dev`:
 *   - the pinned TypeScript-aware runner boots the real import graph with no
 *     TypeScript syntax error and never reintroduces the Node-26-removed
 *     `--experimental-transform-types` flag;
 *   - the loopback-only surface serves the real UI and reports the absent
 *     Guided/gateway state truthfully (503, never a fabricated success);
 *   - a hostile non-loopback Host header is refused;
 *   - the listening socket is loopback-bound only (netstat evidence);
 *   - with every non-trust production input valid, missing operator trust
 *     material refuses the boot BEFORE any listener or Guided database
 *     exists (fail closed, no DEMO fallback).
 *
 * Zero paid / zero physical: every spawned process receives a cloud-sanitized
 * environment (SHUN_CLOUD_ENABLED=0; DEEPSEEK_API_KEY and every SHUN_CLOUD_*
 * authority variable stripped), no Provider install, no UAC, no persistent
 * Windows effect beyond temp fixture files. The suite is Node-version
 * agnostic and runs under whatever native Node invokes it — the generation-2
 * Windows requalification executes it on real Windows Node 24.21.0 AND
 * 26.13.0, and the recorded evidence lists both.
 */
import { type ChildProcess, spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { get as httpGet } from 'node:http';
import { createConnection, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const apiDir = join(repoRoot, 'apps/control-api');
const PINNED_TSX_CLI = join(apiDir, 'node_modules', 'tsx', 'dist', 'cli.mjs');
const PNPM = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm';
const isWindows = process.platform === 'win32';

const TASKKILL_TIMEOUT_MS = 10_000;
const CHILD_EXIT_BOUND_MS = 20_000;

/**
 * Variables that must never reach a spawned Control API process: the cloud
 * lane is forced off and every authority/ledger variable is deleted, so a
 * boundary regression can never reach paid egress from this suite.
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

async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((ready) => probe.listen(0, '127.0.0.1', ready));
  const address = probe.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  await new Promise<void>((closed) => probe.close(() => closed()));
  return port;
}

function collect(child: ChildProcess): { text: () => string } {
  let out = '';
  child.stdout?.on('data', (chunk: Buffer) => (out += chunk.toString('utf8')));
  child.stderr?.on('data', (chunk: Buffer) => (out += chunk.toString('utf8')));
  return { text: () => out };
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
  child: ChildProcess,
  timeoutMs: number,
): Promise<{ code: number | null; signal: NodeJS.Signals | null } | 'TIMEOUT'> {
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
 * Bounded tree termination with honest verification: on Windows the whole
 * pnpm → tsx → node tree is killed via taskkill /T /F (a wrapper-only kill
 * proves nothing); on POSIX the detached process group gets SIGTERM. The
 * caller proves the outcome via bounded exit wait + loopback port refusal.
 */
function terminateTree(child: ChildProcess): void {
  if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
  if (isWindows) {
    const killer = spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
      encoding: 'utf8',
      timeout: TASKKILL_TIMEOUT_MS,
      windowsHide: true,
    });
    if (killer.status !== 0) child.kill('SIGKILL');
  } else {
    try {
      process.kill(-child.pid, 'SIGTERM');
    } catch {
      child.kill('SIGTERM');
    }
  }
}

/**
 * Cleanup that never masks a body failure and is never silent: verifies the
 * child exited and the loopback listener is gone; surfaces a secondary error
 * when the test body passed, or a diagnostic when it already failed.
 */
async function guaranteeCleanup(
  child: ChildProcess,
  port: number,
  bodyFailed: boolean,
): Promise<void> {
  terminateTree(child);
  const exit = await waitForExit(child, CHILD_EXIT_BOUND_MS);
  const portRefused = await portRefusesConnectionEventually(port, 10_000);
  const clean = exit !== 'TIMEOUT' && portRefused;
  if (!clean) {
    const detail = `cleanup failure: exit=${JSON.stringify(exit)} portRefused=${portRefused}`;
    if (bodyFailed) console.error(`[J07-G2] ${detail}`);
    else throw new Error(`[J07-G2] ${detail}`);
  }
}

/** Windows-only loopback binding evidence: every LISTENING row for the port. */
function listeningRows(port: number): string[] {
  const out = spawnSync('netstat', ['-ano', '-p', 'tcp'], {
    encoding: 'utf8',
    timeout: 15_000,
    windowsHide: true,
  });
  if (out.status !== 0 || typeof out.stdout !== 'string') return [];
  return out.stdout
    .split(/\r?\n/)
    .filter((line) => line.includes('LISTENING') && line.includes(`:${port}`));
}

const cleanupRoots: string[] = [];
afterEach(() => {
  for (const root of cleanupRoots.splice(0)) {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        rmSync(root, { recursive: true, force: true });
        break;
      } catch {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
      }
    }
  }
});

describe('R02-V G2 J07: production startup and loopback surface through the exact operator command', () => {
  it(`boots the integrated graph on Node ${process.version}, serves the real UI truthfully, and binds loopback only`, async () => {
    const port = await freePort();
    const child = spawn(PNPM, ['--filter', '@shun/control-api', 'dev'], {
      cwd: repoRoot,
      env: { ...sanitizedEnv({}), SHUN_CONTROL_PORT: String(port) },
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: isWindows,
      detached: !isWindows,
    });
    let bodyFailed = false;
    try {
      const output = collect(child);
      const up = await waitForHttp(port, 60_000);
      const text = output.text();
      expect(up, `server did not come up; output:\n${text}`).toBe(true);
      // G11 runner truthfulness: the pinned runner transforms the real graph
      // and the Node-26-removed flag never reappears.
      expect(text).not.toContain('ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX');
      expect(text).not.toContain('--experimental-transform-types');
      expect(text).toContain('Shun control surface (T08 DEMO ONLY)');
      expect(text).toContain('v0.3 production BUILD inactive');

      // The real static UI surface over loopback.
      const ui = await fetch(`http://127.0.0.1:${port}/v03/index.html`);
      expect(ui.status).toBe(200);
      expect((await ui.text()).includes('v03')).toBe(true);

      // Hostile non-loopback Host header is refused.
      const hostile = await rawGet(port, '/', { host: 'attacker.example' });
      expect(hostile.status).toBe(403);
      expect(hostile.body).toContain('LOCAL_ONLY_VIOLATION');

      // Truthful absence: no Guided service, no gateway — 503, never a fake
      // success shape.
      const guided = await rawGet(port, '/api/v03/guided/state', { host: `127.0.0.1:${port}` });
      expect(guided.status).toBe(503);
      expect(guided.body).toContain('V03_GUIDED_UNAVAILABLE');
      const gateway = await fetch(`http://127.0.0.1:${port}/api/v03/gateway/submit`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ caseId: 'none', request: {} }),
      });
      expect(gateway.status).toBe(503);
      expect(await gateway.text()).toContain('V03_GATEWAY_UNAVAILABLE');

      // Loopback-only binding evidence (native netstat on Windows).
      if (isWindows) {
        const rows = listeningRows(port);
        expect(rows.length, `no LISTENING row found for port ${port}`).toBeGreaterThan(0);
        for (const row of rows) {
          const local = row.trim().split(/\s+/)[1] ?? '';
          expect(local.startsWith(`127.0.0.1:${port}`), `non-loopback listener row: ${row}`).toBe(
            true,
          );
        }
        console.log('[J07-G2] netstat loopback evidence:', JSON.stringify(rows));
      }
      console.log(
        '[J07-G2] native Node startup record:',
        JSON.stringify({ platform: process.platform, node: process.version, port }),
      );
    } catch (error) {
      bodyFailed = true;
      throw error;
    } finally {
      await guaranteeCleanup(child, port, bodyFailed);
    }
  }, 120_000);
});

describe.skipIf(!isWindows)(
  'R02-V G2 J07: real-storage boot refuses before any listener when operator trust is absent',
  () => {
    it('the exact operator command fails closed with no listener and no Guided database', async () => {
      const root = mkdtempSync(join(tmpdir(), 'shun-r02v-g2-j07-trust-'));
      cleanupRoots.push(root);
      const workspace = resolve(join(root, 'workspace'));
      const protectedDir = join(workspace, 'protected');
      mkdirSync(protectedDir, { recursive: true });
      const evidenceDir = resolve(join(root, 'evidence'));
      mkdirSync(evidenceDir, { recursive: true });

      // Real registry authority issued by the shipping issuer script against
      // this exact workspace, so the FIRST missing production input is the
      // fixed ProgramData operator trust material.
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const publicKeyFile = resolve(join(root, 'registry-public.pem'));
      const privateKeyFile = resolve(join(root, 'registry-private.pem'));
      const currentnessFile = resolve(join(root, 'registry-currentness.json'));
      writeFileSync(publicKeyFile, publicKey.export({ type: 'spki', format: 'pem' }).toString());
      writeFileSync(privateKeyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString());
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
      expect(issuer.status, `registry issuer failed: ${issuer.stderr?.slice(0, 2000)}`).toBe(0);

      const guidedDatabase = resolve(join(root, 'guided.sqlite'));
      const port = await freePort();
      // The EXACT operator command (not a direct node invocation); this child
      // is a self-terminating boot refusal, not a live server tree.
      const child = spawn(PNPM, ['--filter', '@shun/control-api', 'dev'], {
        cwd: repoRoot,
        env: {
          ...sanitizedEnv({
            SHUN_CONTROL_MODE: 'real-storage',
            SHUN_REAL_STORAGE_ROOT: workspace,
            SHUN_REAL_STORAGE_PROTECTED: JSON.stringify([protectedDir]),
            SHUN_REAL_STORAGE_DATABASE: resolve(join(root, 'real.sqlite')),
            SHUN_REGISTRY_CURRENTNESS_FILE: currentnessFile,
            SHUN_REGISTRY_PUBLIC_KEY_FILE: publicKeyFile,
            SHUN_REGISTRY_PUBLIC_KEY_SPKI_SHA256: spkiSha256,
            SHUN_REAL_STORAGE_EVIDENCE_DIR: evidenceDir,
            SHUN_CONTROLLER_ISSUANCE_SECRET: 'issuance-secret-r02v-g2-j07',
            SHUN_GRANT_INTEGRITY_SECRET: 'integrity-secret-r02v-g2-j07',
            SHUN_V03_GUIDED_DATABASE: guidedDatabase,
          }),
          SHUN_CONTROL_PORT: String(port),
        },
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: isWindows,
        detached: !isWindows,
      });
      let bodyFailed = false;
      try {
        const output = collect(child);
        const exit = await waitForExit(child, 60_000);
        const text = output.text();
        expect(exit, `boot must refuse and exit; output:\n${text}`).not.toBe('TIMEOUT');
        if (exit !== 'TIMEOUT') expect(exit.code).not.toBe(0);
        // The refusal comes from the trust gate AFTER a healthy runner boot,
        // never from a dev-runner regression.
        expect(text).not.toContain('ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX');
        expect(text).not.toContain('--experimental-transform-types');
        expect(text).toMatch(/GUIDED_TRUST_PIN_UNTRUSTED|GUIDED_TRUST_|GUIDED_PROVENANCE_/);
        expect(text).toContain('KEY_NOT_PROVISIONED');
        // No listener, no REAL banner, no DEMO fallback, no Guided database.
        expect(text).not.toContain('Shun control surface (REAL bounded C-003)');
        expect(text).not.toContain('T08 DEMO ONLY');
        expect(await portRefusesConnectionEventually(port)).toBe(true);
        expect(existsSync(guidedDatabase)).toBe(false);
      } catch (error) {
        bodyFailed = true;
        throw error;
      } finally {
        await guaranteeCleanup(child, port, bodyFailed);
      }
    }, 120_000);
  },
);
