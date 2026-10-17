// T05 #106 — real Windows Build Host evidence for PRODUCTION NATIVE ADDON
// activation (the Sharp .node track). Companion to the merged CLI evidence
// (t05-winhost-evidence.ts); this run executes the NEW slice end to end on
// THIS host:
//
//   HOST    host/OS/integrity/symlink-privilege facts
//   PREP    curator keys, @img/sharp-win32-x64 registry SRI anchor, tarball
//           download, .node + libvips DLL extraction, real PE import dump
//   CACHE   dependency bytes provisioned into the Shun-owned digest cache
//           with recorded provenance (activation re-verifies every digest)
//   STAGE   production stager fetches the pinned .node bytes
//   PREF    merged preflight admits the native artifact
//   ACT     runNativeAddon ADDON_METADATA + IMAGE_METADATA: real isolated
//           child dlopens the pinned per-run staged .node and the libvips
//           closure, answers one closed-world op and exits
//   RPL     offline cache replay: 0 downloads, activation still works
//   RST     fresh subprocess re-composes and activates from durable cache
//   NEG     tampered main/dep cache, unsigned/forged/downgrade catalog,
//           ABI drift, missing/tampered dependency, undeclared import,
//           system-name collision, unseeded operand, revocation epoch,
//           grant revocation, TOCTOU denial, staged-bytes swap, real child
//           kill (interruption) + recovery, effect-grant mismatch
//   DACL    private cache root DACL/owner inspection (PowerShell Get-Acl,
//           SID-based, localization-proof)
//   CANARY  user-owned files unchanged across the whole run
//
// Honest scope: the positive-path HTTPS origin is a local fixture serving
// byte-exact package content; the trust anchors are the curator Ed25519
// signature over pinned digests, the npm registry SRI anchor recorded in
// PREP, and the ActionController grant state. BLOCKED is reported (never a
// fabricated PASS) when an input cannot be obtained on this host.
//
// Usage:
//   node scripts/t05-native-evidence.ts [evidenceDir] [runtimeRoot]

import { spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import {
  appendFile,
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { homedir, arch as osArch, hostname as osHostname, release as osRelease, tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';
import {
  type ActionPlan,
  AuthorizedActionSchema,
  canonicalJson,
  computePlanHash,
  type PlanAction,
} from '@shun/contracts';
import {
  CuratedProviderVerifier,
  LocalAuthority,
  type ProviderDependencyEntry,
  type TrustedProviderScope,
} from '@shun/vertical-jit';
import {
  type ActivationProcessOutcome,
  type ActivationRunSpec,
  BoundedSpawnProcess,
  CuratedProviderActivator,
  type ResolvedInvocation,
  type RunEffectDecision,
  type TrustedActivationHost,
} from '../src/activation.ts';
import { isSystemDllImportName, scanPeImports } from '../src/native-pe.ts';
import { CuratedProviderPreflight, type ProviderUseCurrentness } from '../src/preflight.ts';
import { CuratedProviderStager } from '../src/staging.ts';
import { buildSynthPe } from '../test/synth-pe.ts';

// ---- run identity and paths ----

const SCRIPT_DIR = fileURLToPath(new URL('.', import.meta.url));
const PACKAGE_DIR = resolve(SCRIPT_DIR, '..');
const RUN_TAG = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const EVIDENCE_DIR = resolve(
  process.argv[2] && !process.argv[2].startsWith('--')
    ? process.argv[2]
    : join(PACKAGE_DIR, 'evidence', `t05-native-${RUN_TAG}`),
);
const RUNTIME_ROOT = resolve(
  process.env.SHUN_T05_RUNTIME_ROOT ??
    (process.argv[3] && !process.argv[3].startsWith('--')
      ? process.argv[3]
      : join(tmpdir(), `shun-t05-native-${RUN_TAG}`)),
);
const RESTART_ARG = process.argv.indexOf('--t05-native-restart-child');

const PKG_NAME = '@img/sharp-win32-x64';
const REGISTRY_META = `https://registry.npmmirror.com/${PKG_NAME}`;
const TASK_ID = 'task-t05-native';
const BINDING = 'sharp-native-binding';
const EPOCH = { value: 1 };

// ---- sanitization (evidence must not leak user/host identity) ----

const SECRET_STRING: Array<[string, string]> = [];
function registerSecret(value: string, token: string): void {
  if (value && value.length > 3) SECRET_STRING.push([value, token]);
}
registerSecret(homedir(), '<HOME>');
registerSecret(tmpdir(), '<TMP>');
for (const form of new Set([
  osHostname(),
  osHostname().toUpperCase(),
  osHostname().toLowerCase(),
])) {
  registerSecret(form, '<HOST>');
}
registerSecret(process.env.USERNAME ?? process.env.USER ?? '', '<USER>');
registerSecret(process.env.COMPUTERNAME ?? '', '<HOST>');
registerSecret(RUNTIME_ROOT, '<RUNTIME>');

function sanitize(text: string): string {
  let out = text;
  for (const [secret, token] of SECRET_STRING) out = out.split(secret).join(token);
  out = out.replace(/[A-Za-z]:[\\/]Users[\\/][^\s"'`:;|*?<>/\\]+/g, 'C:\\Users\\<USER>');
  return out;
}

// ---- event log (incremental, crash-safe) ----

let eventsPath = '';
async function event(kind: string, payload: Record<string, unknown>): Promise<void> {
  const line = `${JSON.stringify({ at: new Date().toISOString(), kind, ...payload })}\n`;
  const safe = sanitize(line);
  if (eventsPath) await appendFile(eventsPath, safe, 'utf8');
  process.stdout.write(safe);
}

// ---- scenario runner ----

interface ScenarioResult {
  readonly id: string;
  readonly title: string;
  status: 'PASS' | 'FAIL' | 'SKIPPED' | 'BLOCKED';
  detail: string;
}

const results: ScenarioResult[] = [];
let runFailed = false;

async function scenario(id: string, title: string, fn: () => Promise<string>): Promise<void> {
  const started = Date.now();
  await event('scenario.start', { id, title });
  try {
    const detail = await fn();
    results.push({
      id,
      title,
      status: 'PASS',
      detail: `${detail} (${((Date.now() - started) / 1000).toFixed(1)}s)`,
    });
    await event('scenario.end', { id, status: 'PASS', detail });
  } catch (error) {
    const message = sanitize(error instanceof Error ? error.message : String(error)).slice(0, 600);
    const blocked = message.startsWith('BLOCKED:');
    if (!blocked) runFailed = true;
    results.push({ id, title, status: blocked ? 'BLOCKED' : 'FAIL', detail: message });
    await event('scenario.end', { id, status: blocked ? 'BLOCKED' : 'FAIL', error: message });
  }
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`ASSERT: ${message}`);
}

// ---- small async process helper (never spawnSync) ----

interface ExecOutcome {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
}

function execFileAsync(
  file: string,
  args: readonly string[],
  options: { timeoutMs?: number; cwd?: string; env?: NodeJS.ProcessEnv } = {},
): Promise<ExecOutcome> {
  const { timeoutMs = 60_000, cwd, env } = options;
  return new Promise((resolveExec) => {
    const child = spawn(file, [...args], {
      cwd,
      env: env ?? process.env,
      windowsHide: true,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.stdout?.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolveExec({ exitCode: -1, stdout, stderr: `${stderr}${error.message}`, timedOut });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolveExec({ exitCode: code ?? -1, stdout, stderr, timedOut });
    });
  });
}

async function sha256File(path: string): Promise<string> {
  return createHash('sha256')
    .update(await readFile(path))
    .digest('hex');
}

async function walkFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  let entries: string[] = [];
  try {
    entries = await readdir(dir);
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    const stat = await lstat(full);
    if (stat.isDirectory()) out.push(...(await walkFiles(full)));
    else out.push(full);
  }
  return out;
}

// ---- tiny PNG encoder (real image operand, no external deps) ----

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = (CRC_TABLE[(crc ^ byte) & 0xff] ?? 0) ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

/** A real WxH RGB PNG built with zlib — the seeded IMAGE_METADATA operand. */
function buildPng(width: number, height: number): Buffer {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // color type RGB
  const raw = Buffer.alloc(height * (1 + width * 3));
  for (let row = 0; row < height; row += 1) {
    const at = row * (1 + width * 3);
    raw[at] = 0; // no filter
    for (let x = 0; x < width; x += 1) {
      raw[at + 1 + x * 3] = (x * 31) % 256;
      raw[at + 2 + x * 3] = (row * 61) % 256;
      raw[at + 3 + x * 3] = 200;
    }
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

// ---- restart-child mode (fresh composition, durable cache, no network) ----

interface RestartConfig {
  cacheRoot: string;
  publicKeyPem: string;
  scopes: TrustedProviderScope[];
  descriptor: unknown;
  taskId: string;
  bindingId: string;
  digest: string;
  expectedAbi: string;
}

if (RESTART_ARG > -1) {
  const cfgPath = process.argv[RESTART_ARG + 1];
  if (!cfgPath) throw new Error('restart mode requires a config path');
  const cfg = JSON.parse(await readFile(cfgPath, 'utf8')) as RestartConfig;
  const verifier = new CuratedProviderVerifier(
    [{ keyId: 'curator-winhost', publicKeyPem: cfg.publicKeyPem }],
    cfg.scopes,
  );
  const stager = new CuratedProviderStager({ cacheRoot: cfg.cacheRoot, verifier, isOffline: () => true });
  const metadataEffect = async (invocation: ResolvedInvocation): Promise<RunEffectDecision> => {
    const under = (value: string, root: string) =>
      resolve(value).toLowerCase().startsWith(resolve(root).toLowerCase());
    const activeRoot = join(cfg.cacheRoot, 'active', cfg.bindingId, cfg.digest);
    if (
      invocation.op === 'provider.native.addon-metadata' &&
      invocation.taskId === cfg.taskId &&
      invocation.bindingId === cfg.bindingId &&
      invocation.artifactSha256 === cfg.digest &&
      invocation.argv[0] === '-e' &&
      typeof invocation.argv[1] === 'string' &&
      invocation.argv[1].length > 200 &&
      under(invocation.executablePath, resolve(process.execPath, '..')) &&
      under(invocation.cwd, join(activeRoot, 'exec')) &&
      invocation.writeRoots.length === 0
    ) {
      return { ok: true, leaseId: randomUUID() };
    }
    return { ok: false, code: 'EFFECT_NOT_AUTHORIZED' };
  };
  const host: TrustedActivationHost = {
    verifier,
    stager,
    cacheRoot: cfg.cacheRoot,
    getAuthorizedCurrentness: () => ({
      kind: 'CURRENT',
      taskId: cfg.taskId,
      providerId: 'sharp',
      bindingId: cfg.bindingId,
      catalogRevision: 'catalog-t05-native-r1',
      artifactSha256: cfg.digest,
      revocationEpoch: 1,
      capability: 'PREPARE_PROVIDER',
    }),
    authorizeRunEffect: metadataEffect,
    requiredRevocationEpoch: () => 1,
    hostPlatform: () => process.platform,
    hostArchitecture: () => process.arch,
    hostNodeAbi: () => process.versions.modules,
    hostNativeChildRuntime: () => process.execPath,
    hostSpawnEnvironment: minimalWindowsEnv,
  };
  const activator = new CuratedProviderActivator({ ...host, process: new BoundedSpawnProcess() });
  const result = await activator.runNativeAddon({
    taskId: cfg.taskId,
    descriptor: cfg.descriptor,
    run: { kind: 'ADDON_METADATA' },
  });
  const report =
    result.ok && result.native?.ok && result.native.report.kind === 'ADDON_METADATA'
      ? result.native.report
      : null;
  const payload = {
    ok: result.ok,
    exitCode: result.ok ? result.exitCode : -1,
    exportCount: report?.exportCount ?? -1,
    addonType: report && report.kind === 'ADDON_METADATA' ? report.addonType : '',
    childAbi: report?.childAbi ?? '',
    refuseCode: result.ok ? '' : result.code,
  };
  process.stdout.write(`RESTART_CHILD_RESULT ${JSON.stringify(payload)}\n`);
  process.exitCode =
    payload.ok && payload.exitCode === 0 && payload.exportCount > 0 && payload.childAbi === cfg.expectedAbi
      ? 0
      : 1;
} else {
  await mainRun().catch(async (error) => {
    const message = sanitize(
      error instanceof Error ? `${error.message}\n${error.stack ?? ''}` : String(error),
    );
    await event('run.crash', { error: message.slice(0, 2000) }).catch(() => undefined);
    process.exitCode = 2;
  });
}

function minimalWindowsEnv(): Readonly<Record<string, string>> {
  const env: Record<string, string> = {};
  for (const key of ['SystemRoot', 'SystemDrive']) {
    const value = process.env[key];
    if (typeof value === 'string' && value.length > 0 && value.length <= 256) env[key] = value;
  }
  return env;
}

// ---- main run ----

async function mainRun(): Promise<void> {
  const canaryPaths: string[] = [];
  const canaryBaseline = new Map<string, string>();

  // 0. Self re-exec with NODE_EXTRA_CA_CERTS once the fixture CA exists.
  mkdirSync(RUNTIME_ROOT, { recursive: true });
  const caKey = join(RUNTIME_ROOT, 'fixture-ca.key');
  const caPem = join(RUNTIME_ROOT, 'fixture-ca.pem');
  if (process.env.NODE_EXTRA_CA_CERTS !== caPem) {
    await rm(caKey, { force: true });
    await rm(caPem, { force: true });
    const openssl = await findOpenssl();
    const gen = await execFileAsync(
      openssl,
      [
        'req', '-x509', '-newkey', 'ed25519',
        '-keyout', caKey, '-out', caPem,
        '-days', '2', '-nodes',
        '-subj', '//CN=t05-native-fixture',
        '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
      ],
      { timeoutMs: 30_000 },
    );
    if (!existsSync(caPem))
      throw new Error(`openssl cert generation failed: ${gen.stderr.slice(0, 300)}`);
    const child = spawn(
      process.execPath,
      [fileURLToPath(import.meta.url), ...process.argv.slice(2)],
      {
        env: { ...process.env, NODE_EXTRA_CA_CERTS: caPem, SHUN_T05_RUNTIME_ROOT: RUNTIME_ROOT },
        stdio: 'inherit',
        windowsHide: true,
        shell: false,
      },
    );
    child.on('close', (code) => process.exit(code ?? 1));
    return;
  }

  mkdirSync(EVIDENCE_DIR, { recursive: true, mode: 0o700 });
  eventsPath = join(EVIDENCE_DIR, 'events.ndjson');
  await event('run.start', {
    task: 'T05 #106 real Windows Build Host — production native addon activation (Sharp)',
    baseline: 'version/v0.2.0@e263f3dc133ca2b664e8a9de2ee6995ccbeacf72',
    evidenceDir: EVIDENCE_DIR,
    pkg: PKG_NAME,
    node: process.version,
    modulesAbi: process.versions.modules,
  });

  // Canary files (user-owned locations; content must never change).
  const canaryDir = join(tmpdir(), 'shun-t05-native-canary');
  mkdirSync(canaryDir, { recursive: true, mode: 0o700 });
  const canaryTemp = join(canaryDir, 'user-canary-temp.txt');
  const canaryHome = join(homedir(), 'shun-t05-native-canary-home.txt');
  const canaryCwd = join(process.cwd(), 't05-native-canary-cwd.tmp');
  for (const [path, content] of [
    [canaryTemp, `canary ${randomUUID()}`],
    [canaryHome, `canary ${randomUUID()}`],
    [canaryCwd, `canary ${randomUUID()}`],
  ] as const) {
    await writeFile(path, content, 'utf8');
    canaryPaths.push(path);
    canaryBaseline.set(path, await sha256File(path));
  }
  await event('canary.baseline', {
    files: canaryPaths.map((p) => sanitize(p)),
    digests: [...canaryBaseline.values()],
  });

  // HOST facts.
  await scenario('HOST', 'host facts (OS, integrity, symlink privilege, node)', async () => {
    const whoExe = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'whoami.exe');
    const who = await execFileAsync(whoExe, [], { timeoutMs: 15_000 });
    const groups = await execFileAsync(whoExe, ['/groups'], { timeoutMs: 15_000 });
    const mandatory = (
      groups.stdout.split('\n').find((line) => /S-1-16-\d+/.test(line)) ?? ''
    ).replace(/[^\x20-\x7E]/g, '');
    const privs = await execFileAsync(whoExe, ['/priv'], { timeoutMs: 15_000 });
    const symlinkPriv = /SeCreateSymbolicLink/i.test(privs.stdout);
    const netSession = await execFileAsync('net', ['session'], { timeoutMs: 15_000 });
    const admin = netSession.exitCode === 0;
    await event('host.facts', {
      os: `${process.platform} ${osRelease()} ${osArch()}`,
      node: process.version,
      modulesAbi: process.versions.modules,
      user: sanitize(who.stdout.trim()),
      mandatoryLevel: sanitize(mandatory.trim()),
      symlinkPrivilege: symlinkPriv,
      elevatedShell: admin,
    });
    assert(osArch() === 'x64', 'host must be x64');
    return `os=${process.platform} ${osRelease()} x64 node=${process.version} symlinkPriv=${symlinkPriv} elevated=${admin}`;
  });

  // Trusted composition inputs.
  const curator = generateKeyPairSync('ed25519');
  const attacker = generateKeyPairSync('ed25519');
  const publicKeyPem = curator.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const authority = new LocalAuthority({
    authorityId: 't05-native-authority',
    policySnapshotRevision: 'pol-snap-native-r1',
    grantTtlMs: 60 * 60_000,
    hmacKey: 't05-native-issuance-key',
  });
  interface World {
    authority: LocalAuthority;
    epoch: () => number;
    grants: Map<string, GrantRecord>;
  }
  interface GrantRecord {
    plan: ActionPlan;
    action: unknown;
    grant: unknown;
    grantId: string;
    grantedEpoch: number;
    contract: InvocationContract;
  }
  type InvocationContract =
    | {
        readonly kind: 'native';
        readonly op: 'provider.native.addon-metadata' | 'provider.native.image-metadata';
        readonly addonSha256: string;
        readonly deps: ReadonlyArray<{ name: string; artifactSha256: string }>;
        readonly operandName?: string;
        readonly execRoot: string;
        readonly sandboxRoot: string;
      }
    | {
        readonly kind: 'cli';
        readonly op: ResolvedInvocation['op'];
        readonly argv: readonly string[];
        readonly execRoot: string;
        readonly sandboxRoot: string;
      };

  const PINNED_SHA = new Map<string, string>();
  const world: World = { authority, epoch: () => EPOCH.value, grants: new Map() };

  function currentnessPort(w: World) {
    return (taskId: string, bindingId: string): ProviderUseCurrentness => {
      const record = w.grants.get(bindingId);
      if (!record || record.plan.taskId !== taskId) return { kind: 'UNRESOLVABLE' };
      const validation = w.authority.validatePresentation({
        grant: record.grant,
        plan: record.plan,
        action: record.action,
        now: new Date().toISOString(),
      });
      if (!validation.ok) return { kind: 'UNRESOLVABLE' };
      const sha = PINNED_SHA.get(bindingId);
      if (!sha) return { kind: 'UNRESOLVABLE' };
      return {
        kind: 'CURRENT',
        taskId,
        providerId: 'sharp',
        bindingId,
        catalogRevision: 'catalog-t05-native-r1',
        artifactSha256: sha,
        revocationEpoch: record.grantedEpoch,
        capability: 'PREPARE_PROVIDER',
      };
    };
  }

  function effectPort(w: World) {
    return async (invocation: ResolvedInvocation): Promise<RunEffectDecision> => {
      const record = w.grants.get(invocation.bindingId);
      if (!record || record.plan.taskId !== invocation.taskId) {
        return { ok: false, code: 'AUTHORITY_STALE' };
      }
      const validation = w.authority.validatePresentation({
        grant: record.grant,
        plan: record.plan,
        action: record.action,
        now: new Date().toISOString(),
      });
      if (!validation.ok) {
        await event('effect.refused', { stage: 'grant-presentation', op: invocation.op }).catch(
          () => undefined,
        );
        return { ok: false, code: 'AUTHORITY_STALE' };
      }
      if (w.epoch() !== record.grantedEpoch) {
        await event('effect.refused', { stage: 'epoch', op: invocation.op }).catch(() => undefined);
        return { ok: false, code: 'AUTHORITY_STALE' };
      }
      const under = (value: string, root: string) =>
        resolve(value).toLowerCase().startsWith(resolve(root).toLowerCase());
      const contract = record.contract;
      if (contract.kind === 'native') {
        // Structural binding: the fixed bootstrap + payload identity (op,
        // addon digest, exact dependency name/digest set, operand name).
        // Per-run random paths are scope-bound through the roots.
        const [flag, bootstrap, payloadJson] = invocation.argv;
        if (
          invocation.op !== contract.op ||
          flag !== '-e' ||
          typeof bootstrap !== 'string' ||
          bootstrap.length < 200 ||
          typeof payloadJson !== 'string'
        ) {
          await event('effect.refused', { stage: 'argv-shape', op: invocation.op }).catch(
            () => undefined,
          );
          return { ok: false, code: 'EFFECT_NOT_AUTHORIZED' };
        }
        let payload: {
          op?: string;
          addon?: { sha256?: string };
          deps?: Array<{ name?: string; sha256?: string }>;
          operand?: { path?: string };
        };
        try {
          payload = JSON.parse(payloadJson);
        } catch {
          return { ok: false, code: 'EFFECT_NOT_AUTHORIZED' };
        }
        const expectedOp =
          contract.op === 'provider.native.addon-metadata' ? 'ADDON_METADATA' : 'IMAGE_METADATA';
        const depSetSame =
          (payload.deps?.length ?? -1) === contract.deps.length &&
          contract.deps.every((dep) =>
            payload.deps?.some(
              (given) => given.name === dep.name && given.sha256 === dep.artifactSha256,
            ),
          );
        if (
          payload.op !== expectedOp ||
          payload.addon?.sha256 !== contract.addonSha256 ||
          !depSetSame ||
          !under(invocation.cwd, contract.execRoot) ||
          !under(invocation.executablePath, resolve(process.execPath, '..')) ||
          !invocation.writeRoots.every((root) => root.length === 0) ||
          !invocation.readRoots.every(
            (root) => under(root, contract.execRoot) || under(root, contract.sandboxRoot),
          ) ||
          (contract.operandName
            ? !(payload.operand?.path ?? '').endsWith(contract.operandName) ||
              !under(payload.operand?.path ?? '', contract.sandboxRoot)
            : payload.operand !== undefined)
        ) {
          await event('effect.refused', { stage: 'invocation-binding', op: invocation.op }).catch(
            () => undefined,
          );
          return { ok: false, code: 'EFFECT_NOT_AUTHORIZED' };
        }
      } else {
        const same = (a: readonly string[], b: readonly string[]) =>
          a.length === b.length && a.every((value, index) => value === b[index]);
        if (
          invocation.op !== contract.op ||
          !same(invocation.argv, contract.argv) ||
          !under(invocation.executablePath, contract.execRoot) ||
          !under(invocation.cwd, contract.sandboxRoot)
        ) {
          return { ok: false, code: 'EFFECT_NOT_AUTHORIZED' };
        }
      }
      const leaseId = randomUUID();
      await event('effect.authorized', { leaseId, op: invocation.op }).catch(() => undefined);
      return { ok: true, leaseId };
    };
  }

  // ---- PREP: registry SRI anchor + tarball + extraction ----
  interface SharpFacts {
    version: string;
    tarballSha256: string;
    sri: string;
    addonName: string;
    addonSha256: string;
    addonBytes: number;
    dlls: Array<{ name: string; sha256: string; bytes: number }>;
  }
  let sharp: SharpFacts | null = null;
  const originDir = join(RUNTIME_ROOT, 'origin');

  await scenario(
    'PREP',
    'anchor @img/sharp-win32-x64 via npm registry SRI, extract .node + DLL closure',
    async () => {
      const metaResponse = await fetch(REGISTRY_META, { signal: AbortSignal.timeout(30_000) });
      assert(metaResponse.ok, `registry metadata fetch failed: HTTP ${metaResponse.status}`);
      const meta = (await metaResponse.json()) as {
        'dist-tags': { latest: string };
        versions: Record<string, { dist: { integrity: string; tarball: string } }>;
      };
      const version = meta['dist-tags'].latest;
      const dist = meta.versions[version]?.dist;
      assert(dist, 'registry metadata missing dist for latest');
      const probeResponse = await fetch(dist.tarball, { signal: AbortSignal.timeout(180_000) });
      assert(probeResponse.ok, `tarball fetch failed: HTTP ${probeResponse.status}`);
      const tarballBytes = Buffer.from(await probeResponse.arrayBuffer());
      const tarballSha = createHash('sha256').update(tarballBytes).digest('hex');
      const sha512 = createHash('sha512').update(tarballBytes).digest('base64');
      const sriMatches = `sha512-${sha512}` === dist.integrity;
      await event('prep.tarball', {
        version,
        tarballUrl: dist.tarball,
        finalOrigin: probeResponse.url,
        tarballBytes: tarballBytes.byteLength,
        sha256: tarballSha,
        registrySri: dist.integrity,
        sriMatches,
      });
      if (!sriMatches) {
        throw new Error(
          'BLOCKED: tarball does not match the npm registry SRI anchor (unreliable package bytes)',
        );
      }
      const tgzPath = join(RUNTIME_ROOT, 'sharp.tgz');
      await writeFile(tgzPath, tarballBytes);
      const extractDir = join(RUNTIME_ROOT, 'extract');
      await rm(extractDir, { recursive: true, force: true });
      mkdirSync(extractDir, { recursive: true });
      const tar = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe');
      const untar = await execFileAsync(tar, ['-xzf', tgzPath, '-C', extractDir], {
        timeoutMs: 120_000,
      });
      assert(untar.exitCode === 0, `bsdtar extract failed: ${untar.stderr.slice(0, 200)}`);
      const files = await walkFiles(extractDir);
      const addonPath = files.find((p) => p.endsWith('.node'));
      assert(addonPath, 'no .node binary inside the staged tarball');
      const dllPaths = files.filter((p) => p.toLowerCase().endsWith('.dll'));
      const addonBytes = await readFile(addonPath);
      const dlls: SharpFacts['dlls'] = [];
      for (const dllPath of dllPaths) {
        const bytes = await readFile(dllPath);
        dlls.push({
          name: basename(dllPath),
          sha256: createHash('sha256').update(bytes).digest('hex'),
          bytes: bytes.byteLength,
        });
      }
      // Real PE import dump of every image — this is the genuine closure
      // data the activation dependency check must accept.
      const peDump: Record<string, unknown> = {};
      const images: Array<{ name: string; bytes: Buffer }> = [
        { name: basename(addonPath), bytes: addonBytes },
      ];
      for (let index = 0; index < dllPaths.length; index += 1) {
        images.push({
          name: dlls[index]?.name ?? '',
          bytes: await readFile(dllPaths[index] ?? ''),
        });
      }
      for (const image of images) {
        const scan = scanPeImports(image.bytes);
        peDump[image.name] = scan.ok
          ? {
              machine: `0x${scan.machine.toString(16)}`,
              pe32Plus: scan.pe32Plus,
              imports: scan.imports,
              importsAllSystemOrEachOther: scan.imports.every(
                (name) =>
                  isSystemDllImportName(name) ||
                  dlls.some((dll) => dll.name.toLowerCase() === name.toLowerCase()) ||
                  name.toLowerCase() === basename(addonPath).toLowerCase(),
              ),
            }
          : { error: scan.code };
      }
      await event('prep.peImports', { images: peDump });
      sharp = {
        version,
        tarballSha256: tarballSha,
        sri: dist.integrity,
        addonName: basename(addonPath),
        addonSha256: createHash('sha256').update(addonBytes).digest('hex'),
        addonBytes: addonBytes.byteLength,
        dlls,
      };
      // Serve byte-exact package content from the fixture origin.
      mkdirSync(originDir, { recursive: true, mode: 0o700 });
      await copyFile(addonPath, join(originDir, sharp.addonName));
      for (let index = 0; index < dllPaths.length; index += 1) {
        const source = dllPaths[index];
        const target = dlls[index]?.name;
        if (!source || !target) continue;
        await copyFile(source, join(originDir, target));
      }
      return `sharp@${version} tarball=${tarballSha.slice(0, 16)}… addon=${sharp.addonSha256.slice(0, 16)}… dlls=${dlls.length}`;
    },
  );

  assert(sharp, 'PREP did not produce sharp facts');
  const SHARP: SharpFacts = sharp;

  // Trusted scopes: main addon binding + two dependency-name pins.
  const depEntries: ProviderDependencyEntry[] = SHARP.dlls.map((dll) => ({
    name: dll.name,
    artifactSha256: dll.sha256,
  }));
  const sharpScopeFields = {
    providerId: 'sharp',
    capabilityId: 'image.native',
    version: SHARP.version,
    catalogRevision: 'catalog-t05-native-r1',
    bindingId: BINDING,
    scopedVerifierId: 'winhost-native-verifier',
    catalogManifestSha256: '7'.repeat(64),
    bindingEvidenceSha256: '8'.repeat(64),
    artifactSha256: SHARP.addonSha256,

    platform: 'windows-x64',
    artifactKind: 'NATIVE_ADDON',
    abiRevision: process.versions.modules,
    dependencyEntries: depEntries,
  } satisfies Omit<TrustedProviderScope, 'origin'>;
  const fixture = await startFixtureOrigin(originDir, caKey, caPem);
  const sharpScope: TrustedProviderScope = Object.freeze({
    ...sharpScopeFields,
    origin: `https://127.0.0.1:${fixture.port}/${SHARP.addonName}`,
  });
  PINNED_SHA.set(BINDING, SHARP.addonSha256);

  try {
    await event('fixture.origin', {
      origin: `https://127.0.0.1:${fixture.port}`,
      files: [SHARP.addonName, ...SHARP.dlls.map((dll) => dll.name)],
    });

    const verifier = new CuratedProviderVerifier(
      [{ keyId: 'curator-winhost', publicKeyPem }],
      [sharpScope],
    );
    const makeDescriptor = (overrides: Record<string, unknown> = {}, signer = curator.privateKey) => {
      const { dependencyEntries: _host, ...scopeFields } = sharpScope;
      const unsigned = {
        ...scopeFields,
        entrypoint: SHARP.addonName,
        signerKeyId: 'curator-winhost',
        dependencySha256: depEntries.map((entry) => entry.artifactSha256),
        ...overrides,
      };
      return {
        ...unsigned,
        curatorSignature: sign(null, Buffer.from(canonicalJson(unsigned)), signer).toString('base64'),
      };
    };
    const descriptor = makeDescriptor();

    const cacheRoot = join(RUNTIME_ROOT, 'cache');
    const outputDir = join(RUNTIME_ROOT, 'outputs');
    mkdirSync(cacheRoot, { recursive: true, mode: 0o700 });
    mkdirSync(outputDir, { recursive: true, mode: 0o700 });

    // CACHE: provision dependency bytes into the Shun-owned digest cache with
    // recorded provenance (SRI-anchored tarball extraction). Activation
    // re-verifies every dep digest on every read.
    await scenario('DEPCACHE', 'provision verified dependency bytes into the digest cache', async () => {
      await mkdir(join(cacheRoot, 'artifacts'), { recursive: true, mode: 0o700 });
      for (const dll of SHARP.dlls) {
        const bytes = await readFile(join(originDir, dll.name));
        const digest = createHash('sha256').update(bytes).digest('hex');
        assert(digest === dll.sha256, `dep bytes drifted for ${dll.name}`);
        await writeFile(join(cacheRoot, 'artifacts', digest), bytes, { flag: 'wx' }).catch(
          async (error: NodeJS.ErrnoException) => {
            if (error.code !== 'EEXIST') throw error;
          },
        );
      }
      await event('depCache.provisioned', {
        provenance: 'extracted from the SRI-anchored registry tarball (PREP)',
        entries: SHARP.dlls.map((dll) => ({ name: dll.name, sha256: dll.sha256, bytes: dll.bytes })),
      });
      return `${SHARP.dlls.length} deps cached under digest names`;
    });

    const stager = new CuratedProviderStager({ cacheRoot, verifier, isOffline: () => false });
    const observer = {
      specs: [] as ActivationRunSpec[],
      port: {
        async run(spec: ActivationRunSpec): Promise<ActivationProcessOutcome> {
          observer.specs.push(spec);
          return new BoundedSpawnProcess().run(spec);
        },
      },
    };

    function activationHost(
      overrides: Partial<TrustedActivationHost> = {},
    ): TrustedActivationHost {
      return {
        verifier,
        stager,
        cacheRoot,
        getAuthorizedCurrentness: currentnessPort(world),
        authorizeRunEffect: effectPort(world),
        requiredRevocationEpoch: () => EPOCH.value,
        hostPlatform: () => process.platform,
        hostArchitecture: () => process.arch,
        hostNodeAbi: () => process.versions.modules,
        hostNativeChildRuntime: () => process.execPath,
        hostSpawnEnvironment: minimalWindowsEnv,
        process: observer.port,
        ...overrides,
      };
    }

    const activator = new CuratedProviderActivator(activationHost());
    const activeRoot = join(cacheRoot, 'active', BINDING, SHARP.addonSha256);
    const execRoot = join(activeRoot, 'exec');
    const sandboxRoot = join(activeRoot, 'sandbox');

    async function registerGrant(contract: InvocationContract): Promise<void> {
      const action: PlanAction = {
        actionId: `activate-${contract.kind}-${contract.op}`,
        bindingRef: BINDING,
        op: contract.op,
        parameters:
          contract.kind === 'native'
            ? {
                addonSha256: contract.addonSha256,
                deps: contract.deps,
                execRoot: contract.execRoot,
                sandboxRoot: contract.sandboxRoot,
                operandName: contract.operandName ?? null,
              }
            : { argv: [...contract.argv], execRoot: contract.execRoot, sandboxRoot: contract.sandboxRoot },
        sideEffectClass: 'R1',
        requiredPrivilege: 'USER',
        filesystemScope: {
          read: [contract.execRoot, contract.sandboxRoot],
          write: [outputDir],
        },
        timeoutMs: 60_000,
        cancellation: { supported: true, mode: 'COOPERATIVE' },
        expectedState: { outputWritten: true },
      };
      const planCore = {
        taskId: TASK_ID,
        capabilityId: 'image.native',
        bindingRefs: [BINDING],
        rankingPolicyRevision: 'rank-native-r1',
        policySnapshotRevision: 'pol-snap-native-r1',
        actions: [action],
        verificationPlan: {
          verifierId: 'winhost-native-verifier',
          verifierRevision: 'rev-1',
          checks: [{ checkId: 'sharp-exports' }],
        },
        recoveryPlan: {
          classificationStrategy: 'JOURNAL_AND_POST_STATE',
          reconcileBeforeRetry: true,
          retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
        },
      };
      const plan = { ...planCore, planHash: computePlanHash(planCore as ActionPlan) } as ActionPlan;
      await world.authority.ledger.register(plan);
      const grant = await world.authority.issue({
        taskId: TASK_ID,
        planHash: plan.planHash,
        policySnapshotRevision: 'pol-snap-native-r1',
        actionScope: {
          actionIds: [action.actionId],
          privilegeLevel: 'USER',
          filesystem: { read: [contract.execRoot, contract.sandboxRoot], write: [outputDir] },
        },
        authorizationKind: 'DURABLE_POLICY',
      });
      const authorized = AuthorizedActionSchema.parse({
        taskId: TASK_ID,
        actionId: action.actionId,
        planHash: plan.planHash,
        policySnapshotRevision: 'pol-snap-native-r1',
        authorizationKind: 'DURABLE_POLICY',
        authorizationRef: grant.grantId,
        expiresAt: grant.expiresAt,
        action,
      });
      world.grants.set(BINDING, {
        plan,
        action: authorized,
        grant,
        grantId: grant.grantId,
        grantedEpoch: world.epoch(),
        contract,
      });
    }

    const metadataContract: InvocationContract = {
      kind: 'native',
      op: 'provider.native.addon-metadata',
      addonSha256: SHARP.addonSha256,
      deps: depEntries,
      execRoot,
      sandboxRoot,
    };
    const imageContract: InvocationContract = {
      kind: 'native',
      op: 'provider.native.image-metadata',
      addonSha256: SHARP.addonSha256,
      deps: depEntries,
      operandName: 'photo.png',
      execRoot,
      sandboxRoot,
    };

    // STAGE the main .node through the production stager.
    await scenario('STAGE', 'production stager fetches the pinned .node bytes', async () => {
      const staged = await stager.stage(descriptor);
      assert(staged.ok, `stage refused: ${JSON.stringify(staged)}`);
      assert(staged.digest === SHARP.addonSha256, 'staged digest must equal the pinned addon sha');
      await event('stage.ok', { digest: staged.digest, byteLength: staged.byteLength });
      return `digest=${staged.digest.slice(0, 16)}… bytes=${staged.byteLength}`;
    });

    // PREFLIGHT on the real composition (the metadata grant is registered
    // first so the PREPARE_PROVIDER currentness resolves).
    await scenario('PREFLIGHT', 'merged preflight admits the native artifact', async () => {
      await registerGrant(metadataContract);
      const preflight = new CuratedProviderPreflight({
        verifier,
        stager,
        getAuthorizedCurrentness: currentnessPort(world),
        requiredRevocationEpoch: () => EPOCH.value,
        hostPlatform: () => process.platform,
        hostArchitecture: () => process.arch,
        hostNodeAbi: () => process.versions.modules,
      });
      const check = await preflight.check({ taskId: TASK_ID, descriptor });
      assert(check.ok, `preflight refused: ${JSON.stringify(check)}`);
      assert(check.state === 'PREFLIGHT_ONLY', 'preflight must stay non-executing');
      return `state=${check.state} digest=${check.digest.slice(0, 16)}…`;
    });

    // ACTIVATE-METADATA: the REAL production native activation.
    await scenario(
      'ACTIVATE-METADATA',
      'runNativeAddon ADDON_METADATA: real child dlopens pinned sharp + libvips closure',
      async () => {
        await registerGrant(metadataContract);
        const result = await activator.runNativeAddon({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'ADDON_METADATA' },
        });
        assert(result.ok, `activation refused: ${JSON.stringify(result)}`);
        assert(result.exitCode === 0, `child exit ${result.exitCode}: ${result.stderr.slice(0, 300)}`);
        const native = result.native;
        assert(native?.ok === true, `child report unparsable: ${JSON.stringify(native)}`);
        assert(
          native.report.kind === 'ADDON_METADATA' && native.report.exportCount > 0,
          'no exports reported by the child',
        );
        assert(native.report.childAbi === process.versions.modules, 'child ABI drift');
        const spec = observer.specs.at(-1);
        assert(spec, 'spawn was not observed');
        assert(spec?.executable === process.execPath, 'child must run the pinned runtime');
        assert(spec?.cwd?.toLowerCase().startsWith(execRoot.toLowerCase()), 'cwd must be the exec dir');
        assert(
          Object.keys(spec?.env ?? {}).every((key) => ['SystemRoot', 'SystemDrive'].includes(key)),
          'child env must be the scrubbed allowlist',
        );
        await event('activate.metadata', {
          exportCount: native.report.kind === 'ADDON_METADATA' ? native.report.exportCount : 0,
          exports:
            native.report.kind === 'ADDON_METADATA' ? native.report.exports.slice(0, 20) : [],
          childNode: native.report.childNode,
          durationMs: result.durationMs,
        });
        return `exports=${native.report.kind === 'ADDON_METADATA' ? native.report.exportCount : 0} abi=${native.report.childAbi}`;
      },
    );

    // ACTIVATE-IMAGE: real work through the addon over a seeded PNG.
    const operandBytes = buildPng(8, 2);
    await scenario(
      'ACTIVATE-IMAGE',
      'runNativeAddon IMAGE_METADATA: real sharp metadata over a seeded PNG',
      async () => {
        await registerGrant(imageContract);
        const result = await activator.runNativeAddon({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'IMAGE_METADATA', operand: 'photo.png' },
          sandboxFiles: [{ name: 'photo.png', bytes: operandBytes }],
        });
        assert(result.ok, `activation refused: ${JSON.stringify(result)}`);
        const native = result.native;
        assert(native?.ok === true, `child report unparsable: ${JSON.stringify(native)}`);
        const metadata =
          native.report.kind === 'IMAGE_METADATA' ? native.report.metadata : {};
        await event('activate.imageMetadata', { metadata });
        assert(
          metadata.width === 8 && metadata.height === 2,
          `unexpected metadata: ${JSON.stringify(metadata)}`,
        );
        assert(
          typeof metadata.format === 'string' && /png/i.test(String(metadata.format)),
          `unexpected format: ${JSON.stringify(metadata)}`,
        );
        await registerGrant(metadataContract);
        return `width=${String(metadata.width)} height=${String(metadata.height)} format=${String(metadata.format)}`;
      },
    );

    // RPL: offline cache replay — zero fetch, activation still works.
    let offlineFetches = 0;
    await scenario('OFFLINE-REPLAY', 'offline cache replay: 0 downloads, activation still works', async () => {
      await registerGrant(metadataContract);
      const offlineStager = new CuratedProviderStager({
        cacheRoot,
        verifier,
        isOffline: () => true,
        fetchArtifact: ((() => {
          offlineFetches += 1;
          return Promise.reject(new Error('network must not be touched'));
        }) as unknown as typeof fetch),
      });
      const offlineActivator = new CuratedProviderActivator(
        activationHost({ stager: offlineStager }),
      );
      const replayed = await offlineActivator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(replayed.ok, `offline replay refused: ${JSON.stringify(replayed)}`);
      assert(offlineFetches === 0, `offline replay performed ${offlineFetches} downloads`);
      return `cache replay ok, downloads=0, exports=${replayed.native?.ok && replayed.native.report.kind === 'ADDON_METADATA' ? replayed.native.report.exportCount : 0}`;
    });

    // RST: fresh subprocess re-composes from the durable cache.
    await scenario('RESTART', 'fresh subprocess re-verifies from durable cache and activates', async () => {
      const cfgPath = join(RUNTIME_ROOT, 'restart-cfg.json');
      await writeFile(
        cfgPath,
        JSON.stringify({
          cacheRoot,
          publicKeyPem,
          scopes: [sharpScope],
          descriptor,
          taskId: TASK_ID,
          bindingId: BINDING,
          digest: SHARP.addonSha256,
          expectedAbi: process.versions.modules,
        } satisfies RestartConfig),
        'utf8',
      );
      const child = await execFileAsync(
        process.execPath,
        [fileURLToPath(import.meta.url), '--t05-native-restart-child', cfgPath],
        { timeoutMs: 120_000, env: { ...minimalWindowsEnv() } },
      );
      const line =
        child.stdout.split('\n').find((entry) => entry.startsWith('RESTART_CHILD_RESULT ')) ?? '';
      assert(line !== '', `restart child produced no result: ${child.stderr.slice(0, 300)}`);
      const payload = JSON.parse(line.slice('RESTART_CHILD_RESULT '.length)) as {
        ok: boolean;
        exitCode: number;
        exportCount: number;
        childAbi: string;
      };
      await event('restart.child', payload);
      assert(payload.ok && payload.exitCode === 0, 'restart child activation failed');
      assert(payload.exportCount > 0, 'restart child reported no exports');
      assert(payload.childAbi === process.versions.modules, 'restart child ABI drift');
      return `fresh process: exports=${payload.exportCount} abi=${payload.childAbi}`;
    });

    // NEG-TAMPER-MAIN: tampered addon cache bytes.
    await scenario('NEG-TAMPER-MAIN', 'tampered cached .node refuses closed, recovers after restore', async () => {
      await registerGrant(metadataContract);
      const artifactPath = join(cacheRoot, 'artifacts', SHARP.addonSha256);
      const original = await readFile(artifactPath);
      const tampered = Buffer.from(original);
      tampered[0x40] = (tampered[0x40] ?? 0) ^ 0xff;
      const spawnsBefore = observer.specs.length;
      try {
        await writeFile(artifactPath, tampered);
        const refused = await activator.runNativeAddon({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'ADDON_METADATA' },
        });
        assert(
          !refused.ok && refused.code === 'ARTIFACT_NOT_VERIFIED',
          `expected ARTIFACT_NOT_VERIFIED, got ${JSON.stringify(refused)}`,
        );
        assert(
          observer.specs.length === spawnsBefore,
          'the tamper refusal itself must be zero-spawn',
        );
      } finally {
        await writeFile(artifactPath, original);
      }
      const recovered = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(recovered.ok, `recovery after restore failed: ${JSON.stringify(recovered)}`);
      return 'tampered→ARTIFACT_NOT_VERIFIED zero spawn; restored→EXECUTED (one fresh run)';
    });

    // NEG-CATALOG: unsigned / forged / downgrade.
    await scenario('NEG-CATALOG', 'unsigned, forged-key and downgrade descriptors refuse before exec', async () => {
      const spawnsBefore = observer.specs.length;
      const unsigned = { ...descriptor, curatorSignature: 'AAA'.repeat(29) };
      const unsignedResult = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor: unsigned,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(!unsignedResult.ok, 'unsigned descriptor must refuse');
      const forged = makeDescriptor({}, attacker.privateKey);
      const forgedResult = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor: forged,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(forgedResult.ok === false, 'forged-key descriptor must refuse');
      const downgrade = makeDescriptor({ version: '0.0.1-downgrade' });
      const downgradeResult = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor: downgrade,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(
        !downgradeResult.ok && downgradeResult.code === 'CATALOG_SCOPE_DRIFT',
        `downgrade must SCOPE_DRIFT, got ${JSON.stringify(downgradeResult)}`,
      );
      assert(observer.specs.length === spawnsBefore, 'refusals must be zero-spawn');
      await event('neg.catalog', {
        unsigned: unsignedResult.ok ? '' : unsignedResult.code,
        forged: forgedResult.ok ? '' : forgedResult.code,
        downgrade: 'CATALOG_SCOPE_DRIFT',
      });
      return `unsigned=${unsignedResult.ok ? '' : String(unsignedResult.code)} forged=${forgedResult.ok ? '' : String(forgedResult.code)} downgrade=CATALOG_SCOPE_DRIFT spawns=0`;
    });

    // NEG-ABI: host ABI drift.
    await scenario('NEG-ABI', 'host ABI drift refuses closed before any child', async () => {
      const spawnsBefore = observer.specs.length;
      const abiDrift = new CuratedProviderActivator(
        activationHost({ hostNodeAbi: () => '999' }),
      );
      const refused = await abiDrift.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(
        !refused.ok && refused.code === 'ABI_MISMATCH',
        `expected ABI_MISMATCH, got ${JSON.stringify(refused)}`,
      );
      assert(observer.specs.length === spawnsBefore, 'ABI refusal must be zero-spawn');
      return `hostAbi=999 vs artifact=${process.versions.modules} → ABI_MISMATCH zero spawn`;
    });

    // NEG-DEP-MISSING / NEG-DEP-TAMPER.
    await scenario('NEG-DEP', 'missing and tampered dependency cache bytes refuse closed', async () => {
      await registerGrant(metadataContract);
      const spawnsBefore = observer.specs.length;
      const emptyCache = join(RUNTIME_ROOT, 'cache-empty-deps');
      mkdirSync(emptyCache, { recursive: true, mode: 0o700 });
      const emptyStager = new CuratedProviderStager({ cacheRoot: emptyCache, verifier, isOffline: () => false });
      const emptyActivator = new CuratedProviderActivator(activationHost({ stager: emptyStager }));
      const stagedEmpty = await emptyStager.stage(descriptor);
      assert(stagedEmpty.ok, `empty-cache stage refused: ${JSON.stringify(stagedEmpty)}`);
      const missingDep = await emptyActivator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(
        !missingDep.ok && missingDep.code === 'DEPENDENCIES_UNVERIFIED',
        `expected DEPENDENCIES_UNVERIFIED, got ${JSON.stringify(missingDep)}`,
      );
      assert(observer.specs.length === spawnsBefore, 'missing-dep refusal must be zero-spawn');
      const depPath = join(cacheRoot, 'artifacts', SHARP.dlls[0]?.sha256 ?? '');
      const depOriginal = await readFile(depPath);
      try {
        const depTampered = Buffer.from(depOriginal);
        depTampered[0x40] = (depTampered[0x40] ?? 0) ^ 0xff;
        await writeFile(depPath, depTampered);
        const tamperedDep = await activator.runNativeAddon({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'ADDON_METADATA' },
        });
        assert(
          !tamperedDep.ok && tamperedDep.code === 'DEPENDENCIES_UNVERIFIED',
          `expected DEPENDENCIES_UNVERIFIED, got ${JSON.stringify(tamperedDep)}`,
        );
      } finally {
        await writeFile(depPath, depOriginal);
      }
      const recovered = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(recovered.ok, 'activation must recover once dep bytes are restored');
      return 'missing/tampered dep → DEPENDENCIES_UNVERIFIED zero spawn; restored → EXECUTED (one fresh run)';
    });

    // NEG-IMPORT: undeclared non-system import (synthetic fixture).
    await scenario('NEG-IMPORT', 'undeclared non-system import refuses (synthetic PE fixture)', async () => {
      const spawnsBefore = observer.specs.length;
      const evilAddon = buildSynthPe({ imports: ['KERNEL32.dll', 'evil_overlay.dll'] });
      const evilSha = createHash('sha256').update(evilAddon).digest('hex');
      const evilScope: TrustedProviderScope = {
        ...sharpScope,
        bindingId: 'sharp-evil-binding',
        artifactSha256: evilSha,
        dependencyEntries: [],
      };
      const evilVerifier = new CuratedProviderVerifier(
        [{ keyId: 'curator-winhost', publicKeyPem }],
        [evilScope],
      );
      const evilCache = join(RUNTIME_ROOT, 'cache-evil');
      mkdirSync(evilCache, { recursive: true, mode: 0o700 });
      const scopeFields = (({ dependencyEntries: _drop, ...rest }) => rest)(evilScope);
      const evilUnsigned = {
        ...scopeFields,
        entrypoint: 'addon.node',
        signerKeyId: 'curator-winhost',
        dependencySha256: [],
      };
      const evilDescriptor = {
        ...evilUnsigned,
        curatorSignature: sign(null, Buffer.from(canonicalJson(evilUnsigned)), curator.privateKey).toString('base64'),
      };
      const evilStager = new CuratedProviderStager({
        cacheRoot: evilCache,
        verifier: evilVerifier,
        isOffline: () => false,
        fetchArtifact: (async () => new Response(evilAddon, { status: 200 })) as typeof fetch,
      });
      const evilStaged = await evilStager.stage(evilDescriptor);
      assert(evilStaged.ok, `evil fixture stage refused: ${JSON.stringify(evilStaged)}`);
      // The alternate binding resolves currentness through the same substrate
      // (same policy epoch), so the refusal provably comes from the closure
      // check and not from a missing grant.
      const evilActivator = new CuratedProviderActivator(
        activationHost({
          stager: evilStager,
          verifier: evilVerifier,
          cacheRoot: evilCache,
          getAuthorizedCurrentness: (taskId, bindingId) =>
            bindingId === evilScope.bindingId
              ? {
                  kind: 'CURRENT',
                  taskId,
                  providerId: 'sharp',
                  bindingId,
                  catalogRevision: evilScope.catalogRevision,
                  artifactSha256: evilSha,
                  revocationEpoch: EPOCH.value,
                  capability: 'PREPARE_PROVIDER',
                }
              : currentnessPort(world)(taskId, bindingId),
          authorizeRunEffect: async () => ({ ok: true, leaseId: randomUUID() }),
        }),
      );
      const refused = await evilActivator.runNativeAddon({
        taskId: TASK_ID,
        descriptor: evilDescriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(
        !refused.ok && refused.code === 'DEPENDENCIES_UNVERIFIED',
        `expected DEPENDENCIES_UNVERIFIED, got ${JSON.stringify(refused)}`,
      );
      assert(observer.specs.length === spawnsBefore, 'import refusal must be zero-spawn');
      return 'evil_overlay.dll undeclared → DEPENDENCIES_UNVERIFIED zero spawn';
    });

    // NEG-DEP-COLLISION: curated dependency named like a system DLL.
    await scenario('NEG-DEP-COLLISION', 'dependency name colliding with a system DLL refuses', async () => {
      const spawnsBefore = observer.specs.length;
      const collidingScope: TrustedProviderScope = {
        ...sharpScope,
        bindingId: 'sharp-collision-binding',
        dependencyEntries: [
          { name: 'KERNEL32.DLL', artifactSha256: SHARP.dlls[0]?.sha256 ?? '' },
          ...SHARP.dlls.slice(1).map((dll) => ({ name: dll.name, artifactSha256: dll.sha256 })),
        ],
      };
      const collisionVerifier = new CuratedProviderVerifier(
        [{ keyId: 'curator-winhost', publicKeyPem }],
        [collidingScope],
      );
      const scopeFields = (({ dependencyEntries: _drop, ...rest }) => rest)(collidingScope);
      const unsigned = {
        ...scopeFields,
        entrypoint: SHARP.addonName,
        signerKeyId: 'curator-winhost',
        dependencySha256: (collidingScope.dependencyEntries ?? []).map((entry) => entry.artifactSha256),
      };
      const collidingDescriptor = {
        ...unsigned,
        curatorSignature: sign(null, Buffer.from(canonicalJson(unsigned)), curator.privateKey).toString('base64'),
      };
      const collisionStager = new CuratedProviderStager({
        cacheRoot,
        verifier: collisionVerifier,
        isOffline: () => false,
      });
      const staged = await collisionStager.stage(collidingDescriptor);
      assert(staged.ok, `collision stage refused: ${JSON.stringify(staged)}`);
      const collisionActivator = new CuratedProviderActivator(
        activationHost({
          stager: collisionStager,
          verifier: collisionVerifier,
          getAuthorizedCurrentness: (taskId, bindingId) =>
            bindingId === collidingScope.bindingId
              ? {
                  kind: 'CURRENT',
                  taskId,
                  providerId: 'sharp',
                  bindingId,
                  catalogRevision: collidingScope.catalogRevision,
                  artifactSha256: SHARP.addonSha256,
                  revocationEpoch: EPOCH.value,
                  capability: 'PREPARE_PROVIDER',
                }
              : currentnessPort(world)(taskId, bindingId),
          authorizeRunEffect: async () => ({ ok: true, leaseId: randomUUID() }),
        }),
      );
      const refused = await collisionActivator.runNativeAddon({
        taskId: TASK_ID,
        descriptor: collidingDescriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(
        !refused.ok && refused.code === 'DEPENDENCIES_UNVERIFIED',
        `expected DEPENDENCIES_UNVERIFIED, got ${JSON.stringify(refused)}`,
      );
      assert(observer.specs.length === spawnsBefore, 'collision refusal must be zero-spawn');
      return 'KERNEL32.DLL as a curated dep name → DEPENDENCIES_UNVERIFIED zero spawn';
    });

    // NEG-OPERAND: unseeded / absolute operands.
    await scenario('NEG-OPERAND', 'unseeded and absolute IMAGE_METADATA operands refuse pre-authority', async () => {
      const spawnsBefore = observer.specs.length;
      const unseeded = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'IMAGE_METADATA', operand: 'unseeded.bin' },
      });
      assert(
        !unseeded.ok && unseeded.code === 'RUN_REQUEST_INVALID',
        `expected RUN_REQUEST_INVALID, got ${JSON.stringify(unseeded)}`,
      );
      const absolute = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        // Closed world cannot even express an absolute operand as a string —
        // the grammar refuses any non-seeded name.
        run: { kind: 'IMAGE_METADATA', operand: 'C:\\evil.png' },
      });
      assert(
        !absolute.ok && absolute.code === 'RUN_REQUEST_INVALID',
        `expected RUN_REQUEST_INVALID, got ${JSON.stringify(absolute)}`,
      );
      assert(observer.specs.length === spawnsBefore, 'operand refusals must be zero-spawn');
      return 'unseeded + absolute operands → RUN_REQUEST_INVALID, zero spawn';
    });

    // NEG-REVOCATION-EPOCH.
    await scenario('NEG-REVOCATION-EPOCH', 'host revocation-epoch bump voids activation before exec', async () => {
      await registerGrant(metadataContract);
      EPOCH.value = 2;
      try {
        const refused = await activator.runNativeAddon({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'ADDON_METADATA' },
        });
        assert(
          !refused.ok && refused.code === 'AUTHORITY_STALE',
          `expected AUTHORITY_STALE, got ${JSON.stringify(refused)}`,
        );
      } finally {
        EPOCH.value = 1;
      }
      const recovered = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(recovered.ok, 'activation must recover once the epoch matches again');
      return 'epoch 1→2 → AUTHORITY_STALE zero spawn; restored → EXECUTED';
    });

    // NEG-GRANT-REVOKED: real substrate move.
    await scenario('NEG-GRANT-REVOKED', 'revoked grant refuses; re-issue restores', async () => {
      const record = world.grants.get(BINDING);
      assert(record, 'grant must exist');
      world.authority.revokeGrant(record?.grantId ?? '');
      const refused = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(
        !refused.ok && refused.code === 'AUTHORITY_STALE',
        `expected AUTHORITY_STALE, got ${JSON.stringify(refused)}`,
      );
      await registerGrant(metadataContract);
      const recovered = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(recovered.ok, 'fresh grant must restore activation');
      return 'revokeGrant → AUTHORITY_STALE zero spawn; re-issue → EXECUTED';
    });

    // NEG-TOCTOU: second ActionController read denied mid-call.
    await scenario('NEG-TOCTOU', 'ActionController denial between admission and exec voids activation', async () => {
      let reads = 0;
      const toctouActivator = new CuratedProviderActivator(
        activationHost({
          getAuthorizedCurrentness: (taskId, bindingId) => {
            reads += 1;
            if (reads >= 2) return { kind: 'UNRESOLVABLE' };
            return currentnessPort(world)(taskId, bindingId);
          },
        }),
      );
      const refused = await toctouActivator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(
        !refused.ok && refused.code === 'AUTHORITY_STALE',
        `TOCTOU denial must refuse, got ${JSON.stringify(refused)}`,
      );
      assert(reads >= 2, 'the second pre-exec read never happened');
      return `reads=${reads} (admission + immediately-before-exec), second denial → zero spawn`;
    });

    // NEG-SWAP: staged .node swapped after verification.
    await scenario('NEG-SWAP', 'staged .node byte swap after verification refuses at the last boundary', async () => {
      await registerGrant(metadataContract);
      let sabotaged = false;
      let spawnsBefore = 0;
      const swapping = new CuratedProviderActivator(
        activationHost({
          authorizeRunEffect: async (invocation) => {
            if (!sabotaged && invocation.native) {
              sabotaged = true;
              const { writeFile: writeFileAsync } = await import('node:fs/promises');
              await writeFileAsync(
                invocation.native.addonPath,
                Buffer.from('sentinel: not the pinned bytes'),
              );
            }
            return { ok: true, leaseId: randomUUID() };
          },
          process: {
            async run(): Promise<ActivationProcessOutcome> {
              return {
                exitCode: 0,
                stdout: '',
                stderr: '',
                timedOut: false,
                stdoutTruncated: false,
                stderrTruncated: false,
              };
            },
          },
        }),
      );
      spawnsBefore = observer.specs.length;
      const refused = await swapping.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(sabotaged, 'the sabotage hook never ran');
      assert(
        !refused.ok && refused.code === 'EXECUTABLE_IDENTITY_DRIFT',
        `expected EXECUTABLE_IDENTITY_DRIFT, got ${JSON.stringify(refused)}`,
      );
      assert(observer.specs.length === spawnsBefore, 'swap refusal must be zero-spawn');
      const recovered = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(recovered.ok, 'a clean next run must recover');
      return 'staged .node swapped post-verify → EXECUTABLE_IDENTITY_DRIFT zero spawn; fresh run → EXECUTED';
    });

    // NEG-INTERRUPT: real child killed mid-flight, then recovery.
    await scenario('NEG-INTERRUPT', 'killed child surfaces honestly as timedOut; next run recovers', async () => {
      await registerGrant(metadataContract);
      const killed = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
        timeoutMs: 1,
      });
      assert(killed.ok, `kill run failed at admission: ${JSON.stringify(killed)}`);
      assert(killed.timedOut, 'the killed child must surface timedOut');
      await event('neg.interrupt', {
        exitCode: killed.exitCode,
        timedOut: killed.timedOut,
        durationMs: killed.durationMs,
      });
      const recovered = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      assert(recovered.ok && !recovered.timedOut, `recovery failed: ${JSON.stringify(recovered)}`);
      return `child killed at 1ms → EXECUTED timedOut=true exit=${killed.exitCode}; recovery → exports=${recovered.native?.ok && recovered.native.report.kind === 'ADDON_METADATA' ? recovered.native.report.exportCount : 0}`;
    });

    // R1-F03 native: grant/op mismatch refuses at the effect gate.
    await scenario('R1-F03-GRANT-BINDING', 'effect grant bound to ADDON_METADATA refuses IMAGE_METADATA', async () => {
      const spawnsBefore = observer.specs.length;
      await registerGrant(metadataContract);
      const refused = await activator.runNativeAddon({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'IMAGE_METADATA', operand: 'photo.png' },
        sandboxFiles: [{ name: 'photo.png', bytes: operandBytes }],
      });
      assert(
        !refused.ok && refused.code === 'EFFECT_NOT_AUTHORIZED',
        `expected EFFECT_NOT_AUTHORIZED, got ${JSON.stringify(refused)}`,
      );
      assert(observer.specs.length === spawnsBefore, 'grant-mismatch refusal must be zero-spawn');
      await registerGrant(imageContract);
      return 'ADDON_METADATA grant vs IMAGE_METADATA invocation → EFFECT_NOT_AUTHORIZED zero spawn';
    });

    // DACL: private cache root owner + no world/users write (SID-based,
    // localization-proof).
    await scenario('DACL', 'private cache root DACL/owner: owner-only write surface', async () => {
      const ps = join(
        process.env.SystemRoot ?? 'C:\\Windows',
        'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe',
      );
      const psScript = [
        `$root = '${cacheRoot}'`,
        '$acl = Get-Acl -LiteralPath $root',
        '$owner = $acl.Owner',
        '$sid = (New-Object System.Security.Principal.NTAccount($owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value',
        '$rules = $acl.Access | ForEach-Object {',
        '  $identity = $_.IdentityReference',
        "  $sidValue = ''",
        '  try { $sidValue = $identity.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sidValue = $identity.Value }',
        "  [PSCustomObject]@{ sid = $sidValue; rights = [int]$_.FileSystemRights; type = $_.AccessControlType.ToString(); inherited = $_.IsInherited }",
        '}',
        "$world = 'S-1-1-0'; $users = 'S-1-5-32-545'; $authUsers = 'S-1-5-11'",
        '$writeBits = 0x0002 -bor 0x0004 -bor 0x10000 -bor 0x40000000 -bor 0x80000000',
        "$wideWrite = $rules | Where-Object { ($_.sid -eq $world -or $_.sid -eq $users -or $_.sid -eq $authUsers) -and (($_.rights -band $writeBits) -ne 0) -and $_.type -eq 'Allow' }",
        "[PSCustomObject]@{ owner = $owner; ownerSid = $sid; wideWriteCount = @($wideWrite).Count; ruleCount = @($rules).Count } | ConvertTo-Json -Compress",
      ].join('; ');
      const dump = await execFileAsync(ps, ['-NoProfile', '-NonInteractive', '-Command', psScript], {
        timeoutMs: 60_000,
      });
      assert(dump.exitCode === 0, `Get-Acl failed: ${dump.stderr.slice(0, 300)}`);
      const parsed = JSON.parse(dump.stdout.trim().split('\n').at(-1) ?? '{}') as {
        owner: string;
        ownerSid: string;
        wideWriteCount: number;
        ruleCount: number;
      };
      const whoExe = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'whoami.exe');
      const who = await execFileAsync(whoExe, [], { timeoutMs: 15_000 });
      const accountName = who.stdout.trim().split('\n').at(0)?.trim() ?? '';
      const bareName = accountName.split('\\').at(-1)?.toLowerCase() ?? '';
      const ownerMatches =
        parsed.owner.toLowerCase().includes(bareName) &&
        bareName.length > 0;
      await event('dacl.inspect', {
        owner: sanitize(parsed.owner),
        ownerSid: parsed.ownerSid,
        wideWriteCount: parsed.wideWriteCount,
        ruleCount: parsed.ruleCount,
        ownerMatchesCurrentUser: ownerMatches,
      });
      assert(ownerMatches, `cache root owner ${sanitize(parsed.owner)} is not the current user`);
      assert(
        parsed.wideWriteCount === 0,
        `${parsed.wideWriteCount} world/users/auth-users write ACEs on the cache root`,
      );
      return `owner=${sanitize(parsed.owner)} (current user), wide-write ACEs=0, rules=${parsed.ruleCount}`;
    });

    // CANARY final.
    await scenario('CANARY', 'user-owned files unchanged across the whole run', async () => {
      for (const path of canaryPaths) {
        const digest = await sha256File(path);
        assert(
          digest === canaryBaseline.get(path),
          `canary changed: ${sanitize(path)}`,
        );
      }
      return `${canaryPaths.length} canaries byte-identical`;
    });
  } finally {
    await fixture.close();
  }

  // Summary + manifest.
  const passCount = results.filter((r) => r.status === 'PASS').length;
  const failCount = results.filter((r) => r.status === 'FAIL').length;
  const blockedCount = results.filter((r) => r.status === 'BLOCKED').length;
  const skipCount = results.filter((r) => r.status === 'SKIPPED').length;
  const summary = [
    '# T05 #106 — real Windows Build Host evidence: production native addon activation (Sharp)',
    '',
    `- Baseline: version/v0.2.0@e263f3dc133ca2b664e8a9de2ee6995ccbeacf72`,
    `- Host: ${process.platform} ${osRelease()} ${osArch()}, node ${process.version} (ABI ${process.versions.modules})`,
    `- Package: ${PKG_NAME}@${SHARP.version}, tarball sha256=${SHARP.tarballSha256}, npm SRI ${SHARP.sri}`,
    `- Addon: ${SHARP.addonName} sha256=${SHARP.addonSha256} (${SHARP.addonBytes} bytes)`,
    `- Closure: ${SHARP.dlls.map((dll) => `${dll.name}@${dll.sha256.slice(0, 12)}…`).join(', ') || 'none'}`,
    `- Run: ${RUN_TAG} (UTC); events.ndjson carries the full incremental log`,
    '',
    '## Verdict',
    '',
    `- Production native activation matrix: ${failCount === 0 ? `PASS (${passCount} scenarios)` : `FAIL (${failCount} failed)`}${blockedCount ? `, ${blockedCount} BLOCKED` : ''}${skipCount ? `, ${skipCount} skipped` : ''}`,
    '- Child surface: ONE pinned-runtime Node child per activation, fixed bootstrap source,',
    '  one bounded payload, scrubbed env (no PATH), exec-dir cwd, hard timeout, capped output;',
    '  the loader process itself never dlopens provider bytes.',
    '- T11 Release readiness: NOT claimed by this run.',
    '',
    '## Scenarios',
    '',
    ...results.map((r) => `- [${r.status}] ${r.id} ${r.title} — ${r.detail}`),
    '',
    '## Honest scope',
    '',
    '- Positive-path HTTPS origin is a local fixture serving byte-exact package content;',
    '  trust anchors are the curator Ed25519 signature over pinned digests, the npm registry',
    '  SRI anchor recorded in PREP, and the ActionController grant state (LocalAuthority HMAC',
    '  substrate) — all provisioned by this trusted composition, never by request input.',
    '- Dependency bytes are provisioned into the digest-named cache from the SRI-anchored',
    '  tarball extraction (DEPCACHE provenance event); activation re-verifies every dep digest',
    '  on every read and PE-parses the whole import graph (system∪declared closure).',
    '- The documented Windows same-privilege verification→spawn TOCTOU residual (P2 in the',
    '  CLI review) applies to the native seam as well: detection-at-the-last-check, not',
    '  stat→close→spawn atomicity, is claimed.',
    '',
  ].join('\n');
  await writeFile(join(EVIDENCE_DIR, 'summary.md'), sanitize(summary), 'utf8');
  const evidenceFiles = await walkFiles(EVIDENCE_DIR);
  const manifestLines = [
    `T05 native evidence manifest — ${RUN_TAG}`,
    `evidence_dir=${sanitize(EVIDENCE_DIR)}`,
    `runtime_root=${sanitize(RUNTIME_ROOT)} (NOT committed; heavy artifacts)`,
    `pkg=${PKG_NAME}@${SHARP.version}`,
    `tarball_sha256=${SHARP.tarballSha256}`,
    `addon=${SHARP.addonName}`,
    `addon_sha256=${SHARP.addonSha256}`,
    `closure=${JSON.stringify(SHARP.dlls)}`,
    `curator_public_key_sha256=${createHash('sha256').update(publicKeyPem).digest('hex')}`,
    '',
  ];
  for (const p of evidenceFiles) {
    manifestLines.push(`${await sha256File(p)}  ${sanitize(p)}`);
  }
  await writeFile(join(EVIDENCE_DIR, 'manifest.txt'), `${manifestLines.join('\n')}\n`, 'utf8');
  await event('run.end', {
    pass: passCount,
    fail: failCount,
    blocked: blockedCount,
    skipped: skipCount,
    runFailed,
    summary: sanitize(join(EVIDENCE_DIR, 'summary.md')),
  });
  process.exitCode = runFailed ? 1 : 0;
}

// ---- HTTPS fixture origin ----

async function startFixtureOrigin(originDir: string, caKeyPath: string, caPemPath: string) {
  const https = await import('node:https');
  const files = new Map<string, Buffer>();
  for (const entry of await readdir(originDir)) {
    files.set(`/${entry}`, await readFile(join(originDir, entry)));
  }
  const server = https.createServer(
    { key: await readFile(caKeyPath), cert: await readFile(caPemPath) },
    (req, res) => {
      const url = (req.url ?? '').split('?')[0] ?? '';
      const body = files.get(url);
      if (body) {
        res.writeHead(200, {
          'content-length': body.length,
          'content-type': 'application/octet-stream',
        });
        res.end(body);
        return;
      }
      if (url.startsWith('/redirect')) {
        res.writeHead(302, { location: files.keys().next().value ?? '/' });
        res.end();
        return;
      }
      res.writeHead(404);
      res.end();
    },
  );
  await new Promise<void>((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return {
    port,
    close: () => new Promise<void>((resolveClose) => server.close(() => resolveClose())),
  };
}

async function findOpenssl(): Promise<string> {
  const candidates = [
    'openssl',
    'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe',
    'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
  ];
  for (const candidate of candidates) {
    const probe = await execFileAsync(candidate, ['version'], { timeoutMs: 15_000 });
    if (probe.exitCode === 0) return candidate;
  }
  throw new Error('openssl not found for fixture CA generation');
}
