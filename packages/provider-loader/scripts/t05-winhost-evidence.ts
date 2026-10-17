// T05 #106 + R1 #145 F01–F04 delta — real Windows Build Host evidence run for
// trusted CLI activation with the corrected execution boundary.
//
// Executes the merged signed-provider chain (CuratedProviderVerifier →
// CuratedProviderStager → CuratedProviderPreflight → CuratedProviderActivator)
// on THIS host against the genuine ripgrep 14.1.1 MSVC release bytes, with a
// real HTTPS fixture origin, a real Ed25519 curator key provisioned by this
// trusted composition, and the invocation-scoped authorizeRunEffect port
// (real grant presentation validation + exact op/argv/roots binding, fresh at
// the last boundary) in front of every spawn.
//
//   HOST    host/OS/integrity/symlink-privilege facts
//   PREP    curator keys, HTTPS fixture origin, official ripgrep download
//   S/A/P   stage → preflight → activate positive (version + real search)
//   NEG     PATH substitution, offline, tamper, unsigned/forged/downgrade,
//           redirect (fixture + real github.com), corrupted download,
//           revocation epoch, policy/grant revocation, consent refusal,
//           TOCTOU mid-call denial, interrupted staging, entrypoint traversal
//   R1      F01 --pre inexpressible (zero descendants, marker absent),
//           F02 outside-root operand (zero access), F03 grant/invocation
//           binding mismatch (zero spawn), F04 staged-EXE byte swap +
//           junction/reparse canaries (zero spawn), F05 revocation flip at
//           the spawn seam (zero process invocations)
//   RST     fresh-subprocess restart re-verification (durable cache)
//   CANARY  user-owned files unchanged across the whole run
//   SHARP   separate native-addon ABI probe (@img/sharp-win32-x64 via npm SRI
//           anchor + isolated child dlopen) — honest PASS or BLOCKED; this is
//           an ABI probe, NOT production native activation, which stays
//           fail-closed (ACTIVATION_KIND_UNSUPPORTED)
//
// Usage:
//   NODE_EXTRA_CA_CERTS is set up automatically by a one-shot self re-exec.
//   node scripts/t05-winhost-evidence.ts [evidenceDir] [runtimeRoot]
//
// The run writes events.ndjson incrementally (crash-safe) plus summary.md and
// manifest.txt at the end. Heavy artifacts stay in the runtime root; the
// evidence directory receives sanitized logs only.

import { spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import {
  appendFile,
  copyFile,
  lstat,
  readdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import {
  homedir,
  arch as osArch,
  hostname as osHostname,
  release as osRelease,
  tmpdir,
} from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
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
  type TrustedProviderScope,
} from '@shun/vertical-jit';
import {
  type ActivationProcessOutcome,
  type ActivationRunSpec,
  BoundedSpawnProcess,
  CuratedProviderActivator,
  minimalWindowsSpawnEnvironment,
  type ResolvedInvocation,
  type RunEffectDecision,
  type TrustedActivationHost,
} from '../src/activation.ts';
import { CuratedProviderPreflight, type ProviderUseCurrentness } from '../src/preflight.ts';
import { CuratedProviderStager } from '../src/staging.ts';

// ---- run identity and paths ----

const SCRIPT_DIR = fileURLToPath(new URL('.', import.meta.url));
const PACKAGE_DIR = resolve(SCRIPT_DIR, '..');
const RUN_TAG = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
const EVIDENCE_DIR = resolve(
  process.argv[2] && !process.argv[2].startsWith('--')
    ? process.argv[2]
    : join(PACKAGE_DIR, 'evidence', `t05-winhost-${RUN_TAG}`),
);
// Every run gets a FRESH runtime root: leftover state from an earlier run
// (e.g. bytes a failed negative left tampered) must never leak into a new run.
const RUNTIME_ROOT = resolve(
  process.env.SHUN_T05_RUNTIME_ROOT ??
    (process.argv[3] && !process.argv[3].startsWith('--')
      ? process.argv[3]
      : join(tmpdir(), `shun-t05-winhost-${RUN_TAG}`)),
);
const RESTART_ARG = process.argv.indexOf('--t05-restart-child');

const RG_VERSION = '14.1.1';
const RG_URL = `https://github.com/BurntSushi/ripgrep/releases/download/${RG_VERSION}/ripgrep-${RG_VERSION}-x86_64-pc-windows-msvc.zip`;
const TASK_ID = 'task-t05-winhost';
const BINDING = 'rg-binding-winhost';
const EPOCH = { value: 1 };

// ---- sanitization (evidence must not leak user/host identity) ----

const SECRET_STRING: Array<[string, string]> = [];
function registerSecret(value: string, token: string): void {
  if (value && value.length > 3) SECRET_STRING.push([value, token]);
}
registerSecret(homedir(), '<HOME>');
registerSecret(tmpdir(), '<TMP>');
// NetBIOS output (whoami) can differ in case from os.hostname(); register all
// case variants so no machine-name form survives into the evidence.
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
  // Any remaining user-profile path shape is masked regardless of account.
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
    // A BLOCKED verdict is an honest "cannot obtain", never a product failure.
    const blocked = message.startsWith('BLOCKED:');
    if (!blocked) runFailed = true;
    results.push({ id, title, status: blocked ? 'BLOCKED' : 'FAIL', detail: message });
    await event('scenario.end', { id, status: blocked ? 'BLOCKED' : 'FAIL', error: message });
  }
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`ASSERT: ${message}`);
}

// ---- small async process helper (never spawnSync: the fixture server must stay live) ----

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

// ---- trusted-host composition ----

/** The invocation shape an AuthorizedAction binds, registered before staging. */
interface InvocationContract {
  readonly op: ResolvedInvocation['op'];
  readonly argv: readonly string[];
  /** Executable must land under this root; cwd/sandbox under sandboxRoot. */
  readonly execRoot: string;
  readonly sandboxRoot: string;
}

interface GrantRecord {
  plan: ActionPlan;
  action: unknown;
  grant: unknown;
  grantId: string;
  /** Revocation epoch the host policy was at when this grant was minted. */
  grantedEpoch: number;
  /** The exact invocation (op + argv + scope roots) this grant authorizes. */
  contract: InvocationContract;
}

interface World {
  authority: LocalAuthority;
  epoch: () => number;
  grants: Map<string, GrantRecord>;
}

const PINNED_SHA = new Map<string, string>();
const PROVIDER_OF = new Map<string, string>();
let authorityDetailLogged = false;

function currentnessPort(world: World) {
  return (taskId: string, bindingId: string): ProviderUseCurrentness => {
    const record = world.grants.get(bindingId);
    if (!record || record.plan.taskId !== taskId) return { kind: 'UNRESOLVABLE' };
    // Real grant presentation validation against the CURRENT substrate state
    // (synchronous by contract): HMAC integrity, policy status, revocation
    // lists, expiry, plan hash and action binding all re-checked in here, so
    // every authority move (revoke/corrupt/expire) shows up on the next read.
    const validation = world.authority.validatePresentation({
      grant: record.grant,
      plan: record.plan,
      action: record.action,
      now: new Date().toISOString(),
    });
    if (!validation.ok) {
      // Surface the authority's own refusal detail once: the evidence run must
      // show WHY the ActionController port is unhealthy, not just that it is.
      if (!authorityDetailLogged) {
        authorityDetailLogged = true;
        void event('authority.unhealthy', {
          code: validation.code,
          detail: validation.detail,
        }).catch(() => undefined);
      }
      return { kind: 'UNRESOLVABLE' };
    }
    const sha = PINNED_SHA.get(bindingId);
    if (!sha) return { kind: 'UNRESOLVABLE' };
    return {
      kind: 'CURRENT',
      taskId,
      providerId: PROVIDER_OF.get(bindingId) ?? 'rg',
      bindingId,
      catalogRevision: 'catalog-t05-winhost-r1',
      artifactSha256: sha,
      // The epoch recorded at grant time; the host policy epoch moves
      // independently and is compared against it by the activator.
      revocationEpoch: record.grantedEpoch,
      capability: 'PREPARE_PROVIDER',
    };
  };
}

function sameArgv(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

/**
 * THE execution authority (R1 #145 F03): the trusted composition's
 * invocation-scoped authorizeEffect port. It re-validates the full grant
 * presentation against the CURRENT substrate (real HMAC envelope, policy
 * status, revocation lists, expiry) AND binds the decision to THIS exact
 * invocation — op, argv, executable scope and sandbox scope — fresh at every
 * call. A PREPARE_PROVIDER currentness snapshot never reaches this decision.
 */
function effectPort(world: World) {
  return async (invocation: ResolvedInvocation): Promise<RunEffectDecision> => {
    const record = world.grants.get(invocation.bindingId);
    if (!record || record.plan.taskId !== invocation.taskId) {
      return { ok: false, code: 'AUTHORITY_STALE' };
    }
    const validation = world.authority.validatePresentation({
      grant: record.grant,
      plan: record.plan,
      action: record.action,
      now: new Date().toISOString(),
    });
    if (!validation.ok) {
      await event('effect.refused', {
        stage: 'grant-presentation',
        code: validation.code,
        op: invocation.op,
      }).catch(() => undefined);
      return { ok: false, code: 'AUTHORITY_STALE' };
    }
    // Revocation epoch must still be the granted one AT THIS INSTANT (F05).
    if (world.epoch() !== record.grantedEpoch) {
      await event('effect.refused', { stage: 'epoch', op: invocation.op }).catch(() => undefined);
      return { ok: false, code: 'AUTHORITY_STALE' };
    }
    // Exact invocation binding: the AuthorizedAction names this op and this
    // precise argv, and the paths stay inside the declared scope roots.
    const same = (a: readonly string[], b: readonly string[]) =>
      a.length === b.length && a.every((value, index) => value === b[index]);
    const under = (value: string, root: string) =>
      resolve(value).toLowerCase().startsWith(resolve(root).toLowerCase());
    const contract = record.contract;
    if (
      invocation.op !== contract.op ||
      !same(invocation.argv, contract.argv) ||
      !under(invocation.executablePath, contract.execRoot) ||
      !under(invocation.cwd, contract.sandboxRoot) ||
      !invocation.writeRoots.every((root) => under(root, contract.sandboxRoot)) ||
      !invocation.readRoots.every(
        (root) => under(root, contract.execRoot) || under(root, contract.sandboxRoot),
      )
    ) {
      await event('effect.refused', {
        stage: 'invocation-binding',
        op: invocation.op,
        expectedOp: contract.op,
      }).catch(() => undefined);
      return { ok: false, code: 'EFFECT_NOT_AUTHORIZED' };
    }
    const leaseId = randomUUID();
    await event('effect.authorized', {
      leaseId,
      op: invocation.op,
      argv: invocation.argv.map((arg) => sanitize(arg)),
    }).catch(() => undefined);
    return { ok: true, leaseId };
  };
}

function makeScope(
  extra: Partial<TrustedProviderScope> & { bindingId: string },
): TrustedProviderScope {
  return {
    providerId: 'rg',
    capabilityId: 'file.search',
    version: RG_VERSION,
    catalogRevision: 'catalog-t05-winhost-r1',
    scopedVerifierId: 'winhost-verifier',
    catalogManifestSha256: '5'.repeat(64),
    bindingEvidenceSha256: '6'.repeat(64),
    artifactSha256: PINNED_SHA.get(extra.bindingId) ?? '0'.repeat(64),
    origin: 'https://fixture.invalid/rg.exe',
    platform: 'windows-x64',
    artifactKind: 'CLI',
    ...extra,
  };
}

type KeyPair = ReturnType<typeof generateKeyPairSync>;

function signDescriptor(
  scope: TrustedProviderScope,
  privateKey: KeyPair['privateKey'],
  overrides: Record<string, unknown> = {},
) {
  const unsigned: Record<string, unknown> = {
    ...scope,
    entrypoint: scope.artifactKind === 'CLI' ? 'rg.exe' : 'sharp-win32-x64.node',
    signerKeyId: 'curator-winhost',
    dependencySha256: [],
    ...overrides,
  };
  return {
    ...unsigned,
    curatorSignature: sign(null, Buffer.from(canonicalJson(unsigned)), privateKey).toString(
      'base64',
    ),
  };
}

interface SpawnObserver {
  readonly specs: ActivationRunSpec[];
  readonly port: { run(spec: ActivationRunSpec): Promise<ActivationProcessOutcome> };
}

function observingSpawn(): SpawnObserver {
  const specs: ActivationRunSpec[] = [];
  const inner = new BoundedSpawnProcess();
  return {
    specs,
    port: {
      async run(spec: ActivationRunSpec): Promise<ActivationProcessOutcome> {
        specs.push(spec);
        return inner.run(spec);
      },
    },
  };
}

async function registerGrant(
  world: World,
  bindingId: string,
  contract: InvocationContract,
  outputDir: string,
): Promise<void> {
  const action: PlanAction = {
    actionId: `activate-${bindingId}`,
    bindingRef: bindingId,
    op: contract.op,
    // The action binds the EXACT typed operation this grant may ever execute:
    // full argv plus the executable/sandbox scope roots (R1 #145 F03).
    parameters: {
      argv: [...contract.argv],
      execRoot: contract.execRoot,
      sandboxRoot: contract.sandboxRoot,
    },
    sideEffectClass: 'R1',
    requiredPrivilege: 'USER',
    filesystemScope: { read: [contract.execRoot, contract.sandboxRoot], write: [outputDir] },
    timeoutMs: 60_000,
    cancellation: { supported: true, mode: 'COOPERATIVE' },
    expectedState: { outputWritten: true },
  };
  const planCore = {
    taskId: TASK_ID,
    capabilityId: 'file.search',
    bindingRefs: [bindingId],
    rankingPolicyRevision: 'rank-r1',
    policySnapshotRevision: 'pol-snap-r1',
    actions: [action],
    verificationPlan: {
      verifierId: 'winhost-verifier',
      verifierRevision: 'rev-1',
      checks: [{ checkId: 'rg-version-output' }],
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
    policySnapshotRevision: 'pol-snap-r1',
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
    policySnapshotRevision: 'pol-snap-r1',
    authorizationKind: 'DURABLE_POLICY',
    authorizationRef: grant.grantId,
    expiresAt: grant.expiresAt,
    action,
  });
  world.grants.set(bindingId, {
    plan,
    action: authorized,
    grant,
    grantId: grant.grantId,
    grantedEpoch: world.epoch(),
    contract,
  });
}

// ---- restart-child mode (fresh composition, durable cache, no network) ----

if (RESTART_ARG > -1) {
  const cfgPath = process.argv[RESTART_ARG + 1];
  const cfg = JSON.parse(await readFile(cfgPath, 'utf8')) as {
    cacheRoot: string;
    publicKeyPem: string;
    scopes: TrustedProviderScope[];
    descriptor: unknown;
    taskId: string;
    bindingId: string;
    digest: string;
  };
  const verifier = new CuratedProviderVerifier(
    [{ keyId: 'curator-winhost', publicKeyPem: cfg.publicKeyPem }],
    cfg.scopes,
  );
  const stager = new CuratedProviderStager({
    cacheRoot: cfg.cacheRoot,
    verifier,
    isOffline: () => true,
  });
  // The restart child recomposes the invocation-scoped effect gate itself: a
  // VERSION_PROBE under the trusted cache root is the only shape it accepts.
  const versionProbeEffect = async (invocation: ResolvedInvocation): Promise<RunEffectDecision> => {
    const under = (value: string, root: string) =>
      resolve(value).toLowerCase().startsWith(resolve(root).toLowerCase());
    const activeRoot = join(cfg.cacheRoot, 'active', cfg.bindingId, cfg.digest);
    if (
      invocation.op === 'provider.version.probe' &&
      invocation.taskId === cfg.taskId &&
      invocation.bindingId === cfg.bindingId &&
      invocation.artifactSha256 === cfg.digest &&
      sameArgv(invocation.argv, ['--version']) &&
      under(invocation.executablePath, join(activeRoot, 'exec')) &&
      under(invocation.cwd, join(activeRoot, 'sandbox')) &&
      invocation.writeRoots.every((root) => under(root, join(activeRoot, 'sandbox'))) &&
      invocation.readRoots.every(
        (root) => under(root, join(activeRoot, 'exec')) || under(root, join(activeRoot, 'sandbox')),
      )
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
      providerId: 'rg',
      bindingId: cfg.bindingId,
      catalogRevision: 'catalog-t05-winhost-r1',
      artifactSha256: cfg.digest,
      revocationEpoch: 1,
      capability: 'PREPARE_PROVIDER',
    }),
    authorizeRunEffect: versionProbeEffect,
    requiredRevocationEpoch: () => 1,
    hostPlatform: () => process.platform,
    hostArchitecture: () => process.arch,
    hostNodeAbi: () => process.versions.modules,
    hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
  };
  const observer = observingSpawn();
  const activator = new CuratedProviderActivator({ ...host, process: observer.port });
  const result = await activator.runCli({
    taskId: cfg.taskId,
    descriptor: cfg.descriptor,
    run: { kind: 'VERSION_PROBE' },
  });
  const spec = observer.specs.at(0);
  const payload = {
    ok: result.ok,
    exitCode: result.ok ? result.exitCode : -1,
    versionLine: result.ok ? (result.stdout.split('\n').at(0) ?? '') : '',
    executableUnderCache: spec ? spec.executable.startsWith(resolve(cfg.cacheRoot)) : false,
    envKeys: spec ? Object.keys(spec.env).sort() : [],
    refuseCode: result.ok ? '' : result.code,
  };
  process.stdout.write(`RESTART_CHILD_RESULT ${JSON.stringify(payload)}\n`);
  process.exitCode = payload.ok && payload.executableUnderCache ? 0 : 1;
} else {
  await mainRun().catch(async (error) => {
    const message = sanitize(
      error instanceof Error ? `${error.message}\n${error.stack ?? ''}` : String(error),
    );
    await event('run.crash', { error: message.slice(0, 2000) }).catch(() => undefined);
    process.exitCode = 2;
  });
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
        'req',
        '-x509',
        '-newkey',
        'ed25519',
        '-keyout',
        caKey,
        '-out',
        caPem,
        '-days',
        '2',
        '-nodes',
        '-subj',
        '//CN=t05-fixture',
        '-addext',
        'subjectAltName=IP:127.0.0.1,DNS:localhost',
      ],
      { timeoutMs: 30_000 },
    );
    if (!existsSync(caPem))
      throw new Error(`openssl cert generation failed: ${gen.stderr.slice(0, 300)}`);
    const child = spawn(
      process.execPath,
      [fileURLToPath(import.meta.url), ...process.argv.slice(2)],
      {
        env: {
          ...process.env,
          NODE_EXTRA_CA_CERTS: caPem,
          SHUN_T05_RUNTIME_ROOT: RUNTIME_ROOT,
        },
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
    task: 'T05 #106 real Windows Build Host — trusted ripgrep CLI activation',
    baseline: 'version/v0.2.0@5e0bb2ba4b0f3409247e0f300950b84381d32661',
    evidenceDir: EVIDENCE_DIR,
    rgVersion: RG_VERSION,
    rgUrl: RG_URL,
    node: process.version,
    modulesAbi: process.versions.modules,
  });

  // Canary files (user-owned locations; content must never change).
  const canaryDir = join(tmpdir(), 'shun-t05-canary');
  mkdirSync(canaryDir, { recursive: true, mode: 0o700 });
  const canaryTemp = join(canaryDir, 'user-canary-temp.txt');
  const canaryHome = join(homedir(), 'shun-t05-canary-home.txt');
  const canaryCwd = join(process.cwd(), 't05-canary-cwd.tmp');
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
    // Absolute System32 path: a Git-Bash coreutils `whoami` shadows the
    // Windows one on PATH and does not understand /groups.
    const whoExe = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'whoami.exe');
    const who = await execFileAsync(whoExe, [], { timeoutMs: 15_000 });
    const groups = await execFileAsync(whoExe, ['/groups'], { timeoutMs: 15_000 });
    // Integrity level is matched by its stable SID (S-1-16-xxxxx), not by an
    // English label: localized Windows output does not say "Mandatory". The
    // whoami console output is GBK-encoded on this host — keep ASCII only.
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

  // Provision curator key + acquire genuine ripgrep release.
  const curator = generateKeyPairSync('ed25519');
  const attacker = generateKeyPairSync('ed25519');
  const publicKeyPem = curator.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const authority = new LocalAuthority({
    authorityId: 't05-winhost-authority',
    policySnapshotRevision: 'pol-snap-r1',
    grantTtlMs: 60 * 60_000,
    hmacKey: 't05-winhost-issuance-key',
  });

  const originDir = join(RUNTIME_ROOT, 'origin');
  const rgExePath = join(originDir, 'rg.exe');
  let zipSha = '';
  await scenario('PREP', 'download official ripgrep release and pin exact bytes', async () => {
    mkdirSync(originDir, { recursive: true, mode: 0o700 });
    const zipPath = join(RUNTIME_ROOT, 'ripgrep.zip');
    // The public internet flaked during earlier runs; alternate direct and
    // local-proxy attempts and require curl to actually succeed.
    const attempts: string[] = [];
    let downloaded = false;
    for (let attempt = 1; attempt <= 4 && !downloaded; attempt += 1) {
      const viaProxy = attempt % 2 === 0;
      const result = await execFileAsync(
        'curl',
        [
          '-sS',
          '-L',
          '--max-time',
          '120',
          ...(viaProxy ? ['-x', 'http://127.0.0.1:10808'] : []),
          '-o',
          zipPath,
          RG_URL,
        ],
        { timeoutMs: 150_000 },
      );
      const size = existsSync(zipPath) ? (await lstat(zipPath)).size : 0;
      downloaded = result.exitCode === 0 && size > 1024;
      attempts.push(
        `attempt${attempt}${viaProxy ? '(proxy)' : '(direct)'}:exit=${result.exitCode},bytes=${size}`,
      );
      if (!downloaded) {
        await event('prep.download.retry', {
          attempt,
          viaProxy,
          exitCode: result.exitCode,
          bytes: size,
        });
        await rm(zipPath, { force: true });
        await new Promise((pause) => setTimeout(pause, 3_000));
      }
    }
    assert(downloaded, `ripgrep zip download failed: ${attempts.join('; ')}`);
    await event('prep.download', { attempts });
    zipSha = await sha256File(zipPath);
    const tar = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe');
    const extractDir = join(RUNTIME_ROOT, 'extract');
    await rm(extractDir, { recursive: true, force: true });
    mkdirSync(extractDir, { recursive: true });
    const untar = await execFileAsync(tar, ['-xf', zipPath, '-C', extractDir], {
      timeoutMs: 60_000,
    });
    assert(untar.exitCode === 0, `bsdtar extract failed: ${untar.stderr.slice(0, 200)}`);
    const extracted = (await walkFiles(extractDir)).find((p) => basename(p) === 'rg.exe');
    assert(extracted, 'rg.exe not found in release zip');
    await rm(rgExePath, { force: true });
    await copyFile(extracted, rgExePath);
    const rgSha = await sha256File(rgExePath);
    PINNED_SHA.set(BINDING, rgSha);
    const contents = await walkFiles(extractDir);
    await event('prep.ripgrep', {
      url: RG_URL,
      zipSha256: zipSha,
      rgExeSha256: rgSha,
      rgExeBytes: (await lstat(rgExePath)).size,
      zipContents: contents.map((p) => basename(p)).sort(),
      dllFiles: contents.filter((p) => p.toLowerCase().endsWith('.dll')).length,
    });
    // Optional independent anchor: winget manifest InstallerSha256 (best effort).
    const wingetShow = await execFileAsync(
      'winget',
      ['show', '--id', 'BurntSushi.ripgrep.MSVC', '--exact'],
      { timeoutMs: 60_000 },
    );
    const hashLine =
      wingetShow.stdout.split('\n').find((line) => /installer hash/i.test(line)) ?? '';
    const wingetHash = /([a-f0-9]{64})/i.exec(hashLine)?.[1]?.toLowerCase() ?? '';
    await event('prep.wingetAnchor', {
      available: wingetHash !== '',
      matchesZip: wingetHash === zipSha,
      note: 'informational anchor only; trust anchor is the curator signature over the pinned digest',
    });
    return `zip=${zipSha.slice(0, 16)}… rg.exe=${rgSha.slice(0, 16)}… bytes=${(await lstat(rgExePath)).size} wingetAnchor=${wingetHash === zipSha ? 'MATCH' : wingetHash ? 'MISMATCH' : 'UNAVAILABLE'}`;
  });

  // Start the HTTPS fixture origin.
  const fixture = await startFixtureOrigin(rgExePath, caKey, caPem);
  try {
    await event('fixture.origin', {
      origin: `https://127.0.0.1:${fixture.port}`,
      endpoints: ['/rg.exe', '/rg-corrupt.exe', '/redirect', '/hang'],
    });

    // Pin all scopes and build verifier + authority world.
    for (const bindingId of [
      'rg-binding-redirect',
      'rg-binding-corrupt',
      'rg-binding-hang',
      'rg-binding-github',
    ]) {
      PINNED_SHA.set(bindingId, PINNED_SHA.get(BINDING) ?? '');
    }
    const scopes: TrustedProviderScope[] = [
      makeScope({ bindingId: BINDING, origin: `https://127.0.0.1:${fixture.port}/rg.exe` }),
      makeScope({
        bindingId: 'rg-binding-redirect',
        origin: `https://127.0.0.1:${fixture.port}/redirect`,
      }),
      makeScope({
        bindingId: 'rg-binding-corrupt',
        origin: `https://127.0.0.1:${fixture.port}/rg-corrupt.exe`,
      }),
      makeScope({ bindingId: 'rg-binding-hang', origin: `https://127.0.0.1:${fixture.port}/hang` }),
      makeScope({ bindingId: 'rg-binding-github', origin: RG_URL }),
    ];
    const verifier = new CuratedProviderVerifier(
      [{ keyId: 'curator-winhost', publicKeyPem }],
      scopes,
    );
    const world: World = { authority, epoch: () => EPOCH.value, grants: new Map() };

    const cacheRoot = join(RUNTIME_ROOT, 'cache');
    const outputDir = join(RUNTIME_ROOT, 'outputs');
    mkdirSync(cacheRoot, { recursive: true, mode: 0o700 });
    mkdirSync(outputDir, { recursive: true, mode: 0o700 });
    const descriptor = signDescriptor(scopes[0], curator.privateKey);
    const stager = new CuratedProviderStager({ cacheRoot, verifier, isOffline: () => false });
    const mainObserver = observingSpawn();

    function activationHost(
      observer: SpawnObserver,
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
        hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
        process: observer.port,
        ...overrides,
      };
    }
    const activator = new CuratedProviderActivator(activationHost(mainObserver));
    // The grant binds the invocation CONTRACT (op + exact argv + scope
    // roots), not a pre-known random per-run path: every run materializes a
    // fresh exec/<uuid>/rg.exe and sandbox/<uuid>/ under these roots.
    const activeRoot = join(cacheRoot, 'active', BINDING, PINNED_SHA.get(BINDING) ?? '');
    const versionContract: InvocationContract = {
      op: 'provider.version.probe',
      argv: ['--version'],
      execRoot: join(activeRoot, 'exec'),
      sandboxRoot: join(activeRoot, 'sandbox'),
    };
    const searchContract: InvocationContract = {
      op: 'provider.ripgrep.file-search',
      argv: ['-n', '--no-heading', '-e', 'needle', '--', 'corpus.txt'],
      execRoot: join(activeRoot, 'exec'),
      sandboxRoot: join(activeRoot, 'sandbox'),
    };
    await registerGrant(world, BINDING, versionContract, outputDir);

    // S: stage the genuine bytes through the production stager (real fetch).
    await scenario(
      'STAGE',
      'production stager fetches fixture origin and pins digest',
      async () => {
        const staged = await stager.stage(descriptor);
        assert(staged.ok, `stage refused: ${JSON.stringify(staged)}`);
        assert(
          staged.digest === PINNED_SHA.get(BINDING),
          'staged digest must equal pinned rg.exe sha256',
        );
        await event('stage.ok', {
          digest: staged.digest,
          byteLength: staged.byteLength,
          state: staged.state,
        });
        return `digest=${staged.digest.slice(0, 16)}… bytes=${staged.byteLength}`;
      },
    );

    // P: preflight on the real composition.
    await scenario(
      'PREFLIGHT',
      'merged CuratedProviderPreflight admits the staged artifact',
      async () => {
        const probingPort = (taskId: string, bindingId: string): ProviderUseCurrentness => {
          const snapshot = currentnessPort(world)(taskId, bindingId);
          void event('port.snapshot', {
            taskId,
            bindingId,
            snapshot: JSON.stringify(snapshot),
            pinnedSha: PINNED_SHA.get(bindingId) ?? 'MISSING',
            grantRecorded: world.grants.has(bindingId),
          }).catch(() => undefined);
          return snapshot;
        };
        const preflight = new CuratedProviderPreflight({
          verifier,
          stager,
          getAuthorizedCurrentness: probingPort,
          requiredRevocationEpoch: () => EPOCH.value,
          hostPlatform: () => process.platform,
          hostArchitecture: () => process.arch,
          hostNodeAbi: () => process.versions.modules,
        });
        const check = await preflight.check({ taskId: TASK_ID, descriptor });
        assert(check.ok, `preflight refused: ${JSON.stringify(check)}`);
        assert(check.state === 'PREFLIGHT_ONLY', 'preflight must stay non-executing');
        return `state=${check.state} digest=${check.digest.slice(0, 16)}…`;
      },
    );

    // A1: activation runs rg --version (real spawn, scrubbed env).
    await scenario('ACTIVATE-VERSION', 'activation executes pinned rg.exe --version', async () => {
      await registerGrant(world, BINDING, versionContract, outputDir);
      const result = await activator.runCli({
        taskId: TASK_ID,
        descriptor,
        run: { kind: 'VERSION_PROBE' },
      });
      assert(result.ok, `activation refused: ${JSON.stringify(result)}`);
      assert(
        result.exitCode === 0,
        `rg --version exit ${result.exitCode}: ${result.stderr.slice(0, 200)}`,
      );
      assert(
        /ripgrep \d+\.\d+\.\d+/.test(result.stdout),
        `unexpected version output: ${result.stdout.slice(0, 120)}`,
      );
      const spec = mainObserver.specs.at(-1);
      assert(spec, 'spawn was not observed');
      assert(
        spec.executable.toLowerCase().startsWith(resolve(cacheRoot).toLowerCase()),
        'executable must live under the trusted cache root',
      );
      assert(
        Object.keys(spec.env).every((key) => ['SystemRoot', 'SystemDrive'].includes(key)),
        'child env must be the minimal scrubbed allowlist',
      );
      await event('activate.version', {
        stdoutFirstLine: result.stdout.split('\n').at(0)?.trim() ?? '',
        executable: sanitize(spec.executable),
        envKeys: Object.keys(spec.env).sort(),
        durationMs: result.durationMs,
      });
      return `stdout="${result.stdout.split('\n').at(0)?.trim()}" exit=${result.exitCode}`;
    });

    // A2: activation runs a real search over seeded sandbox inputs. The
    // effect gate binds THIS exact search argv; the grant for it is minted
    // separately from the --version grant (never interchangeable).
    await scenario(
      'ACTIVATE-SEARCH',
      'activation runs a real ripgrep search in its sandbox',
      async () => {
        await registerGrant(world, BINDING, searchContract, outputDir);
        const corpus = ['hay line one', 'the needle is here', 'hay line three'];
        const result = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: {
            kind: 'FILE_SEARCH',
            pattern: 'needle',
            operands: ['corpus.txt'],
            lineNumbers: true,
          },
          sandboxFiles: [
            { name: 'corpus.txt', bytes: Buffer.from(`${corpus.join('\n')}\n`, 'utf8') },
          ],
        });
        assert(result.ok, `activation refused: ${JSON.stringify(result)}`);
        assert(
          result.exitCode === 0,
          `rg search exit ${result.exitCode}: ${result.stderr.slice(0, 200)}`,
        );
        assert(
          /(^|\n)2:the needle is here/.test(result.stdout),
          `unexpected search output: ${result.stdout.slice(0, 200)}`,
        );
        await event('activate.search', { stdout: result.stdout.trim(), exitCode: result.exitCode });
        // Restore the version grant for the following scenarios.
        await registerGrant(world, BINDING, versionContract, outputDir);
        return `match="${result.stdout.trim().slice(0, 80)}" exit=0`;
      },
    );

    // A3: hostile PATH cannot substitute the provider.
    await scenario(
      'NEG-PATH-SUBSTITUTION',
      'hostile PATH entry cannot substitute the pinned provider',
      async () => {
        const fakeDir = join(RUNTIME_ROOT, 'path-ambush');
        mkdirSync(fakeDir, { recursive: true, mode: 0o700 });
        const cmd = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'cmd.exe');
        await copyFile(cmd, join(fakeDir, 'rg.exe'));
        const originalPath = process.env.PATH ?? '';
        process.env.PATH = `${fakeDir};${originalPath}`;
        try {
          const result = await activator.runCli({
            taskId: TASK_ID,
            descriptor,
            run: { kind: 'VERSION_PROBE' },
          });
          assert(result.ok, `activation refused under hostile PATH: ${JSON.stringify(result)}`);
          assert(
            /ripgrep \d+\.\d+\.\d+/.test(result.stdout),
            'executed binary was NOT the pinned ripgrep',
          );
          const spec = mainObserver.specs.at(-1);
          assert(
            spec && !spec.executable.startsWith(fakeDir),
            'spawn resolved the ambush directory',
          );
        } finally {
          process.env.PATH = originalPath;
        }
        return 'pinned cache executable won; ambush rg.exe never spawned';
      },
    );

    // A4: offline cache replay — zero fetch, still executes.
    let offlineFetches = 0;
    await scenario(
      'OFFLINE-REPLAY',
      'offline cache replay: 0 downloads, activation still works',
      async () => {
        const countingFetch: typeof fetch = ((
          input: Parameters<typeof fetch>[0],
          init?: Parameters<typeof fetch>[1],
        ) => {
          offlineFetches += 1;
          return fetch(input, init);
        }) as typeof fetch;
        const offlineStager = new CuratedProviderStager({
          cacheRoot,
          verifier,
          isOffline: () => true,
          fetchArtifact: countingFetch,
        });
        const restaged = await offlineStager.stage(descriptor);
        assert(restaged.ok, `offline cache replay refused: ${JSON.stringify(restaged)}`);
        assert(offlineFetches === 0, `offline replay performed ${offlineFetches} downloads`);
        const result = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(result.ok && offlineFetches === 0, 'activation must not fetch');
        return `cache replay ok, downloads=0, exit=${result.ok ? result.exitCode : -1}`;
      },
    );

    // A5: offline with an empty cache fails closed.
    await scenario(
      'NEG-OFFLINE-EMPTY',
      'offline + empty cache refuses closed (no download attempt)',
      async () => {
        const emptyRoot = join(RUNTIME_ROOT, 'cache-offline-empty');
        mkdirSync(emptyRoot, { recursive: true, mode: 0o700 });
        let fetches = 0;
        const offlineStager = new CuratedProviderStager({
          cacheRoot: emptyRoot,
          verifier,
          isOffline: () => true,
          fetchArtifact: (() => {
            fetches += 1;
            return Promise.reject(new Error('network must not be touched'));
          }) as typeof fetch,
        });
        const staged = await offlineStager.stage(descriptor);
        assert(
          !staged.ok && staged.code === 'OFFLINE',
          `expected OFFLINE, got ${JSON.stringify(staged)}`,
        );
        const offlineObserver = observingSpawn();
        const offlineActivator = new CuratedProviderActivator(
          activationHost(offlineObserver, { stager: offlineStager }),
        );
        const refused = await offlineActivator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(
          !refused.ok && refused.code === 'ARTIFACT_NOT_VERIFIED',
          `expected ARTIFACT_NOT_VERIFIED, got ${JSON.stringify(refused)}`,
        );
        assert(
          offlineObserver.specs.length === 0 && fetches === 0,
          'refusal must be zero-spawn zero-fetch',
        );
        return 'OFFLINE at stage; ARTIFACT_NOT_VERIFIED at activation; 0 spawns 0 fetches';
      },
    );

    // RST: fresh subprocess re-composes everything from the durable cache.
    await scenario(
      'RESTART',
      'fresh subprocess re-verifies from durable cache and executes',
      async () => {
        const cfgPath = join(RUNTIME_ROOT, 'restart-cfg.json');
        await writeFile(
          cfgPath,
          JSON.stringify({
            cacheRoot,
            publicKeyPem,
            scopes,
            descriptor,
            taskId: TASK_ID,
            bindingId: BINDING,
            digest: PINNED_SHA.get(BINDING),
          }),
          'utf8',
        );
        const child = await execFileAsync(
          process.execPath,
          [fileURLToPath(import.meta.url), '--t05-restart-child', cfgPath],
          { timeoutMs: 90_000, env: { ...minimalWindowsSpawnEnvironment() } },
        );
        const line =
          child.stdout.split('\n').find((entry) => entry.startsWith('RESTART_CHILD_RESULT ')) ?? '';
        assert(line !== '', `restart child produced no result: ${child.stderr.slice(0, 300)}`);
        const payload = JSON.parse(line.slice('RESTART_CHILD_RESULT '.length)) as {
          ok: boolean;
          exitCode: number;
          versionLine: string;
          executableUnderCache: boolean;
          envKeys: string[];
        };
        await event('restart.child', {
          ...payload,
          versionLine: sanitize(payload.versionLine ?? ''),
        });
        assert(payload.ok && payload.exitCode === 0, 'restart child activation failed');
        assert(
          /ripgrep \d+\.\d+\.\d+/.test(payload.versionLine ?? ''),
          'restart child did not run real ripgrep',
        );
        assert(payload.executableUnderCache, 'restart child executed outside the cache root');
        assert(
          (payload.envKeys ?? []).every((key) => ['SystemRoot', 'SystemDrive'].includes(key)),
          'restart child env not scrubbed',
        );
        return `fresh process: ${payload.versionLine?.trim()} env=[${payload.envKeys?.join(',')}]`;
      },
    );

    // N1: tampered cache bytes.
    await scenario(
      'NEG-TAMPER-CACHE',
      'tampered cached bytes refuse closed, recovery after restore',
      async () => {
        const artifactPath = join(cacheRoot, 'artifacts', PINNED_SHA.get(BINDING) ?? '');
        const original = await readFile(artifactPath);
        const tampered = Buffer.from(original);
        tampered[0x40] ^= 0xff;
        // Restore in a finally: a failed negative must never leave tampered
        // bytes behind for later scenarios (or later runs) to trip over.
        try {
          await writeFile(artifactPath, tampered);
          const refused = await activator.runCli({
            taskId: TASK_ID,
            descriptor,
            run: { kind: 'VERSION_PROBE' },
          });
          assert(
            !refused.ok && refused.code === 'ARTIFACT_NOT_VERIFIED',
            `expected ARTIFACT_NOT_VERIFIED, got ${JSON.stringify(refused)}`,
          );
        } finally {
          await writeFile(artifactPath, original);
        }
        const recovered = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(recovered.ok, `recovery after restore failed: ${JSON.stringify(recovered)}`);
        return 'tampered→ARTIFACT_NOT_VERIFIED zero spawn; restored→EXECUTED';
      },
    );

    // N2: unsigned / forged / downgrade catalog presentations.
    await scenario(
      'NEG-CATALOG',
      'unsigned, forged-key and downgrade descriptors refuse before exec',
      async () => {
        const spawnsBefore = mainObserver.specs.length;
        const unsigned = { ...descriptor, curatorSignature: 'AAA'.repeat(29) };
        const unsignedResult = await activator.runCli({
          taskId: TASK_ID,
          descriptor: unsigned,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(!unsignedResult.ok, 'unsigned descriptor must refuse');
        const forged = signDescriptor(scopes[0], attacker.privateKey);
        const forgedResult = await activator.runCli({
          taskId: TASK_ID,
          descriptor: forged,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(!forgedResult.ok, 'forged-key descriptor must refuse');
        const downgrade = signDescriptor(scopes[0], curator.privateKey, { version: '14.1.0' });
        const downgradeResult = await activator.runCli({
          taskId: TASK_ID,
          descriptor: downgrade,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(
          !downgradeResult.ok && downgradeResult.code === 'CATALOG_SCOPE_DRIFT',
          `downgrade must SCOPE_DRIFT, got ${JSON.stringify(downgradeResult)}`,
        );
        assert(mainObserver.specs.length === spawnsBefore, 'refusals must be zero-spawn');
        await event('neg.catalog', {
          unsigned: unsignedResult.ok ? '' : unsignedResult.code,
          forged: forgedResult.ok ? '' : forgedResult.code,
          downgrade: downgradeResult.ok ? '' : downgradeResult.code,
        });
        return `unsigned=${unsignedResult.code ?? ''} forged=${forgedResult.code ?? ''} downgrade=CATALOG_SCOPE_DRIFT spawns=0`;
      },
    );

    // N3: redirect refusals — fixture 302 and the REAL github.com release URL.
    await scenario(
      'NEG-REDIRECT',
      'redirect origins refuse: fixture 302 and real github.com 302',
      async () => {
        const redirectDescriptor = signDescriptor(scopes[1], curator.privateKey);
        const redirectCache = join(RUNTIME_ROOT, 'cache-redirect');
        mkdirSync(redirectCache, { recursive: true, mode: 0o700 });
        const redirectStager = new CuratedProviderStager({
          cacheRoot: redirectCache,
          verifier,
          isOffline: () => false,
        });
        const staged = await redirectStager.stage(redirectDescriptor);
        assert(
          !staged.ok && staged.code === 'REDIRECT_REFUSED',
          `fixture redirect must refuse, got ${JSON.stringify(staged)}`,
        );
        const githubDescriptor = signDescriptor(scopes[4], curator.privateKey);
        const githubCache = join(RUNTIME_ROOT, 'cache-github');
        mkdirSync(githubCache, { recursive: true, mode: 0o700 });
        const githubStager = new CuratedProviderStager({
          cacheRoot: githubCache,
          verifier,
          isOffline: () => false,
        });
        // The real github.com fetch travels the public internet; a transient
        // network failure must read as SKIPPED-network, never as a pass/fail
        // of the redirect refusal itself. Retry a few times, honestly.
        let githubStaged: Awaited<ReturnType<typeof githubStager.stage>> | null = null;
        for (let attempt = 1; attempt <= 3; attempt += 1) {
          githubStaged = await githubStager.stage(githubDescriptor);
          if (githubStaged.ok || githubStaged.code !== 'SOURCE_UNAVAILABLE') break;
          await event('neg.redirect.githubRetry', { attempt, code: githubStaged.code });
          await new Promise((pause) => setTimeout(pause, 2_000));
        }
        if (githubStaged && !githubStaged.ok && githubStaged.code === 'SOURCE_UNAVAILABLE') {
          await event('neg.redirect', {
            fixture: 'REDIRECT_REFUSED',
            github: 'SKIPPED_SOURCE_UNAVAILABLE',
            url: RG_URL,
          });
          return 'fixture 302 → REDIRECT_REFUSED; github.com unreachable from this network this run (skipped, not failed)';
        }
        assert(
          !!githubStaged && !githubStaged.ok && githubStaged.code === 'REDIRECT_REFUSED',
          `github redirect must refuse, got ${JSON.stringify(githubStaged)}`,
        );
        await event('neg.redirect', {
          fixture: 'REDIRECT_REFUSED',
          github: 'REDIRECT_REFUSED',
          url: RG_URL,
        });
        return 'fixture 302 → REDIRECT_REFUSED; real github.com release 302 → REDIRECT_REFUSED';
      },
    );

    // N4: corrupted download never lands in the cache.
    await scenario(
      'NEG-CORRUPT-DOWNLOAD',
      'corrupted bytes over the wire refuse with hash mismatch',
      async () => {
        const corruptDescriptor = signDescriptor(scopes[2], curator.privateKey);
        const corruptCache = join(RUNTIME_ROOT, 'cache-corrupt');
        mkdirSync(corruptCache, { recursive: true, mode: 0o700 });
        const corruptStager = new CuratedProviderStager({
          cacheRoot: corruptCache,
          verifier,
          isOffline: () => false,
        });
        const staged = await corruptStager.stage(corruptDescriptor);
        assert(
          !staged.ok && staged.code === 'ARTIFACT_HASH_MISMATCH',
          `corrupt download must mismatch, got ${JSON.stringify(staged)}`,
        );
        const cached = await walkFiles(join(corruptCache, 'artifacts'));
        assert(cached.length === 0, 'corrupt bytes must not be cached');
        // A live grant for this binding so the activation refusal below comes
        // from the missing verified bytes, not from a missing authorization.
        const corruptRoot = join(
          corruptCache,
          'active',
          'rg-binding-corrupt',
          PINNED_SHA.get('rg-binding-corrupt') ?? '',
        );
        await registerGrant(
          world,
          'rg-binding-corrupt',
          {
            op: 'provider.version.probe',
            argv: ['--version'],
            execRoot: join(corruptRoot, 'exec'),
            sandboxRoot: join(corruptRoot, 'sandbox'),
          },
          outputDir,
        );
        const corruptObserver = observingSpawn();
        const corruptActivator = new CuratedProviderActivator(
          activationHost(corruptObserver, { stager: corruptStager }),
        );
        const refused = await corruptActivator.runCli({
          taskId: TASK_ID,
          descriptor: corruptDescriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(
          !refused.ok && refused.code === 'ARTIFACT_NOT_VERIFIED',
          `expected ARTIFACT_NOT_VERIFIED, got ${JSON.stringify(refused)}`,
        );
        assert(corruptObserver.specs.length === 0, 'must be zero-spawn');
        return 'ARTIFACT_HASH_MISMATCH, cache stays empty, activation zero-spawn';
      },
    );

    // N5: revocation epoch bump.
    await scenario(
      'NEG-REVOCATION-EPOCH',
      'host revocation-epoch bump voids activation before exec',
      async () => {
        EPOCH.value = 2;
        try {
          const refused = await activator.runCli({
            taskId: TASK_ID,
            descriptor,
            run: { kind: 'VERSION_PROBE' },
          });
          assert(
            !refused.ok && refused.code === 'AUTHORITY_STALE',
            `expected AUTHORITY_STALE, got ${JSON.stringify(refused)}`,
          );
        } finally {
          EPOCH.value = 1;
        }
        const recovered = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(recovered.ok, 'activation must recover once the epoch matches again');
        return 'epoch 1→2 → AUTHORITY_STALE zero spawn; restored → EXECUTED';
      },
    );

    // N6: real authority policy revocation (LocalAuthority state move).
    await scenario(
      'NEG-POLICY-REVOKED',
      'revoked authorization policy voids activation (real grant substrate)',
      async () => {
        const spawnsBefore = mainObserver.specs.length;
        authority.revokePolicy();
        const refused = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(
          !refused.ok && refused.code === 'AUTHORITY_STALE',
          `expected AUTHORITY_STALE, got ${JSON.stringify(refused)}`,
        );
        assert(mainObserver.specs.length === spawnsBefore, 'policy revocation must be zero-spawn');
        return 'revokePolicy() → AUTHORITY_STALE zero spawn';
      },
    );

    // N7: consent refused (unresolvable currentness).
    await scenario(
      'NEG-CONSENT-REFUSED',
      'unresolvable currentness refuses activation (consent denied)',
      async () => {
        authority.corruptCurrentness('operator refused consent for provider activation');
        const refused = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(
          !refused.ok && refused.code === 'AUTHORITY_STALE',
          `expected AUTHORITY_STALE, got ${JSON.stringify(refused)}`,
        );
        return 'corruptCurrentness(consent refused) → AUTHORITY_STALE zero spawn';
      },
    );

    // N8: grant revoked while policy healthy again (fresh authority + fresh grant).
    await scenario(
      'NEG-GRANT-REVOKED',
      'revoked grant refuses activation; fresh grant restores it',
      async () => {
        const freshAuthority = new LocalAuthority({
          authorityId: 't05-winhost-authority',
          policySnapshotRevision: 'pol-snap-r1',
          grantTtlMs: 60 * 60_000,
          hmacKey: 't05-winhost-issuance-key',
        });
        world.authority = freshAuthority;
        await registerGrant(world, BINDING, versionContract, outputDir);
        const record = world.grants.get(BINDING);
        assert(record, 'grant registration failed');
        freshAuthority.revokeGrant(record.grantId);
        const refused = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(
          !refused.ok && refused.code === 'AUTHORITY_STALE',
          `revoked grant must refuse, got ${JSON.stringify(refused)}`,
        );
        await registerGrant(world, BINDING, versionContract, outputDir);
        const recovered = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(recovered.ok, 'fresh grant must restore activation');
        return 'revokeGrant → AUTHORITY_STALE zero spawn; re-issue → EXECUTED';
      },
    );

    // N9: TOCTOU — the ActionController port is read twice; a mid-call denial voids exec.
    await scenario(
      'NEG-TOCTOU',
      'ActionController denial between admission and exec voids activation',
      async () => {
        let reads = 0;
        const toctouObserver = observingSpawn();
        const toctouActivator = new CuratedProviderActivator(
          activationHost(toctouObserver, {
            getAuthorizedCurrentness: (taskId, bindingId) => {
              reads += 1;
              if (reads >= 2) return { kind: 'UNRESOLVABLE' };
              return currentnessPort(world)(taskId, bindingId);
            },
          }),
        );
        const refused = await toctouActivator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(
          !refused.ok && refused.code === 'AUTHORITY_STALE',
          `TOCTOU denial must refuse, got ${JSON.stringify(refused)}`,
        );
        assert(toctouObserver.specs.length === 0, 'TOCTOU refusal must be zero-spawn');
        assert(reads >= 2, 'the second pre-exec read never happened');
        return `reads=${reads} (admission + immediately-before-exec), second denial → zero spawn`;
      },
    );

    // N10: interrupted staging over the wire (socket destroyed mid-response).
    await scenario(
      'NEG-INTERRUPT',
      'interrupted staging (socket destroyed) fails closed and recovers',
      async () => {
        const hangDescriptor = signDescriptor(scopes[3], curator.privateKey);
        const hangCache = join(RUNTIME_ROOT, 'cache-hang');
        mkdirSync(hangCache, { recursive: true, mode: 0o700 });
        const hangStager = new CuratedProviderStager({
          cacheRoot: hangCache,
          verifier,
          isOffline: () => false,
        });
        const staged = await hangStager.stage(hangDescriptor);
        assert(
          !staged.ok && staged.code === 'SOURCE_UNAVAILABLE',
          `interrupted stage must fail closed, got ${JSON.stringify(staged)}`,
        );
        const cached = (await walkFiles(join(hangCache, 'artifacts'))).filter(
          (p) => !p.endsWith('.partial'),
        );
        assert(cached.length === 0, 'interrupted staging must not leave a READY artifact');
        const recovered = await stager.stage(descriptor);
        assert(recovered.ok, 'main cache must be untouched and reusable');
        return 'SOURCE_UNAVAILABLE, no artifact cached; main cache still EXECUTES';
      },
    );

    // N11: entrypoint traversal.
    await scenario(
      'NEG-ENTRYPOINT',
      'path-traversal entrypoint refuses and materializes nothing',
      async () => {
        const traversal = signDescriptor(scopes[0], curator.privateKey, {
          entrypoint: `..${String.fromCharCode(92)}evil.exe`,
        });
        const before = (await walkFiles(join(cacheRoot, 'active'))).length;
        const refused = await activator.runCli({
          taskId: TASK_ID,
          descriptor: traversal,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(
          !refused.ok && refused.code === 'ENTRYPOINT_INVALID',
          `expected ENTRYPOINT_INVALID, got ${JSON.stringify(refused)}`,
        );
        const evil = (await walkFiles(join(cacheRoot, 'active'))).filter((p) =>
          p.toLowerCase().includes('evil'),
        );
        assert(evil.length === 0, 'evil.exe must never materialize');
        return `ENTRYPOINT_INVALID; no evil.exe under cache (files before=${before})`;
      },
    );

    // ---- R1 #145 F01–F05 delta canaries (disposable roots ONLY) ----

    // R1-F01: the closed grammar cannot express a `--pre` subprocess. The
    // would-be helper's marker file must stay absent and zero descendants
    // can exist because no spawn happens at all.
    await scenario(
      'R1-F01-PRE-CANARY',
      'ripgrep --pre is INEXPRESSIBLE: request refused pre-spawn, helper marker absent',
      async () => {
        const helperDir = join(RUNTIME_ROOT, 'pre-helper');
        mkdirSync(helperDir, { recursive: true, mode: 0o700 });
        const helper = join(helperDir, 'canary-helper.cmd');
        const marker = join(helperDir, 'helper-marker.txt');
        // If any descendant were ever spawned, this helper would leave a
        // marker in its disposable root. Content is throwaway only.
        await writeFile(
          helper,
          `@echo invoked %* > "${marker}"\r\necho helper-ran-for-canary\r\n`,
          'utf8',
        );
        await rm(marker, { force: true });
        const spawnsBefore = mainObserver.specs.length;
        // Old-argv shape: ['--pre', helper, 'CANARY', 'inside.txt'] cannot be
        // built anymore — there is no args field. The closest expressible
        // attempts both refuse at request validation, before ANY authority
        // read, materialization or spawn.
        const asOperand = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'FILE_SEARCH', pattern: 'CANARY', operands: [helper] },
          sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('canary inside') }],
        });
        assert(
          !asOperand.ok && asOperand.code === 'RUN_REQUEST_INVALID',
          `--pre helper operand must be RUN_REQUEST_INVALID, got ${JSON.stringify(asOperand)}`,
        );
        // The would-be authorized search still runs (real rg, single spawn).
        // Register the EXACT search contract for THIS invocation shape first.
        await registerGrant(world, BINDING, searchContract, outputDir);
        const normal = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: {
            kind: 'FILE_SEARCH',
            pattern: 'needle',
            operands: ['corpus.txt'],
            lineNumbers: true,
          },
          sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('a canary needle inside') }],
        });
        assert(normal.ok, `sanity search must run, got ${JSON.stringify(normal)}`);
        assert(
          mainObserver.specs.length === spawnsBefore + 1,
          'exactly one additional spawn (rg itself) may occur',
        );
        const markerExists = existsSync(marker);
        assert(!markerExists, 'preprocessor helper marker EXISTS — a descendant ran!');
        await event('r1f01.pre', {
          refused: asOperand.code,
          helperMarkerAbsent: !markerExists,
          realSearchExit: normal.exitCode,
          spawnCount: mainObserver.specs.length - spawnsBefore,
        });
        return 'RUN_REQUEST_INVALID / 0 helper spawns / marker absent; real rg search still works';
      },
    );

    // R1-F02: an outside-root file operand cannot be searched. Both canary
    // files are disposable, non-secret; the outside one must be untouched.
    await scenario(
      'R1-F02-OUTSIDE-CANARY',
      'outside-root operand refuses closed: no spawn, no outside read',
      async () => {
        const outsideDir = join(RUNTIME_ROOT, 'outside-canary');
        mkdirSync(outsideDir, { recursive: true, mode: 0o700 });
        const outside = join(outsideDir, 'outside.txt');
        const outsideContent = `CANARY_NEEDLE outside ${randomUUID()}`;
        await writeFile(outside, outsideContent, 'utf8');
        const spawnsBefore = mainObserver.specs.length;
        for (const operand of [
          outside,
          `..\\..\\${basename(outsideDir)}\\outside.txt`,
          `\\\\127.0.0.1\\nonexistent\\outside.txt`,
          `C:${join(outsideDir, 'outside.txt').slice(2)}`,
        ]) {
          const refused = await activator.runCli({
            taskId: TASK_ID,
            descriptor,
            run: { kind: 'FILE_SEARCH', pattern: 'CANARY_NEEDLE', operands: [operand] },
            sandboxFiles: [{ name: 'inside.txt', bytes: Buffer.from('CANARY_NEEDLE inside') }],
          });
          assert(
            !refused.ok && refused.code === 'RUN_REQUEST_INVALID',
            `outside operand must refuse RUN_REQUEST_INVALID, got ${JSON.stringify(refused)}`,
          );
        }
        assert(
          mainObserver.specs.length === spawnsBefore,
          'outside-operand refusals must be zero-spawn',
        );
        const after = await readFile(outside, 'utf8');
        assert(after === outsideContent, 'outside canary bytes changed!');
        // Zero-access proof: the outside canary CONTAINS the needle, the
        // in-sandbox corpus does NOT. A bound search over the sandbox-only
        // operand must exit 1 with empty stdout — had rg followed anything
        // outside, the needle would have matched.
        await registerGrant(world, BINDING, searchContract, outputDir);
        const approved = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: {
            kind: 'FILE_SEARCH',
            pattern: 'needle',
            operands: ['corpus.txt'],
            lineNumbers: true,
          },
          sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('nothing interesting here') }],
        });
        assert(approved.ok, `approved inside operand must still run: ${JSON.stringify(approved)}`);
        assert(approved.exitCode === 1, `rg must find nothing in the sandbox, got ${JSON.stringify(approved)}`);
        assert(approved.stdout === '', `outside content leaked: ${approved.stdout.slice(0, 200)}`);
        await event('r1f02.outside', {
          refusedVariants: 4,
          spawnCount: mainObserver.specs.length - spawnsBefore,
          outsideBytesUnchanged: true,
          sandboxSearchExit: approved.exitCode,
        });
        return 'absolute/UNC/drive/.. operands → RUN_REQUEST_INVALID, 0 spawns, outside bytes intact';
      },
    );

    // R1-F03: an invocation-scoped grant for `rg --version` must NOT
    // authorize a file-search invocation, even with fully CURRENT
    // PREPARE_PROVIDER state (the exact R1 falsifier shape).
    await scenario(
      'R1-F03-INVOCATION-BINDING',
      'a --version grant does NOT authorize a different invocation (zero spawn)',
      async () => {
        // Bind the version grant EXPLICITLY — grant state is per-scenario,
        // never inherited from whatever an earlier scenario left behind.
        await registerGrant(world, BINDING, versionContract, outputDir);
        const spawnsBefore = mainObserver.specs.length;
        const hijack = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: {
            kind: 'FILE_SEARCH',
            pattern: 'needle',
            operands: ['corpus.txt'],
            lineNumbers: true,
          },
          sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('the needle here') }],
        });
        assert(
          !hijack.ok && hijack.code === 'EFFECT_NOT_AUTHORIZED',
          `version grant must NOT authorize a search, got ${JSON.stringify(hijack)}`,
        );
        assert(mainObserver.specs.length === spawnsBefore, 'binding mismatch must be zero-spawn');
        // The correctly-bound search grant restores execution.
        await registerGrant(world, BINDING, searchContract, outputDir);
        const bound = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: {
            kind: 'FILE_SEARCH',
            pattern: 'needle',
            operands: ['corpus.txt'],
            lineNumbers: true,
          },
          sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('the needle here') }],
        });
        assert(bound.ok, `bound search must run, got ${JSON.stringify(bound)}`);
        await event('r1f03.binding', {
          mismatch: hijack.code,
          boundExit: bound.exitCode,
        });
        return 'version-grant + search-request → EFFECT_NOT_AUTHORIZED zero spawn; bound grant → EXECUTED';
      },
    );

    // R1-F04a: bytes swapped after verification must never spawn. The swap
    // is injected through the composition's effect-port seam (which runs
    // after staging); the last-boundary identity re-read refuses.
    await scenario(
      'R1-F04-EXE-SWAP',
      'staged EXE bytes swapped after verify → EXECUTABLE_IDENTITY_DRIFT, 0 spawns',
      async () => {
        await registerGrant(world, BINDING, versionContract, outputDir);
        const spawnsBefore = mainObserver.specs.length;
        let swappedPath = '';
        const swapObserver = observingSpawn();
        const swapActivator = new CuratedProviderActivator(
          activationHost(swapObserver, {
            authorizeRunEffect: async (invocation) => {
              swappedPath = invocation.executablePath;
              // Harmless sentinel bytes, disposable root, same-privilege
              // writer — exactly the R1 adversarial window.
              await writeFile(invocation.executablePath, Buffer.from('sentinel swapped bytes'));
              return { ok: true, leaseId: randomUUID() };
            },
          }),
        );
        const refused = await swapActivator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(swappedPath !== '', 'the effect gate never observed the invocation');
        assert(
          !refused.ok && refused.code === 'EXECUTABLE_IDENTITY_DRIFT',
          `swap must refuse EXECUTABLE_IDENTITY_DRIFT, got ${JSON.stringify(refused)}`,
        );
        assert(swapObserver.specs.length === 0, 'swapped EXE must never spawn');
        assert(
          mainObserver.specs.length === spawnsBefore,
          'the sabotage must not touch the main activator',
        );
        // A clean run right after stages fresh verified bytes and executes.
        const recovered = await activator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(recovered.ok, `recovery run failed: ${JSON.stringify(recovered)}`);
        assert(
          /ripgrep \d+\.\d+\.\d+/.test(recovered.stdout),
          'recovery must execute the pinned ripgrep',
        );
        await event('r1f04.swap', { refused: refused.code, recoveredExit: recovered.exitCode });
        return 'post-verify swap → EXECUTABLE_IDENTITY_DRIFT 0 spawns; next run EXECUTED (pinned rg)';
      },
    );

    // R1-F04b: reparse-point canaries on the REAL Windows host — a junction
    // over a seeded sandbox operand, and a cache root reached through a
    // junctioned ancestor. Both must refuse before any spawn.
    await scenario(
      'R1-F04-REPARSE',
      'junction canaries: operand redirect and unanchored cache root refuse closed',
      async () => {
        assert(process.platform === 'win32', 'reparse canaries run on the Windows host only');
        await registerGrant(world, BINDING, versionContract, outputDir);
        const spawnsBefore = mainObserver.specs.length;
        // (a) junction over the seeded operand → SANDBOX_UNSAFE.
        const junctionObserver = observingSpawn();
        const junctionActivator = new CuratedProviderActivator(
          activationHost(junctionObserver, {
            authorizeRunEffect: async (invocation) => {
              const outside = join(RUNTIME_ROOT, 'junction-outside');
              mkdirSync(outside, { recursive: true, mode: 0o700 });
              await writeFile(join(outside, 'corpus.txt'), 'OUTSIDE CANARY NEEDLE', 'utf8');
              const operandPath = join(invocation.cwd, 'corpus.txt');
              await rm(operandPath, { force: true });
              await symlink(outside, operandPath, 'junction');
              return { ok: true, leaseId: randomUUID() };
            },
          }),
        );
        const operandRefused = await junctionActivator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'FILE_SEARCH', pattern: 'needle', operands: ['corpus.txt'] },
          sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('inside needle') }],
        });
        assert(
          !operandRefused.ok && operandRefused.code === 'SANDBOX_UNSAFE',
          `junction operand must refuse SANDBOX_UNSAFE, got ${JSON.stringify(operandRefused)}`,
        );
        assert(junctionObserver.specs.length === 0, 'junction operand must be zero-spawn');
        // (b) cache root reached THROUGH a junction → refuse before staging.
        const realRoot = join(RUNTIME_ROOT, 'anchor-real');
        const linkRoot = join(RUNTIME_ROOT, 'anchor-link');
        await rm(realRoot, { recursive: true, force: true });
        await rm(linkRoot, { recursive: true, force: true });
        mkdirSync(realRoot, { recursive: true, mode: 0o700 });
        await symlink(realRoot, linkRoot, 'junction');
        const anchoredObserver = observingSpawn();
        const anchoredActivator = new CuratedProviderActivator(
          activationHost(anchoredObserver, { cacheRoot: join(linkRoot, 'cache') }),
        );
        const anchoredRefused = await anchoredActivator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(
          !anchoredRefused.ok && anchoredRefused.code === 'ACTIVATION_CACHE_UNAVAILABLE',
          `junctioned cache root must refuse, got ${JSON.stringify(anchoredRefused)}`,
        );
        assert(anchoredObserver.specs.length === 0, 'unanchored root must be zero-spawn');
        assert(mainObserver.specs.length === spawnsBefore, 'reparse canaries must not add spawns');
        await event('r1f04.reparse', {
          operandRefused: operandRefused.code,
          anchoredRefused: anchoredRefused.code,
        });
        return 'operand junction → SANDBOX_UNSAFE; junctioned cache root → ACTIVATION_CACHE_UNAVAILABLE; 0 spawns';
      },
    );

    // R1-F05: a revocation epoch flip DURING sandbox setup — observed by the
    // injected hostSpawnEnvironment seam, i.e. AFTER admission and staging —
    // must void the run at the LAST authority gate with zero process calls.
    await scenario(
      'R1-F05-REVOKE-AT-SEAM',
      'revocation flip at the spawn seam → effect gate refuses, 0 process invocations',
      async () => {
        await registerGrant(world, BINDING, versionContract, outputDir);
        const spawnsBefore = mainObserver.specs.length;
        let seamFlipped = false;
        let gateCalls = 0;
        const seamObserver = observingSpawn();
        const seamActivator = new CuratedProviderActivator(
          activationHost(seamObserver, {
            hostSpawnEnvironment: () => {
              if (!seamFlipped) {
                seamFlipped = true;
                EPOCH.value = EPOCH.value + 1;
              }
              return minimalWindowsSpawnEnvironment();
            },
          }),
        );
        const refused = await seamActivator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(seamFlipped, 'the seam flip never happened');
        assert(
          !refused.ok && refused.code === 'AUTHORITY_STALE',
          `post-admission revocation must refuse, got ${JSON.stringify(refused)}`,
        );
        assert(seamObserver.specs.length === 0, 'revoked-at-seam run must be zero-spawn');
        // The gate itself demonstrably ran and refused (count via a second
        // gate-only probe; the epoch is restored first).
        EPOCH.value = 1;
        gateCalls = 0;
        const probeActivator = new CuratedProviderActivator(
          activationHost(seamObserver, {
            authorizeRunEffect: async (_invocation) => {
              gateCalls += 1;
              return { ok: false, code: 'EFFECT_NOT_AUTHORIZED' };
            },
          }),
        );
        const probe = await probeActivator.runCli({
          taskId: TASK_ID,
          descriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(gateCalls === 1, 'the last-boundary gate must run exactly once per run');
        assert(probe.ok === false, 'probe refusal expected');
        assert(
          mainObserver.specs.length === spawnsBefore,
          'the whole F05 block must be zero-spawn on the main activator',
        );
        await event('r1f05.seam', {
          seamRefused: refused.code,
          gateCalls,
          restored: EPOCH.value,
        });
        return 'epoch flip at seam → AUTHORITY_STALE 0 spawns; last-boundary gate ran exactly once';
      },
    );

    // CANARY: every user-owned canary byte-identical after the whole matrix.
    await scenario(
      'CANARY',
      'user-owned canary files unchanged across the entire run',
      async () => {
        for (const path of canaryPaths) {
          const digest = await sha256File(path);
          assert(digest === canaryBaseline.get(path), `canary ${sanitize(path)} changed!`);
        }
        return `${canaryPaths.length} canaries intact (temp + user profile + cwd)`;
      },
    );

    // SHARP: separate native-addon ABI probe.
    await scenario(
      'SHARP',
      'native addon ABI probe: @img/sharp-win32-x64 real dlopen in isolated child',
      async () => {
        const metaResponse = await fetch('https://registry.npmmirror.com/@img/sharp-win32-x64', {
          signal: AbortSignal.timeout(30_000),
        });
        assert(metaResponse.ok, `registry metadata fetch failed: HTTP ${metaResponse.status}`);
        const meta = (await metaResponse.json()) as {
          'dist-tags': { latest: string };
          versions: Record<string, { dist: { integrity: string; tarball: string } }>;
        };
        const version = meta['dist-tags'].latest;
        const dist = meta.versions[version]?.dist;
        assert(dist, 'registry metadata missing dist for latest');
        const probeResponse = await fetch(dist.tarball, { signal: AbortSignal.timeout(120_000) });
        assert(probeResponse.ok, `tarball probe fetch failed: HTTP ${probeResponse.status}`);
        const probeBytes = Buffer.from(await probeResponse.arrayBuffer());
        const sha256 = createHash('sha256').update(probeBytes).digest('hex');
        const sha512 = createHash('sha512').update(probeBytes).digest('base64');
        const sriMatches = `sha512-${sha512}` === dist.integrity;
        await event('sharp.metadata', {
          version,
          tarballUrl: dist.tarball,
          tarballBytes: probeBytes.byteLength,
          sha256,
          registrySri: dist.integrity,
          sriMatches,
        });
        if (!sriMatches) {
          throw new Error(
            'BLOCKED: downloaded tarball does not match the npm registry SRI anchor (unreliable signed package)',
          );
        }
        // The registry tarball path 302-redirects to the CDN; the product
        // refuses redirects by design, so pin the redirect-FREE final URL as
        // the origin and let the production stager prove it serves directly.
        const directOrigin = probeResponse.url;
        assert(
          directOrigin.startsWith('https://'),
          `final origin is not HTTPS: ${sanitize(directOrigin)}`,
        );
        const sharpScope = makeScope({
          bindingId: 'sharp-win32-x64-binding',
          providerId: 'sharp',
          capabilityId: 'image.native',
          version,
          origin: directOrigin,
          artifactKind: 'NATIVE_ADDON',
          artifactSha256: sha256,
          abiRevision: process.versions.modules,
        });
        PINNED_SHA.set(sharpScope.bindingId, sha256);
        PROVIDER_OF.set(sharpScope.bindingId, 'sharp');
        const sharpVerifier = new CuratedProviderVerifier(
          [{ keyId: 'curator-winhost', publicKeyPem }],
          [...scopes, sharpScope],
        );
        const sharpDescriptor = signDescriptor(sharpScope, curator.privateKey, {
          entrypoint: 'sharp-win32-x64.node',
        });
        const sharpCache = join(RUNTIME_ROOT, 'cache-sharp');
        mkdirSync(sharpCache, { recursive: true, mode: 0o700 });
        const sharpStager = new CuratedProviderStager({
          cacheRoot: sharpCache,
          verifier: sharpVerifier,
          isOffline: () => false,
        });
        const staged = await sharpStager.stage(sharpDescriptor);
        if (!staged.ok && staged.code === 'REDIRECT_REFUSED') {
          throw new Error(
            `BLOCKED: pinned final origin still redirects (unusable as a redirect-free provider origin): ${JSON.stringify(staged)}`,
          );
        }
        assert(staged.ok, `sharp tarball stage refused: ${JSON.stringify(staged)}`);
        const stagedBytes = await readFile(join(sharpCache, 'artifacts', sha256));
        assert(
          `sha512-${createHash('sha512').update(stagedBytes).digest('base64')}` === dist.integrity,
          'staged bytes fail the registry SRI anchor',
        );
        const extractDir = join(RUNTIME_ROOT, 'sharp-extract');
        await rm(extractDir, { recursive: true, force: true });
        mkdirSync(extractDir, { recursive: true });
        const tgzPath = join(RUNTIME_ROOT, 'sharp.tgz');
        await writeFile(tgzPath, stagedBytes);
        const untar = await execFileAsync(
          join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe'),
          ['-xzf', tgzPath, '-C', extractDir],
          { timeoutMs: 60_000 },
        );
        assert(untar.exitCode === 0, `tar extract failed: ${untar.stderr.slice(0, 200)}`);
        const nodeBin = (await walkFiles(extractDir)).find((p) => p.endsWith('.node'));
        assert(nodeBin, 'no .node binary inside the staged tarball');
        const nodeSha = await sha256File(nodeBin);
        await event('sharp.addon', {
          addon: basename(nodeBin),
          sha256: nodeSha,
          hostAbi: process.versions.modules,
          node: process.version,
        });
        // Fail-closed check: production activation refuses native addons in
        // this slice. Composed with the SHARP verifier so the catalog itself
        // is trusted and the refusal provably comes from the KIND gate, not
        // from an untrusted catalog. The sharp stage/preflight earlier in
        // this scenario is an ABI probe only — never a native activation.
        const sharpRoot = join(sharpCache, 'active', sharpScope.bindingId, sha256);
        await registerGrant(
          world,
          sharpScope.bindingId,
          {
            op: 'provider.version.probe',
            argv: ['--version'],
            execRoot: join(sharpRoot, 'exec'),
            sandboxRoot: join(sharpRoot, 'sandbox'),
          },
          outputDir,
        );
        const sharpObserver = observingSpawn();
        const sharpActivator = new CuratedProviderActivator({
          verifier: sharpVerifier,
          stager: sharpStager,
          cacheRoot: sharpCache,
          getAuthorizedCurrentness: currentnessPort(world),
          authorizeRunEffect: effectPort(world),
          requiredRevocationEpoch: () => EPOCH.value,
          hostPlatform: () => process.platform,
          hostArchitecture: () => process.arch,
          hostNodeAbi: () => process.versions.modules,
          hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
          process: sharpObserver.port,
        });
        const nativeRefused = await sharpActivator.runCli({
          taskId: TASK_ID,
          descriptor: sharpDescriptor,
          run: { kind: 'VERSION_PROBE' },
        });
        assert(
          !nativeRefused.ok && nativeRefused.code === 'ACTIVATION_KIND_UNSUPPORTED',
          `native activation must stay fail-closed, got ${JSON.stringify(nativeRefused)}`,
        );
        assert(sharpObserver.specs.length === 0, 'native refusal must be zero-spawn');
        // Isolated child dlopen with the pinned absolute path and scrubbed env.
        const bootstrapPath = join(RUNTIME_ROOT, 'sharp-dlopen.mjs');
        await writeFile(
          bootstrapPath,
          [
            'const addonPath = process.argv[2];',
            'const target = { exports: {} };',
            'try {',
            '  process.dlopen(target, addonPath);',
            "  console.log('DLOADED ' + Object.keys(target.exports).length + ' exports: ' + Object.keys(target.exports).sort().join(','));",
            "  console.log('NAPI_ABI_OK node=' + process.version + ' modules=' + process.versions.modules);",
            '} catch (error) {',
            "  console.log('DLOPEN_FAILED ' + (error && error.message));",
            '  process.exit(2);',
            '}',
            '',
          ].join('\n'),
          'utf8',
        );
        const child = await execFileAsync(process.execPath, [bootstrapPath, nodeBin], {
          timeoutMs: 60_000,
          env: { ...minimalWindowsSpawnEnvironment() },
        });
        await event('sharp.dlopen', {
          exitCode: child.exitCode,
          stdout: child.stdout.trim(),
          stderr: child.stderr.trim().slice(0, 300),
        });
        assert(
          child.exitCode === 0 &&
            /DLOADED \d+ exports/.test(child.stdout) &&
            /NAPI_ABI_OK/.test(child.stdout),
          `isolated dlopen did not succeed: ${child.stdout.slice(0, 200)} ${child.stderr.slice(0, 200)}`,
        );
        return `sharp-win32-x64@${version} sha256=${sha256.slice(0, 16)}… SRI-anchored+staged+ABI=${process.versions.modules}+dlopen OK; production native activation stays fail-closed (ACTIVATION_KIND_UNSUPPORTED)`;
      },
    );
  } finally {
    await fixture.close();
  }

  // Summary + manifest.
  const passCount = results.filter((r) => r.status === 'PASS').length;
  const failCount = results.filter((r) => r.status === 'FAIL').length;
  const skipCount = results.filter((r) => r.status === 'SKIPPED').length;
  const sharpResult = results.find((r) => r.id === 'SHARP');
  const r1Results = results.filter((r) => r.id.startsWith('R1-'));
  const r1Fail = r1Results.filter((r) => r.status !== 'PASS').length;
  const summary = [
    '# T05 #106 + R1 #145 F01–F04 delta — real Windows Build Host evidence',
    '',
    `- Baseline: PR #144 HEAD 9f4e1f3372497f031bc8ed68c822976934a20c77 (delta applies the R1 repair contract)`,
    `- Host: ${process.platform} ${osRelease()} ${osArch()}, node ${process.version} (ABI ${process.versions.modules})`,
    `- ripgrep: ${RG_VERSION} official MSVC release, zip sha256=${zipSha || 'n/a'}`,
    `- Run: ${RUN_TAG} (UTC); events.ndjson carries the full incremental log`,
    '',
    '## Verdict',
    '',
    `- CLI activation matrix: ${failCount === 0 ? `PASS (${passCount} scenarios)` : `FAIL (${failCount} failed)`}${skipCount ? `, ${skipCount} skipped` : ''}`,
    `- R1 #145 F01–F05 delta canaries: ${r1Fail === 0 ? `PASS (${r1Results.length} scenarios)` : `FAIL (${r1Fail} failed)`}`,
    `- Native addon (Sharp): ${sharpResult ? sharpResult.status : 'NOT RUN'}${sharpResult ? ` — ${sharpResult.detail}` : ''}`,
    '- Native production activation stays fail-closed (ACTIVATION_KIND_UNSUPPORTED);',
    '  the Sharp row is an ABI probe only and is NOT a native activation result.',
    '- T11 Release readiness: NOT claimed by this run',
    '',
    '## Scenarios',
    '',
    ...results.map((r) => `- [${r.status}] ${r.id} ${r.title} — ${r.detail}`),
    '',
    '## Honest scope',
    '',
    '- Fixture origin is a local HTTPS server (NODE_EXTRA_CA_CERTS trust anchor) serving',
    '  byte-exact official release content; github.com itself 302-redirects, which the',
    '  product refuses by design — proven live in NEG-REDIRECT against the real URL.',
    '- Trust anchors are the curator Ed25519 signature over the pinned digest and the',
    '  ActionController grant state (LocalAuthority HMAC substrate), both provisioned',
    '  by this trusted composition, never by request input. The invocation-scoped',
    '  authorizeRunEffect port re-validates the full grant presentation AND binds the',
    '  exact op/argv/scope roots fresh at the last boundary (R1 #145 F03).',
    '- Execution argv is host-derived from a closed-world typed operation; --pre,',
    '  config/pattern files and outside-root operands are INEXPRESSIBLE, not',
    '  blacklisted (R1 #145 F01/F02).',
    '- The staged executable lives in a fresh per-run random directory under a',
    '  reparse-free anchored chain; identity (dev/ino via the staging handle +',
    '  on-disk lstat) and the full digest are re-verified at the LAST boundary',
    '  before the spawn seam — deletion, symlink/junction swap and byte',
    '  overwrite are all refused with zero spawns (R1 #145 F04, proven live in',
    '  R1-F04-EXE-SWAP and R1-F04-REPARSE). Residual risk (measured, not',
    '  claimed away): the runtime opens files with FILE_SHARE_DELETE, so no',
    '  user-mode handle blocks a same-privilege writer, and the sub-millisecond',
    '  window between the final identity re-check and CreateProcess image open',
    '  cannot be closed without kernel/exclusive-share primitives; this run',
    '  claims detection-at-the-last-check, not stat→close→spawn atomicity.',
    '- Revocation/policy moves observable at the spawn seam are caught by the final',
    '  invocation-scoped gate with zero process invocations (R1 #145 F05).',
    '',
  ].join('\n');
  await writeFile(join(EVIDENCE_DIR, 'summary.md'), sanitize(summary), 'utf8');
  const evidenceFiles = await walkFiles(EVIDENCE_DIR);
  const manifestLines = [
    `T05 winhost evidence manifest — ${RUN_TAG}`,
    `evidence_dir=${sanitize(EVIDENCE_DIR)}`,
    `runtime_root=${sanitize(RUNTIME_ROOT)} (NOT committed; heavy artifacts)`,
    `rg_zip_sha256=${zipSha}`,
    `rg_exe_sha256=${PINNED_SHA.get(BINDING) ?? 'n/a'}`,
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
    skipped: skipCount,
    runFailed,
    summary: sanitize(join(EVIDENCE_DIR, 'summary.md')),
  });
  process.exitCode = runFailed ? 1 : 0;
}

// ---- HTTPS fixture origin ----

async function startFixtureOrigin(rgBytesPath: string, caKeyPath: string, caPemPath: string) {
  const https = await import('node:https');
  const genuine = await readFile(rgBytesPath);
  const corrupt = Buffer.from(genuine);
  corrupt[0x200] ^= 0xff;
  const server = https.createServer(
    { key: await readFile(caKeyPath), cert: await readFile(caPemPath) },
    (req, res) => {
      const url = req.url ?? '';
      if (url.startsWith('/rg.exe')) {
        res.writeHead(200, {
          'content-length': genuine.length,
          'content-type': 'application/octet-stream',
        });
        res.end(genuine);
        return;
      }
      if (url.startsWith('/rg-corrupt.exe')) {
        res.writeHead(200, {
          'content-length': corrupt.length,
          'content-type': 'application/octet-stream',
        });
        res.end(corrupt);
        return;
      }
      if (url.startsWith('/redirect')) {
        res.writeHead(302, { location: '/rg.exe' });
        res.end();
        return;
      }
      if (url.startsWith('/hang')) {
        // Destroy the socket mid-response: a real interrupted transfer.
        const socket = req.socket;
        setTimeout(() => socket.destroy(), 2_500);
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
