import { spawn } from 'node:child_process';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalJson } from '@shun/contracts';
import { CuratedProviderVerifier, type TrustedProviderScope } from '@shun/vertical-jit';
import { afterEach, describe, expect, it } from 'vitest';
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
import {
  NATIVE_CHILD_BOOTSTRAP_SOURCE,
  NATIVE_CHILD_RESULT_PREFIX,
  parseNativeChildResult,
} from '../src/native-child.ts';
import type { ProviderUseCurrentness } from '../src/preflight.ts';
import { CuratedProviderStager } from '../src/staging.ts';
import { buildSynthPe } from './synth-pe.ts';

const keyPair = generateKeyPairSync('ed25519');
const attackerKey = generateKeyPairSync('ed25519');
const roots: string[] = [];

// The synthetic addon image: a structurally valid PE that imports nothing
// beyond system DLLs (kernel32) — the shape of a self-contained addon.
const addonImage = buildSynthPe({ imports: ['KERNEL32.dll'] });
const addonSha = createHash('sha256').update(addonImage).digest('hex');
// A synthetic dependency that imports only system DLLs.
const depImage = buildSynthPe({ imports: ['KERNEL32.dll', 'WS2_32.dll'] });
const depSha = createHash('sha256').update(depImage).digest('hex');
const DEP_NAME = 'mydeps.dll';

const scope: TrustedProviderScope = {
  providerId: 'sharp',
  capabilityId: 'image.native',
  version: '0.35.5',
  catalogRevision: 'catalog-r2',
  bindingId: 'sharp-binding',
  scopedVerifierId: 'safe-verifier',
  catalogManifestSha256: 'a'.repeat(64),
  bindingEvidenceSha256: 'b'.repeat(64),
  artifactSha256: addonSha,
  origin: 'https://trusted.invalid/addon.node',
  platform: 'windows-x64',
  artifactKind: 'NATIVE_ADDON',
  abiRevision: '137',
};

function currentness(trust: TrustedProviderScope = scope): ProviderUseCurrentness {
  return {
    kind: 'CURRENT',
    taskId: 'task-1',
    providerId: trust.providerId,
    bindingId: trust.bindingId,
    catalogRevision: trust.catalogRevision,
    artifactSha256: trust.artifactSha256,
    revocationEpoch: 1,
    capability: 'PREPARE_PROVIDER',
  };
}

function makeDescriptor(
  trust: TrustedProviderScope = scope,
  overrides: Record<string, unknown> = {},
  signer: typeof keyPair = keyPair,
) {
  // Host-derived scope config (dependency name pins) is NEVER part of the
  // signed descriptor payload — the wire schema is strict and has no field
  // for it.
  const { dependencyEntries: _hostDerived, ...signedScope } = trust;
  const unsigned = {
    ...signedScope,
    entrypoint: trust.artifactKind === 'CLI' ? 'rg.exe' : 'addon.node',
    signerKeyId: 'key-1',
    dependencySha256: (trust.dependencyEntries ?? []).map((entry) => entry.artifactSha256),
    ...overrides,
  };
  return {
    ...unsigned,
    curatorSignature: sign(null, Buffer.from(canonicalJson(unsigned)), signer.privateKey).toString(
      'base64',
    ),
  };
}

const okEffect = (): RunEffectDecision => ({ ok: true, leaseId: randomUUID() });

interface NativeHarness {
  activator: CuratedProviderActivator;
  stager: CuratedProviderStager;
  verifier: CuratedProviderVerifier;
  specs: ActivationRunSpec[];
  invocations: ResolvedInvocation[];
  cacheRoot: string;
}

interface HostOptions {
  /** Overrides applied to the TrustedActivationHost composition. */
  host?: Partial<TrustedActivationHost>;
  /** Verifier scopes; defaults to [trust]. */
  scopes?: readonly TrustedProviderScope[];
  trust?: TrustedProviderScope;
  /** Real BoundedSpawnProcess instead of the scripted recorder. */
  realProcess?: boolean;
  /** Bytes the fixture fetch origin serves; defaults to the addon image. */
  fetchBytes?: Buffer;
}

function makeNativeHost(options: HostOptions = {}): NativeHarness {
  const trust = options.trust ?? scope;
  const dir = mkdtempSync(join(tmpdir(), 'shun-t05-native-'));
  roots.push(dir);
  const verifier = new CuratedProviderVerifier(
    [
      {
        keyId: 'key-1',
        publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      },
    ],
    options.scopes ?? [trust],
  );
  const fetchBytes = options.fetchBytes ?? addonImage;
  const stager = new CuratedProviderStager({
    cacheRoot: dir,
    verifier,
    isOffline: () => false,
    fetchArtifact: (async () => new Response(fetchBytes, { status: 200 })) as typeof fetch,
  });
  const state = currentness(trust);
  const specs: ActivationRunSpec[] = [];
  const invocations: ResolvedInvocation[] = [];
  const scripted: ActivationProcessOutcome = {
    exitCode: 0,
    stdout: `${NATIVE_CHILD_RESULT_PREFIX}${JSON.stringify({
      ok: true,
      kind: 'ADDON_METADATA',
      exportCount: 2,
      exports: ['alpha', 'beta'],
      addonType: 'function',
      childAbi: '137',
      childNode: 'v24.0.0',
    })}\n`,
    stderr: '',
    timedOut: false,
    stdoutTruncated: false,
    stderrTruncated: false,
  };
  const port = {
    specs,
    async run(spec: ActivationRunSpec): Promise<ActivationProcessOutcome> {
      specs.push(spec);
      return scripted;
    },
  };
  const realRecordingPort = {
    specs,
    async run(spec: ActivationRunSpec): Promise<ActivationProcessOutcome> {
      specs.push(spec);
      return new BoundedSpawnProcess().run(spec);
    },
  };
  const authorizeRunEffect = async (invocation: ResolvedInvocation): Promise<RunEffectDecision> => {
    invocations.push(invocation);
    return okEffect();
  };
  const host: TrustedActivationHost = {
    verifier,
    stager,
    cacheRoot: dir,
    getAuthorizedCurrentness: () => state,
    authorizeRunEffect,
    requiredRevocationEpoch: () => 1,
    hostPlatform: () => 'win32',
    hostArchitecture: () => 'x64',
    hostNodeAbi: () => '137',
    hostNativeChildRuntime: () => process.execPath,
    hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
    process: options.realProcess ? realRecordingPort : port,
    ...options.host,
  };
  return {
    activator: new CuratedProviderActivator(host),
    stager,
    verifier,
    specs,
    invocations,
    cacheRoot: dir,
  };
}

/** Writes dependency bytes straight into the digest-named cache layout. */
async function placeDependency(cacheRoot: string, digest: string, bytes: Buffer): Promise<void> {
  await mkdir(join(cacheRoot, 'artifacts'), { recursive: true });
  writeFileSync(join(cacheRoot, 'artifacts', digest), bytes);
}

async function stagedNative(
  options: HostOptions = {},
): Promise<{ host: NativeHarness; descriptor: ReturnType<typeof makeDescriptor> }> {
  const host = makeNativeHost(options);
  const descriptor = makeDescriptor(options.trust ?? scope);
  expect((await host.stager.stage(descriptor)).ok).toBe(true);
  return { host, descriptor };
}

/** Residue under active/: anything inside the per-run exec/ or sandbox/ trees. */
function leftoversUnderActive(cacheRoot: string, bindingId: string, digest: string): string[] {
  const active = join(cacheRoot, 'active', bindingId, digest);
  const out: string[] = [];
  const walk = (dir: string, depth: number): void => {
    if (depth > 8) return;
    let entries: string[] = [];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      out.push(full);
      walk(full, depth + 1);
    }
  };
  for (const container of ['exec', 'sandbox']) walk(join(active, container), 0);
  return out;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('T05 native addon activation — closed child surface', () => {
  it('spawns ONE pinned-runtime child with the fixed bootstrap, a bounded payload, exec-dir cwd and scrubbed env', async () => {
    const { host, descriptor } = await stagedNative();
    const result = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(result).toMatchObject({ ok: true, state: 'EXECUTED', bindingId: 'sharp-binding' });
    if (!result.ok) return;
    expect(result.native).toMatchObject({
      ok: true,
      report: { ok: true, kind: 'ADDON_METADATA', exportCount: 2 },
    });
    expect(host.specs).toHaveLength(1);
    const spec = host.specs[0];
    if (!spec) return;
    expect(spec.executable).toBe(process.execPath);
    expect(spec.args).toHaveLength(3);
    expect(spec.args[0]).toBe('-e');
    const [bootstrap, payloadJson] = [spec.args[1] ?? '', spec.args[2] ?? ''];
    const payload = JSON.parse(payloadJson) as {
      v: number;
      op: string;
      addon: { path: string; sha256: string };
      deps: unknown[];
    };
    expect(bootstrap.length).toBeGreaterThan(200);
    expect(bootstrap).not.toMatch(/["\n]/);
    expect(payload).toMatchObject({ v: 1, op: 'ADDON_METADATA', addon: { sha256: addonSha } });
    expect(payload.addon.path.startsWith(join(host.cacheRoot, 'active'))).toBe(true);
    expect(payload.deps).toEqual([]);
    expect(spec.cwd?.startsWith(join(host.cacheRoot, 'active'))).toBe(true);
    expect(Object.keys(spec.env).every((key) => ['SystemRoot', 'SystemDrive'].includes(key))).toBe(
      true,
    );
    const invocation = host.invocations[0];
    expect(invocation).toMatchObject({
      op: 'provider.native.addon-metadata',
      taskId: 'task-1',
      bindingId: 'sharp-binding',
      artifactSha256: addonSha,
      writeRoots: [],
    });
    expect(invocation?.executablePath).toBe(process.execPath);
    expect(invocation?.native?.addonPath).toBe(payload.addon.path);
    // Per-run directories are cleaned after the run.
    expect(leftoversUnderActive(host.cacheRoot, 'sharp-binding', addonSha)).toEqual([]);
  });

  it('binds the operand identity into the payload for IMAGE_METADATA and seeds only that file', async () => {
    const { host, descriptor } = await stagedNative();
    const imageBytes = Buffer.from(
      '89504e470d0a1a0a0000000d49484452000000010000000108060000',
      'hex',
    );
    const result = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'IMAGE_METADATA', operand: 'photo.bin' },
      sandboxFiles: [{ name: 'photo.bin', bytes: imageBytes }],
    });
    expect(result).toMatchObject({ ok: true, state: 'EXECUTED' });
    const invocation = host.invocations[0];
    expect(invocation).toMatchObject({ op: 'provider.native.image-metadata' });
    const payload = JSON.parse(host.specs[0]?.args[2] ?? '{}') as {
      operand?: { path: string; sha256: string; maxBytes: number };
    };
    expect(
      payload.operand?.path.startsWith(
        join(host.cacheRoot, 'active', 'sharp-binding', addonSha, 'sandbox'),
      ),
    ).toBe(true);
    expect(payload.operand?.path.endsWith('photo.bin')).toBe(true);
    expect(payload.operand?.sha256).toBe(createHash('sha256').update(imageBytes).digest('hex'));
    expect(payload.operand?.maxBytes).toBe(1024 * 1024);
    expect(leftoversUnderActive(host.cacheRoot, 'sharp-binding', addonSha)).toEqual([]);
  });

  it('refuses unseeded, absolute and traversal operands before any authority read', async () => {
    const { host, descriptor } = await stagedNative();
    for (const operand of ['unseeded.bin', 'C:\\evil.bin', '..\\evil.bin', 'a/b.bin']) {
      const refused = await host.activator.runNativeAddon({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'IMAGE_METADATA', operand },
      });
      expect(refused).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    }
    // ADDON_METADATA cannot smuggle sandbox inputs either.
    const withFiles = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
      sandboxFiles: [{ name: 'x.bin', bytes: Buffer.from('x') }],
    });
    expect(withFiles).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    expect(host.specs).toHaveLength(0);
    expect(host.invocations).toHaveLength(0);
  });

  it('refuses CLI artifacts on the native path and native artifacts on the CLI path', async () => {
    const cliScope: TrustedProviderScope = {
      ...scope,
      artifactKind: 'CLI',
      abiRevision: undefined,
      bindingId: 'cli-binding',
      providerId: 'rg',
    };
    const cliHost = makeNativeHost({ trust: cliScope });
    const cliDescriptor = makeDescriptor(cliScope);
    await cliHost.stager.stage(cliDescriptor);
    const nativeOnCli = await cliHost.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor: cliDescriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(nativeOnCli).toEqual({ ok: false, code: 'ACTIVATION_KIND_UNSUPPORTED' });
    const { host, descriptor } = await stagedNative();
    const cliOnNative = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'VERSION_PROBE' },
    });
    expect(cliOnNative).toEqual({ ok: false, code: 'ACTIVATION_KIND_UNSUPPORTED' });
    expect(host.specs).toHaveLength(0);
    expect(cliHost.specs).toHaveLength(0);
  });
});

describe('T05 native addon activation — trust chain before any child', () => {
  it('refuses before verified cache bytes exist, and tampered cache bytes forever after (zero spawns)', async () => {
    const host = makeNativeHost();
    const descriptor = makeDescriptor();
    const refused = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(refused).toEqual({ ok: false, code: 'ARTIFACT_NOT_VERIFIED' });
    expect((await host.stager.stage(descriptor)).ok).toBe(true);
    const artifactPath = join(host.cacheRoot, 'artifacts', addonSha);
    const original = readFileSync(artifactPath);
    const tampered = Buffer.from(original);
    tampered[0x40] = (tampered[0x40] ?? 0) ^ 0xff;
    try {
      writeFileSync(artifactPath, tampered);
      const tamperedResult = await host.activator.runNativeAddon({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      });
      expect(tamperedResult).toEqual({ ok: false, code: 'ARTIFACT_NOT_VERIFIED' });
    } finally {
      writeFileSync(artifactPath, original);
    }
    const recovered = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(recovered).toMatchObject({ ok: true, state: 'EXECUTED' });
    expect(host.specs).toHaveLength(1);
  });

  it('refuses unsigned, wrong-key and drifting catalog presentations (zero spawns)', async () => {
    const { host, descriptor } = await stagedNative();
    const spawnsBefore = host.specs.length;
    const unsigned = { ...descriptor, curatorSignature: 'AAA'.repeat(29) };
    const unsignedResult = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor: unsigned,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(unsignedResult.ok).toBe(false);
    const forged = makeDescriptor(scope, {}, attackerKey);
    const forgedResult = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor: forged,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(forgedResult).toMatchObject({ ok: false, code: 'CATALOG_SIGNATURE_INVALID' });
    const downgrade = makeDescriptor(scope, { version: '0.35.4' });
    const downgradeResult = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor: downgrade,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(downgradeResult).toMatchObject({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
    expect(host.specs.length).toBe(spawnsBefore);
  });

  it('refuses host/platform/ABI drift before any child', async () => {
    const linux = makeNativeHost({ host: { hostPlatform: () => 'linux' } });
    const { descriptor } = await stagedNative();
    await linux.stager.stage(descriptor);
    const refused = await linux.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(refused).toEqual({ ok: false, code: 'HOST_UNSUPPORTED' });
    const abiDrift = makeNativeHost({ host: { hostNodeAbi: () => '115' } });
    await abiDrift.stager.stage(descriptor);
    const abiResult = await abiDrift.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(abiResult).toEqual({ ok: false, code: 'ABI_MISMATCH' });
    const arm = makeNativeHost({ host: { hostArchitecture: () => 'arm64' } });
    await arm.stager.stage(descriptor);
    expect(
      await arm.activator.runNativeAddon({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      }),
    ).toEqual({ ok: false, code: 'HOST_UNSUPPORTED' });
    expect(linux.specs).toHaveLength(0);
    expect(abiDrift.specs).toHaveLength(0);
    expect(arm.specs).toHaveLength(0);
  });

  it('re-reads the ActionController immediately before exec and refuses mid-call drift', async () => {
    const { host, descriptor } = await stagedNative();
    let reads = 0;
    const toctou = makeNativeHost({
      host: {
        getAuthorizedCurrentness: () => {
          reads += 1;
          if (reads >= 2) return { kind: 'UNRESOLVABLE' };
          return currentness();
        },
      },
    });
    await toctou.stager.stage(descriptor);
    const refused = await toctou.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(refused).toEqual({ ok: false, code: 'AUTHORITY_STALE' });
    expect(toctou.specs).toHaveLength(0);
    expect(reads).toBeGreaterThanOrEqual(2);
    // A refusal from the invocation-scoped effect gate passes through verbatim.
    const denying = makeNativeHost({
      host: { authorizeRunEffect: async () => ({ ok: false, code: 'EFFECT_NOT_AUTHORIZED' }) },
    });
    await denying.stager.stage(descriptor);
    const denied = await denying.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(denied).toEqual({ ok: false, code: 'EFFECT_NOT_AUTHORIZED' });
    expect(denying.specs).toHaveLength(0);
    expect(host.specs).toHaveLength(0);
  });

  it('refuses a staged addon byte swap after verification at the last boundary (zero spawns)', async () => {
    let sabotaged = false;
    let sabotagedPath = '';
    let spawns = 0;
    const swapping = makeNativeHost({
      host: {
        authorizeRunEffect: async (invocation) => {
          if (!sabotaged && invocation.native) {
            sabotaged = true;
            sabotagedPath = invocation.native.addonPath;
            writeFileSync(sabotagedPath, Buffer.from('sentinel: not the pinned bytes'));
          }
          return okEffect();
        },
        process: {
          async run(): Promise<ActivationProcessOutcome> {
            spawns += 1;
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
      },
    });
    const descriptor = makeDescriptor();
    await swapping.stager.stage(descriptor);
    const refused = await swapping.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(sabotagedPath).not.toBe('');
    expect(refused).toEqual({ ok: false, code: 'EXECUTABLE_IDENTITY_DRIFT' });
    expect(spawns).toBe(0);
    expect(swapping.specs).toHaveLength(0);
    expect(leftoversUnderActive(swapping.cacheRoot, 'sharp-binding', addonSha)).toEqual([]);
  });
});

describe('T05 native dependency closure — signed names, digest cache, PE import graph', () => {
  const depScope: TrustedProviderScope = {
    ...scope,
    dependencyEntries: [{ name: DEP_NAME, artifactSha256: depSha }],
  };

  function makeClosureHost(options: HostOptions = {}): NativeHarness {
    return makeNativeHost({ ...options, trust: depScope });
  }

  async function placeGoodDep(cacheRoot: string): Promise<void> {
    await placeDependency(cacheRoot, depSha, depImage);
  }

  it('stages the declared closure under its curated name and runs the child from that directory', async () => {
    const host = makeClosureHost();
    await placeGoodDep(host.cacheRoot);
    const descriptor = makeDescriptor(depScope);
    expect((await host.stager.stage(descriptor)).ok).toBe(true);
    const result = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(result).toMatchObject({ ok: true, state: 'EXECUTED' });
    const payload = JSON.parse(host.specs[0]?.args[2] ?? '{}') as {
      deps: Array<{ name: string; sha256: string; path: string }>;
    };
    expect(payload.deps).toEqual([
      { name: DEP_NAME, sha256: depSha, path: join(host.specs[0]?.cwd ?? '', DEP_NAME) },
    ]);
    expect(leftoversUnderActive(host.cacheRoot, depScope.bindingId, addonSha)).toEqual([]);
  });

  it('refuses an undeclared non-system import anywhere in the closure graph (zero spawns)', async () => {
    const evilAddon = buildSynthPe({ imports: ['KERNEL32.dll', 'evil_overlay.dll'] });
    const evilSha = createHash('sha256').update(evilAddon).digest('hex');
    const evilScope: TrustedProviderScope = { ...scope, artifactSha256: evilSha };
    const evilHost = makeNativeHost({ trust: evilScope, fetchBytes: evilAddon });
    const descriptor = makeDescriptor(evilScope);
    await evilHost.stager.stage(descriptor);
    const refused = await evilHost.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(refused).toEqual({ ok: false, code: 'DEPENDENCIES_UNVERIFIED' });
    expect(evilHost.specs).toHaveLength(0);
    expect(leftoversUnderActive(evilHost.cacheRoot, evilScope.bindingId, evilSha)).toEqual([]);
    // A dependency that itself imports an undeclared DLL is equally refused.
    const evilDep = buildSynthPe({ imports: ['KERNEL32.dll', 'sneaky.dll'] });
    const evilDepSha = createHash('sha256').update(evilDep).digest('hex');
    const evilDepScope: TrustedProviderScope = {
      ...scope,
      dependencyEntries: [{ name: DEP_NAME, artifactSha256: evilDepSha }],
    };
    const evilDepHost = makeNativeHost({ trust: evilDepScope });
    await placeDependency(evilDepHost.cacheRoot, evilDepSha, evilDep);
    const evilDepDescriptor = makeDescriptor(evilDepScope);
    await evilDepHost.stager.stage(evilDepDescriptor);
    expect(
      await evilDepHost.activator.runNativeAddon({
        taskId: 'task-1',
        descriptor: evilDepDescriptor,
        run: { kind: 'ADDON_METADATA' },
      }),
    ).toEqual({ ok: false, code: 'DEPENDENCIES_UNVERIFIED' });
    expect(evilDepHost.specs).toHaveLength(0);
  });

  it('refuses missing or tampered dependency cache bytes (zero spawns)', async () => {
    const missing = makeClosureHost();
    const descriptor = makeDescriptor(depScope);
    await missing.stager.stage(descriptor);
    expect(
      await missing.activator.runNativeAddon({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      }),
    ).toEqual({ ok: false, code: 'DEPENDENCIES_UNVERIFIED' });
    const tamperedHost = makeClosureHost();
    await placeDependency(tamperedHost.cacheRoot, depSha, Buffer.from('tampered dependency bytes'));
    const tamperedDescriptor = makeDescriptor(depScope);
    await tamperedHost.stager.stage(tamperedDescriptor);
    expect(
      await tamperedHost.activator.runNativeAddon({
        taskId: 'task-1',
        descriptor: tamperedDescriptor,
        run: { kind: 'ADDON_METADATA' },
      }),
    ).toEqual({ ok: false, code: 'DEPENDENCIES_UNVERIFIED' });
    expect(missing.specs).toHaveLength(0);
    expect(tamperedHost.specs).toHaveLength(0);
  });

  it('refuses a dependency whose curated name collides with a system DLL', async () => {
    const collisionScope: TrustedProviderScope = {
      ...scope,
      dependencyEntries: [{ name: 'KERNEL32.DLL', artifactSha256: depSha }],
    };
    const host = makeNativeHost({ trust: collisionScope });
    await placeDependency(host.cacheRoot, depSha, depImage);
    const descriptor = makeDescriptor(collisionScope);
    await host.stager.stage(descriptor);
    const refused = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(refused).toEqual({ ok: false, code: 'DEPENDENCIES_UNVERIFIED' });
    expect(host.specs).toHaveLength(0);
  });

  it('refuses a non-AMD64 addon image as HOST_UNSUPPORTED and unparsable images as closure failures', async () => {
    const i386 = buildSynthPe({ imports: ['KERNEL32.dll'], machine: 0x14c });
    const i386Sha = createHash('sha256').update(i386).digest('hex');
    const i386Scope: TrustedProviderScope = { ...scope, artifactSha256: i386Sha };
    const i386Host = makeNativeHost({ trust: i386Scope, fetchBytes: i386 });
    const i386Descriptor = makeDescriptor(i386Scope);
    await i386Host.stager.stage(i386Descriptor);
    expect(
      await i386Host.activator.runNativeAddon({
        taskId: 'task-1',
        descriptor: i386Descriptor,
        run: { kind: 'ADDON_METADATA' },
      }),
    ).toEqual({ ok: false, code: 'HOST_UNSUPPORTED' });
    const garbage = Buffer.from('definitely not a PE image, just filler bytes..........');
    const garbageSha = createHash('sha256').update(garbage).digest('hex');
    const garbageScope: TrustedProviderScope = { ...scope, artifactSha256: garbageSha };
    const garbageHost = makeNativeHost({ trust: garbageScope, fetchBytes: garbage });
    const garbageDescriptor = makeDescriptor(garbageScope);
    await garbageHost.stager.stage(garbageDescriptor);
    expect(
      await garbageHost.activator.runNativeAddon({
        taskId: 'task-1',
        descriptor: garbageDescriptor,
        run: { kind: 'ADDON_METADATA' },
      }),
    ).toEqual({ ok: false, code: 'DEPENDENCIES_UNVERIFIED' });
    expect(i386Host.specs).toHaveLength(0);
    expect(garbageHost.specs).toHaveLength(0);
  });
});

describe('T05 native child — bounded outcome and recovery', () => {
  it('clamps the timeout into the bounded window and reports a real killed child honestly', async () => {
    const { host, descriptor } = await stagedNative({ realProcess: true });
    const clamped = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
      timeoutMs: 999_999,
    });
    expect(clamped).toMatchObject({ ok: true });
    expect(host.specs[0]?.timeoutMs).toBe(120_000);
    // A 1 ms timeout kills the real child mid-flight: an honest timedOut
    // outcome, structured as EXECUTED with the kill surfaced on the outcome.
    const killed = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
      timeoutMs: 1,
    });
    expect(killed).toMatchObject({ ok: true, timedOut: true });
    // Recovery: the next run proceeds normally (fresh per-run staging).
    const recovered = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(recovered).toMatchObject({ ok: true, timedOut: false });
    expect(leftoversUnderActive(host.cacheRoot, 'sharp-binding', addonSha)).toEqual([]);
  });

  it('runs the REAL bootstrap child end-to-end: structured digest-drift and dlopen refusals', async () => {
    const { host, descriptor } = await stagedNative({ realProcess: true });
    // The staged bytes are a structurally valid PE, so the child re-hashes
    // them successfully and fails AT THE DLOPEN with a structured refusal.
    const executed = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(executed).toMatchObject({ ok: true, state: 'EXECUTED', exitCode: 0 });
    if (!executed.ok) return;
    expect(executed.native).toMatchObject({
      ok: false,
      code: 'NATIVE_CHILD_REFUSED',
      childCode: 'DLOPEN_FAILED',
    });
    expect(executed.stderr).toBe('');
    expect(leftoversUnderActive(host.cacheRoot, 'sharp-binding', addonSha)).toEqual([]);
  });

  it('surfaces an unresolvable native child runtime as a refusal (zero spawns)', async () => {
    const { host, descriptor } = await stagedNative({
      host: { hostNativeChildRuntime: () => 'node' },
    });
    const refused = await host.activator.runNativeAddon({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'ADDON_METADATA' },
    });
    expect(refused).toEqual({ ok: false, code: 'NATIVE_RUNTIME_UNAVAILABLE' });
    expect(host.specs).toHaveLength(0);
  });
});

describe('native child bootstrap protocol (real child processes, disposable roots)', () => {
  function runBootstrap(
    payload: unknown,
    env = minimalWindowsSpawnEnvironment(),
  ): Promise<{
    exitCode: number;
    stdout: string;
  }> {
    return new Promise((resolveRun) => {
      const child = spawn(
        process.execPath,
        ['-e', NATIVE_CHILD_BOOTSTRAP_SOURCE, JSON.stringify(payload)],
        {
          env: { ...env },
          windowsHide: true,
          shell: false,
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      let stdout = '';
      child.stdout?.on('data', (chunk: Buffer) => {
        stdout += chunk.toString('utf8');
      });
      child.on('close', (code) => resolveRun({ exitCode: code ?? -1, stdout }));
      child.on('error', () => resolveRun({ exitCode: -1, stdout }));
    });
  }

  it('answers REQUEST_INVALID for a malformed payload', async () => {
    const out = await runBootstrap({ v: 2, op: 'ADDON_METADATA' });
    const parsed = parseNativeChildResult(out.stdout);
    expect(parsed).toMatchObject({
      ok: false,
      code: 'NATIVE_CHILD_REFUSED',
      childCode: 'REQUEST_INVALID',
    });
  });

  it('reports ADDON_DIGEST_MISMATCH for drifting addon bytes', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-t05-bootstrap-'));
    roots.push(dir);
    const addonPath = join(dir, 'addon.node');
    writeFileSync(addonPath, addonImage);
    const otherSha = createHash('sha256').update(Buffer.from('different bytes')).digest('hex');
    const out = await runBootstrap({
      v: 1,
      op: 'ADDON_METADATA',
      addon: { path: addonPath, sha256: otherSha },
      deps: [],
    });
    expect(out.exitCode).toBe(0);
    expect(parseNativeChildResult(out.stdout)).toMatchObject({
      ok: false,
      code: 'NATIVE_CHILD_REFUSED',
      childCode: 'ADDON_DIGEST_MISMATCH',
    });
  });

  it('reports DEPENDENCY_DIGEST_MISMATCH for drifting dependency bytes', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-t05-bootstrap-'));
    roots.push(dir);
    writeFileSync(join(dir, 'addon.node'), addonImage);
    writeFileSync(join(dir, DEP_NAME), depImage);
    const out = await runBootstrap({
      v: 1,
      op: 'ADDON_METADATA',
      addon: { path: join(dir, 'addon.node'), sha256: addonSha },
      deps: [
        {
          name: DEP_NAME,
          sha256: createHash('sha256').update(Buffer.from('x')).digest('hex'),
          path: join(dir, DEP_NAME),
        },
      ],
    });
    expect(parseNativeChildResult(out.stdout)).toMatchObject({
      ok: false,
      childCode: 'DEPENDENCY_DIGEST_MISMATCH',
    });
  });

  it('refuses a dependency outside the addon directory (REQUEST_INVALID)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-t05-bootstrap-'));
    roots.push(dir);
    writeFileSync(join(dir, 'addon.node'), addonImage);
    const otherDir = mkdtempSync(join(tmpdir(), 'shun-t05-bootstrap-other-'));
    roots.push(otherDir);
    const outside = join(otherDir, DEP_NAME);
    writeFileSync(outside, depImage);
    const out = await runBootstrap({
      v: 1,
      op: 'ADDON_METADATA',
      addon: { path: join(dir, 'addon.node'), sha256: addonSha },
      deps: [{ name: DEP_NAME, sha256: depSha, path: outside }],
    });
    expect(parseNativeChildResult(out.stdout)).toMatchObject({
      ok: false,
      childCode: 'REQUEST_INVALID',
    });
  });
});

describe('parent-side child-response validation', () => {
  it('re-validates and caps every field of a structured metadata report', () => {
    const line = `${NATIVE_CHILD_RESULT_PREFIX}${JSON.stringify({
      ok: true,
      kind: 'IMAGE_METADATA',
      metadata: {
        width: 3,
        format: 'png',
        nested: { evil: true },
        list: [1, 2],
        boolField: true,
      },
      childAbi: '137',
      childNode: 'v24.0.0',
    })}\n`;
    const parsed = parseNativeChildResult(line);
    expect(parsed).toMatchObject({ ok: true });
    if (!parsed.ok) return;
    if (parsed.report.kind !== 'IMAGE_METADATA') return;
    expect(parsed.report.metadata).toEqual({ width: 3, format: 'png', boolField: true });
  });

  it('finds the result line among trailing noise and refuses unparsable output', () => {
    const noise = 'some warning\n';
    const line = `${NATIVE_CHILD_RESULT_PREFIX}${JSON.stringify({
      ok: true,
      kind: 'ADDON_METADATA',
      exportCount: 1,
      exports: ['only'],
      addonType: 'function',
      childAbi: '137',
      childNode: 'v24',
    })}\n`;
    expect(parseNativeChildResult(`${noise}${line}${noise}`)).toMatchObject({ ok: true });
    expect(parseNativeChildResult('total garbage without any result line')).toEqual({
      ok: false,
      code: 'NATIVE_CHILD_NO_RESULT',
    });
    expect(parseNativeChildResult(`${NATIVE_CHILD_RESULT_PREFIX}{"ok":"neither"}\n`)).toEqual({
      ok: false,
      code: 'NATIVE_CHILD_NO_RESULT',
    });
  });

  it('maps a structured child refusal with its code', () => {
    const line = `${NATIVE_CHILD_RESULT_PREFIX}${JSON.stringify({
      ok: false,
      code: 'METADATA_FAILED',
      message: 'Input file has corrupt header',
    })}\n`;
    expect(parseNativeChildResult(line)).toEqual({
      ok: false,
      code: 'NATIVE_CHILD_REFUSED',
      childCode: 'METADATA_FAILED',
      message: 'Input file has corrupt header',
    });
  });
});

describe('native PE import scanner', () => {
  it('parses the synthetic images and fails closed on truncated or foreign bytes', async () => {
    const { scanPeImports } = await import('../src/native-pe.ts');
    const dual = buildSynthPe({ imports: ['KERNEL32.dll', 'mydeps.dll'] });
    const scanned = scanPeImports(dual);
    expect(scanned).toMatchObject({ ok: true, machine: 0x8664, pe32Plus: true });
    if (scanned.ok) expect([...scanned.imports].sort()).toEqual(['KERNEL32.dll', 'mydeps.dll']);
    const delayed = buildSynthPe({ imports: [], delayImports: ['ole32.dll', 'shell32.dll'] });
    const delayScan = scanPeImports(delayed);
    expect(delayScan.ok).toBe(true);
    if (delayScan.ok) expect([...delayScan.imports].sort()).toEqual(['ole32.dll', 'shell32.dll']);
    expect(scanPeImports(buildSynthPe({ imports: ['KERNEL32.dll'] }).subarray(0, 0x50))).toEqual({
      ok: false,
      code: 'PE_PARSE_FAILED',
    });
    expect(scanPeImports(Buffer.from('not a PE image at all, just text.........'))).toEqual({
      ok: false,
      code: 'PE_PARSE_FAILED',
    });
  });

  it('treats API-set virtual DLLs as system and everything else as declarable', async () => {
    const { isSystemDllImportName } = await import('../src/native-pe.ts');
    expect(isSystemDllImportName('KERNEL32.dll')).toBe(true);
    expect(isSystemDllImportName('node.exe')).toBe(true);
    expect(isSystemDllImportName('api-ms-win-crt-stdio-l1-1-0.dll')).toBe(true);
    expect(isSystemDllImportName('IPHLPAPI.DLL')).toBe(true);
    expect(isSystemDllImportName('vcruntime140.dll')).toBe(true);
    expect(isSystemDllImportName('libvips-42.dll')).toBe(false);
    expect(isSystemDllImportName('evil_overlay.dll')).toBe(false);
  });
});

describe('native PE scanner against the genuine sharp/libvips closure shape', () => {
  it('accepts exactly the system∪declared import surface of the real 0.35.5 win32-x64 images', async () => {
    // Recorded from the real @img/sharp-win32-x64@0.35.5 images (see the T05
    // native evidence run): the addon imports kernel32, node.exe and the two
    // libvips DLLs; libvips-cpp imports kernel32 and libvips-42; libvips-42
    // imports only system/API-set DLLs.
    const { isSystemDllImportName } = await import('../src/native-pe.ts');
    const addonImports = ['KERNEL32.dll', 'libvips-42.dll', 'libvips-cpp-8.18.7.dll', 'node.exe'];
    const declared = new Set(['libvips-42.dll', 'libvips-cpp-8.18.7.dll']);
    for (const name of addonImports) {
      expect(isSystemDllImportName(name) || declared.has(name.toLowerCase())).toBe(true);
    }
    const libvipsImports = [
      'KERNEL32.dll',
      'api-ms-win-crt-stdio-l1-1-0.dll',
      'ADVAPI32.dll',
      'SHELL32.dll',
      'ole32.dll',
      'USER32.dll',
      'WS2_32.dll',
      'ntdll.dll',
      'bcryptprimitives.dll',
      'bcrypt.dll',
      'IPHLPAPI.DLL',
      'SHLWAPI.dll',
      'DNSAPI.dll',
    ];
    for (const name of libvipsImports) {
      expect(isSystemDllImportName(name)).toBe(true);
    }
  });
});

describe('native run request sanity', () => {
  it('rejects malformed requests before consulting any authority', async () => {
    const { host, descriptor } = await stagedNative();
    expect(
      await host.activator.runNativeAddon({
        taskId: '',
        descriptor,
        run: { kind: 'ADDON_METADATA' },
      }),
    ).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    expect(
      await host.activator.runNativeAddon({
        taskId: 'task-1',
        descriptor,
        // @ts-expect-error closed world: unknown operations are unexpressible
        run: { kind: 'ARBITRARY', args: ['--evil'] },
      }),
    ).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    expect(
      await host.activator.runNativeAddon({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'IMAGE_METADATA', operand: 'missing.bin' },
      }),
    ).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    expect(host.invocations).toHaveLength(0);
    expect(host.specs).toHaveLength(0);
    expect(existsSync(join(host.cacheRoot, 'active'))).toBe(false);
  });
});
