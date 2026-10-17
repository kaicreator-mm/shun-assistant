import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
  type TrustedActivationHost,
} from '../src/activation.ts';
import type { ProviderUseCurrentness } from '../src/preflight.ts';
import { CuratedProviderStager } from '../src/staging.ts';

const keyPair = generateKeyPairSync('ed25519');
const attackerKey = generateKeyPairSync('ed25519');
const bytes = Buffer.from('bounded fake CLI payload; the unit suite never executes it');
const sha = createHash('sha256').update(bytes).digest('hex');
const roots: string[] = [];
const win = process.platform === 'win32';
const scope: TrustedProviderScope = {
  providerId: 'rg',
  capabilityId: 'file.search',
  version: '14.1.1',
  catalogRevision: 'catalog-r1',
  bindingId: 'rg-binding',
  scopedVerifierId: 'safe-verifier',
  catalogManifestSha256: 'a'.repeat(64),
  bindingEvidenceSha256: 'b'.repeat(64),
  artifactSha256: sha,
  origin: 'https://trusted.invalid/rg.exe',
  platform: 'windows-x64',
  artifactKind: 'CLI',
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
  const unsigned = {
    ...trust,
    entrypoint: trust.artifactKind === 'CLI' ? 'rg.exe' : 'addon.node',
    signerKeyId: 'key-1',
    dependencySha256: [] as string[],
    ...overrides,
  };
  return {
    ...unsigned,
    curatorSignature: sign(null, Buffer.from(canonicalJson(unsigned)), signer.privateKey).toString(
      'base64',
    ),
  };
}

interface Harness {
  activator: CuratedProviderActivator;
  stager: CuratedProviderStager;
  state: ProviderUseCurrentness;
  specs: ActivationRunSpec[];
  cacheRoot: string;
}

function makeHost(
  trust: TrustedProviderScope = scope,
  overrides: Partial<TrustedActivationHost> = {},
): Harness {
  const dir = mkdtempSync(join(tmpdir(), 'shun-t05-activation-'));
  roots.push(dir);
  const verifier = new CuratedProviderVerifier(
    [
      {
        keyId: 'key-1',
        publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      },
    ],
    [trust],
  );
  const stager = new CuratedProviderStager({
    cacheRoot: dir,
    verifier,
    isOffline: () => false,
    fetchArtifact: (async () => new Response(bytes, { status: 200 })) as typeof fetch,
  });
  const state = currentness(trust);
  const specs: ActivationRunSpec[] = [];
  const scripted: ActivationProcessOutcome = {
    exitCode: 0,
    stdout: 'ripgrep 14.1.1',
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
  const host: TrustedActivationHost = {
    verifier,
    stager,
    cacheRoot: dir,
    getAuthorizedCurrentness: () => state,
    requiredRevocationEpoch: () => 1,
    hostPlatform: () => 'win32',
    hostArchitecture: () => 'x64',
    hostNodeAbi: () => '137',
    hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
    process: port,
    ...overrides,
  };
  return {
    activator: new CuratedProviderActivator(host),
    stager,
    state,
    specs,
    cacheRoot: dir,
  };
}

async function stagedProvider(
  trust: TrustedProviderScope = scope,
  overrides: Record<string, unknown> = {},
): Promise<{ host: Harness; descriptor: ReturnType<typeof makeDescriptor> }> {
  const host = makeHost(trust);
  const descriptor = makeDescriptor(trust, overrides);
  expect((await host.stager.stage(descriptor)).ok).toBe(true);
  return { host, descriptor };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('T05 bounded CLI activation (executes the pinned verified bytes only)', () => {
  it('executes the materialized pinned path with a scrubbed bounded spawn surface', async () => {
    const { host, descriptor } = await stagedProvider();
    const result = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      args: ['--version'],
    });
    expect(result).toMatchObject({
      ok: true,
      state: 'EXECUTED',
      bindingId: 'rg-binding',
      digest: sha,
      exitCode: 0,
      stdout: 'ripgrep 14.1.1',
      timedOut: false,
    });
    expect(host.specs).toHaveLength(1);
    const spec = host.specs.at(0);
    if (!spec) return;
    expect(spec.executable.startsWith(join(host.cacheRoot, 'active', 'rg-binding', sha))).toBe(
      true,
    );
    expect(spec.executable.endsWith('rg.exe')).toBe(true);
    expect(spec.args).toEqual(['--version']);
    expect(spec.cwd.startsWith(join(host.cacheRoot, 'active', 'rg-binding', sha))).toBe(true);
    // The child env is exactly the composed scrubbed allowlist — whatever the
    // platform provides (empty on Linux CI), never the parent environment.
    expect(spec.env).toEqual(minimalWindowsSpawnEnvironment());
    expect(Object.keys(spec.env).every((key) => ['SystemRoot', 'SystemDrive'].includes(key))).toBe(
      true,
    );
    expect(spec.env.PATH).toBeUndefined();
    expect(spec.timeoutMs).toBeGreaterThan(0);
  });

  it('clamps the run timeout into a fixed bounded window', async () => {
    const { host, descriptor } = await stagedProvider();
    await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      args: ['x'],
      timeoutMs: 10 * 60_000,
    });
    expect(host.specs.at(0)?.timeoutMs).toBe(120_000);
    await host.activator.runCli({ taskId: 'task-1', descriptor, args: ['x'], timeoutMs: 0 });
    expect(host.specs.at(1)?.timeoutMs).toBe(1);
  });

  it('seeds declared sandbox inputs inside the sandbox only', async () => {
    const { descriptor } = await stagedProvider();
    let seeded: string | undefined;
    const probing = {
      async run(spec: ActivationRunSpec): Promise<ActivationProcessOutcome> {
        seeded = readFileSync(join(spec.cwd, 'corpus.txt'), 'utf8');
        return {
          exitCode: 0,
          stdout: '',
          stderr: '',
          timedOut: false,
          stdoutTruncated: false,
          stderrTruncated: false,
        };
      },
    };
    const host = makeHost(scope, { process: probing });
    await host.stager.stage(descriptor);
    const result = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      args: ['-n', 'needle', 'corpus.txt'],
      sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('haystack needle hay') }],
    });
    expect(result).toMatchObject({ ok: true });
    expect(seeded).toBe('haystack needle hay');
  });

  it('refuses to run before verified cache bytes exist (zero spawns)', async () => {
    const host = makeHost();
    const result = await host.activator.runCli({
      taskId: 'task-1',
      descriptor: makeDescriptor(),
      args: ['--version'],
    });
    expect(result).toEqual({ ok: false, code: 'ARTIFACT_NOT_VERIFIED' });
    expect(host.specs).toHaveLength(0);
  });

  it('refuses tampered cached bytes before any spawn', async () => {
    const { host, descriptor } = await stagedProvider();
    writeFileSync(join(host.cacheRoot, 'artifacts', sha), Buffer.from('tampered payload bytes'));
    const result = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      args: ['--version'],
    });
    expect(result).toEqual({ ok: false, code: 'ARTIFACT_NOT_VERIFIED' });
    expect(host.specs).toHaveLength(0);
  });

  it('refuses unsigned, wrong-key and drifting catalog presentations (zero spawns)', async () => {
    const { host, descriptor } = await stagedProvider();
    const unsignedGarbage = { ...descriptor, curatorSignature: 'not-a-signature' };
    expect(
      await host.activator.runCli({ taskId: 'task-1', descriptor: unsignedGarbage, args: [] }),
    ).toEqual({ ok: false, code: 'CATALOG_SIGNATURE_INVALID' });
    const forged = makeDescriptor(scope, {}, attackerKey);
    expect(await host.activator.runCli({ taskId: 'task-1', descriptor: forged, args: [] })).toEqual(
      { ok: false, code: 'CATALOG_SIGNATURE_INVALID' },
    );
    const downgrade = makeDescriptor({ ...scope, version: '14.1.0' });
    expect(
      await host.activator.runCli({ taskId: 'task-1', descriptor: downgrade, args: [] }),
    ).toEqual({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
    expect(host.specs).toHaveLength(0);
  });

  it('refuses stale, denied or unreadable ActionController currentness before any spawn', async () => {
    const { descriptor } = await stagedProvider();
    const unresolvable = makeHost(scope, {
      getAuthorizedCurrentness: () => ({ kind: 'UNRESOLVABLE' }),
    });
    await unresolvable.stager.stage(descriptor);
    expect(await unresolvable.activator.runCli({ taskId: 'task-1', descriptor, args: [] })).toEqual(
      { ok: false, code: 'AUTHORITY_STALE' },
    );
    const wrongTask = makeHost(scope);
    await wrongTask.stager.stage(descriptor);
    expect(
      await wrongTask.activator.runCli({ taskId: 'wrong-task', descriptor, args: [] }),
    ).toEqual({ ok: false, code: 'AUTHORITY_STALE' });
    const revoking = makeHost(scope, { requiredRevocationEpoch: () => 2 });
    await revoking.stager.stage(descriptor);
    expect(await revoking.activator.runCli({ taskId: 'task-1', descriptor, args: [] })).toEqual({
      ok: false,
      code: 'AUTHORITY_STALE',
    });
    const throwing = makeHost(scope, {
      getAuthorizedCurrentness: () => {
        throw new Error('authority read failed');
      },
    });
    await throwing.stager.stage(descriptor);
    expect(await throwing.activator.runCli({ taskId: 'task-1', descriptor, args: [] })).toEqual({
      ok: false,
      code: 'AUTHORITY_UNAVAILABLE',
    });
    expect(unresolvable.specs).toHaveLength(0);
    expect(wrongTask.specs).toHaveLength(0);
    expect(revoking.specs).toHaveLength(0);
    expect(throwing.specs).toHaveLength(0);
  });

  it('re-reads the ActionController immediately before exec and refuses mid-call drift', async () => {
    const { descriptor } = await stagedProvider();
    let reads = 0;
    const flipping = makeHost(scope, {
      getAuthorizedCurrentness: () => {
        reads += 1;
        return reads >= 2 ? { kind: 'UNRESOLVABLE' } : currentness();
      },
    });
    await flipping.stager.stage(descriptor);
    expect(
      await flipping.activator.runCli({
        taskId: 'task-1',
        descriptor,
        args: ['--version'],
      }),
    ).toEqual({ ok: false, code: 'AUTHORITY_STALE' });
    expect(flipping.specs).toHaveLength(0);
    expect(reads).toBe(2);
  });

  it('refuses non-Windows hosts, ABI drift and unverified dependency closure', async () => {
    const { descriptor } = await stagedProvider();
    const linux = makeHost(scope, { hostPlatform: () => 'linux' });
    await linux.stager.stage(descriptor);
    expect(await linux.activator.runCli({ taskId: 'task-1', descriptor, args: [] })).toEqual({
      ok: false,
      code: 'HOST_UNSUPPORTED',
    });
    const nativeScope: TrustedProviderScope = {
      ...scope,
      artifactKind: 'NATIVE_ADDON',
      abiRevision: '137',
    };
    const nativeDescriptor = makeDescriptor(nativeScope);
    const abiDrift = makeHost(nativeScope, { hostNodeAbi: () => '115' });
    await abiDrift.stager.stage(nativeDescriptor);
    expect(
      await abiDrift.activator.runCli({ taskId: 'task-1', descriptor: nativeDescriptor, args: [] }),
    ).toEqual({ ok: false, code: 'ABI_MISMATCH' });
    const nativeMatching = makeHost(nativeScope);
    await nativeMatching.stager.stage(nativeDescriptor);
    expect(
      await nativeMatching.activator.runCli({
        taskId: 'task-1',
        descriptor: nativeDescriptor,
        args: [],
      }),
    ).toEqual({ ok: false, code: 'ACTIVATION_KIND_UNSUPPORTED' });
    const withDeps = await stagedProvider(scope, { dependencySha256: ['c'.repeat(64)] });
    expect(
      await withDeps.host.activator.runCli({
        taskId: 'task-1',
        descriptor: withDeps.descriptor,
        args: [],
      }),
    ).toEqual({ ok: false, code: 'DEPENDENCIES_UNVERIFIED' });
    expect(linux.specs).toHaveLength(0);
    expect(abiDrift.specs).toHaveLength(0);
    expect(nativeMatching.specs).toHaveLength(0);
    expect(withDeps.host.specs).toHaveLength(0);
  });

  it('refuses unsafe entrypoint names and never materializes outside the cache root', async () => {
    const { host } = await stagedProvider();
    for (const entrypoint of ['..\\evil.exe', 'sub/dir.exe', 'a/b/c.exe', 'a:b.exe']) {
      const mutated = makeDescriptor(scope, { entrypoint });
      const result = await host.activator.runCli({
        taskId: 'task-1',
        descriptor: mutated,
        args: [],
      });
      expect(result).toEqual({ ok: false, code: 'ENTRYPOINT_INVALID' });
    }
    // A dot-bearing but path-free file name is a legal bare segment and runs.
    const dotted = makeDescriptor(scope, { entrypoint: '.hidden..exe2' });
    expect(
      await host.activator.runCli({ taskId: 'task-1', descriptor: dotted, args: [] }),
    ).toMatchObject({ ok: true, state: 'EXECUTED' });
    // An empty entrypoint cannot pass the frozen catalog schema at all.
    expect(
      await host.activator.runCli({
        taskId: 'task-1',
        descriptor: makeDescriptor(scope, { entrypoint: '' }),
        args: [],
      }),
    ).toEqual({ ok: false, code: 'CATALOG_UNTRUSTED' });
    expect(host.specs).toHaveLength(1);
  });

  it('refuses malformed run requests before consulting any authority', async () => {
    const { descriptor } = await stagedProvider();
    let authorityReads = 0;
    const counting = makeHost(scope, {
      getAuthorizedCurrentness: () => {
        authorityReads += 1;
        return currentness();
      },
    });
    await counting.stager.stage(descriptor);
    expect(
      await counting.activator.runCli({
        taskId: 'task-1',
        descriptor,
        args: Array.from({ length: 33 }, () => 'a'),
      }),
    ).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    expect(
      await counting.activator.runCli({ taskId: 'task-1', descriptor, args: ['bad\0nul'] }),
    ).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    expect(
      await counting.activator.runCli({
        taskId: 'task-1',
        descriptor,
        args: ['ok'],
        sandboxFiles: [{ name: '../escape.txt', bytes: Buffer.from('x') }],
      }),
    ).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    expect(counting.specs).toHaveLength(0);
    expect(authorityReads).toBe(0);
  });

  it('treats a spawn-seam interruption as zero-effect and recovers on the next run', async () => {
    const { host, descriptor } = await stagedProvider();
    let fail = true;
    const flaky = makeHost(scope, {
      process: {
        async run(): Promise<ActivationProcessOutcome> {
          if (fail) throw new Error('spawn seam interrupted');
          return {
            exitCode: 0,
            stdout: 'recovered',
            stderr: '',
            timedOut: false,
            stdoutTruncated: false,
            stderrTruncated: false,
          };
        },
      },
    });
    await flaky.stager.stage(descriptor);
    expect(await flaky.activator.runCli({ taskId: 'task-1', descriptor, args: [] })).toEqual({
      ok: false,
      code: 'ACTIVATION_INTERRUPTED',
    });
    fail = false;
    expect(await flaky.activator.runCli({ taskId: 'task-1', descriptor, args: [] })).toMatchObject({
      ok: true,
      state: 'EXECUTED',
      stdout: 'recovered',
    });
    expect(host.specs).toHaveLength(0);
  });

  it('re-materializes the executable from verified bytes every run, so tampered leftovers never run', async () => {
    const { host, descriptor } = await stagedProvider();
    const executablePath = join(host.cacheRoot, 'active', scope.bindingId, sha, 'rg.exe');
    await host.activator.runCli({ taskId: 'task-1', descriptor, args: [] });
    writeFileSync(executablePath, Buffer.from('attacker replaced these bytes'));
    const second = await host.activator.runCli({ taskId: 'task-1', descriptor, args: [] });
    expect(second).toMatchObject({ ok: true, exitCode: 0 });
    expect(readFileSync(executablePath).equals(bytes)).toBe(true);
  });
});

describe('BoundedSpawnProcess (real transport, unit-scoped)', () => {
  const cmd = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'cmd.exe');
  const powershell = join(
    process.env.SystemRoot ?? 'C:\\Windows',
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  );

  it.skipIf(!win)('spawns without a shell and reports transport facts', async () => {
    const port = new BoundedSpawnProcess();
    const outcome = await port.run({
      executable: cmd,
      args: ['/d', '/s', '/c', 'exit 3'],
      cwd: tmpdir(),
      env: minimalWindowsSpawnEnvironment(),
      timeoutMs: 10_000,
      outputLimitBytes: 1024,
    });
    expect(outcome.exitCode).toBe(3);
    expect(outcome.timedOut).toBe(false);
  });

  it.skipIf(!win)(
    'enforces the hard timeout and marks the run timed out',
    { timeout: 20_000 },
    async () => {
      const port = new BoundedSpawnProcess();
      const outcome = await port.run({
        executable: join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'ping.exe'),
        args: ['-n', '30', '127.0.0.1'],
        cwd: tmpdir(),
        env: minimalWindowsSpawnEnvironment(),
        timeoutMs: 1_000,
        outputLimitBytes: 1024,
      });
      expect(outcome.timedOut).toBe(true);
    },
  );

  it.skipIf(!win)('caps captured output at the configured byte limit', async () => {
    const port = new BoundedSpawnProcess();
    const outcome = await port.run({
      executable: powershell,
      args: ['-NoProfile', '-Command', "Write-Output ([string]::new('x', 5000))"],
      cwd: tmpdir(),
      env: minimalWindowsSpawnEnvironment(),
      timeoutMs: 30_000,
      outputLimitBytes: 1024,
    });
    expect(outcome.stdout.length).toBeLessThanOrEqual(1024);
    expect(outcome.stdoutTruncated).toBe(true);
  });
});
