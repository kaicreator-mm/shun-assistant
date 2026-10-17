import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { mkdir, readdir, rm, symlink } from 'node:fs/promises';
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

const okEffect = (): RunEffectDecision => ({ ok: true, leaseId: randomUUID() });

interface Harness {
  activator: CuratedProviderActivator;
  stager: CuratedProviderStager;
  state: ProviderUseCurrentness;
  specs: ActivationRunSpec[];
  invocations: ResolvedInvocation[];
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
  const invocations: ResolvedInvocation[] = [];
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
    hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
    process: port,
    ...overrides,
  };
  return {
    activator: new CuratedProviderActivator(host),
    stager,
    state,
    specs,
    invocations,
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

/**
 * Residue under active/: anything inside the per-run `exec/` or `sandbox/`
 * containers. The (empty) containers themselves are permanent structure.
 */
async function leftoversUnderActive(cacheRoot: string): Promise<string[]> {
  const active = join(cacheRoot, 'active');
  const out: string[] = [];
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > 8) return;
    let entries: string[];
    try {
      entries = await readdir(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      out.push(full);
      await walk(full, depth + 1);
    }
  };
  for (const container of ['exec', 'sandbox']) {
    await walk(join(active, scope.bindingId, sha, container), 0);
  }
  return out;
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('T05 bounded CLI activation (executes the pinned verified bytes only)', () => {
  it('executes the staged per-run pinned path with a scrubbed bounded spawn surface', async () => {
    const { host, descriptor } = await stagedProvider();
    const result = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'VERSION_PROBE' },
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
    // Per-run private staging directory: fresh random exec/<uuid>/ path.
    expect(spec.executable.includes(join('exec', ''))).toBe(true);
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
      run: { kind: 'VERSION_PROBE' },
      timeoutMs: 10 * 60_000,
    });
    expect(host.specs.at(0)?.timeoutMs).toBe(120_000);
    await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'VERSION_PROBE' },
      timeoutMs: 0,
    });
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
      run: { kind: 'FILE_SEARCH', pattern: 'needle', operands: ['corpus.txt'], lineNumbers: true },
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
      run: { kind: 'VERSION_PROBE' },
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
      run: { kind: 'VERSION_PROBE' },
    });
    expect(result).toEqual({ ok: false, code: 'ARTIFACT_NOT_VERIFIED' });
    expect(host.specs).toHaveLength(0);
  });

  it('refuses unsigned, wrong-key and drifting catalog presentations (zero spawns)', async () => {
    const { host, descriptor } = await stagedProvider();
    const unsignedGarbage = { ...descriptor, curatorSignature: 'not-a-signature' };
    expect(
      await host.activator.runCli({
        taskId: 'task-1',
        descriptor: unsignedGarbage,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'CATALOG_SIGNATURE_INVALID' });
    const forged = makeDescriptor(scope, {}, attackerKey);
    expect(
      await host.activator.runCli({
        taskId: 'task-1',
        descriptor: forged,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'CATALOG_SIGNATURE_INVALID' });
    const downgrade = makeDescriptor({ ...scope, version: '14.1.0' });
    expect(
      await host.activator.runCli({
        taskId: 'task-1',
        descriptor: downgrade,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
    expect(host.specs).toHaveLength(0);
  });

  it('refuses stale, denied or unreadable ActionController currentness before any spawn', async () => {
    const { descriptor } = await stagedProvider();
    const unresolvable = makeHost(scope, {
      getAuthorizedCurrentness: () => ({ kind: 'UNRESOLVABLE' }),
    });
    await unresolvable.stager.stage(descriptor);
    expect(
      await unresolvable.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'AUTHORITY_STALE' });
    const wrongTask = makeHost(scope);
    await wrongTask.stager.stage(descriptor);
    expect(
      await wrongTask.activator.runCli({
        taskId: 'wrong-task',
        descriptor,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'AUTHORITY_STALE' });
    const revoking = makeHost(scope, { requiredRevocationEpoch: () => 2 });
    await revoking.stager.stage(descriptor);
    expect(
      await revoking.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'AUTHORITY_STALE' });
    const throwing = makeHost(scope, {
      getAuthorizedCurrentness: () => {
        throw new Error('authority read failed');
      },
    });
    await throwing.stager.stage(descriptor);
    expect(
      await throwing.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'AUTHORITY_UNAVAILABLE' });
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
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'AUTHORITY_STALE' });
    expect(flipping.specs).toHaveLength(0);
    expect(reads).toBe(2);
  });

  it('refuses non-Windows hosts, ABI drift and unverified dependency closure', async () => {
    const { descriptor } = await stagedProvider();
    const linux = makeHost(scope, { hostPlatform: () => 'linux' });
    await linux.stager.stage(descriptor);
    expect(
      await linux.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'HOST_UNSUPPORTED' });
    const nativeScope: TrustedProviderScope = {
      ...scope,
      artifactKind: 'NATIVE_ADDON',
      abiRevision: '137',
    };
    const nativeDescriptor = makeDescriptor(nativeScope);
    const abiDrift = makeHost(nativeScope, { hostNodeAbi: () => '115' });
    await abiDrift.stager.stage(nativeDescriptor);
    expect(
      await abiDrift.activator.runCli({
        taskId: 'task-1',
        descriptor: nativeDescriptor,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'ABI_MISMATCH' });
    const nativeMatching = makeHost(nativeScope);
    await nativeMatching.stager.stage(nativeDescriptor);
    expect(
      await nativeMatching.activator.runCli({
        taskId: 'task-1',
        descriptor: nativeDescriptor,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'ACTIVATION_KIND_UNSUPPORTED' });
    const withDeps = await stagedProvider(scope, { dependencySha256: ['c'.repeat(64)] });
    expect(
      await withDeps.host.activator.runCli({
        taskId: 'task-1',
        descriptor: withDeps.descriptor,
        run: { kind: 'VERSION_PROBE' },
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
        run: { kind: 'VERSION_PROBE' },
      });
      expect(result).toEqual({ ok: false, code: 'ENTRYPOINT_INVALID' });
    }
    // A dot-bearing but path-free file name is a legal bare segment and runs.
    const dotted = makeDescriptor(scope, { entrypoint: '.hidden..exe2' });
    expect(
      await host.activator.runCli({
        taskId: 'task-1',
        descriptor: dotted,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toMatchObject({ ok: true, state: 'EXECUTED' });
    // An empty entrypoint cannot pass the frozen catalog schema at all.
    expect(
      await host.activator.runCli({
        taskId: 'task-1',
        descriptor: makeDescriptor(scope, { entrypoint: '' }),
        run: { kind: 'VERSION_PROBE' },
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
    const invalidRuns: unknown[] = [
      null,
      {},
      { kind: 'SHELL_OUT', command: 'del /q *' },
      { kind: 'FILE_SEARCH' },
      { kind: 'FILE_SEARCH', pattern: '', operands: ['.'] },
      { kind: 'FILE_SEARCH', pattern: 'bad\u0000nul', operands: ['.'] },
      { kind: 'FILE_SEARCH', pattern: 'ok', operands: [] },
      { kind: 'FILE_SEARCH', pattern: 'ok', operands: Array.from({ length: 17 }, () => '.') },
      { kind: 'FILE_SEARCH', pattern: 'ok', operands: ['a.txt', 'a.txt'] },
      { kind: 'FILE_SEARCH', pattern: 'ok', operands: ['.'], lineNumbers: 'yes' },
    ];
    for (const run of invalidRuns) {
      expect(
        await counting.activator.runCli({
          taskId: 'task-1',
          descriptor,
          run: run as never,
        }),
      ).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    }
    expect(
      await counting.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'FILE_SEARCH', pattern: 'ok', operands: ['.'] },
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
    expect(
      await flaky.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toEqual({ ok: false, code: 'ACTIVATION_INTERRUPTED' });
    fail = false;
    expect(
      await flaky.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'VERSION_PROBE' },
      }),
    ).toMatchObject({ ok: true, state: 'EXECUTED', stdout: 'recovered' });
    expect(host.specs).toHaveLength(0);
  });

  it('stages a fresh per-run executable every run, so tampered leftovers never run', async () => {
    const { host, descriptor } = await stagedProvider();
    const first = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'VERSION_PROBE' },
    });
    expect(first).toMatchObject({ ok: true });
    // Everything a run materializes under active/ is cleaned up afterwards.
    expect(await leftoversUnderActive(host.cacheRoot)).toEqual([]);
    // The old shared active/<binding>/<sha>/rg.exe path no longer exists at all.
    expect(existsSync(join(host.cacheRoot, 'active', 'rg-binding', sha, 'rg.exe'))).toBe(false);
    // A leftover tampered artifact from any older layout must not help or
    // hurt: the next run re-stages fresh bytes in a fresh random directory.
    const second = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'VERSION_PROBE' },
    });
    expect(second).toMatchObject({ ok: true, exitCode: 0 });
    expect(host.specs.at(0)?.executable).not.toBe(host.specs.at(1)?.executable);
    expect(await leftoversUnderActive(host.cacheRoot)).toEqual([]);
  });
});

describe('R1 #145 F01 — closed-world typed grammar (no arbitrary argv channel)', () => {
  it('derives the FULL spawn argv from the typed operation, byte for byte', async () => {
    const { host, descriptor } = await stagedProvider();
    await host.stager.stage(descriptor);
    const files = [
      { name: 'corpus.txt', bytes: Buffer.from('haystack needle hay') },
      { name: 'more.txt', bytes: Buffer.from('needle two') },
    ];
    const result = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: {
        kind: 'FILE_SEARCH',
        pattern: 'needle',
        operands: ['corpus.txt', 'more.txt'],
        lineNumbers: true,
      },
      sandboxFiles: files,
    });
    expect(result).toMatchObject({ ok: true });
    expect(host.specs.at(0)?.args).toEqual([
      '-n',
      '--no-heading',
      '-e',
      'needle',
      '--',
      'corpus.txt',
      'more.txt',
    ]);
    const probe = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'VERSION_PROBE' },
    });
    expect(probe).toMatchObject({ ok: true });
    expect(host.specs.at(1)?.args).toEqual(['--version']);
  });

  it('cannot be coaxed into process-opening or config-loading flags', async () => {
    const { descriptor } = await stagedProvider();
    let authorityReads = 0;
    const seen: ActivationRunSpec[] = [];
    const counting = makeHost(scope, {
      getAuthorizedCurrentness: () => {
        authorityReads += 1;
        return currentness();
      },
      process: {
        async run(spec: ActivationRunSpec): Promise<ActivationProcessOutcome> {
          seen.push(spec);
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
    });
    await counting.stager.stage(descriptor);
    // Operand slot: flag-shaped strings are never seeded names → refused as
    // malformed requests before ANY authority read or spawn.
    for (const smuggled of ['--pre', '--pre-glob', '-f', '--config', '@response-file']) {
      const viaOperand = await counting.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'FILE_SEARCH', pattern: 'x', operands: [smuggled] },
        sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('x') }],
      });
      expect(viaOperand).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    }
    expect(seen).toHaveLength(0);
    expect(authorityReads).toBe(0);
    // Pattern slot: even a flag-shaped PATTERN is inert — it is bound as the
    // `-e` VALUE before the `--` separator, so rg can never parse it as a
    // flag. The spawn seam proves the exact inert argv.
    for (const inert of ['--pre', '-f', '--pre=something']) {
      const asPattern = await counting.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'FILE_SEARCH', pattern: inert, operands: ['corpus.txt'] },
        sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('x') }],
      });
      expect(asPattern).toMatchObject({ ok: true, state: 'EXECUTED' });
      expect(seen.at(-1)?.args).toEqual(['--no-heading', '-e', inert, '--', 'corpus.txt']);
    }
  });
});

describe('R1 #145 F02 — operands are sandbox-only, everything else refuses closed', () => {
  it.each([
    ['absolute drive path', 'C:\\shun-t05-fixture\\outside.txt'],
    ['absolute posix path', '/etc/outside.txt'],
    ['UNC path', '\\\\attacker-host\\share\\outside.txt'],
    ['parent traversal', '..\\..\\outside.txt'],
    ['traversal segments', 'a/../../outside.txt'],
    ['drive-relative', 'C:outside.txt'],
    ['nested path', 'sub\\outside.txt'],
    ['nested posix path', 'sub/outside.txt'],
    ['unseeded bare name', 'outside.txt'],
    ['pattern-file flag as operand', '-f'],
  ])('refuses %s with zero authority reads and zero spawns', async (_label, operand) => {
    const { descriptor } = await stagedProvider();
    let authorityReads = 0;
    let spawns = 0;
    const counting = makeHost(scope, {
      getAuthorizedCurrentness: () => {
        authorityReads += 1;
        return currentness();
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
    });
    await counting.stager.stage(descriptor);
    const result = await counting.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'FILE_SEARCH', pattern: 'CANARY_NEEDLE', operands: [operand] },
      sandboxFiles: [{ name: 'inside.txt', bytes: Buffer.from('inside content') }],
    });
    expect(result).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    expect(authorityReads).toBe(0);
    expect(spawns).toBe(0);
  });

  it('never touches an outside canary file and leaves no leftovers (real sandbox proof)', async () => {
    const { host, descriptor } = await stagedProvider();
    await host.stager.stage(descriptor);
    // A real canary OUTSIDE the cache root; content must survive byte-exact.
    const outsideDir = mkdtempSync(join(tmpdir(), 'shun-t05-outside-'));
    roots.push(outsideDir);
    const outside = join(outsideDir, 'outside.txt');
    const outsideContent = `CANARY ${randomUUID()}`;
    writeFileSync(outside, outsideContent, 'utf8');
    const refused = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'FILE_SEARCH', pattern: 'CANARY_NEEDLE', operands: [outside] },
      sandboxFiles: [{ name: 'inside.txt', bytes: Buffer.from('inside content') }],
    });
    expect(refused).toEqual({ ok: false, code: 'RUN_REQUEST_INVALID' });
    expect(host.specs).toHaveLength(0);
    expect(readFileSync(outside, 'utf8')).toBe(outsideContent);
    // The approved-path twin still runs normally inside the sandbox.
    const approved = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'FILE_SEARCH', pattern: 'CANARY_NEEDLE', operands: ['inside.txt'] },
      sandboxFiles: [{ name: 'inside.txt', bytes: Buffer.from('CANARY_NEEDLE here') }],
    });
    expect(approved).toMatchObject({ ok: true });
    expect(await leftoversUnderActive(host.cacheRoot)).toEqual([]);
  });
});

describe('R1 #145 F03 — invocation-scoped execution grant (PREPARE never substitutes)', () => {
  it('presents the EXACT derived invocation to authorizeRunEffect before the spawn seam', async () => {
    const { host, descriptor } = await stagedProvider();
    await host.stager.stage(descriptor);
    const result = await host.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'FILE_SEARCH', pattern: 'needle', operands: ['corpus.txt'] },
      sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('needle') }],
    });
    expect(result).toMatchObject({ ok: true });
    expect(host.invocations).toHaveLength(1);
    const invocation = host.invocations.at(0);
    if (!invocation) return;
    expect(invocation.op).toBe('provider.ripgrep.file-search');
    expect(invocation.taskId).toBe('task-1');
    expect(invocation.bindingId).toBe('rg-binding');
    expect(invocation.artifactSha256).toBe(sha);
    expect(invocation.argv).toEqual(['--no-heading', '-e', 'needle', '--', 'corpus.txt']);
    expect(invocation.cwd.startsWith(join(host.cacheRoot, 'active'))).toBe(true);
    expect(invocation.executablePath.startsWith(join(host.cacheRoot, 'active'))).toBe(true);
    expect(invocation.writeRoots).toEqual([invocation.cwd]);
    expect(invocation.readRoots).toContain(invocation.cwd);
  });

  it('refuses execution when the invocation-scoped grant does not match this call', async () => {
    const { descriptor } = await stagedProvider();
    let spawns = 0;
    // The registered grant names ONLY `rg --version` for this task (the R1
    // falsifier shape). A file search is a DIFFERENT effect and must never
    // inherit it — even though PREPARE_PROVIDER currentness is fully CURRENT.
    const versionOnly = makeHost(scope, {
      authorizeRunEffect: async (invocation) =>
        invocation.op === 'provider.version.probe'
          ? okEffect()
          : { ok: false, code: 'EFFECT_NOT_AUTHORIZED' },
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
    });
    await versionOnly.stager.stage(descriptor);
    const refused = await versionOnly.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'FILE_SEARCH', pattern: 'needle', operands: ['corpus.txt'] },
      sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('needle') }],
    });
    expect(refused).toEqual({ ok: false, code: 'EFFECT_NOT_AUTHORIZED' });
    expect(spawns).toBe(0);
    expect(versionOnly.specs).toHaveLength(0);
    expect(await leftoversUnderActive(versionOnly.cacheRoot)).toEqual([]);
  });

  it('passes authority refusals of the effect gate through verbatim (zero spawns)', async () => {
    const { descriptor } = await stagedProvider();
    for (const code of ['AUTHORITY_STALE', 'AUTHORITY_UNAVAILABLE'] as const) {
      const refusing = makeHost(scope, {
        authorizeRunEffect: async () => ({ ok: false, code }),
      });
      await refusing.stager.stage(descriptor);
      const refused = await refusing.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'VERSION_PROBE' },
      });
      expect(refused).toEqual({ ok: false, code });
      expect(refusing.specs).toHaveLength(0);
      expect(await leftoversUnderActive(refusing.cacheRoot)).toEqual([]);
    }
  });

  it('throws a configuration refusal when the effect port is missing', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-t05-activation-'));
    roots.push(dir);
    const verifier = new CuratedProviderVerifier(
      [
        {
          keyId: 'key-1',
          publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        },
      ],
      [scope],
    );
    const incomplete = {
      verifier,
      stager: new CuratedProviderStager({ cacheRoot: dir, verifier, isOffline: () => false }),
      cacheRoot: dir,
      getAuthorizedCurrentness: () => currentness(),
      requiredRevocationEpoch: () => 1,
      hostPlatform: () => 'win32',
      hostArchitecture: () => 'x64',
      hostNodeAbi: () => '137',
      hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
    } as unknown as TrustedActivationHost;
    expect(() => new CuratedProviderActivator(incomplete)).toThrow(
      'PROVIDER_ACTIVATION_CONFIGURATION_REFUSED',
    );
  });
});

describe('R1 #145 F04 — executable identity across verify→spawn (per-run private staging)', () => {
  it('refuses with zero spawns when the staged EXE bytes are swapped after verification', async () => {
    const { descriptor } = await stagedProvider();
    let spawns = 0;
    let sabotagedPath = '';
    let sabotaged = false;
    const swapping = makeHost(scope, {
      authorizeRunEffect: async (invocation) => {
        // Adversary with same-privilege write access strikes AFTER staging and
        // BEFORE the last boundary — once. Harmless sentinel bytes, disposable
        // root. The runtime shares delete/write, so this overwrite lands.
        if (!sabotaged) {
          sabotaged = true;
          sabotagedPath = invocation.executablePath;
          writeFileSync(invocation.executablePath, Buffer.from('sentinel: not the pinned bytes'));
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
    });
    await swapping.stager.stage(descriptor);
    const refused = await swapping.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'VERSION_PROBE' },
    });
    expect(sabotagedPath).not.toBe('');
    expect(refused).toEqual({ ok: false, code: 'EXECUTABLE_IDENTITY_DRIFT' });
    expect(spawns).toBe(0);
    expect(swapping.specs).toHaveLength(0);
    expect(await leftoversUnderActive(swapping.cacheRoot)).toEqual([]);
    // A clean next run stages fresh verified bytes and executes normally.
    const recovered = await swapping.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'VERSION_PROBE' },
    });
    expect(recovered).toMatchObject({ ok: true, exitCode: 0 });
  });

  it('refuses when the staged EXE is deleted after verification (zero spawns)', async () => {
    const { descriptor } = await stagedProvider();
    let spawns = 0;
    let deleted = false;
    const deleting = makeHost(scope, {
      authorizeRunEffect: async (invocation) => {
        // The runtime shares delete: a same-privilege adversary CAN unlink
        // the staged executable before the spawn seam. The last-boundary
        // identity check must catch it with zero spawns.
        if (!deleted) {
          deleted = true;
          await rm(invocation.executablePath, { force: true });
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
    });
    await deleting.stager.stage(descriptor);
    const refused = await deleting.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'VERSION_PROBE' },
    });
    expect(deleted).toBe(true);
    expect(refused).toEqual({ ok: false, code: 'EXECUTABLE_IDENTITY_DRIFT' });
    expect(spawns).toBe(0);
    expect(deleting.specs).toHaveLength(0);
  });

  it.skipIf(!win)(
    'refuses a junction swapped in over a seeded sandbox operand (zero spawns)',
    { timeout: 30_000 },
    async () => {
      const { descriptor } = await stagedProvider();
      let spawns = 0;
      const juggling = makeHost(scope, {
        authorizeRunEffect: async (invocation) => {
          // Redirect the seeded operand through a junction to a disposable
          // outside directory. Windows junctions need no privilege, mirroring
          // the real attacker capability; the boundary check must refuse.
          const outside = mkdtempSync(join(tmpdir(), 'shun-t05-junction-'));
          roots.push(outside);
          writeFileSync(join(outside, 'corpus.txt'), Buffer.from('OUTSIDE CANARY NEEDLE'));
          const operandPath = join(invocation.cwd, 'corpus.txt');
          await rm(operandPath, { force: true });
          await symlink(outside, operandPath, 'junction');
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
      });
      await juggling.stager.stage(descriptor);
      const refused = await juggling.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'FILE_SEARCH', pattern: 'needle', operands: ['corpus.txt'] },
        sandboxFiles: [{ name: 'corpus.txt', bytes: Buffer.from('inside needle') }],
      });
      expect(refused).toEqual({ ok: false, code: 'SANDBOX_UNSAFE' });
      expect(spawns).toBe(0);
      expect(juggling.specs).toHaveLength(0);
      expect(await leftoversUnderActive(juggling.cacheRoot)).toEqual([]);
    },
  );

  it.skipIf(!win)(
    'refuses a cache root reached through a junctioned ancestor (unanchored chain)',
    { timeout: 30_000 },
    async () => {
      // The cache root itself is reached THROUGH a junction: the chain check
      // must refuse before anything is staged or spawned.
      const base = mkdtempSync(join(tmpdir(), 'shun-t05-anchor-'));
      roots.push(base);
      const realDir = join(base, 'real');
      const linkDir = join(base, 'link');
      await mkdir(realDir, { recursive: true });
      await symlink(realDir, linkDir, 'junction');
      const host = makeHost(scope, { cacheRoot: join(linkDir, 'cache') });
      const descriptor = makeDescriptor();
      await host.stager.stage(descriptor);
      const refused = await host.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'VERSION_PROBE' },
      });
      expect(refused).toEqual({ ok: false, code: 'ACTIVATION_CACHE_UNAVAILABLE' });
      expect(host.specs).toHaveLength(0);
    },
  );

  it.skipIf(win)(
    'refuses a symlink swapped in over the staged executable (zero spawns)',
    async () => {
      const { descriptor } = await stagedProvider();
      let spawns = 0;
      const linking = makeHost(scope, {
        authorizeRunEffect: async (invocation) => {
          const outside = mkdtempSync(join(tmpdir(), 'shun-t05-symlink-'));
          roots.push(outside);
          writeFileSync(join(outside, 'rg.exe'), Buffer.from('sentinel outside bytes'));
          await rm(invocation.executablePath, { force: true });
          await symlink(join(outside, 'rg.exe'), invocation.executablePath);
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
      });
      await linking.stager.stage(descriptor);
      const refused = await linking.activator.runCli({
        taskId: 'task-1',
        descriptor,
        run: { kind: 'VERSION_PROBE' },
      });
      expect(refused).toEqual({ ok: false, code: 'EXECUTABLE_IDENTITY_DRIFT' });
      expect(spawns).toBe(0);
      expect(linking.specs).toHaveLength(0);
    },
  );
});

describe('R1 #145 F05 — revocation moving at the last boundary yields zero invocations', () => {
  it('flipping the revocation epoch during setup voids the run before the process seam', async () => {
    const { descriptor } = await stagedProvider();
    const epoch = { value: 1 };
    let spawns = 0;
    let effectGateCalls = 0;
    const racing = makeHost(scope, {
      requiredRevocationEpoch: () => epoch.value,
      // The injected setup seam: flipping happens DURING the run, after
      // staging/sandbox work and just before the process-port call.
      hostSpawnEnvironment: () => {
        epoch.value = 2;
        return minimalWindowsSpawnEnvironment();
      },
      authorizeRunEffect: async (_invocation) => {
        effectGateCalls += 1;
        // Real composition semantics: the grant was minted under epoch 1.
        return epoch.value === 1 ? okEffect() : { ok: false, code: 'AUTHORITY_STALE' };
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
    });
    await racing.stager.stage(descriptor);
    const refused = await racing.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'VERSION_PROBE' },
    });
    expect(refused).toEqual({ ok: false, code: 'AUTHORITY_STALE' });
    expect(effectGateCalls).toBe(1);
    expect(spawns).toBe(0);
    expect(racing.specs).toHaveLength(0);
    expect(await leftoversUnderActive(racing.cacheRoot)).toEqual([]);
  });

  it('still denies at the effect gate when only the port observes the revocation', async () => {
    const { descriptor } = await stagedProvider();
    let spawns = 0;
    const revokedLate = makeHost(scope, {
      hostSpawnEnvironment: () => {
        // Simulates the composition observing a revocation that reached the
        // substrate after admission: the effect gate re-reads CURRENT state.
        return minimalWindowsSpawnEnvironment();
      },
      authorizeRunEffect: async () => ({ ok: false, code: 'AUTHORITY_STALE' }),
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
    });
    await revokedLate.stager.stage(descriptor);
    const refused = await revokedLate.activator.runCli({
      taskId: 'task-1',
      descriptor,
      run: { kind: 'VERSION_PROBE' },
    });
    expect(refused).toEqual({ ok: false, code: 'AUTHORITY_STALE' });
    expect(spawns).toBe(0);
    expect(revokedLate.specs).toHaveLength(0);
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
