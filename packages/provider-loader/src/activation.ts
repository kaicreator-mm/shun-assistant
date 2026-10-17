// T05 bounded Provider activation. This is the FIRST slice in the loader that
// executes anything, so every trust input is re-established inside the call
// and immediately again before the spawn:
//
//   signature + pinned scope → ActionController currentness (capability
//   PREPARE_PROVIDER) + revocation epoch → OS/arch → exact-ABI (native) →
//   transitive dependency closure → cache bytes re-hashed → materialize into
//   the Shun-owned cache → REPEAT signature + ActionController re-check →
//   spawn the one pinned absolute path.
//
// Hard surface rules (T05 #106 real-host boundary):
//   - the executable is ONLY the materialized verified bytes; PATH is never
//     consulted (spawn takes one absolute path, scrubbed env has no PATH),
//     no JS require/dynamic import of provider content, no DLL search input.
//   - argv is a bounded string list, cwd/env/timeout/output are host-owned,
//     the sandbox lives under the trusted cache root, never a user path.
//   - native addon activation is NOT implemented in this slice and refuses
//     closed (ACTIVATION_KIND_UNSUPPORTED); the CLI/native proofs stay
//     separate.
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, rm } from 'node:fs/promises';
import { basename, isAbsolute, join, resolve } from 'node:path';
import type {
  CuratedProviderVerifier,
  ProviderVerificationRefusal,
  ProviderVerificationResult,
} from '@shun/vertical-jit';
import type { ProviderUseCurrentness } from './preflight.ts';
import type { CuratedProviderStager } from './staging.ts';

const MAX_RUN_ARGS = 32;
const MAX_ARG_LENGTH = 4096;
const MAX_SANDBOX_FILES = 16;
const MAX_SANDBOX_FILE_BYTES = 1024 * 1024;
const MAX_SANDBOX_TOTAL_BYTES = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 120_000;
const MAX_OUTPUT_BYTES = 1024 * 1024;
/**
 * Reserved Windows path characters beyond separators; never enter a segment.
 * Control characters are exactly what must never appear in a path segment
 * used for process spawn, hence the explicit range.
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional path-segment hardening
const UNSAFE_SEGMENT = /[<>:"/\\|?*\u0000-\u001f]/;

export type ActivationRefusal =
  | 'CATALOG_UNTRUSTED'
  | 'CATALOG_SCOPE_DRIFT'
  | 'CATALOG_SIGNATURE_INVALID'
  | 'AUTHORITY_UNAVAILABLE'
  | 'AUTHORITY_STALE'
  | 'DEPENDENCIES_UNVERIFIED'
  | 'ABI_MISMATCH'
  | 'HOST_UNSUPPORTED'
  | 'ARTIFACT_NOT_VERIFIED'
  | 'ACTIVATION_KIND_UNSUPPORTED'
  | 'ACTIVATION_CACHE_UNAVAILABLE'
  | 'ENTRYPOINT_INVALID'
  | 'ACTIVATION_INTERRUPTED'
  | 'RUN_REQUEST_INVALID';

export interface SandboxInputFile {
  /** Bare file name created inside the per-run sandbox; never a path. */
  readonly name: string;
  readonly bytes: Uint8Array;
}

export interface ActivationRunRequest {
  readonly taskId: string;
  readonly descriptor: unknown;
  /** Bounded typed argv for the pinned executable (argv[0] is never caller-set). */
  readonly args: readonly string[];
  readonly timeoutMs?: number;
  readonly sandboxFiles?: readonly SandboxInputFile[];
}

export type VerifiedCliArtifact = Extract<ProviderVerificationResult, { ok: true }>['artifact'];

export interface ActivationRunOutcome {
  readonly bindingId: string;
  readonly digest: string;
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  readonly durationMs: number;
}

export type ActivationResult =
  | ({ ok: true; state: 'EXECUTED' } & ActivationRunOutcome)
  | { ok: false; code: ActivationRefusal };

/** The exact spawn surface the activator uses; injection point for tests. */
export interface ActivationRunSpec {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  /** Fully scrubbed environment; production passes ONLY the host allowlist. */
  readonly env: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
  readonly outputLimitBytes: number;
}

export interface ActivationProcessOutcome {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
}

export interface ActivationProcessPort {
  run(spec: ActivationRunSpec): Promise<ActivationProcessOutcome>;
}

export type TrustedActivationHost = Readonly<{
  verifier: CuratedProviderVerifier;
  stager: Pick<CuratedProviderStager, 'readVerified'>;
  /**
   * Trusted backend-owned cache root. Materialized executables and run
   * sandboxes live under it; it must never come from a request, Recipe,
   * model or HTTP input.
   */
  cacheRoot: string;
  /** Unforgeable private ActionController port; re-read twice per activation. */
  getAuthorizedCurrentness: (taskId: string, bindingId: string) => ProviderUseCurrentness;
  /** Host product policy owns the exact revoked epoch and never trusts a request. */
  requiredRevocationEpoch: (bindingId: string) => number;
  /** OS/runtime values come from the trusted executor, not request fields. */
  hostPlatform: () => string;
  hostArchitecture: () => string;
  hostNodeAbi: () => string;
  /** Scrubbed spawn environment owned by the trusted host composition. */
  hostSpawnEnvironment: () => Readonly<Record<string, string>>;
  /** Injectable only for tests; production composes BoundedSpawnProcess. */
  process?: ActivationProcessPort;
}>;

/** Production minimal Windows spawn env: nothing beyond CRT bootstrap needs. */
export function minimalWindowsSpawnEnvironment(): Readonly<Record<string, string>> {
  const env: Record<string, string> = {};
  for (const key of ['SystemRoot', 'SystemDrive']) {
    const value = process.env[key];
    if (typeof value === 'string' && value.length > 0 && value.length <= 256) env[key] = value;
  }
  return env;
}

function isSafeSegment(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 128 &&
    value !== '.' &&
    value !== '..' &&
    !UNSAFE_SEGMENT.test(value)
  );
}

function refusalFromVerification(code: ProviderVerificationRefusal): ActivationRefusal {
  switch (code) {
    case 'CATALOG_SCOPE_DRIFT':
    case 'CATALOG_SIGNATURE_INVALID':
      return code;
    default:
      // CATALOG_UNTRUSTED covers schema/scope/key refusals; the digest code
      // never comes back from verify() and means the bytes are not provable.
      return code === 'ARTIFACT_HASH_MISMATCH' ? 'ARTIFACT_NOT_VERIFIED' : 'CATALOG_UNTRUSTED';
  }
}

function validateRunRequest(request: ActivationRunRequest): boolean {
  if (typeof request.taskId !== 'string' || request.taskId.length < 1) return false;
  if (!Array.isArray(request.args) || request.args.length > MAX_RUN_ARGS) return false;
  for (const arg of request.args) {
    if (typeof arg !== 'string' || arg.length > MAX_ARG_LENGTH || arg.includes('\u0000')) {
      return false;
    }
  }
  if (request.timeoutMs !== undefined && !Number.isSafeInteger(request.timeoutMs)) return false;
  const files = request.sandboxFiles ?? [];
  if (files.length > MAX_SANDBOX_FILES) return false;
  let total = 0;
  const seen = new Set<string>();
  for (const file of files) {
    if (!file || !isSafeSegment(file.name) || seen.has(file.name)) return false;
    seen.add(file.name);
    if (!(file.bytes instanceof Uint8Array) || file.bytes.byteLength > MAX_SANDBOX_FILE_BYTES) {
      return false;
    }
    total += file.bytes.byteLength;
    if (total > MAX_SANDBOX_TOTAL_BYTES) return false;
  }
  return true;
}

async function safeReadMaterialized(path: string): Promise<Buffer | null> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const before = await lstat(path);
    if (!before.isFile() || before.isSymbolicLink()) return null;
    const flags = constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW);
    handle = await open(path, flags);
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) return null;
    const bytes = await handle.readFile();
    const after = await lstat(path);
    if (after.isSymbolicLink() || after.dev !== opened.dev || after.ino !== opened.ino) return null;
    return bytes;
  } catch {
    return null;
  } finally {
    try {
      await handle?.close();
    } catch {
      // read-only verification; failure only downgrades to "not verified"
    }
  }
}

interface ByteSink {
  data: Buffer;
  truncated: boolean;
}

/**
 * Real bounded spawn used in production: shell-free, one absolute executable,
 * scrubbed env, byte-capped captured output, hard timeout. The child never
 * receives the parent environment and never inherits a PATH to search.
 */
export class BoundedSpawnProcess implements ActivationProcessPort {
  run(spec: ActivationRunSpec): Promise<ActivationProcessOutcome> {
    return new Promise((resolve) => {
      const out: ByteSink = { data: Buffer.alloc(0), truncated: false };
      const err: ByteSink = { data: Buffer.alloc(0), truncated: false };
      let timedOut = false;
      let settled = false;
      const child = spawn(spec.executable, [...spec.args], {
        cwd: spec.cwd,
        env: { ...spec.env },
        windowsHide: true,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      const append = (sink: ByteSink, chunk: Buffer): void => {
        if (sink.data.length < spec.outputLimitBytes) {
          const room = spec.outputLimitBytes - sink.data.length;
          sink.data =
            sink.data.length === 0
              ? Buffer.from(chunk.subarray(0, room))
              : Buffer.concat([sink.data, chunk.subarray(0, room)]);
          if (chunk.length > room) sink.truncated = true;
        } else {
          sink.truncated = true;
        }
        if (sink.truncated && !child.killed) child.kill();
      };
      child.stdout?.on('data', (chunk: Buffer) => append(out, chunk));
      child.stderr?.on('data', (chunk: Buffer) => append(err, chunk));
      const finish = (exitCode: number): void => {
        if (settled) return;
        settled = true;
        resolve({
          exitCode,
          stdout: out.data.toString('utf8'),
          stderr: err.data.toString('utf8'),
          timedOut,
          stdoutTruncated: out.truncated,
          stderrTruncated: err.truncated,
        });
      };
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill();
      }, spec.timeoutMs);
      child.on('error', () => {
        clearTimeout(timer);
        finish(-1);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        finish(code ?? -1);
      });
    });
  }
}

interface AdmissionSnapshot {
  readonly currentness: ProviderUseCurrentness;
  readonly revokedEpoch: number;
  readonly platform: string;
  readonly arch: string;
  readonly abi: string;
}

type AdmissionOutcome =
  | { readonly ok: true; readonly revokedEpoch: number }
  | { readonly ok: false; readonly code: ActivationRefusal };

/**
 * Executes the verified CLI provider bytes in a bounded sandbox. This class
 * is the privileged half of the loader: every call re-derives trust from the
 * pinned verifier and the ActionController port, materializes the one
 * executable from re-hashed cache bytes, re-checks the ActionController
 * immediately before spawn, and never consults PATH, shell or dynamic imports.
 */
export class CuratedProviderActivator {
  private readonly host: TrustedActivationHost;
  private readonly root: string;
  private readonly processPort: ActivationProcessPort;

  constructor(host: TrustedActivationHost) {
    if (
      !host?.verifier ||
      typeof host.verifier.verify !== 'function' ||
      !host.stager ||
      typeof host.stager.readVerified !== 'function' ||
      !isAbsolute(host.cacheRoot) ||
      typeof host.getAuthorizedCurrentness !== 'function' ||
      typeof host.requiredRevocationEpoch !== 'function' ||
      typeof host.hostPlatform !== 'function' ||
      typeof host.hostArchitecture !== 'function' ||
      typeof host.hostNodeAbi !== 'function' ||
      typeof host.hostSpawnEnvironment !== 'function'
    ) {
      throw new Error('PROVIDER_ACTIVATION_CONFIGURATION_REFUSED');
    }
    this.host = host;
    this.root = resolve(host.cacheRoot);
    this.processPort = host.process ?? new BoundedSpawnProcess();
  }

  async runCli(request: ActivationRunRequest): Promise<ActivationResult> {
    const started = Date.now();
    if (!validateRunRequest(request)) return { ok: false, code: 'RUN_REQUEST_INVALID' };
    // 1+2. Signature + pinned scope, and the first ActionController read.
    let proof: ProviderVerificationResult;
    try {
      proof = this.host.verifier.verify(request.descriptor);
    } catch {
      return { ok: false, code: 'CATALOG_UNTRUSTED' };
    }
    if (!proof.ok) return { ok: false, code: refusalFromVerification(proof.code) };
    const artifact = proof.artifact;
    const first = await this.admit(request.taskId, artifact);
    if (!first.ok) return first;
    // 3. Cache bytes re-hashed on every activation; presence is never trust.
    let bytes: Buffer | null;
    try {
      bytes = await this.host.stager.readVerified(request.descriptor);
    } catch {
      return { ok: false, code: 'ARTIFACT_NOT_VERIFIED' };
    }
    if (!bytes) return { ok: false, code: 'ARTIFACT_NOT_VERIFIED' };
    // 4. The invoked file name is catalog data and must stay a bare segment;
    // the bindingId is trusted catalog data too but never a raw path part.
    if (!isSafeSegment(artifact.entrypoint) || !isSafeSegment(artifact.bindingId)) {
      return { ok: false, code: 'ENTRYPOINT_INVALID' };
    }
    // 5. Materialize the one executable from the verified bytes. Every run
    // rewrites it from cache bytes and re-hashes what landed on disk, so a
    // tampered leftover can never survive into a later activation.
    const activeDir = join(this.root, 'active', artifact.bindingId, artifact.artifactSha256);
    const executablePath = join(activeDir, artifact.entrypoint);
    if (!(await this.materialize(activeDir, executablePath, bytes, artifact.artifactSha256))) {
      return { ok: false, code: 'ACTIVATION_CACHE_UNAVAILABLE' };
    }
    // 6. Signature + ActionController are read AGAIN immediately before the
    // spawn: a revocation, epoch move, policy change or digest drift between
    // admission and execution voids this activation with zero effects.
    let secondProof: ProviderVerificationResult;
    try {
      secondProof = this.host.verifier.verify(request.descriptor);
    } catch {
      return { ok: false, code: 'CATALOG_UNTRUSTED' };
    }
    if (!secondProof.ok) return { ok: false, code: refusalFromVerification(secondProof.code) };
    const second = await this.admit(request.taskId, secondProof.artifact);
    if (!second.ok) return second;
    if (
      second.revokedEpoch !== first.revokedEpoch ||
      secondProof.artifact.artifactSha256 !== artifact.artifactSha256
    ) {
      return { ok: false, code: 'AUTHORITY_STALE' };
    }
    // 7. Per-run sandbox under the trusted cache root; seeded inputs are
    // bounded, Shun-owned bytes written only inside this directory.
    const sandbox = join(activeDir, 'sandbox', randomUUID());
    try {
      await mkdir(sandbox, { recursive: true, mode: 0o700 });
      for (const file of request.sandboxFiles ?? []) {
        const handle = await open(join(sandbox, file.name), 'wx', 0o600);
        await handle.writeFile(file.bytes);
        await handle.close();
      }
    } catch {
      await this.cleanup(sandbox);
      return { ok: false, code: 'ACTIVATION_CACHE_UNAVAILABLE' };
    }
    // 8. Bounded shell-free spawn of the one absolute pinned path.
    const timeoutMs =
      request.timeoutMs === undefined
        ? DEFAULT_TIMEOUT_MS
        : Math.min(Math.max(request.timeoutMs, 1), MAX_TIMEOUT_MS);
    let outcome: ActivationProcessOutcome;
    try {
      outcome = await this.processPort.run({
        executable: resolve(executablePath),
        args: [...request.args],
        cwd: resolve(sandbox),
        env: { ...this.host.hostSpawnEnvironment() },
        timeoutMs,
        outputLimitBytes: MAX_OUTPUT_BYTES,
      });
    } catch {
      await this.cleanup(sandbox);
      return { ok: false, code: 'ACTIVATION_INTERRUPTED' };
    }
    await this.cleanup(sandbox);
    return {
      ok: true,
      state: 'EXECUTED',
      bindingId: artifact.bindingId,
      digest: artifact.artifactSha256,
      exitCode: outcome.exitCode,
      stdout: outcome.stdout,
      stderr: outcome.stderr,
      timedOut: outcome.timedOut,
      stdoutTruncated: outcome.stdoutTruncated,
      stderrTruncated: outcome.stderrTruncated,
      durationMs: Date.now() - started,
    };
  }

  /** Shared admission checks, executed at BOTH the admission and exec boundary. */
  private async admit(taskId: string, artifact: VerifiedCliArtifact): Promise<AdmissionOutcome> {
    let snapshot: AdmissionSnapshot;
    try {
      snapshot = {
        currentness: this.host.getAuthorizedCurrentness(taskId, artifact.bindingId),
        revokedEpoch: this.host.requiredRevocationEpoch(artifact.bindingId),
        platform: this.host.hostPlatform(),
        arch: this.host.hostArchitecture(),
        abi: this.host.hostNodeAbi(),
      };
    } catch {
      return { ok: false, code: 'AUTHORITY_UNAVAILABLE' };
    }
    const state = snapshot.currentness;
    if (
      state.kind !== 'CURRENT' ||
      state.capability !== 'PREPARE_PROVIDER' ||
      state.taskId !== taskId ||
      state.providerId !== artifact.providerId ||
      state.bindingId !== artifact.bindingId ||
      state.catalogRevision !== artifact.catalogRevision ||
      state.artifactSha256 !== artifact.artifactSha256 ||
      !Number.isSafeInteger(snapshot.revokedEpoch) ||
      snapshot.revokedEpoch < 0 ||
      state.revocationEpoch !== snapshot.revokedEpoch
    ) {
      return { ok: false, code: 'AUTHORITY_STALE' };
    }
    if (
      snapshot.platform !== 'win32' ||
      snapshot.arch !== 'x64' ||
      artifact.platform !== 'windows-x64'
    ) {
      return { ok: false, code: 'HOST_UNSUPPORTED' };
    }
    if (artifact.artifactKind === 'NATIVE_ADDON' && artifact.abiRevision !== snapshot.abi) {
      return { ok: false, code: 'ABI_MISMATCH' };
    }
    // Dependency closure needs independently signed transitive manifests; this
    // slice refuses every nonempty set. Never waived, not even for "CLI".
    if (artifact.dependencySha256.length !== 0) {
      return { ok: false, code: 'DEPENDENCIES_UNVERIFIED' };
    }
    if (artifact.artifactKind !== 'CLI') {
      // Native addon activation is a separate later slice; fail closed here.
      return { ok: false, code: 'ACTIVATION_KIND_UNSUPPORTED' };
    }
    return { ok: true, revokedEpoch: snapshot.revokedEpoch };
  }

  private async materialize(
    activeDir: string,
    executablePath: string,
    bytes: Buffer,
    expectedDigest: string,
  ): Promise<boolean> {
    const temp = join(activeDir, `${basename(executablePath)}.${randomUUID()}.partial`);
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      await mkdir(activeDir, { recursive: true, mode: 0o700 });
      handle = await open(temp, 'wx', 0o600);
      await handle.writeFile(bytes);
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temp, executablePath);
      const landed = await safeReadMaterialized(executablePath);
      if (!landed || landed.length !== bytes.length) return false;
      const digest = createHash('sha256').update(landed).digest('hex');
      return digest === expectedDigest;
    } catch {
      return false;
    } finally {
      try {
        await handle?.close();
      } catch {
        /* best-effort close */
      }
      try {
        await rm(temp, { force: true });
      } catch {
        /* no partial left behind */
      }
    }
  }

  private async cleanup(sandbox: string): Promise<void> {
    try {
      await rm(sandbox, { recursive: true, force: true });
    } catch {
      // best-effort; the sandbox is inside the Shun-owned cache root either way
    }
  }
}
