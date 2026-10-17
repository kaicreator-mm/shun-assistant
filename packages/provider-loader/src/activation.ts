// T05 bounded Provider activation. This is the FIRST slice in the loader that
// executes anything, so every trust input is re-established inside the call
// and again at the last boundary before the spawn:
//
//   signature + pinned scope → ActionController currentness (capability
//   PREPARE_PROVIDER, preparation only) + revocation epoch → OS/arch →
//   exact-ABI (native) → transitive dependency closure → cache bytes
//   re-hashed → per-run private executable staging (fresh random directory,
//   digest-verified through a held-open handle, reparse-free anchored chain)
//   → REPEAT signature + ActionController re-check → sandbox seeding →
//   invocation-scoped authorizeEffect (the REAL execution grant, exact
//   op/argv/roots, fresh at this instant) → final executable identity
//   re-read → spawn the one pinned absolute path.
//
// Hard surface rules (T05 #106 real-host boundary, R1 #145 corrections):
//   - the executable is ONLY the freshly staged verified bytes in a per-run
//     private directory; PATH is never consulted (spawn takes one absolute
//     path, scrubbed env has no PATH), no JS require/dynamic import of
//     provider content, no DLL search input.
//   - the caller NEVER supplies spawn argv. Requests carry a closed-world
//     typed operation (a version probe or a ripgrep file search over seeded
//     sandbox operands); every spawn argument is host-derived from that type,
//     so `--pre`, config files, pattern files, response files, absolute/UNC/
//     traversal operands and any unrecognized form are INEXPRESSIBLE.
//   - a PREPARE_PROVIDER currentness snapshot only ever gates signature/cache
//     staging and preparation. Actual execution requires the host-owned
//     `authorizeRunEffect` port to accept THIS exact invocation (op, argv,
//     executable, cwd, read/write roots) immediately before the process seam.
//     That port is where the trusted composition runs the REAL ActionController
//     authorizeEffect gate (plan + AuthorizedAction + grant presentation).
//   - cwd/env/timeout/output are host-owned; the sandbox lives under the
//     trusted cache root, never a user path.
//   - native addon activation is NOT implemented in this slice and refuses
//     closed (ACTIVATION_KIND_UNSUPPORTED); the CLI/native proofs stay
//     separate and a native ABI probe is not a native activation result.
//   - Windows residual risk (measured, not claimed away): the runtime opens
//     files with FILE_SHARE_DELETE, so NO user-mode handle blocks another
//     same-privilege process from deleting or overwriting the staged
//     executable, and there is no exclusive share mode to close the final
//     window between the last identity re-check and CreateProcess's image
//     open. What this run guarantees: the executable is staged fresh per run
//     in a random directory under a reparse-free anchored chain, its identity
//     (dev/ino through our own open handle + on-disk lstat cross-check) and
//     full digest are re-verified at the LAST boundary before the spawn seam,
//     and any drift — deletion, symlink/junction swap, byte overwrite — is
//     refused with zero spawns. This run does NOT claim stat→close→spawn
//     atomicity; it claims detection-at-the-last-check plus a documented,
//     unavoidable sub-millisecond residual window.
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { lstat, mkdir, open, realpath, rm } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
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
// biome-ignore lint/suspicious/noControlCharactersInRegex: patterns are spawn args too
const UNSAFE_TEXT = /[\u0000-\u001f\u007f]/;

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
  | 'RUN_REQUEST_INVALID'
  | 'EXECUTABLE_IDENTITY_DRIFT'
  | 'SANDBOX_UNSAFE'
  | 'EFFECT_NOT_AUTHORIZED';

/**
 * Closed-world typed operations. This is the ONLY thing a requester can ask
 * the pinned executable to do; there is no free-form argv channel anymore
 * (R1 #145 F01/F02). Each variant maps to one fixed host-derived argv.
 */
export type ProviderCliOperation =
  | Readonly<{ kind: 'VERSION_PROBE' }>
  | Readonly<{
      kind: 'FILE_SEARCH';
      /** Single regex pattern, bound with `-e` so it can never parse as a flag. */
      pattern: string;
      /**
       * Bare names seeded via `sandboxFiles`, or `.` for the sandbox root.
       * Absolute paths, drive/UNC forms, separators, `..` and unseeded names
       * are refused before any authority read or spawn.
       */
      operands: readonly string[];
      readonly lineNumbers?: boolean;
    }>;

/** The concrete invocation the host derives from a typed operation. */
export interface ResolvedInvocation {
  /** Typed operation id the AuthorizedAction must bind. */
  readonly op: 'provider.version.probe' | 'provider.ripgrep.file-search';
  readonly taskId: string;
  readonly bindingId: string;
  readonly artifactSha256: string;
  readonly executablePath: string;
  readonly cwd: string;
  /** The complete final spawn argv, exactly as the process seam will receive it. */
  readonly argv: readonly string[];
  /** Every filesystem location the child can read (sandbox cwd + exec dir). */
  readonly readRoots: readonly string[];
  /** The only filesystem location the child can write: the sandbox cwd. */
  readonly writeRoots: readonly string[];
}

export type RunEffectRefusal =
  | 'AUTHORITY_UNAVAILABLE'
  | 'AUTHORITY_STALE'
  | 'EFFECT_NOT_AUTHORIZED';

export type RunEffectDecision =
  | {
      readonly ok: true /** Fresh one-run lease id minted by the port. */;
      readonly leaseId: string;
    }
  | { readonly ok: false; readonly code: RunEffectRefusal };

/**
 * Trusted host-only invocation port for the REAL ActionController
 * `authorizeEffect` gate (R1 #145 F03). The activator calls it exactly once
 * per run, after sandbox materialization and immediately before the process
 * seam, with the exact derived invocation. The trusted composition maps that
 * invocation to the one AuthorizedAction and grant that name it — same
 * taskId, plan, op, argv and filesystem roots — re-validates the full grant
 * presentation against CURRENT authority/policy/epoch state and returns a
 * fresh decision. A `PREPARE_PROVIDER` currentness snapshot never
 * substitutes for this decision; this port may never be derived from request
 * input.
 */
export type AuthorizeRunEffectPort = (invocation: ResolvedInvocation) => Promise<RunEffectDecision>;

export interface SandboxInputFile {
  /** Bare file name created inside the per-run sandbox; never a path. */
  readonly name: string;
  readonly bytes: Uint8Array;
}

export interface ActivationRunRequest {
  readonly taskId: string;
  readonly descriptor: unknown;
  /** Closed-world typed operation; every spawn arg is derived from it. */
  readonly run: ProviderCliOperation;
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
  /**
   * Unforgeable private ActionController port for PREPARE_PROVIDER
   * currentness. Read twice per activation, but it only ever gates
   * preparation — never execution (see authorizeRunEffect).
   */
  getAuthorizedCurrentness: (taskId: string, bindingId: string) => ProviderUseCurrentness;
  /**
   * The invocation-scoped execution authority: the REAL ActionController
   * authorizeEffect gate behind a trusted host-only seam (F03). Required.
   */
  authorizeRunEffect: AuthorizeRunEffectPort;
  /** Host product policy owns the exact revoked epoch and never trusts a request. */
  requiredRevocationEpoch: (bindingId: string) => number;
  /** OS/runtime values come from the trusted executor, not request fields. */
  hostPlatform: () => string;
  hostArchitecture: () => string;
  hostNodeAbi: () => string;
  /**
   * Scrubbed spawn environment owned by the trusted host composition. Read
   * BEFORE the final authorizeRunEffect call so any policy move observable
   * through it is still caught by that last gate.
   */
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

/**
 * Closed-world validation of the typed operation. Everything a caller could
 * smuggle (`--pre`, `-f`, config/response files, absolute or traversal
 * operands) is absent from this grammar, so it is INEXPRESSIBLE rather than
 * blacklisted. Operands must already be seeded sandbox input names.
 */
function validateOperation(run: ProviderCliOperation, seededNames: ReadonlySet<string>): boolean {
  if (!run || typeof run !== 'object') return false;
  if ((run as { kind?: unknown }).kind === 'VERSION_PROBE') return true;
  if ((run as { kind?: unknown }).kind !== 'FILE_SEARCH') return false;
  const search = run as {
    pattern?: unknown;
    operands?: unknown;
    lineNumbers?: unknown;
  };
  if (
    typeof search.pattern !== 'string' ||
    search.pattern.length < 1 ||
    search.pattern.length > MAX_ARG_LENGTH ||
    UNSAFE_TEXT.test(search.pattern)
  ) {
    return false;
  }
  if (search.lineNumbers !== undefined && typeof search.lineNumbers !== 'boolean') return false;
  if (
    !Array.isArray(search.operands) ||
    search.operands.length < 1 ||
    search.operands.length > MAX_SANDBOX_FILES
  ) {
    return false;
  }
  const seen = new Set<string>();
  for (const operand of search.operands) {
    if (operand === '.') continue;
    if (typeof operand !== 'string' || !isSafeSegment(operand) || !seededNames.has(operand)) {
      return false;
    }
    seen.add(operand);
  }
  return seen.size === search.operands.filter((operand) => operand !== '.').length;
}

/** Host-derived fixed argv; the caller never contributes a single byte. */
function deriveArgv(run: ProviderCliOperation): readonly string[] {
  if (run.kind === 'VERSION_PROBE') return ['--version'];
  return [
    ...(run.lineNumbers ? ['-n'] : []),
    '--no-heading',
    '-e',
    run.pattern,
    '--',
    ...run.operands,
  ];
}

function invocationOp(run: ProviderCliOperation): ResolvedInvocation['op'] {
  return run.kind === 'VERSION_PROBE' ? 'provider.version.probe' : 'provider.ripgrep.file-search';
}

function validateRunRequest(request: ActivationRunRequest): boolean {
  if (typeof request.taskId !== 'string' || request.taskId.length < 1) return false;
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
  if (!validateOperation(request.run, seen)) return false;
  // The whole derived argv must stay within the same bounded arg envelope.
  return deriveArgv(request.run).length <= MAX_RUN_ARGS;
}

async function reparseFreeDirectoryChain(leaf: string): Promise<boolean> {
  const full = resolve(leaf);
  const isWindowsPath = /^[A-Za-z]:/.test(full);
  const segments = full.split(/[\\/]+/).filter((s) => s.length > 0 && !/^[A-Za-z]:$/.test(s));
  let current = isWindowsPath ? full.slice(0, 3) : '/';
  for (const segment of segments) {
    current = join(current, segment);
    try {
      const stats = await lstat(current);
      if (!stats.isDirectory() || stats.isSymbolicLink()) return false;
    } catch {
      return false;
    }
  }
  return true;
}

function samePath(a: string, b: string): boolean {
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/**
 * A seeded operand must still be the regular file this run created, at the
 * exact path inside the sandbox: no symlink/junction redirect, no escape
 * (R1 #145 F02 canary surface).
 */
async function operandIsSeededSandboxFile(sandbox: string, name: string): Promise<boolean> {
  const expected = join(sandbox, name);
  try {
    const stats = await lstat(expected);
    if (!stats.isFile() || stats.isSymbolicLink()) return false;
    return samePath(await realpath(expected), expected);
  } catch {
    return false;
  }
}

/** The sandbox directory itself must be the directory we created. */
async function isUnmodifiedDirectory(path: string): Promise<boolean> {
  try {
    const stats = await lstat(path);
    if (!stats.isDirectory() || stats.isSymbolicLink()) return false;
    return samePath(await realpath(path), resolve(path));
  } catch {
    return false;
  }
}

function digestOf(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Reads exactly `size` bytes at explicit positions. Positioned reads never
 * move the handle's file position, so the SAME held handle can be re-read
 * at the last boundary and still observe the whole file from offset 0.
 */
async function readPositionedAll(handle: FileHandle, size: number): Promise<Buffer> {
  const buffer = Buffer.alloc(size);
  let read = 0;
  while (read < size) {
    const { bytesRead } = await handle.read(buffer, read, size - read, read);
    if (bytesRead === 0) break;
    read += bytesRead;
  }
  return read === size ? buffer : buffer.subarray(0, read);
}

interface StagedExecutable {
  readonly dir: string;
  readonly path: string;
  /**
   * Held open across authorization + spawn. NOT a write/delete lock (the
   * runtime shares delete): its role is a stable identity anchor — fstat
   * dev/ino from THIS handle is re-cross-checked against the on-disk lstat
   * and a full re-digest at the last boundary.
   */
  readonly handle: FileHandle;
  readonly dev: number;
  readonly ino: number;
}

type StagingOutcome =
  | { readonly ok: true; readonly staged: StagedExecutable }
  | {
      readonly ok: false;
      readonly code: 'ACTIVATION_CACHE_UNAVAILABLE' | 'EXECUTABLE_IDENTITY_DRIFT';
    };

/**
 * Per-run private executable staging (R1 #145 F04): a FRESH random directory
 * under the verified cache root, the entrypoint written once ('wx') from the
 * re-hashed verified bytes, digest-verified through a handle that STAYS OPEN
 * so the bytes provably cannot be deleted or renamed out from under the run.
 */
async function stagePerRunExecutable(
  activeDir: string,
  entrypoint: string,
  bytes: Buffer,
  expectedDigest: string,
): Promise<StagingOutcome> {
  const dir = join(activeDir, 'exec', randomUUID());
  const path = join(dir, entrypoint);
  let write: FileHandle | undefined;
  let held: FileHandle | undefined;
  try {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    // The freshly created chain must be reparse-free RIGHT NOW (a junction
    // swapped in before our mkdir would fail here, not at spawn time).
    if (!(await reparseFreeDirectoryChain(dir))) {
      return { ok: false, code: 'ACTIVATION_CACHE_UNAVAILABLE' };
    }
    write = await open(path, 'wx', 0o600);
    await write.writeFile(bytes);
    await write.sync();
    await write.close();
    write = undefined;
    // Reopen READ-ONLY and keep the handle for the whole run as the identity
    // anchor (dev/ino) the last boundary re-verifies against. It is not a
    // delete/write lock: Node opens files with FILE_SHARE_DELETE.
    held = await open(path, constants.O_RDONLY);
    const opened = await held.stat();
    const onDisk = await lstat(path);
    if (
      !opened.isFile() ||
      onDisk.isSymbolicLink() ||
      opened.dev !== onDisk.dev ||
      opened.ino !== onDisk.ino
    ) {
      return { ok: false, code: 'EXECUTABLE_IDENTITY_DRIFT' };
    }
    const landed = await readPositionedAll(held, opened.size);
    if (digestOf(landed) !== expectedDigest) {
      await held.close().catch(() => undefined);
      held = undefined;
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
      return { ok: false, code: 'EXECUTABLE_IDENTITY_DRIFT' };
    }
    return {
      ok: true,
      staged: { dir, path, handle: held, dev: opened.dev, ino: opened.ino },
    };
  } catch {
    if (held) await held.close().catch(() => undefined);
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    return { ok: false, code: 'ACTIVATION_CACHE_UNAVAILABLE' };
  } finally {
    if (write) {
      try {
        await write.close();
      } catch {
        /* the staging failure path cleans the directory below */
      }
    }
  }
}

/**
 * Last-instant identity revalidation through the STILL-OPEN staging handle:
 * same dev/ino on both the handle and the on-disk lstat, still a regular
 * non-reparse file, and the bytes re-digest to the pinned hash. Deletion,
 * symlink/junction swap and in-place overwrite are ALL caught here with
 * zero spawns. (The handle itself is not a lock — the runtime shares
 * delete — it is the identity anchor this check re-verifies.)
 */
async function executableIdentityHolds(
  staged: StagedExecutable,
  expectedDigest: string,
): Promise<boolean> {
  try {
    const opened = await staged.handle.stat();
    const onDisk = await lstat(staged.path);
    const parent = await lstat(staged.dir);
    if (
      opened.dev !== staged.dev ||
      opened.ino !== staged.ino ||
      onDisk.dev !== staged.dev ||
      onDisk.ino !== staged.ino ||
      onDisk.isSymbolicLink() ||
      !onDisk.isFile() ||
      !parent.isDirectory() ||
      parent.isSymbolicLink()
    ) {
      return false;
    }
    const bytes = await readPositionedAll(staged.handle, opened.size);
    return digestOf(bytes) === expectedDigest;
  } catch {
    return false;
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
 * pinned verifier and the ActionController ports, stages a per-run private
 * executable from re-hashed cache bytes, and gates the actual spawn behind
 * the invocation-scoped authorizeRunEffect decision taken at the last
 * boundary. It never consults PATH, shell or dynamic imports, and it never
 * forwards caller-supplied argv.
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
      typeof host.authorizeRunEffect !== 'function' ||
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
    // 1+2. Signature + pinned scope, and the first ActionController read
    // (PREPARE_PROVIDER currentness — preparation only, never an execution
    // grant by itself).
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
    // 5. The trusted cache root itself must be anchored: every ancestor down
    // to the cache root reparse-free BEFORE anything lands under it (the
    // deeper freshly-created chain is re-checked right after mkdir).
    const activeDir = join(this.root, 'active', artifact.bindingId, artifact.artifactSha256);
    if (!(await reparseFreeDirectoryChain(this.root))) {
      return { ok: false, code: 'ACTIVATION_CACHE_UNAVAILABLE' };
    }
    // 6. Per-run private executable staging from the verified bytes: fresh
    // random directory, write-once creation, digest verified through a
    // held-open handle that stays open until after the spawn.
    const staging = await stagePerRunExecutable(
      activeDir,
      artifact.entrypoint,
      bytes,
      artifact.artifactSha256,
    );
    if (!staging.ok) return { ok: false, code: staging.code };
    const staged = staging.staged;
    // Path is created (mkdir) only at step 8; declaring it here lets every
    // refusal path below clean the per-run directories symmetrically.
    const sandbox = join(activeDir, 'sandbox', randomUUID());
    try {
      // 7. Signature + ActionController currentness are read AGAIN before the
      // exec boundary: a revocation, epoch move, policy change or digest
      // drift between admission and execution voids this activation.
      let secondProof: ProviderVerificationResult;
      try {
        secondProof = this.host.verifier.verify(request.descriptor);
      } catch {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'CATALOG_UNTRUSTED' };
      }
      if (!secondProof.ok) {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: refusalFromVerification(secondProof.code) };
      }
      const second = await this.admit(request.taskId, secondProof.artifact);
      if (!second.ok) {
        await this.cleanupAll(staged, sandbox);
        return second;
      }
      if (
        second.revokedEpoch !== first.revokedEpoch ||
        secondProof.artifact.artifactSha256 !== artifact.artifactSha256
      ) {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'AUTHORITY_STALE' };
      }
      // 8. Per-run sandbox under the trusted cache root; seeded inputs are
      // bounded, Shun-owned bytes written only inside this directory.
      const argv = deriveArgv(request.run);
      try {
        await mkdir(sandbox, { recursive: true, mode: 0o700 });
        for (const file of request.sandboxFiles ?? []) {
          const handle = await open(join(sandbox, file.name), 'wx', 0o600);
          await handle.writeFile(file.bytes);
          await handle.close();
        }
      } catch {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'ACTIVATION_CACHE_UNAVAILABLE' };
      }
      // 9. Scrubbed environment snapshot BEFORE the final authority gate so
      // any policy move observable here is still caught by it (F05 seam).
      const spawnEnvironment = this.host.hostSpawnEnvironment();
      // 10. THE execution grant: invocation-scoped, fresh at this instant,
      // for THIS exact op/argv/executable/cwd/roots (F03). This is the last
      // authority decision; PREPARE_PROVIDER currentness above never
      // substitutes for it.
      const invocation: ResolvedInvocation = {
        op: invocationOp(request.run),
        taskId: request.taskId,
        bindingId: artifact.bindingId,
        artifactSha256: artifact.artifactSha256,
        executablePath: staged.path,
        cwd: resolve(sandbox),
        argv,
        readRoots: [resolve(staged.dir), resolve(sandbox)],
        writeRoots: [resolve(sandbox)],
      };
      let effect: RunEffectDecision;
      try {
        effect = await this.host.authorizeRunEffect(invocation);
      } catch {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'AUTHORITY_UNAVAILABLE' };
      }
      if (!effect.ok) {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: effect.code };
      }
      // 11. THE LAST EFFECT BOUNDARY — after the final authority decision,
      // only pure local checks remain before the spawn seam. An adversary
      // striking at (or after) the authority gate is caught HERE:
      //   a. the sandbox is still the directory we created (no junction
      //      redirect of cwd itself),
      //   b. every operand is still exactly the seeded file inside THIS
      //      sandbox — no symlink/junction redirect, no escape (F02 closure),
      //   c. the executable identity still holds: same dev/ino through the
      //      staging handle and on disk, regular non-reparse file, full
      //      re-digest equals the pinned hash (F04).
      const resolvedSandbox = resolve(sandbox);
      if (!(await isUnmodifiedDirectory(resolvedSandbox))) {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'SANDBOX_UNSAFE' };
      }
      for (const operand of request.run.kind === 'FILE_SEARCH' ? request.run.operands : []) {
        if (operand === '.') continue;
        if (!(await operandIsSeededSandboxFile(resolvedSandbox, operand))) {
          await this.cleanupAll(staged, sandbox);
          return { ok: false, code: 'SANDBOX_UNSAFE' };
        }
      }
      if (!(await executableIdentityHolds(staged, artifact.artifactSha256))) {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'EXECUTABLE_IDENTITY_DRIFT' };
      }
      // 12. Bounded shell-free spawn of the one absolute per-run pinned path.
      const timeoutMs =
        request.timeoutMs === undefined
          ? DEFAULT_TIMEOUT_MS
          : Math.min(Math.max(request.timeoutMs, 1), MAX_TIMEOUT_MS);
      let outcome: ActivationProcessOutcome;
      try {
        outcome = await this.processPort.run({
          executable: staged.path,
          args: [...argv],
          cwd: resolvedSandbox,
          env: { ...spawnEnvironment },
          timeoutMs,
          outputLimitBytes: MAX_OUTPUT_BYTES,
        });
      } catch {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'ACTIVATION_INTERRUPTED' };
      }
      await this.cleanupAll(staged, sandbox);
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
    } finally {
      // The staging handle is ALWAYS closed exactly once, on every path.
      try {
        await staged.handle.close();
      } catch {
        /* already closed by a cleanup-all path */
      }
    }
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
      // A native ABI probe elsewhere is NOT a native activation result.
      return { ok: false, code: 'ACTIVATION_KIND_UNSUPPORTED' };
    }
    return { ok: true, revokedEpoch: snapshot.revokedEpoch };
  }

  private async cleanupAll(staged: StagedExecutable, sandbox: string): Promise<void> {
    // Windows cannot delete open files: release the held handle first.
    try {
      await staged.handle.close();
    } catch {
      /* close-on-failure already handled in runCli's finally */
    }
    await this.cleanup(staged.dir);
    await this.cleanup(sandbox);
  }

  private async cleanup(sandbox: string): Promise<void> {
    try {
      await rm(sandbox, { recursive: true, force: true });
    } catch {
      // best-effort; the directory is inside the Shun-owned cache root either way
    }
  }
}
