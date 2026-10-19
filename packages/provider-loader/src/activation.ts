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
//   - native addon activation (runNativeAddon) loads the pinned addon ONLY
//     in a separate short-lived Node child process whose entire program is
//     the fixed NATIVE_CHILD_BOOTSTRAP_SOURCE string: it re-hashes the addon
//     and every dependency on disk, dlopens the one pinned per-run staged
//     path into a fresh module object, answers ONE closed-world operation and
//     exits. The loader process itself never dlopens provider bytes, and no
//     provider JS is ever required or evaluated. The child inherits a
//     scrubbed env (no PATH), a hard timeout, byte-capped output, and its
//     cwd is the per-run staging directory so seeded sandbox files sit
//     outside the DLL search chain.
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
//     unavoidable sub-millisecond residual window (same documented P2 class
//     applies to the native child seam).
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
import {
  NATIVE_CHILD_BOOTSTRAP_SOURCE,
  type NativeChildPayload,
  type NativeChildRunReport,
  parseNativeChildResult,
} from './native-child.ts';
import { isSystemDllImportName, scanPeImports } from './native-pe.ts';
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
/** The native child payload is one bounded argv element. */
const MAX_PAYLOAD_JSON_CHARS = 16384;
/** Only AMD64 PE32+/PE32 images are admitted on the windows-x64 executor. */
const PE_MACHINE_AMD64 = 0x8664;
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
  | 'EFFECT_NOT_AUTHORIZED'
  | 'NATIVE_RUNTIME_UNAVAILABLE';

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
  readonly op:
    | 'provider.version.probe'
    | 'provider.ripgrep.file-search'
    | 'provider.native.addon-metadata'
    | 'provider.native.image-metadata';
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
  /**
   * Native-addon runs only: the structured child payload the parent derived
   * from the typed operation. The invocation-scoped grant binds this identity
   * (op, addon digest, exact dependency name/digest set, operand name) rather
   * than the per-run random absolute paths inside it, which are scope-bound
   * through readRoots/executablePath like the CLI executable.
   */
  readonly native?: NativeInvocationPayload;
}

/** The per-run child request, carried in argv[1] of the native child spawn. */
export interface NativeInvocationPayload {
  readonly op: 'ADDON_METADATA' | 'IMAGE_METADATA';
  readonly addonPath: string;
  readonly addonSha256: string;
  readonly deps: ReadonlyArray<{
    readonly name: string;
    readonly sha256: string;
    readonly path: string;
  }>;
  readonly operandPath?: string;
  readonly operandSha256?: string;
  readonly operandMaxBytes?: number;
}

/**
 * Closed-world typed NATIVE operations. `ADDON_METADATA` loads the pinned
 * addon and reports its bounded export surface; `IMAGE_METADATA` additionally
 * runs the addon over ONE seeded sandbox image buffer and reports bounded
 * metadata fields. There is no free-form request channel: paths, argv and
 * limits are host-derived.
 */
export type ProviderNativeOperation =
  | Readonly<{ kind: 'ADDON_METADATA' }>
  | Readonly<{
      kind: 'IMAGE_METADATA';
      /** Bare seeded sandbox file name; absolute paths/traversal refused. */
      operand: string;
    }>;

export interface NativeActivationRunRequest {
  readonly taskId: string;
  readonly descriptor: unknown;
  /** Closed-world typed native operation; every child input derives from it. */
  readonly run: ProviderNativeOperation;
  readonly timeoutMs?: number;
  readonly sandboxFiles?: readonly SandboxInputFile[];
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
  /**
   * Native-addon runs only: the re-validated structured child response
   * (child output is untrusted DATA; nothing here is ever followed as a path
   * or instruction). CLI runs leave this undefined.
   */
  readonly native?: NativeChildRunReport;
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
  stager: Pick<CuratedProviderStager, 'readVerified' | 'readVerifiedDependency'>;
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
   * Absolute path of the trusted Node runtime that executes native-addon
   * children. Production pins `process.execPath`; it must never come from a
   * request, provider content or PATH lookup.
   */
  hostNativeChildRuntime: () => string;
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

/**
 * Closed-world validation of a NATIVE run request. ADDON_METADATA carries no
 * sandbox inputs at all; IMAGE_METADATA names exactly one seeded sandbox file
 * as its operand. Nothing else can be expressed.
 */
function validateNativeRunRequest(request: NativeActivationRunRequest): boolean {
  if (!request || typeof request !== 'object') return false;
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
  const kind = (request.run as { kind?: unknown } | undefined)?.kind;
  if (kind === 'ADDON_METADATA') {
    // No inputs to hash; a metadata probe over seeded files is meaningless.
    return files.length === 0;
  }
  if (kind !== 'IMAGE_METADATA') return false;
  const operand = (request.run as { operand?: unknown }).operand;
  return typeof operand === 'string' && isSafeSegment(operand) && seen.has(operand);
}

/**
 * Independent native dependency-closure verification over the VERIFIED BYTES
 * (before anything is staged or spawned): the addon and every declared
 * dependency must be parseable AMD64 PE images whose direct DLL imports are
 * each either a known system DLL or a declared, staged closure member.
 */
function verifyNativeImageClosure(
  addonBytes: Buffer,
  dependencies: ReadonlyArray<{ readonly name: string; readonly bytes: Buffer }>,
): { ok: true } | { ok: false; code: ActivationRefusal } {
  const declared = new Set(dependencies.map((dep) => dep.name.toLowerCase()));
  const addonScan = scanPeImports(addonBytes);
  if (!addonScan.ok) return { ok: false, code: 'DEPENDENCIES_UNVERIFIED' };
  if (addonScan.machine !== PE_MACHINE_AMD64) return { ok: false, code: 'HOST_UNSUPPORTED' };
  for (const name of addonScan.imports) {
    if (!isSystemDllImportName(name) && !declared.has(name.toLowerCase())) {
      return { ok: false, code: 'DEPENDENCIES_UNVERIFIED' };
    }
  }
  for (const dep of dependencies) {
    const scan = scanPeImports(dep.bytes);
    if (!scan.ok || scan.machine !== PE_MACHINE_AMD64) {
      return { ok: false, code: 'DEPENDENCIES_UNVERIFIED' };
    }
    for (const name of scan.imports) {
      if (!isSystemDllImportName(name) && !declared.has(name.toLowerCase())) {
        return { ok: false, code: 'DEPENDENCIES_UNVERIFIED' };
      }
    }
  }
  return { ok: true };
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

interface StagedImageFile {
  readonly path: string;
  readonly digest: string;
  readonly dev: number;
  readonly ino: number;
}

interface StagedExecutable {
  readonly dir: string;
  /** Entry-point path (the CLI exe or the native addon image). */
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
  /** Entry-point first, then every staged dependency image. */
  readonly files: readonly StagedImageFile[];
}

type StagingOutcome =
  | { readonly ok: true; readonly staged: StagedExecutable }
  | {
      readonly ok: false;
      readonly code: 'ACTIVATION_CACHE_UNAVAILABLE' | 'EXECUTABLE_IDENTITY_DRIFT';
    };

/**
 * Per-run private image staging (R1 #145 F04): a FRESH random directory
 * under the verified cache root; every image written once ('wx') from its
 * re-hashed verified bytes; the entrypoint is digest-verified through a
 * handle that STAYS OPEN so the entrypoint bytes provably cannot be deleted
 * or renamed out from under the run; every file is re-digested from disk
 * before staging reports success.
 */
async function stagePerRunImages(
  activeDir: string,
  images: ReadonlyArray<{ readonly name: string; readonly bytes: Buffer; readonly digest: string }>,
): Promise<StagingOutcome> {
  const entrypoint = images[0];
  if (!entrypoint) return { ok: false, code: 'ACTIVATION_CACHE_UNAVAILABLE' };
  const dir = join(activeDir, 'exec', randomUUID());
  const entrypointPath = join(dir, entrypoint.name);
  let write: FileHandle | undefined;
  let held: FileHandle | undefined;
  let transferred = false;
  try {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    // The freshly created chain must be reparse-free RIGHT NOW (a junction
    // swapped in before our mkdir would fail here, not at spawn time).
    if (!(await reparseFreeDirectoryChain(dir))) {
      return { ok: false, code: 'ACTIVATION_CACHE_UNAVAILABLE' };
    }
    const files: StagedImageFile[] = [];
    for (const image of images) {
      const imagePath = join(dir, image.name);
      write = await open(imagePath, 'wx', 0o600);
      await write.writeFile(image.bytes);
      await write.sync();
      await write.close();
      write = undefined;
      const onDisk = await lstat(imagePath);
      if (!onDisk.isFile() || onDisk.isSymbolicLink()) {
        return { ok: false, code: 'EXECUTABLE_IDENTITY_DRIFT' };
      }
      files.push({ path: imagePath, digest: image.digest, dev: onDisk.dev, ino: onDisk.ino });
    }
    // Reopen the ENTRYPOINT read-only and keep the handle for the whole run
    // as the identity anchor (dev/ino) the last boundary re-verifies against.
    // It is not a delete/write lock: Node opens files with FILE_SHARE_DELETE.
    held = await open(entrypointPath, constants.O_RDONLY);
    const opened = await held.stat();
    const onDisk = await lstat(entrypointPath);
    if (
      !opened.isFile() ||
      onDisk.isSymbolicLink() ||
      opened.dev !== onDisk.dev ||
      opened.ino !== onDisk.ino
    ) {
      return { ok: false, code: 'EXECUTABLE_IDENTITY_DRIFT' };
    }
    for (const file of files) {
      const isEntrypoint = file.path === entrypointPath;
      const size = isEntrypoint ? opened.size : (await lstat(file.path)).size;
      const handle = isEntrypoint ? held : await open(file.path, constants.O_RDONLY);
      try {
        const landed = await readPositionedAll(handle, size);
        if (digestOf(landed) !== file.digest) {
          return { ok: false, code: 'EXECUTABLE_IDENTITY_DRIFT' };
        }
      } finally {
        if (!isEntrypoint) await handle.close().catch(() => undefined);
      }
    }
    transferred = true;
    return {
      ok: true,
      staged: {
        dir,
        path: entrypointPath,
        handle: held,
        dev: opened.dev,
        ino: opened.ino,
        files: Object.freeze(files),
      },
    };
  } catch {
    return { ok: false, code: 'ACTIVATION_CACHE_UNAVAILABLE' };
  } finally {
    if (write) await write.close().catch(() => undefined);
    // A typed refusal returned inside try MUST clean staged handles/bytes,
    // exactly like a thrown filesystem error. On success ownership passes
    // exclusively to the caller's cleanup/recovery path.
    if (!transferred) {
      if (held) await held.close().catch(() => undefined);
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  }
}

/**
 * Last-instant identity revalidation of EVERY staged image through the
 * STILL-OPEN entrypoint staging handle plus on-disk cross-checks:
 * same dev/ino on the handle and the on-disk lstat, still a regular
 * non-reparse file, and every file's bytes re-digest to its pinned hash.
 * Deletion, symlink/junction swap and in-place overwrite are ALL caught
 * here with zero spawns. (The entrypoint handle itself is not a lock — the
 * runtime shares delete — it is the identity anchor this check re-verifies.)
 */
async function stagedImagesIdentityHolds(staged: StagedExecutable): Promise<boolean> {
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
    const entryAnchor = staged.files[0];
    if (!entryAnchor) return false;
    const entryBytes = await readPositionedAll(staged.handle, opened.size);
    if (digestOf(entryBytes) !== entryAnchor.digest) return false;
    for (const file of staged.files.slice(1)) {
      const depOnDisk = await lstat(file.path);
      if (
        depOnDisk.isSymbolicLink() ||
        !depOnDisk.isFile() ||
        depOnDisk.dev !== file.dev ||
        depOnDisk.ino !== file.ino
      ) {
        return false;
      }
      const depHandle = await open(file.path, constants.O_RDONLY);
      try {
        const depBytes = await readPositionedAll(depHandle, depOnDisk.size);
        if (digestOf(depBytes) !== file.digest) return false;
      } finally {
        await depHandle.close().catch(() => undefined);
      }
    }
    return true;
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
      typeof host.hostNativeChildRuntime !== 'function' ||
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
    const first = await this.admit(request.taskId, artifact, 'CLI');
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
    const staging = await stagePerRunImages(activeDir, [
      { name: artifact.entrypoint, bytes, digest: artifact.artifactSha256 },
    ]);
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
      const second = await this.admit(request.taskId, secondProof.artifact, 'CLI');
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
      if (!(await stagedImagesIdentityHolds(staged))) {
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

  /**
   * Executes a verified NATIVE addon in a bounded, isolated child process.
   * The trust chain mirrors runCli — signature + pinned scope, ActionController
   * currentness, revocation epoch, OS/arch, exact ABI, dependency closure,
   * cache re-hash, per-run private staging, REPEAT signature + authority
   * checks, invocation-scoped authorizeRunEffect at the last boundary, final
   * identity re-verification — with three native-specific differences:
   *
   *   1. the signed dependency closure is REQUIRED to resolve: every digest
   *      is read from the digest-named cache, re-hashed, PE-scanned together
   *      with the addon (direct imports must each be a system DLL or a
   *      declared member), and staged under its host-curated name;
   *   2. the "executable" is the host-pinned Node runtime; the child program
   *      is the fixed bootstrap source plus one bounded payload (argv), the
   *      child re-verifies every digest itself, dlopens the one pinned addon
   *      path into a fresh module, answers ONE closed-world operation and
   *      exits — the loader process never dlopens provider bytes;
   *   3. the child cwd is the per-run staging directory (verified closure
   *      bytes only), so the seeded sandbox — and anything a caller could
   *      name into it — is outside the DLL search chain.
   */
  async runNativeAddon(request: NativeActivationRunRequest): Promise<ActivationResult> {
    const started = Date.now();
    if (!validateNativeRunRequest(request)) return { ok: false, code: 'RUN_REQUEST_INVALID' };
    let runtime: string;
    try {
      runtime = this.host.hostNativeChildRuntime();
    } catch {
      return { ok: false, code: 'NATIVE_RUNTIME_UNAVAILABLE' };
    }
    if (typeof runtime !== 'string' || !isAbsolute(runtime)) {
      return { ok: false, code: 'NATIVE_RUNTIME_UNAVAILABLE' };
    }
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
    const first = await this.admit(request.taskId, artifact, 'NATIVE_ADDON');
    if (!first.ok) return first;
    // 3. Cache bytes re-hashed on every activation; presence is never trust.
    let bytes: Buffer | null;
    try {
      bytes = await this.host.stager.readVerified(request.descriptor);
    } catch {
      return { ok: false, code: 'ARTIFACT_NOT_VERIFIED' };
    }
    if (!bytes) return { ok: false, code: 'ARTIFACT_NOT_VERIFIED' };
    // 4. Catalog-derived names must stay bare segments.
    if (!isSafeSegment(artifact.entrypoint) || !isSafeSegment(artifact.bindingId)) {
      return { ok: false, code: 'ENTRYPOINT_INVALID' };
    }
    // 5. Dependency closure: every signed digest must resolve to verified
    // cached bytes under its host-curated name, and the whole image set must
    // form a closed import graph. All of this fails closed BEFORE staging.
    const dependencies: Array<{ name: string; bytes: Buffer; digest: string }> = [];
    for (const entry of artifact.dependencyEntries) {
      if (
        !isSafeSegment(entry.name) ||
        isSystemDllImportName(entry.name) ||
        entry.name.toLowerCase() === artifact.entrypoint.toLowerCase()
      ) {
        return { ok: false, code: 'DEPENDENCIES_UNVERIFIED' };
      }
      let depBytes: Buffer | null;
      try {
        depBytes = await this.host.stager.readVerifiedDependency(
          request.descriptor,
          entry.artifactSha256,
        );
      } catch {
        return { ok: false, code: 'DEPENDENCIES_UNVERIFIED' };
      }
      if (!depBytes) return { ok: false, code: 'DEPENDENCIES_UNVERIFIED' };
      dependencies.push({ name: entry.name, bytes: depBytes, digest: entry.artifactSha256 });
    }
    const closure = verifyNativeImageClosure(bytes, dependencies);
    if (!closure.ok) return closure;
    // 6. The trusted cache root itself must be anchored: every ancestor down
    // to the cache root reparse-free BEFORE anything lands under it.
    const activeDir = join(this.root, 'active', artifact.bindingId, artifact.artifactSha256);
    if (!(await reparseFreeDirectoryChain(this.root))) {
      return { ok: false, code: 'ACTIVATION_CACHE_UNAVAILABLE' };
    }
    // 7. Per-run private image staging: addon first (identity anchor), then
    // every dependency under its exact curated name — the property the
    // Windows loader search (LOAD_WITH_ALTERED_SEARCH_PATH) resolves against.
    const staging = await stagePerRunImages(activeDir, [
      { name: artifact.entrypoint, bytes, digest: artifact.artifactSha256 },
      ...dependencies.map((dep) => ({ name: dep.name, bytes: dep.bytes, digest: dep.digest })),
    ]);
    if (!staging.ok) return { ok: false, code: staging.code };
    const staged = staging.staged;
    const sandbox = join(activeDir, 'sandbox', randomUUID());
    try {
      // 8. Signature + ActionController currentness are read AGAIN before the
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
      const second = await this.admit(request.taskId, secondProof.artifact, 'NATIVE_ADDON');
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
      // 9. Sandbox seeding: metadata probes seed nothing; image probes seed
      // exactly the operand named by the typed operation.
      const run = request.run;
      const seededOperand =
        run.kind === 'IMAGE_METADATA'
          ? (request.sandboxFiles ?? []).find((file) => file.name === run.operand)
          : undefined;
      const operandDigest = seededOperand ? digestOf(Buffer.from(seededOperand.bytes)) : '';
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
      // 10. The bounded child payload: everything derives from the typed
      // operation and the verified staging state; no caller byte enters.
      const payload: NativeChildPayload = {
        v: 1,
        op: run.kind,
        addon: { path: staged.path, sha256: artifact.artifactSha256 },
        deps: staged.files.slice(1).map((file, index) => ({
          name: dependencies[index]?.name ?? file.path,
          sha256: file.digest,
          path: file.path,
        })),
        ...(run.kind === 'IMAGE_METADATA' && seededOperand
          ? {
              operand: {
                path: join(sandbox, run.operand),
                sha256: operandDigest,
                maxBytes: MAX_SANDBOX_FILE_BYTES,
              },
            }
          : {}),
      };
      const payloadJson = JSON.stringify(payload);
      if (payloadJson.length > MAX_PAYLOAD_JSON_CHARS) {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'RUN_REQUEST_INVALID' };
      }
      // 11. Scrubbed environment snapshot BEFORE the final authority gate.
      const spawnEnvironment = this.host.hostSpawnEnvironment();
      // 12. THE execution grant: invocation-scoped, fresh at this instant.
      const invocation: ResolvedInvocation = {
        op:
          request.run.kind === 'ADDON_METADATA'
            ? 'provider.native.addon-metadata'
            : 'provider.native.image-metadata',
        taskId: request.taskId,
        bindingId: artifact.bindingId,
        artifactSha256: artifact.artifactSha256,
        executablePath: runtime,
        cwd: resolve(staged.dir),
        argv: ['-e', NATIVE_CHILD_BOOTSTRAP_SOURCE, payloadJson],
        readRoots: [resolve(staged.dir), resolve(sandbox)],
        writeRoots: [],
        native: {
          op: request.run.kind,
          addonPath: staged.path,
          addonSha256: artifact.artifactSha256,
          deps: payload.deps,
          operandPath: payload.operand?.path,
          operandSha256: payload.operand?.sha256,
          operandMaxBytes: payload.operand?.maxBytes,
        },
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
      // 13. THE LAST EFFECT BOUNDARY — after the final authority decision:
      // the sandbox is still the directory we created, the operand (if any)
      // is still exactly the seeded file inside it, and every staged image
      // still holds its pinned identity and full digest.
      const resolvedSandbox = resolve(sandbox);
      if (!(await isUnmodifiedDirectory(resolvedSandbox))) {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'SANDBOX_UNSAFE' };
      }
      if (
        request.run.kind === 'IMAGE_METADATA' &&
        !(await operandIsSeededSandboxFile(resolvedSandbox, request.run.operand))
      ) {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'SANDBOX_UNSAFE' };
      }
      if (!(await stagedImagesIdentityHolds(staged))) {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'EXECUTABLE_IDENTITY_DRIFT' };
      }
      // 14. One bounded, shell-free child spawn: pinned runtime, fixed
      // bootstrap, one payload, scrubbed env, hard timeout, capped output.
      const timeoutMs =
        request.timeoutMs === undefined
          ? DEFAULT_TIMEOUT_MS
          : Math.min(Math.max(request.timeoutMs, 1), MAX_TIMEOUT_MS);
      let outcome: ActivationProcessOutcome;
      try {
        outcome = await this.processPort.run({
          executable: runtime,
          args: ['-e', NATIVE_CHILD_BOOTSTRAP_SOURCE, payloadJson],
          cwd: staged.dir,
          env: { ...spawnEnvironment },
          timeoutMs,
          outputLimitBytes: MAX_OUTPUT_BYTES,
        });
      } catch {
        await this.cleanupAll(staged, sandbox);
        return { ok: false, code: 'ACTIVATION_INTERRUPTED' };
      }
      const native = parseNativeChildResult(outcome.stdout);
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
        native,
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

  /**
   * Shared admission checks, executed at BOTH the admission and exec boundary.
   * `expectedKind` selects the activation slice: CLI runs refuse native
   * artifacts and every nonempty dependency closure; native runs require an
   * exact-ABI NATIVE_ADDON whose signed dependency digests all carry
   * host-curated names (the verifier bijection).
   */
  private async admit(
    taskId: string,
    artifact: VerifiedCliArtifact,
    expectedKind: 'CLI' | 'NATIVE_ADDON',
  ): Promise<AdmissionOutcome> {
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
    if (expectedKind === 'CLI') {
      // Dependency closure needs independently signed transitive manifests;
      // the CLI slice refuses every nonempty set. Never waived.
      if (artifact.dependencySha256.length !== 0) {
        return { ok: false, code: 'DEPENDENCIES_UNVERIFIED' };
      }
    } else {
      // Native slice: every signed dependency digest must have resolved to a
      // host-curated name (verifier bijection; re-checked here fail-closed).
      if (artifact.dependencyEntries.length !== artifact.dependencySha256.length) {
        return { ok: false, code: 'DEPENDENCIES_UNVERIFIED' };
      }
    }
    if (artifact.artifactKind !== expectedKind) {
      // The other activation slice owns this artifact kind; fail closed.
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
