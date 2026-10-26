// T07 F03: host-owned Windows handle-anchored authorized file mutation
// (copy / move / rename). This trusted physical bridge performs REAL Win32
// effects exclusively through the committed native addon binary extended in
// this lane (packages/recipe-runtime/native/impl/shun_win32_impl.node, loaded
// read-only across the package boundary; no recipe-runtime source is used or
// modified). The anchoring discipline mirrors the independently reviewed T04
// oracle and F02B observation:
//   - BOTH the source and destination drives are attested as fixed local
//     volumes by two purely local kernel questions BEFORE any handle exists
//     (mapped SMB, subst and every other alias device refused with zero
//     opens);
//   - every directory is opened through a single name component anchored at
//     an already-verified parent handle with FILE_OPEN_REPARSE_POINT, so a
//     junction/symlink ancestor or entry yields the reparse point itself
//     (refused from attributes) and its target is never touched;
//   - the source object is identity-checked through the 64-bit FileId of the
//     SAME anchored handle its content is read through, and the relocation
//     handle is cross-checked against that FileId, so a path-to-handle swap
//     between the read and the rename is refused;
//   - a destination can only come into existence through NtCreateFile with
//     disposition FILE_CREATE (fails on any existing name) and a relocation
//     only through FileRenameInformation with ReplaceIfExists = FALSE: there
//     is NO overwrite code path anywhere in this bridge;
//   - move/rename additionally refuses when the verified source file and
//     destination parent live on different volumes (no cross-volume
//     relocation is attempted), and a positive receipt requires an
//     independent post-state re-open of the destination through a second
//     handle whose FileId matches the created/moved object and which is
//     proven to be EXACTLY the source bytes: full digest re-read plus a
//     1-byte EOF probe at offset size, so an appended tail (or any
//     truncate/repad divergence under FILE_SHARE_ALL concurrency) refuses
//     instead of minting a false COMPLETED_VERIFIED — zero-length sources
//     included.
// This module performs no authorization of its own beyond fail-closed
// structural admission of the AuthorizedAction shape: grant integrity and
// per-effect currentness re-validation (ActionController.authorizeEffect)
// and the durable STARTED journal ordering live in the trusted host boundary
// (recipe-runtime sqlite-file-mutation-host), which is the ONLY caller this
// entry is composed for. It accepts no caller callbacks. Nothing here is
// exported through the package exports map (src/index.ts); tests reach the
// internal seam directly.
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { types } from 'node:util';
import { attestsFixedLocalVolume } from './host-observation.ts';

const MAX_PATH = 2048;
/** Hard per-file bound: a mutation larger than this is refused BEFORE any
 * destination IO happens (the source is read first, bounded by this cap). */
const MAX_FILE_BYTES = 8 << 20;
/** Chunk for the bounded pre-effect source read (one probe decides size). */
const SIZE_PROBE_BYTES = MAX_FILE_BYTES;

// NTSTATUS STATUS_END_OF_FILE (0xC0000011): a synchronous read that starts
// at or crosses EOF completes with this status. (A size-0 probe read returns
// exactly this with returned=0.)
const NT_STATUS_END_OF_FILE = 0xc0000011;
const FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
const FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

export type FileMutationOp = 'file.copy' | 'file.move' | 'file.rename';
export const FILE_MUTATION_OPS: readonly FileMutationOp[] = [
  'file.copy',
  'file.move',
  'file.rename',
];

export type FileMutationRefusalCode =
  | 'FILE_MUTATION_AUTHORIZATION_REFUSED'
  | 'FILE_MUTATION_SCOPE_REFUSED'
  | 'FILE_MUTATION_NATIVE_UNAVAILABLE'
  | 'FILE_MUTATION_DRIVE_REFUSED'
  | 'FILE_MUTATION_ALIAS_REFUSED'
  | 'FILE_MUTATION_BOUNDS_EXCEEDED'
  | 'FILE_MUTATION_CROSS_VOLUME_REFUSED'
  | 'FILE_MUTATION_COLLISION_REFUSED'
  | 'FILE_MUTATION_EFFECT_REFUSED';

/**
 * Receipt shape minted on a fully verified effect. Deliberately a plain
 * frozen object (this package adds no runtime dependency on @shun/contracts);
 * the recipe-runtime boundary re-validates it against the real
 * ExecutionReceiptSchema before any COMMITTED classification exists.
 */
export type FileMutationReceipt = Readonly<{
  actionId: string;
  environmentId: 'local-windows-user';
  providerId: 'shun-win32-file-mutation';
  providerVersion: '0.2.0';
  startedAt: string;
  finishedAt: string;
  terminal: 'SUCCEEDED';
  outputRefs: readonly [];
  sideEffectEvidence: Readonly<{
    sideEffectClass: 'R2';
    recoveryClassification: 'COMPLETED_VERIFIED';
    postStateVerified: true;
  }>;
}>;

export type FileMutationResult =
  | { ok: true; receipt: FileMutationReceipt }
  | { ok: false; code: FileMutationRefusalCode };

/**
 * PACKAGE-INTERNAL test/audit-only seam (same discipline as F02B's
 * HostObservationInstrument): synchronous observation of what the bridge
 * actually did, so negative controls can prove ZERO destination IO beyond
 * the admitted prefix (destCreates / writes / renames all 0 on refusal).
 * Reachable only inside this package; the authorized entry below never
 * accepts or invokes caller callbacks.
 */
export type FileMutationInstrument = Readonly<{
  onStage?: (stage: FileMutationStage, detail: string) => void;
  onSourceOpened?: (rel: string) => void;
  onDestCreate?: (rel: string) => void;
  onRename?: (from: string, to: string) => void;
}>;

export type FileMutationStage =
  | 'STATIC_ADMITTED'
  | 'DRIVE_ATTESTED'
  | 'SOURCE_OPENED'
  | 'DEST_PARENT_OPENED'
  | 'PRECOMMIT_DURABLE'
  | 'EFFECT_REFUSED'
  | 'COMPLETED_VERIFIED';

/**
 * T07 F04B2a immutable pre-effect commitment: captured AFTER both drives are
 * attested, the source is identity-checked and fully read through one
 * anchored handle, and the destination parent chain is verified with the
 * destination name observed ABSENT — and durably persisted write-once
 * BEFORE the first exclusive create or no-replace relocation exists. Plain
 * frozen data (strings/numbers only, JSON-stable); the 64-bit FileId is a
 * decimal string because JSON cannot carry bigint.
 */
export type FileMutationPrecommitment = Readonly<{
  kind: 'file-mutation-precommit-v1';
  actionId: string;
  op: FileMutationOp;
  sourcePath: string;
  destinationPath: string;
  source: Readonly<{
    fileId: string;
    volumeSerial: number;
    size: number;
    sha256: string;
  }>;
  destinationPrestate: Readonly<{ destinationExisted: false }>;
}>;

/**
 * T07 F04B2a durable-checkpoint capability the trusted host boundary
 * (recipe-runtime sqlite-file-mutation-host) injects into the authorized
 * composition. `durablePrecommit` must persist the commitment write-once
 * with a durable readback and return true BEFORE the effect proceeds;
 * false (or a throw) refuses the mutation with ZERO destination IO. The
 * source is then RE-observed through the same verified handle and any
 * drift from the commitment refuses the effect. Checkpoints are OPTIONAL
 * only to preserve the F03-era internal-seam composition under test:
 * absent checkpoints keep the un-checkpointed legacy behavior inside this
 * package, and the trusted bootstrap must always supply the journal-backed
 * implementation. A present-but-malformed checkpoints object refuses.
 */
export type FileMutationCheckpoints = Readonly<{
  durablePrecommit: (commitment: FileMutationPrecommitment) => boolean;
}>;

class Refusal extends Error {
  constructor(public readonly code: FileMutationRefusalCode) {
    super(code);
  }
}

function refuse(code: FileMutationRefusalCode): never {
  throw new Refusal(code);
}

// ---------------------------------------------------------------------------
// Static scope admission (zero IO, platform independent). Duplicated
// deliberately from host-observation.ts so this effect surface stays
// independently reviewable; the two copies must agree.
// ---------------------------------------------------------------------------

const RESERVED_DOS_NAMES =
  /^(con|prn|aux|nul|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\.|$)/i;
const BIDI_OR_ISOLATION = /[\u202a-\u202e\u2066-\u2069]/u;

function hasControlCharacters(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 32 || (code >= 127 && code <= 159)) return true;
  }
  return false;
}

function validComponent(part: string): boolean {
  return (
    part.length > 0 &&
    part.length <= 255 &&
    part !== '.' &&
    part !== '..' &&
    !part.includes(':') &&
    !/[<>:"|?*\\/]/.test(part) &&
    !BIDI_OR_ISOLATION.test(part) &&
    !hasControlCharacters(part) &&
    !RESERVED_DOS_NAMES.test(part) &&
    !/[. ]$/.test(part)
  );
}

type StaticAdmission = Readonly<{ drive: string; components: readonly string[] }>;

function staticPathAdmission(raw: unknown): StaticAdmission | null {
  if (typeof raw !== 'string' || raw.length < 3 || raw.length > MAX_PATH) return null;
  if (raw.includes('\u0000')) return null;
  const path = raw;
  // Fixed-drive absolute syntax only, judged on the RAW caller form: no UNC
  // shares, no device namespace, no ADS colon (refused per component), no
  // drive-relative or rooted-relative re-anchoring, and no forward slashes —
  // the canonical separator is backslash, a foreign separator is refused
  // rather than silently normalized.
  if (!/^[a-zA-Z]:\\/.test(path)) return null;
  if (path.includes('/')) return null;
  // Canonical component vector, NO silent normalization: every component
  // must be non-empty (doubled/trailing separators refuse instead of
  // collapsing), and at least one PARENT directory must exist, so the
  // lexical scope parent every authorization layer binds is exactly the
  // handle-anchored parent this bridge opens (recipe-runtime dirnameOf; the
  // two must agree).
  const components = path.slice(3).split('\\');
  if (components.length < 2) return null;
  for (const component of components) {
    if (component.length === 0) return null;
    if (!validComponent(component)) return null;
  }
  return { drive: `${path[0]?.toUpperCase()}:${'\\'}`, components };
}

function dirnameAdmission(admission: StaticAdmission): StaticAdmission {
  // The caller guarantees at least one component (a file name); the parent
  // chain is every component before it.
  return { drive: admission.drive, components: admission.components.slice(0, -1) };
}

// ---------------------------------------------------------------------------
// Structural admission of the AuthorizedAction (fail-closed mirror of the
// recipe-runtime boundary gate; expiry REQUIRED and not elapsed; exact
// scope binding to the source/destination parent directories).
// ---------------------------------------------------------------------------

const AUTHORIZATION_KINDS = ['AUTOMATIC', 'EXPLICIT_APPROVAL', 'DURABLE_POLICY'] as const;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

function plainWithExactKeys(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  if (types.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Reflect.ownKeys(descriptors);
  return (
    names.length === keys.length &&
    keys.every(
      (key) =>
        descriptors[key]?.get === undefined &&
        descriptors[key]?.set === undefined &&
        Object.hasOwn(descriptors, key),
    )
  );
}

function nonEmptyString(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

function dirnameOfAdmitted(admission: StaticAdmission): string {
  return `${admission.drive}${dirnameAdmission(admission).components.join('\\')}`;
}

type AdmittedMutation = Readonly<{
  op: FileMutationOp;
  owner: string;
  sourcePath: string;
  destinationPath: string;
  sourceAdmission: StaticAdmission;
  destinationAdmission: StaticAdmission;
}>;

/**
 * Structural + semantic admission of one AuthorizedAction for a mutation
 * effect. Everything else — including a `dryRun`-style extra parameter, a
 * missing/malformed/elapsed expiry, a foreign op, a widened read or write
 * scope, or any network/registry/secret scope — refuses before any IO.
 */
function admittedMutationAction(value: unknown): AdmittedMutation | null {
  if (
    !plainWithExactKeys(value, [
      'taskId',
      'actionId',
      'planHash',
      'policySnapshotRevision',
      'authorizationKind',
      'authorizationRef',
      'expiresAt',
      'action',
    ])
  )
    return null;
  const top = value as Record<string, unknown>;
  if (
    !nonEmptyString(top.taskId, 128) ||
    !nonEmptyString(top.actionId, 128) ||
    !nonEmptyString(top.policySnapshotRevision, 128) ||
    !nonEmptyString(top.authorizationRef, 128)
  )
    return null;
  if (typeof top.planHash !== 'string' || !SHA256_HEX.test(top.planHash)) return null;
  if (
    typeof top.authorizationKind !== 'string' ||
    !AUTHORIZATION_KINDS.includes(top.authorizationKind as (typeof AUTHORIZATION_KINDS)[number])
  )
    return null;
  if (
    typeof top.expiresAt !== 'string' ||
    !ISO_INSTANT.test(top.expiresAt) ||
    !Number.isFinite(Date.parse(top.expiresAt))
  )
    return null;
  if (Date.parse(top.expiresAt) <= Date.now()) return null;
  if (
    !plainWithExactKeys(top.action, [
      'actionId',
      'bindingRef',
      'op',
      'parameters',
      'sideEffectClass',
      'requiredPrivilege',
      'filesystemScope',
    ])
  )
    return null;
  const action = top.action as Record<string, unknown>;
  if (typeof action.actionId !== 'string' || action.actionId !== top.actionId) return null;
  if (!nonEmptyString(action.bindingRef, 128)) return null;
  if (
    typeof action.op !== 'string' ||
    !(FILE_MUTATION_OPS as readonly string[]).includes(action.op)
  )
    return null;
  if (action.sideEffectClass !== 'R2') return null;
  if (action.requiredPrivilege !== 'USER') return null;
  if (!plainWithExactKeys(action.parameters, ['sourcePath', 'destinationPath'])) return null;
  const parameters = action.parameters as Record<string, unknown>;
  if (typeof parameters.sourcePath !== 'string' || typeof parameters.destinationPath !== 'string')
    return null;
  const sourceAdmission = staticPathAdmission(parameters.sourcePath);
  const destinationAdmission = staticPathAdmission(parameters.destinationPath);
  if (sourceAdmission === null || destinationAdmission === null) return null;
  // Distinct source and destination objects: an effect whose destination is
  // the source path (case-insensitively) is refused outright.
  if (parameters.sourcePath.toLowerCase() === parameters.destinationPath.toLowerCase()) return null;
  if (!plainWithExactKeys(action.filesystemScope, ['read', 'write'])) return null;
  const scope = action.filesystemScope as Record<string, unknown>;
  if (
    !Array.isArray(scope.read) ||
    scope.read.length !== 1 ||
    typeof scope.read[0] !== 'string' ||
    !Array.isArray(scope.write)
  )
    return null;
  const sourceDir = dirnameOfAdmitted(sourceAdmission);
  const destDir = dirnameOfAdmitted(destinationAdmission);
  if (scope.read[0].toLowerCase() !== sourceDir.toLowerCase()) return null;
  // Exact write binding (case-insensitive): the destination parent for a
  // copy, plus the source parent for move/rename where the entry leaves it.
  const expectedWrite =
    action.op === 'file.copy'
      ? [destDir.toLowerCase()]
      : [...new Set([sourceDir, destDir].map((d) => d.toLowerCase()))].sort();
  const declaredWrite = scope.write;
  if (declaredWrite.length !== expectedWrite.length) return null;
  const declaredSorted = declaredWrite
    .filter((entry): entry is string => typeof entry === 'string')
    .map((d) => d.toLowerCase())
    .sort();
  if (declaredSorted.some((d, i) => d !== expectedWrite[i])) return null;
  return {
    op: action.op as FileMutationOp,
    owner: top.actionId,
    sourcePath: parameters.sourcePath,
    destinationPath: parameters.destinationPath,
    sourceAdmission,
    destinationAdmission,
  };
}

// ---------------------------------------------------------------------------
// Native adapter: the committed addon binary (T04 readonly surface + the F03
// mutation extension), loaded read-only. Failure to load fails closed; there
// is NO pathname-based fallback and NO ambient fs/shell mutation.
// ---------------------------------------------------------------------------

interface MutationNativeAddon {
  dosDevice(letter: string): string | null;
  driveType(root: string): number | null;
  openDir(parent: bigint | null, name: string): bigint | null;
  openFile(parent: bigint, name: string): bigint | null;
  openFileForDelete(parent: bigint, name: string): bigint | null;
  entryInfo(handle: bigint): number | null;
  entryId(handle: bigint): { attrs: number; index: bigint } | null;
  finalPath(handle: bigint): string | null;
  volumeSerial(handle: bigint): number | null;
  createFileExclusive(parent: bigint, name: string): bigint | null;
  writeFile(
    handle: bigint,
    data: Buffer,
  ): { status: number; returned: number; data: Buffer } | null;
  readFileAt(
    handle: bigint,
    offset: bigint,
    length: number,
  ): { status: number; returned: number; data: Buffer } | null;
  readFile(
    handle: bigint,
    length: number,
  ): { status: number; returned: number; data: Buffer } | null;
  flushFile(handle: bigint): boolean;
  renameNoReplace(handle: bigint, newParent: bigint, newName: string): boolean;
  close(handle: bigint): void;
}

export type { MutationNativeAddon };

/**
 * PACKAGE-INTERNAL accessor for the committed addon binary, shared with the
 * read-only poststate verifier (file-mutation-poststate.ts) so exactly one
 * loader/cache exists per process. Not exported through the package exports
 * map.
 */
export function loadMutationNativeAddon(): MutationNativeAddon | null {
  return loadNativeAddon();
}

let nativeAddon: MutationNativeAddon | null | undefined;

function loadNativeAddon(): MutationNativeAddon | null {
  if (nativeAddon !== undefined) return nativeAddon;
  try {
    nativeAddon = createRequire(import.meta.url)(
      '../../recipe-runtime/native/impl/shun_win32_impl.node',
    ) as MutationNativeAddon;
  } catch {
    // Fail closed: no anchored native host, no mutation at all.
    nativeAddon = null;
  }
  return nativeAddon;
}

// ---------------------------------------------------------------------------
// Anchored physical effect.
// ---------------------------------------------------------------------------

/** Open the parent directory of an admitted path through the verified
 * ancestor chain; any reparse in the chain is refused before anything below
 * it is touched. Returns the parent handle; all opens are tracked. */
function openVerifiedParent(
  native: MutationNativeAddon,
  admission: StaticAdmission,
  openHandles: bigint[],
): { parent: bigint; leafName: string } {
  const driveHandle = native.openDir(null, `\\??\\${admission.drive}`);
  if (driveHandle === null) refuse('FILE_MUTATION_DRIVE_REFUSED');
  openHandles.push(driveHandle);
  const driveAttrs = native.entryInfo(driveHandle);
  if (
    driveAttrs === null ||
    (driveAttrs & FILE_ATTRIBUTE_DIRECTORY) === 0 ||
    (driveAttrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0
  )
    refuse('FILE_MUTATION_DRIVE_REFUSED');
  const finalPath = native.finalPath(driveHandle);
  if (finalPath === null) refuse('FILE_MUTATION_DRIVE_REFUSED');
  const stripped = finalPath.startsWith('\\\\?\\') ? finalPath.slice(4) : finalPath;
  if (stripped.toLowerCase() !== admission.drive.toLowerCase())
    refuse('FILE_MUTATION_DRIVE_REFUSED');
  const components = dirnameAdmission(admission).components;
  let parent = driveHandle;
  for (const component of components) {
    const child = native.openDir(parent, component);
    if (child === null) refuse('FILE_MUTATION_SCOPE_REFUSED');
    openHandles.push(child);
    const attrs = native.entryInfo(child);
    if (attrs === null || (attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0)
      refuse('FILE_MUTATION_ALIAS_REFUSED');
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) === 0) refuse('FILE_MUTATION_SCOPE_REFUSED');
    parent = child;
  }
  const leafName = admission.components[admission.components.length - 1];
  if (leafName === undefined) refuse('FILE_MUTATION_SCOPE_REFUSED');
  return { parent, leafName };
}

/**
 * Pure relocation decision for unit coverage: a move/rename is admitted only
 * between objects the OS reports on the SAME volume serial. (Physical runs
 * compare the verified source file's serial with the verified destination
 * parent's serial.)
 */
export function sameVolumeDecision(sourceSerial: number, destSerial: number): boolean {
  return sourceSerial === destSerial;
}

type BoundedSource = Readonly<{
  parent: bigint;
  handle: bigint;
  fileId: bigint;
  volumeSerial: number;
  size: number;
  content: Buffer;
  digest: string;
}>;

/** Close one tracked handle and remove it from the list: a raw handle value
 * can be recycled by the OS, so a double close is never acceptable. */
function closeTracked(native: MutationNativeAddon, openHandles: bigint[], handle: bigint): void {
  const at = openHandles.indexOf(handle);
  if (at >= 0) openHandles.splice(at, 1);
  native.close(handle);
}

/**
 * Post-state proof through the SAME verified second handle that the
 * destination is EXACTLY the source object: a full re-read of [0, size)
 * whose digest matches, AND a 1-byte probe at offset `size` that must
 * complete with STATUS_END_OF_FILE and zero bytes. Every handle in this
 * bridge is FILE_SHARE_ALL, so a concurrent actor can append to a freshly
 * created/renamed destination; an N-byte digest match alone would prove
 * only a PREFIX and a longer (or truncated-then-repadded) file would mint
 * a false COMPLETED_VERIFIED. The zero-length source runs the same EOF
 * probe at offset 0 — an empty destination that gained any byte refuses.
 */
function verifyExactDestination(
  native: MutationNativeAddon,
  handle: bigint,
  source: Readonly<{ size: number; digest: string }>,
): void {
  if (source.size > 0) {
    const back = native.readFileAt(handle, 0n, source.size);
    if (
      back === null ||
      (back.status !== 0 && back.status !== NT_STATUS_END_OF_FILE) ||
      back.returned !== source.size ||
      createHash('sha256').update(back.data.subarray(0, back.returned)).digest('hex') !==
        source.digest
    )
      refuse('FILE_MUTATION_EFFECT_REFUSED');
  }
  const eof = native.readFileAt(handle, BigInt(source.size), 1);
  if (eof === null || eof.status !== NT_STATUS_END_OF_FILE || eof.returned !== 0)
    refuse('FILE_MUTATION_EFFECT_REFUSED');
}

/**
 * Open the admitted source through its verified parent, identity-check it,
 * and read its FULL bounded content through the SAME handle (one 8 MiB probe
 * plus a 1-byte follow-up decides the size; anything larger is refused
 * BEFORE any destination IO exists).
 */
function openBoundedSource(
  native: MutationNativeAddon,
  admission: StaticAdmission,
  openHandles: bigint[],
  instrument: FileMutationInstrument,
): BoundedSource {
  const { parent, leafName } = openVerifiedParent(native, admission, openHandles);
  const handle = native.openFile(parent, leafName);
  if (handle === null) refuse('FILE_MUTATION_EFFECT_REFUSED');
  openHandles.push(handle);
  const identity = native.entryId(handle);
  if (
    identity === null ||
    (identity.attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0 ||
    (identity.attrs & FILE_ATTRIBUTE_DIRECTORY) !== 0
  )
    refuse('FILE_MUTATION_ALIAS_REFUSED');
  const volumeSerial = native.volumeSerial(handle);
  if (volumeSerial === null) refuse('FILE_MUTATION_EFFECT_REFUSED');
  const probe = native.readFile(handle, SIZE_PROBE_BYTES);
  if (probe === null) refuse('FILE_MUTATION_EFFECT_REFUSED');
  if (probe.status !== 0 && probe.status !== NT_STATUS_END_OF_FILE)
    refuse('FILE_MUTATION_EFFECT_REFUSED');
  if (
    !Number.isSafeInteger(probe.returned) ||
    probe.returned < 0 ||
    probe.returned > probe.data.length
  )
    refuse('FILE_MUTATION_EFFECT_REFUSED');
  let content: Buffer;
  if (probe.returned < SIZE_PROBE_BYTES) {
    content = probe.data.subarray(0, probe.returned);
  } else {
    // The probe saturated: either exactly at the cap, or larger. One more
    // bounded read decides — a second data byte means the file exceeds the
    // per-file bound and the mutation is refused before any destination IO.
    const follow = native.readFile(handle, 1);
    if (follow === null) refuse('FILE_MUTATION_EFFECT_REFUSED');
    if (follow.status === 0 && follow.returned > 0) refuse('FILE_MUTATION_BOUNDS_EXCEEDED');
    if (follow.status !== 0 && follow.status !== NT_STATUS_END_OF_FILE)
      refuse('FILE_MUTATION_EFFECT_REFUSED');
    content = probe.data.subarray(0, SIZE_PROBE_BYTES);
  }
  instrument.onSourceOpened?.(`${admission.drive}${admission.components.join('\\')}`);
  return {
    parent,
    handle,
    fileId: identity.index,
    volumeSerial,
    size: content.length,
    content,
    digest: createHash('sha256').update(content).digest('hex'),
  };
}

/**
 * T07 F04B2a drift re-check: after the durable precommit checkpoint, the
 * ORIGINAL source handle is re-observed (identity + volume serial + a full
 * positioned re-read of [0, size) plus a 1-byte EOF probe at `size`) and
 * every value must still equal the commitment. Any concurrent modification
 * of the source between the checkpoint and the effect refuses the mutation
 * before any destination IO exists — the attempt is then conservatively
 * UNCERTAIN at the journal layer, never silently retried.
 */
function reverifyCommittedSource(
  native: MutationNativeAddon,
  handle: bigint,
  committed: Readonly<{ fileId: string; volumeSerial: number; size: number; sha256: string }>,
): void {
  const identity = native.entryId(handle);
  if (identity === null || identity.index.toString() !== committed.fileId)
    refuse('FILE_MUTATION_EFFECT_REFUSED');
  if (native.volumeSerial(handle) !== committed.volumeSerial)
    refuse('FILE_MUTATION_EFFECT_REFUSED');
  if (committed.size > 0) {
    const back = native.readFileAt(handle, 0n, committed.size);
    if (
      back === null ||
      (back.status !== 0 && back.status !== NT_STATUS_END_OF_FILE) ||
      back.returned !== committed.size ||
      createHash('sha256').update(back.data.subarray(0, back.returned)).digest('hex') !==
        committed.sha256
    )
      refuse('FILE_MUTATION_EFFECT_REFUSED');
  }
  const eof = native.readFileAt(handle, BigInt(committed.size), 1);
  if (eof === null || eof.status !== NT_STATUS_END_OF_FILE || eof.returned !== 0)
    refuse('FILE_MUTATION_EFFECT_REFUSED');
}

function mintReceipt(actionId: string, startedAt: string): FileMutationReceipt {
  return Object.freeze({
    actionId,
    environmentId: 'local-windows-user',
    providerId: 'shun-win32-file-mutation',
    providerVersion: '0.2.0',
    startedAt,
    finishedAt: new Date(Math.max(Date.now(), Date.parse(startedAt))).toISOString(),
    terminal: 'SUCCEEDED',
    outputRefs: Object.freeze([] as const),
    sideEffectEvidence: Object.freeze({
      sideEffectClass: 'R2',
      recoveryClassification: 'COMPLETED_VERIFIED',
      postStateVerified: true,
    }),
  });
}

/**
 * PACKAGE-INTERNAL physical seam (same discipline as F02B's
 * `observeVerifiedFileDuplicates`): direct `{op, sourcePath, destinationPath}`
 * mutation of statically admitted fixed-local paths with deterministic IO
 * observation. It exists so the in-package falsifiers can prove zero
 * destination IO on every refusal; src/index.ts does NOT re-export it, so
 * nothing outside this package can reach an unmediated mutation. `owner` is
 * only the receipt's actionId. Production access is exclusively
 * `executeAuthorizedFileMutation` below, which takes no callbacks and only
 * an AuthorizedAction.
 */
export function executeVerifiedFileMutation(
  request: unknown,
  owner: string,
  instrument: FileMutationInstrument = {},
  checkpoints?: FileMutationCheckpoints,
): FileMutationResult {
  const stage = (s: FileMutationStage, detail: string) => instrument.onStage?.(s, detail);
  try {
    if (
      !plainWithExactKeys(request, ['op', 'sourcePath', 'destinationPath']) ||
      typeof (request as Record<string, unknown>).sourcePath !== 'string' ||
      typeof (request as Record<string, unknown>).destinationPath !== 'string' ||
      typeof (request as Record<string, unknown>).op !== 'string' ||
      !(FILE_MUTATION_OPS as readonly string[]).includes(
        (request as Record<string, unknown>).op as string,
      )
    )
      refuse('FILE_MUTATION_SCOPE_REFUSED');
    const req = request as { op: FileMutationOp; sourcePath: string; destinationPath: string };
    const sourceAdmission = staticPathAdmission(req.sourcePath);
    const destinationAdmission = staticPathAdmission(req.destinationPath);
    if (sourceAdmission === null || destinationAdmission === null)
      refuse('FILE_MUTATION_SCOPE_REFUSED');
    if (req.sourcePath.toLowerCase() === req.destinationPath.toLowerCase())
      refuse('FILE_MUTATION_SCOPE_REFUSED');
    const admitted: AdmittedMutation = {
      op: req.op,
      owner,
      sourcePath: req.sourcePath,
      destinationPath: req.destinationPath,
      sourceAdmission,
      destinationAdmission,
    };
    if (process.platform !== 'win32') refuse('FILE_MUTATION_NATIVE_UNAVAILABLE');
    const native = loadNativeAddon();
    if (native === null) refuse('FILE_MUTATION_NATIVE_UNAVAILABLE');
    stage('STATIC_ADMITTED', admitted.op);

    // Both drives attested BEFORE any handle on either drive exists.
    for (const drive of [admitted.sourceAdmission.drive, admitted.destinationAdmission.drive]) {
      const dosDeviceAnswer = native.dosDevice(drive.slice(0, 2));
      const driveTypeAnswer = native.driveType(drive);
      if (!attestsFixedLocalVolume(dosDeviceAnswer, driveTypeAnswer))
        refuse('FILE_MUTATION_DRIVE_REFUSED');
    }
    stage(
      'DRIVE_ATTESTED',
      `${admitted.sourceAdmission.drive[0]}>${admitted.destinationAdmission.drive[0]}`,
    );

    const openHandles: bigint[] = [];
    const startedAt = new Date().toISOString();
    try {
      const source = openBoundedSource(native, admitted.sourceAdmission, openHandles, instrument);
      stage('SOURCE_OPENED', `${source.size}B`);

      // Verified destination parent (reparse-refusing chain on its own
      // drive). Cross-volume relocation is refused BEFORE any destination IO.
      const { parent: destParent, leafName: destName } = openVerifiedParent(
        native,
        admitted.destinationAdmission,
        openHandles,
      );
      const destVolume = native.volumeSerial(destParent);
      if (destVolume === null) refuse('FILE_MUTATION_EFFECT_REFUSED');
      stage('DEST_PARENT_OPENED', admitted.destinationAdmission.drive);
      if (admitted.op !== 'file.copy' && !sameVolumeDecision(source.volumeSerial, destVolume))
        refuse('FILE_MUTATION_CROSS_VOLUME_REFUSED');

      // T07 F04B2a pre-effect checkpoint: the destination prestate is
      // observed (name ABSENT in the verified parent — an existing name
      // refuses as a collision BEFORE any commitment exists), the immutable
      // commitment is built from the already-verified source identity, and
      // the trusted durable write must succeed with zero destination IO
      // before the effect may proceed. The source is then re-observed
      // through the same handle; any drift refuses with zero destination IO.
      if (checkpoints !== undefined) {
        const existing = native.openFile(destParent, destName);
        if (existing !== null) {
          native.close(existing);
          refuse('FILE_MUTATION_COLLISION_REFUSED');
        }
        const commitment: FileMutationPrecommitment = Object.freeze({
          kind: 'file-mutation-precommit-v1',
          actionId: owner,
          op: admitted.op,
          sourcePath: admitted.sourcePath,
          destinationPath: admitted.destinationPath,
          source: Object.freeze({
            fileId: source.fileId.toString(),
            volumeSerial: source.volumeSerial,
            size: source.size,
            sha256: source.digest,
          }),
          destinationPrestate: Object.freeze({ destinationExisted: false }),
        });
        if (checkpoints.durablePrecommit(commitment) !== true)
          refuse('FILE_MUTATION_EFFECT_REFUSED');
        stage('PRECOMMIT_DURABLE', `${source.size}B`);
        reverifyCommittedSource(native, source.handle, commitment.source);
      }

      if (admitted.op === 'file.copy') {
        // Exclusive create: an existing destination name refuses the effect
        // with the pre-existing object untouched.
        const created = native.createFileExclusive(destParent, destName);
        if (created === null) refuse('FILE_MUTATION_COLLISION_REFUSED');
        openHandles.push(created);
        instrument.onDestCreate?.(
          `${admitted.destinationAdmission.drive}${admitted.destinationAdmission.components.join('\\')}`,
        );
        const createdIdentity = native.entryId(created);
        if (createdIdentity === null || (createdIdentity.attrs & FILE_ATTRIBUTE_DIRECTORY) !== 0)
          refuse('FILE_MUTATION_EFFECT_REFUSED');
        if (source.size > 0) {
          const written = native.writeFile(created, source.content);
          if (
            written === null ||
            written.status !== 0 ||
            written.returned !== source.content.length
          )
            refuse('FILE_MUTATION_EFFECT_REFUSED');
        }
        if (!native.flushFile(created)) refuse('FILE_MUTATION_EFFECT_REFUSED');
        const createdId = createdIdentity.index;
        closeTracked(native, openHandles, created);

        // Independent post-state: a SECOND open of the destination through
        // the same verified parent; its FileId must be the created object
        // and it must be EXACTLY the source content and length (digest +
        // EOF proof — see verifyExactDestination). The created handle is
        // already closed, so this proves the durable on-disk object, not a
        // live buffer.
        const verify = native.openFile(destParent, destName);
        if (verify === null) refuse('FILE_MUTATION_EFFECT_REFUSED');
        openHandles.push(verify);
        const verifyIdentity = native.entryId(verify);
        if (verifyIdentity === null || verifyIdentity.index !== createdId)
          refuse('FILE_MUTATION_EFFECT_REFUSED');
        verifyExactDestination(native, verify, source);
        closeTracked(native, openHandles, verify);
        stage('COMPLETED_VERIFIED', 'file.copy');
        return { ok: true, receipt: mintReceipt(owner, startedAt) };
      }

      // file.move / file.rename: relocation through a DELETE-access handle
      // anchored at the SAME verified source parent, whose FileId is
      // cross-checked against the read handle, so a path-to-handle swap
      // between read and rename is refused. The rename itself is
      // ReplaceIfExists = FALSE — an existing destination refuses the effect
      // and leaves BOTH objects untouched.
      const sourceComponents = admitted.sourceAdmission.components;
      const sourceName = sourceComponents[sourceComponents.length - 1];
      if (sourceName === undefined) refuse('FILE_MUTATION_SCOPE_REFUSED');
      const deleteHandle = native.openFileForDelete(source.parent, sourceName);
      if (deleteHandle === null) refuse('FILE_MUTATION_EFFECT_REFUSED');
      openHandles.push(deleteHandle);
      const deleteIdentity = native.entryId(deleteHandle);
      if (deleteIdentity === null || deleteIdentity.index !== source.fileId)
        refuse('FILE_MUTATION_EFFECT_REFUSED');
      const renamed = native.renameNoReplace(deleteHandle, destParent, destName);
      if (!renamed) refuse('FILE_MUTATION_COLLISION_REFUSED');
      instrument.onRename?.(admitted.sourcePath, admitted.destinationPath);
      closeTracked(native, openHandles, deleteHandle);
      closeTracked(native, openHandles, source.handle);

      // Independent post-state: the destination exists as the SAME object
      // (FileId preserved through the relocation — this proves move, not
      // copy+delete), it is EXACTLY the source content and length (digest +
      // EOF proof — see verifyExactDestination), and the source name is
      // gone from its verified parent.
      const moved = native.openFile(destParent, destName);
      if (moved === null) refuse('FILE_MUTATION_EFFECT_REFUSED');
      openHandles.push(moved);
      const movedIdentity = native.entryId(moved);
      if (movedIdentity === null || movedIdentity.index !== source.fileId)
        refuse('FILE_MUTATION_EFFECT_REFUSED');
      verifyExactDestination(native, moved, source);
      closeTracked(native, openHandles, moved);
      const oldName = native.openFile(source.parent, sourceName);
      if (oldName !== null) {
        native.close(oldName);
        refuse('FILE_MUTATION_EFFECT_REFUSED');
      }
      stage('COMPLETED_VERIFIED', admitted.op);
      return { ok: true, receipt: mintReceipt(owner, startedAt) };
    } finally {
      for (const handle of openHandles.reverse()) native.close(handle);
    }
  } catch (error) {
    if (error instanceof Refusal) {
      instrument.onStage?.('EFFECT_REFUSED', error.code);
      return { ok: false, code: error.code };
    }
    // Never disclose scope paths, native errors or partial effects.
    return { ok: false, code: 'FILE_MUTATION_EFFECT_REFUSED' };
  }
}

/**
 * The ONLY production-shaped entry into the physical mutation bridge: one
 * handle-anchored, journal-ordered copy/move/rename of the exact
 * source/destination an ActionController AuthorizedAction names. The caller
 * supplies no paths, no handles and NO callbacks — the intent comes
 * exclusively from the structurally admitted action, and grant-integrity /
 * per-effect currentness re-validation plus the durable STARTED ordering
 * belong to the trusted host boundary that composes this entry
 * (recipe-runtime sqlite-file-mutation-host). That boundary additionally
 * supplies the F04B2a durable precommit checkpoints so the immutable
 * commitment is persisted BEFORE the first destination IO; checkpoints are
 * optional only for the F03-era internal composition — a present but
 * malformed checkpoints object is refused before any IO. Structural
 * authorization failures return FILE_MUTATION_AUTHORIZATION_REFUSED before
 * any IO; physical refusals keep their own codes. Refusals (including
 * pre-IO ones) are conservatively UNCERTAIN at the journal level: the
 * boundary never replays the attempt identity.
 */
export function executeAuthorizedFileMutation(
  action: unknown,
  checkpoints?: FileMutationCheckpoints,
): FileMutationResult {
  const admitted = admittedMutationAction(action);
  if (admitted === null) {
    return Object.freeze({ ok: false as const, code: 'FILE_MUTATION_AUTHORIZATION_REFUSED' });
  }
  let safeCheckpoints: FileMutationCheckpoints | undefined;
  if (checkpoints !== undefined) {
    if (
      !plainWithExactKeys(checkpoints, ['durablePrecommit']) ||
      typeof (checkpoints as Record<string, unknown>).durablePrecommit !== 'function'
    ) {
      return Object.freeze({ ok: false as const, code: 'FILE_MUTATION_AUTHORIZATION_REFUSED' });
    }
    safeCheckpoints = checkpoints;
  }
  // The internal seam is invoked with NO instrument: the authorized path
  // never runs caller-visible callbacks.
  return executeVerifiedFileMutation(
    {
      op: admitted.op,
      sourcePath: admitted.sourcePath,
      destinationPath: admitted.destinationPath,
    },
    admitted.owner,
    {},
    safeCheckpoints,
  );
}
