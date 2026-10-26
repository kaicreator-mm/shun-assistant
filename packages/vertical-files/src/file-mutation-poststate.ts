// T07 F04B2b: read-only independent post-state observation of ONE committed
// file-mutation attempt. This module NEVER mutates anything: it reopens BOTH
// parent chains through verified handle-relative opens (single-component,
// FILE_OPEN_REPARSE_POINT, reparse-refusing — the same anchoring discipline
// as the F03 bridge), re-observes the source and destination objects the
// immutable F04B2a precommitment pinned, and classifies the observed world
// against that commitment. Its native interface deliberately omits every
// mutation export of the addon, so no code path here can create, write,
// flush or rename anything.
//
// Classification honesty (the F04B2 admission contract, PR #186 R1 P1-03):
//   - There is NO PROVEN verdict in this vocabulary. A single current
//     snapshot — however identity-anchored — cannot distinguish THIS
//     attempt's effect from an unrelated actor performing the same
//     id-preserving relocation, or moving the committed object back after
//     the attempt ran: object-identity continuity is NECESSARY evidence for
//     completion but is not a causality witness bound to the attempt. The
//     ceiling for a move world whose destination carries the committed
//     64-bit FileId/volume and whose source name is gone is
//     CONSISTENT_WITH_COMPLETION; the ceiling for the committed object
//     intact under its original name with the destination kernel-confirmed
//     absent is CONSISTENT_WITH_NOT_EXECUTED.
//   - file.copy can never exceed CONSISTENT_* for the same reason (identical
//     bytes prove nothing about which actor created them).
//   - Anything else (drifted source, unexplained identities, both names
//     gone, destination longer/shorter than committed) stays UNKNOWN:
//     insufficient evidence is never upgraded, and no verdict here is ever
//     replay authority — reconcile decisions belong to the trusted host
//     boundary (recipe-runtime), which joins this verifier with the durable
//     journal.
//
// Absence honesty (PR #186 R1 P1-02): a leaf name counts as ABSENT only when
// the kernel itself reports STATUS_OBJECT_NAME_NOT_FOUND /
// STATUS_OBJECT_PATH_NOT_FOUND through the status-aware anchored open. Every
// other open failure (sharing violation, access denied, delete pending...)
// is an AMBIGUOUS observation — a present-but-unopenable object must never
// be read as absent — and refuses the whole observation (no verdict at all,
// never a negative one). A directory occupying the leaf name is a
// present-but-diverged object, not an absent one.
//
// The precommitment arrives as PLAIN DATA (typically read back from the
// durable journal by the trusted host): it is structurally admitted
// fail-closed and is never treated as authorization for anything. Nothing
// here is exported through the package exports map (src/index.ts).
import { createHash } from 'node:crypto';
import { types } from 'node:util';
import {
  FILE_MUTATION_OPS,
  type FileMutationOp,
  loadMutationNativeAddon,
} from './file-mutation-host.ts';
import { attestsFixedLocalVolume } from './host-observation.ts';

const MAX_PATH = 2048;
const MAX_FILE_BYTES = 8 << 20;

// NTSTATUS STATUS_END_OF_FILE (0xC0000011); see file-mutation-host.ts.
const NT_STATUS_END_OF_FILE = 0xc0000011;
// NTSTATUS leaf/chain absence as reported by the kernel itself — the ONLY
// failures that may be read as "absent" (PR #186 R1 P1-02).
const NT_STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
const NT_STATUS_OBJECT_PATH_NOT_FOUND = 0xc0000035;
// NTSTATUS STATUS_FILE_IS_A_DIRECTORY: the leaf NAME exists but is occupied
// by a directory (FILE_NON_DIRECTORY_FILE refuses the open) — a
// present-but-diverged object, not an absent one.
const NT_STATUS_FILE_IS_A_DIRECTORY = 0xc00000ba;
const FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
const FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

/**
 * PR #186 R1 P1-03: no PROVEN verdict exists. A single current snapshot
 * cannot witness that THIS attempt caused the observed world (an unrelated
 * actor can perform the same id-preserving relocation, or move the
 * committed object back after the attempt ran); identity-anchored world
 * state caps at CONSISTENT_*, and everything insufficient stays UNKNOWN.
 */
export type FileMutationPoststateVerdict =
  | 'CONSISTENT_WITH_COMPLETION'
  | 'CONSISTENT_WITH_NOT_EXECUTED'
  | 'UNKNOWN';

export type FileMutationPoststateRefusalCode =
  | 'POSTSTATE_PRECOMMIT_REFUSED'
  | 'POSTSTATE_SCOPE_REFUSED'
  | 'POSTSTATE_NATIVE_UNAVAILABLE'
  | 'POSTSTATE_DRIVE_REFUSED'
  | 'POSTSTATE_ALIAS_REFUSED'
  | 'POSTSTATE_OBSERVATION_REFUSED';

export type FileMutationPoststateResult =
  | { ok: true; verdict: FileMutationPoststateVerdict; evidence: FileMutationPoststateEvidence }
  | { ok: false; code: FileMutationPoststateRefusalCode };

export type FileMutationPoststateEvidence = Readonly<{
  kind: 'file-mutation-poststate-v1';
  actionId: string;
  sourcePresent: boolean;
  destPresent: boolean;
  /** null when the object is absent or its identity could not be observed. */
  sourceMatchesCommitment: boolean | null;
  destMatchesCommitment: boolean | null;
  /** move only: destination FileId + volume equal the committed source. */
  destIdentityContinuity: boolean | null;
  observedAt: string;
}>;

class Refusal extends Error {
  constructor(public readonly code: FileMutationPoststateRefusalCode) {
    super(code);
  }
}

function refuse(code: FileMutationPoststateRefusalCode): never {
  throw new Refusal(code);
}

// ---------------------------------------------------------------------------
// Static admission, duplicated deliberately from file-mutation-host.ts so
// this read-only surface stays independently reviewable; the copies must
// agree.
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
  if (!/^[a-zA-Z]:\\/.test(path)) return null;
  if (path.includes('/')) return null;
  const components = path.slice(3).split('\\');
  if (components.length < 2) return null;
  for (const component of components) {
    if (component.length === 0) return null;
    if (!validComponent(component)) return null;
  }
  return { drive: `${path[0]?.toUpperCase()}:${'\\'}`, components };
}

function dirnameAdmission(admission: StaticAdmission): StaticAdmission {
  return { drive: admission.drive, components: admission.components.slice(0, -1) };
}

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

// ---------------------------------------------------------------------------
// Precommitment admission (fail-closed structural mirror of the shape the
// F03 bridge mints in file-mutation-host.ts).
// ---------------------------------------------------------------------------

const SHA256_HEX = /^[a-f0-9]{64}$/;
const DECIMAL_FILE_ID = /^\d{1,20}$/;

type AdmittedPrecommitment = Readonly<{
  actionId: string;
  op: FileMutationOp;
  sourcePath: string;
  destinationPath: string;
  sourceAdmission: StaticAdmission;
  destinationAdmission: StaticAdmission;
  source: Readonly<{ fileId: string; volumeSerial: number; size: number; sha256: string }>;
}>;

export function admittedPoststatePrecommitment(value: unknown): AdmittedPrecommitment | null {
  if (
    !plainWithExactKeys(value, [
      'kind',
      'actionId',
      'op',
      'sourcePath',
      'destinationPath',
      'source',
      'destinationPrestate',
    ])
  )
    return null;
  const raw = value as Record<string, unknown>;
  if (raw.kind !== 'file-mutation-precommit-v1') return null;
  if (typeof raw.actionId !== 'string' || raw.actionId.length === 0 || raw.actionId.length > 128)
    return null;
  if (typeof raw.op !== 'string' || !(FILE_MUTATION_OPS as readonly string[]).includes(raw.op))
    return null;
  if (typeof raw.sourcePath !== 'string' || typeof raw.destinationPath !== 'string') return null;
  const sourceAdmission = staticPathAdmission(raw.sourcePath);
  const destinationAdmission = staticPathAdmission(raw.destinationPath);
  if (sourceAdmission === null || destinationAdmission === null) return null;
  if (raw.sourcePath.toLowerCase() === raw.destinationPath.toLowerCase()) return null;
  if (!plainWithExactKeys(raw.source, ['fileId', 'volumeSerial', 'size', 'sha256'])) return null;
  const source = raw.source as Record<string, unknown>;
  if (typeof source.fileId !== 'string' || !DECIMAL_FILE_ID.test(source.fileId)) return null;
  if (
    !Number.isSafeInteger(source.volumeSerial) ||
    (source.volumeSerial as number) < 0 ||
    (source.volumeSerial as number) > 0xffffffff
  )
    return null;
  if (
    !Number.isSafeInteger(source.size) ||
    (source.size as number) < 0 ||
    (source.size as number) > MAX_FILE_BYTES
  )
    return null;
  if (typeof source.sha256 !== 'string' || !SHA256_HEX.test(source.sha256)) return null;
  if (!plainWithExactKeys(raw.destinationPrestate, ['destinationExisted'])) return null;
  if ((raw.destinationPrestate as Record<string, unknown>).destinationExisted !== false)
    return null;
  return {
    actionId: raw.actionId,
    op: raw.op as FileMutationOp,
    sourcePath: raw.sourcePath,
    destinationPath: raw.destinationPath,
    sourceAdmission,
    destinationAdmission,
    source: {
      fileId: source.fileId,
      volumeSerial: source.volumeSerial as number,
      size: source.size as number,
      sha256: source.sha256,
    },
  };
}

// ---------------------------------------------------------------------------
// Read-only native surface: every mutation export of the addon is OMITTED
// from this interface, so observation cannot create/write/rename anything.
// ---------------------------------------------------------------------------

interface PoststateNative {
  dosDevice(letter: string): string | null;
  driveType(root: string): number | null;
  openDir(parent: bigint | null, name: string): bigint | null;
  /** PR #186 R1 P1-02: status-aware twin of openFile so kernel-confirmed
   * absence is distinguishable from ambiguous open failures. napi-rs
   * serializes the Rust Option<BigInt> None as JS undefined. */
  openFileStatus(
    parent: bigint,
    name: string,
  ): { status: number; handle: bigint | undefined } | null;
  entryInfo(handle: bigint): number | null;
  entryId(handle: bigint): { attrs: number; index: bigint } | null;
  volumeSerial(handle: bigint): number | null;
  readFileAt(
    handle: bigint,
    offset: bigint,
    length: number,
  ): { status: number; returned: number; data: Buffer } | null;
  close(handle: bigint): void;
}

/**
 * PACKAGE-INTERNAL test/audit-only seam: synchronous observation of which
 * anchored objects were opened, so falsifiers can prove the refusal paths
 * performed ZERO opens beyond the admitted prefix. Reachable only inside
 * this package; the observation entry below never invokes caller callbacks
 * on the privileged path.
 */
export type PoststateInstrument = Readonly<{
  onSourceOpened?: (rel: string) => void;
  onDestOpened?: (rel: string) => void;
}>;

/** Open the verified (reparse-refusing) parent chain of an admitted path. */
function openVerifiedParent(
  native: PoststateNative,
  admission: StaticAdmission,
  openHandles: bigint[],
): { parent: bigint; leafName: string } {
  const driveHandle = native.openDir(null, `\\??\\${admission.drive}`);
  if (driveHandle === null) refuse('POSTSTATE_OBSERVATION_REFUSED');
  openHandles.push(driveHandle);
  const driveAttrs = native.entryInfo(driveHandle);
  if (
    driveAttrs === null ||
    (driveAttrs & FILE_ATTRIBUTE_DIRECTORY) === 0 ||
    (driveAttrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0
  )
    refuse('POSTSTATE_OBSERVATION_REFUSED');
  const components = dirnameAdmission(admission).components;
  let parent = driveHandle;
  for (const component of components) {
    const child = native.openDir(parent, component);
    if (child === null) refuse('POSTSTATE_SCOPE_REFUSED');
    openHandles.push(child);
    const attrs = native.entryInfo(child);
    if (attrs === null || (attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0)
      refuse('POSTSTATE_ALIAS_REFUSED');
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) === 0) refuse('POSTSTATE_SCOPE_REFUSED');
    parent = child;
  }
  const leafName = admission.components[admission.components.length - 1];
  if (leafName === undefined) refuse('POSTSTATE_SCOPE_REFUSED');
  return { parent, leafName };
}

type ObservedObject = Readonly<{
  present: boolean;
  /** null when absent or not a plain file object. */
  fileId: string | null;
  volumeSerial: number | null;
  /** null when absent or content/EOF could not be verified exactly. */
  matches: boolean | null;
}>;

/**
 * Observe one leaf name in its verified parent: present or absent, its
 * 64-bit FileId + volume serial when it is a plain file, and whether its
 * content is EXACTLY the committed bytes (full positioned re-read of
 * [0, size) with digest match plus a 1-byte EOF probe at `size` — a longer
 * or truncated-then-repadded object does NOT match, mirroring the F03
 * exact-destination discipline).
 *
 * PR #186 R1 P1-02: absence is a KERNEL verdict only. A failed open counts
 * as absent exclusively on STATUS_OBJECT_NAME_NOT_FOUND /
 * STATUS_OBJECT_PATH_NOT_FOUND; a directory occupying the name is a
 * present-but-diverged object; every other status (sharing violation,
 * access denied, delete pending...) is AMBIGUOUS — a present-but-unopenable
 * object must never be read as absent — and refuses the whole observation
 * (no verdict, never a negative one).
 */
function observeLeaf(
  native: PoststateNative,
  admission: StaticAdmission,
  committed: Readonly<{ fileId: string; volumeSerial: number; size: number; sha256: string }>,
  openHandles: bigint[],
  onOpened: (rel: string) => void,
): ObservedObject {
  const { parent, leafName } = openVerifiedParent(native, admission, openHandles);
  const opened = native.openFileStatus(parent, leafName);
  if (opened === null) refuse('POSTSTATE_OBSERVATION_REFUSED');
  if (opened.handle === undefined || opened.handle === null) {
    if (opened.status === NT_STATUS_FILE_IS_A_DIRECTORY) {
      // Present, but no longer a plain file object: an observable divergence,
      // not an observation failure.
      return { present: true, fileId: null, volumeSerial: null, matches: false };
    }
    if (
      opened.status !== NT_STATUS_OBJECT_NAME_NOT_FOUND &&
      opened.status !== NT_STATUS_OBJECT_PATH_NOT_FOUND
    )
      refuse('POSTSTATE_OBSERVATION_REFUSED');
    return { present: false, fileId: null, volumeSerial: null, matches: null };
  }
  const handle = opened.handle;
  openHandles.push(handle);
  onOpened(`${admission.drive}${admission.components.join('\\')}`);
  const identity = native.entryId(handle);
  if (
    identity === null ||
    (identity.attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0 ||
    (identity.attrs & FILE_ATTRIBUTE_DIRECTORY) !== 0
  ) {
    // Present, but no longer a plain file object: an observable divergence,
    // not an observation failure.
    return { present: true, fileId: null, volumeSerial: null, matches: false };
  }
  const serial = native.volumeSerial(handle);
  if (serial === null) refuse('POSTSTATE_OBSERVATION_REFUSED');
  let matches = true;
  if (committed.size > 0) {
    const back = native.readFileAt(handle, 0n, committed.size);
    if (
      back === null ||
      (back.status !== 0 && back.status !== NT_STATUS_END_OF_FILE) ||
      back.returned !== committed.size ||
      createHash('sha256').update(back.data.subarray(0, back.returned)).digest('hex') !==
        committed.sha256
    )
      matches = false;
  }
  if (matches) {
    const eof = native.readFileAt(handle, BigInt(committed.size), 1);
    if (eof === null || eof.status !== NT_STATUS_END_OF_FILE || eof.returned !== 0) {
      if (eof === null) refuse('POSTSTATE_OBSERVATION_REFUSED');
      matches = false;
    }
  }
  return {
    present: true,
    fileId: identity.index.toString(),
    volumeSerial: serial,
    matches,
  };
}

/**
 * Pure classification of one observed world against one admitted
 * commitment (unit-testable without any IO). PR #186 R1 P1-03: no PROVEN
 * verdict exists — a single snapshot cannot witness that THIS attempt
 * caused the world. A move world whose destination carries the committed
 * FileId/volume continuity with the source name gone caps at
 * CONSISTENT_WITH_COMPLETION; the committed object intact at its original
 * name with the destination kernel-confirmed absent caps at
 * CONSISTENT_WITH_NOT_EXECUTED (an unrelated actor can produce both worlds
 * without this attempt ever running); a copy can never exceed CONSISTENT_*;
 * everything insufficient stays UNKNOWN.
 */
export function classifyPoststate(
  op: FileMutationOp,
  observed: Readonly<{
    sourcePresent: boolean;
    destPresent: boolean;
    sourceMatches: boolean | null;
    destMatches: boolean | null;
    destIdentityContinuity: boolean | null;
  }>,
): FileMutationPoststateVerdict {
  if (op !== 'file.copy') {
    if (
      observed.destPresent &&
      observed.destMatches === true &&
      observed.destIdentityContinuity === true &&
      !observed.sourcePresent
    )
      return 'CONSISTENT_WITH_COMPLETION';
    if (observed.sourcePresent && observed.sourceMatches === true && !observed.destPresent)
      return 'CONSISTENT_WITH_NOT_EXECUTED';
    return 'UNKNOWN';
  }
  if (observed.destPresent && observed.destMatches === true && observed.sourceMatches === true)
    return 'CONSISTENT_WITH_COMPLETION';
  if (!observed.destPresent && observed.sourcePresent && observed.sourceMatches === true)
    return 'CONSISTENT_WITH_NOT_EXECUTED';
  return 'UNKNOWN';
}

/**
 * PACKAGE-INTERNAL read-only observation entry: independently re-observe
 * the exact source/destination objects an F04B2a precommitment pinned and
 * classify the world against it. `precommit` is PLAIN DATA (fail-closed
 * structural admission, never authorization); on Windows this performs
 * real anchored opens through the committed addon binary — read-only, no
 * callback on the privileged path, all handles closed before returning.
 */
export function observeFileMutationPoststate(
  precommit: unknown,
  instrument: PoststateInstrument = Object.create(null),
): FileMutationPoststateResult {
  try {
    const admitted = admittedPoststatePrecommitment(precommit);
    if (admitted === null) refuse('POSTSTATE_PRECOMMIT_REFUSED');
    if (process.platform !== 'win32') refuse('POSTSTATE_NATIVE_UNAVAILABLE');
    const native = loadMutationNativeAddon() as PoststateNative | null;
    if (native === null) refuse('POSTSTATE_NATIVE_UNAVAILABLE');

    // Both drives attested BEFORE any handle on either drive exists.
    for (const drive of [admitted.sourceAdmission.drive, admitted.destinationAdmission.drive]) {
      const dosDeviceAnswer = native.dosDevice(drive.slice(0, 2));
      const driveTypeAnswer = native.driveType(drive);
      if (!attestsFixedLocalVolume(dosDeviceAnswer, driveTypeAnswer))
        refuse('POSTSTATE_DRIVE_REFUSED');
    }

    const openHandles: bigint[] = [];
    try {
      const source = observeLeaf(
        native,
        admitted.sourceAdmission,
        admitted.source,
        openHandles,
        (rel) => instrument.onSourceOpened?.(rel),
      );
      const dest = observeLeaf(
        native,
        admitted.destinationAdmission,
        admitted.source,
        openHandles,
        (rel) => instrument.onDestOpened?.(rel),
      );
      const sourceMatches =
        source.present &&
        source.fileId === admitted.source.fileId &&
        source.volumeSerial === admitted.source.volumeSerial &&
        source.matches === true;
      const destMatches = dest.present && dest.matches === true;
      const destIdentityContinuity =
        dest.present &&
        dest.fileId !== null &&
        dest.fileId === admitted.source.fileId &&
        dest.volumeSerial === admitted.source.volumeSerial;
      const verdict = classifyPoststate(admitted.op, {
        sourcePresent: source.present,
        destPresent: dest.present,
        sourceMatches: source.present ? sourceMatches : null,
        destMatches: dest.present ? destMatches : null,
        destIdentityContinuity: dest.present ? destIdentityContinuity : null,
      });
      return Object.freeze({
        ok: true as const,
        verdict,
        evidence: Object.freeze({
          kind: 'file-mutation-poststate-v1' as const,
          actionId: admitted.actionId,
          sourcePresent: source.present,
          destPresent: dest.present,
          sourceMatchesCommitment: source.present ? sourceMatches : null,
          destMatchesCommitment: dest.present ? destMatches : null,
          destIdentityContinuity: dest.present ? destIdentityContinuity : null,
          observedAt: new Date().toISOString(),
        }),
      });
    } finally {
      for (const handle of openHandles.reverse()) native.close(handle);
    }
  } catch (error) {
    if (error instanceof Refusal) return { ok: false, code: error.code };
    // Never disclose scope paths, native errors or observations.
    return { ok: false, code: 'POSTSTATE_OBSERVATION_REFUSED' };
  }
}
