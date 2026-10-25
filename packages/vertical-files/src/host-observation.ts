// T07 F02B: host-owned Windows handle-anchored read-only duplicate
// observation. This is the trusted physical bridge that F02A's pure report
// explicitly deferred (`pendingTrustedChecks`); it consumes NO caller
// metadata — F02A's metadata digest is not provenance here. Every fact is
// re-derived from the OS through the SAME committed native addon binary T04
// reviewed (packages/recipe-runtime/native/impl/shun_win32_impl.node, loaded
// read-only across the package boundary; no recipe-runtime source is used or
// modified). The anchoring discipline mirrors the independently reviewed T04
// oracle:
//   - the drive letter is attested as a fixed local volume by two purely
//     local kernel questions BEFORE any handle exists (refuses mapped SMB,
//     subst and every other alias device with zero opens);
//   - every directory and file is opened through a single name component
//     anchored at an already-verified parent handle with
//     FILE_OPEN_REPARSE_POINT, so a junction/symlink entry or ancestor
//     yields the reparse point itself (refused from attributes) and its
//     target is never touched;
//   - every opened object is identity-checked against the 64-bit FileId
//     enumerated from its verified parent, so a same-name swap between
//     enumeration and open is refused before a content byte is read;
//   - a positive observation requires TWO independent anchored passes whose
//     fingerprints (relative path, kind, size, mtime, file identity AND a
//     content digest read through the same anchored handle) are
//     byte-identical — a mid-scan mutation preserving name/size/mtime is
//     refused, never verified.
// This module performs NO writes, grants no authority, accepts no callbacks
// with capability, and refuses incomplete walks rather than returning an
// apparently complete partial result.
//
// R1 authorization boundary (PR #182 review P1-01/P2-01): a handle anchor is
// path integrity, NOT user authorization. The ONLY entry a production caller
// can reach is `observeAuthorizedFileDuplicates`, which consumes an
// AuthorizedAction produced by the T04 central ActionController
// (packages/authorization + @shun/contracts plan.ts AuthorizedActionSchema):
// the action must name this capability's op, be R0 read-only, carry no
// write/network/registry/secret scope, bind its single filesystem read scope
// EXACTLY to the one scopeRoot it observes, and still be inside its bounded
// expiry when the scan starts. The per-effect currentness/grant-integrity
// re-validation (ActionController.authorizeEffect) stays with the trusted
// host bootstrap that wires this bridge, exactly as in T04's
// executeTrustedWindowsR0Search. The older `{scopeRoot}`-shaped entry below
// is a package-internal test/audit seam: it is deliberately NOT exported
// through the package exports map (src/index.ts), so Recipe/model/HTTP code
// cannot initiate an unmediated scan, and it accepts no caller callbacks on
// the authorized path.
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { types } from 'node:util';

const MAX_PATH = 2048;
const MAX_ENTRIES = 4096;
const MAX_DIRS = 512;
const MAX_DEPTH = 8;
const MAX_DUPLICATE_GROUPS = 128;
const FILE_CONTENT_CAP_BYTES = 262_144;
const WALK_CONTENT_BUDGET_BYTES = 32 << 20;
const ENUM_BUFFER_BYTES = 65_536;

const NT_STATUS_NO_MORE_FILES = 0x80000006;
const NT_STATUS_BUFFER_OVERFLOW = 0x80000005;
const NT_STATUS_END_OF_FILE = 0x80000004;
const FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
const FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
const DRIVE_FIXED = 3;

export type VerifiedDuplicateGroup = Readonly<{
  sizeBytes: number;
  contentDigestSha256: string;
  relativePaths: readonly string[];
}>;

export type HostDuplicateObservation = Readonly<{
  schema: 'shun.files.duplicate-verification.v02';
  status: 'HOST_OBSERVED_CONTENT_VERIFIED';
  trust: 'VERIFIED_HOST_OBSERVATION';
  scopeRoot: string;
  inspectedEntries: number;
  observedFiles: number;
  verifiedDuplicateGroups: readonly VerifiedDuplicateGroup[];
  inventoryDigestSha256: string;
  filesystemObserved: true;
  duplicatesVerified: true;
  executionAuthorized: false;
  cloudDisclosure: false;
  completedTrustedChecks: readonly [
    'WINDOWS_HANDLE_ANCHORED_INVENTORY',
    'NO_REPARSE_OR_NETWORK_FOLLOW',
    'CONTENT_DIGEST_FROM_VERIFIED_HANDLES',
    'INDEPENDENT_POSTSTATE_CHECK',
  ];
}>;

export type HostObservationRefusalCode =
  | 'HOST_OBSERVE_AUTHORIZATION_REFUSED'
  | 'HOST_OBSERVE_SCOPE_REFUSED'
  | 'HOST_OBSERVE_NATIVE_UNAVAILABLE'
  | 'HOST_OBSERVE_DRIVE_REFUSED'
  | 'HOST_OBSERVE_ALIAS_REFUSED'
  | 'HOST_OBSERVE_BOUNDS_EXCEEDED'
  | 'HOST_OBSERVE_MUTATION_REFUSED';

export type HostObservationResult =
  | { ok: true; observation: HostDuplicateObservation }
  | { ok: false; code: HostObservationRefusalCode };

/**
 * PACKAGE-INTERNAL test/audit-only seam (R1 P2-01 resolution): synchronous
 * observation of what the bridge actually opened, used by the negative
 * controls to prove zero IO beyond the admitted prefix and to stage
 * deterministic mutations between passes. It is reachable ONLY inside this
 * package (tests import the module file directly; src/index.ts does not
 * re-export it or the seam entry that accepts it), and the authorized public
 * entry below never accepts or invokes caller callbacks — an untrusted
 * caller cannot inject execution hooks into a privileged scan.
 */
export type HostObservationInstrument = Readonly<{
  onStage?: (stage: HostObservationStage, detail: string) => void;
  onDirOpen?: (depth: number, name: string) => void;
  onFileOpen?: (rel: string) => void;
  onPassCompleted?: (pass: 1 | 2) => void;
}>;

export type HostObservationStage =
  | 'STATIC_ADMITTED'
  | 'DRIVE_ATTESTED'
  | 'DRIVE_OPENED'
  | 'ANCESTOR_OPENED'
  | 'ADMITTED'
  | 'REFUSED';

const COMPLETED_CHECKS = Object.freeze([
  'WINDOWS_HANDLE_ANCHORED_INVENTORY',
  'NO_REPARSE_OR_NETWORK_FOLLOW',
  'CONTENT_DIGEST_FROM_VERIFIED_HANDLES',
  'INDEPENDENT_POSTSTATE_CHECK',
] as const);

class Refusal extends Error {
  constructor(public readonly code: HostObservationRefusalCode) {
    super(code);
  }
}

function refuse(code: HostObservationRefusalCode): never {
  throw new Refusal(code);
}

// ---------------------------------------------------------------------------
// Static scope admission (zero IO, platform independent).
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
    // NUL and every other control character is refused by
    // hasControlCharacters below; this regex covers separators only.
    !/[<>:"|?*\\/]/.test(part) &&
    !BIDI_OR_ISOLATION.test(part) &&
    !hasControlCharacters(part) &&
    !RESERVED_DOS_NAMES.test(part) &&
    !/[. ]$/.test(part)
  );
}

type StaticAdmission = Readonly<{ drive: string; components: readonly string[] }>;

function staticScopeAdmission(root: unknown): StaticAdmission | null {
  if (typeof root !== 'string' || root.length < 3 || root.length > MAX_PATH) return null;
  if (root.includes('\u0000')) return null;
  const path = root.replaceAll('/', '\\');
  // Fixed-drive syntax only, judged on the RAW caller form so a drive-relative
  // path ("C:relative") can never be silently re-anchored to the cwd: no UNC
  // shares, no device namespace, no rooted or relative paths.
  if (!/^[a-zA-Z]:\\/.test(path)) return null;
  const components = path
    .slice(3)
    .split('\\')
    .filter((part) => part.length > 0);
  for (const component of components) {
    if (!validComponent(component)) return null;
  }
  return { drive: `${path[0]?.toUpperCase()}:${'\\'}`, components };
}

/**
 * The OS-attested fixed-local-drive decision over the two raw attestation
 * answers. Exported for unit coverage of the mapped-SMB device form
 * (\Device\LanmanRedirector\...) without requiring a physical mapping.
 */
export function attestsFixedLocalVolume(
  dosDeviceAnswer: string | null,
  driveTypeAnswer: number | null,
): boolean {
  if (typeof dosDeviceAnswer !== 'string' || dosDeviceAnswer.length === 0) return false;
  // A fixed local volume device only. This refuses drive letters backed by
  // the network redirector, subst aliases (\??\C:\path) and every other
  // non-volume device.
  if (!dosDeviceAnswer.toLowerCase().startsWith('\\device\\harddiskvolume')) return false;
  if (driveTypeAnswer !== DRIVE_FIXED) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Native adapter: the committed T04 addon binary, loaded read-only. Failure
// to load fails closed (refuse); there is NO pathname-based fallback.
// ---------------------------------------------------------------------------

interface NativeAddon {
  dosDevice(letter: string): string | null;
  driveType(root: string): number | null;
  openDir(parent: bigint | null, name: string): bigint | null;
  openFile(parent: bigint, name: string): bigint | null;
  entryInfo(handle: bigint): number | null;
  entryId(handle: bigint): { attrs: number; index: bigint } | null;
  finalPath(handle: bigint): string | null;
  enumerate(
    handle: bigint,
    restart: boolean,
    bufferBytes: number,
  ): { status: number; returned: number; data: Buffer } | null;
  readFile(
    handle: bigint,
    length: number,
  ): { status: number; returned: number; data: Buffer } | null;
  close(handle: bigint): void;
}

let nativeAddon: NativeAddon | null | undefined;

function loadNativeAddon(): NativeAddon | null {
  if (nativeAddon !== undefined) return nativeAddon;
  try {
    nativeAddon = createRequire(import.meta.url)(
      '../../recipe-runtime/native/impl/shun_win32_impl.node',
    ) as NativeAddon;
  } catch {
    // Fail closed: no anchored native host, no observation at all.
    nativeAddon = null;
  }
  return nativeAddon;
}

// ---------------------------------------------------------------------------
// Independent enumeration decoder (Buffer-method based; deliberately a
// third construction beside the two T04 decoders).
// ---------------------------------------------------------------------------

// FILE_ID_BOTH_DIR_INFORMATION field offsets on x64.
const FIELD = {
  nextEntryOffset: 0,
  lastWriteTime: 24,
  endOfFile: 40,
  attributes: 56,
  fileNameLength: 60,
  fileId: 96,
  fileName: 104,
} as const;

type EnumeratedEntry = Readonly<{
  name: string;
  attrs: number;
  fileId: bigint;
  size: bigint;
  lastWriteMs: bigint;
}>;

function decodeEnumerateBuffer(data: Buffer, returned: number): EnumeratedEntry[] {
  const entries: EnumeratedEntry[] = [];
  let offset = 0;
  for (;;) {
    if (offset + FIELD.fileName > returned) return [];
    const next = data.readUInt32LE(offset + FIELD.nextEntryOffset);
    const attrs = data.readUInt32LE(offset + FIELD.attributes);
    const nameLength = data.readUInt32LE(offset + FIELD.fileNameLength);
    const nameStart = offset + FIELD.fileName;
    // A chain entry must cover the fixed header and never run past the
    // returned byte count.
    if (nameLength % 2 !== 0 || nameStart + nameLength > returned) return [];
    entries.push({
      name: data.toString('utf16le', nameStart, nameStart + nameLength),
      attrs,
      fileId: data.readBigUInt64LE(offset + FIELD.fileId),
      size: data.readBigUInt64LE(offset + FIELD.endOfFile),
      lastWriteMs:
        data.readBigUInt64LE(offset + FIELD.lastWriteTime) / 10_000n - 11_644_473_600_000n,
    });
    if (next === 0) break;
    if (next < FIELD.fileName || next % 8 !== 0 || offset + next > returned) return [];
    offset += next;
  }
  return entries;
}

// ---------------------------------------------------------------------------
// One anchored observation pass. All handles are tracked and closed on every
// exit path. Entries are processed in sorted name order, so the content
// budget is deterministic for a given tree.
// ---------------------------------------------------------------------------

type PassResult = Readonly<{ lines: readonly string[]; entries: number; files: number }>;

function anchoredPass(
  native: NativeAddon,
  admission: StaticAdmission,
  instrument: HostObservationInstrument,
): PassResult {
  const stage = (s: HostObservationStage, detail: string) => instrument.onStage?.(s, detail);
  const openHandles: bigint[] = [];
  try {
    const driveHandle = native.openDir(null, `\\??\\${admission.drive}`);
    if (driveHandle === null) {
      stage('REFUSED', 'drive-open');
      refuse('HOST_OBSERVE_DRIVE_REFUSED');
    }
    openHandles.push(driveHandle);
    instrument.onDirOpen?.(0, admission.drive);
    stage('DRIVE_OPENED', admission.drive);
    const driveAttrs = native.entryInfo(driveHandle);
    if (
      driveAttrs === null ||
      (driveAttrs & FILE_ATTRIBUTE_DIRECTORY) === 0 ||
      (driveAttrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0
    )
      refuse('HOST_OBSERVE_DRIVE_REFUSED');
    const finalPath = native.finalPath(driveHandle);
    if (finalPath === null) refuse('HOST_OBSERVE_DRIVE_REFUSED');
    const stripped = finalPath.startsWith('\\\\?\\') ? finalPath.slice(4) : finalPath;
    if (stripped.toLowerCase() !== admission.drive.toLowerCase())
      refuse('HOST_OBSERVE_DRIVE_REFUSED');

    // Anchored descent through the full ancestor chain: every open is one
    // component inside the previous verified handle, so no junction alias in
    // any ancestor can redirect resolution. The junction component itself
    // opens with FILE_OPEN_REPARSE_POINT and is refused from its own
    // attributes before anything below it is touched.
    let rootHandle = driveHandle;
    for (const component of admission.components) {
      const child = native.openDir(rootHandle, component);
      if (child === null) {
        stage('REFUSED', `ancestor-open:${component}`);
        refuse('HOST_OBSERVE_SCOPE_REFUSED');
      }
      openHandles.push(child);
      instrument.onDirOpen?.(openHandles.length, component);
      stage('ANCESTOR_OPENED', component);
      const attrs = native.entryInfo(child);
      if (attrs === null) refuse('HOST_OBSERVE_ALIAS_REFUSED');
      if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0) refuse('HOST_OBSERVE_ALIAS_REFUSED');
      if ((attrs & FILE_ATTRIBUTE_DIRECTORY) === 0) refuse('HOST_OBSERVE_SCOPE_REFUSED');
      rootHandle = child;
    }
    stage('ADMITTED', admission.drive);

    const rootIdentity = native.entryId(rootHandle);
    if (rootIdentity === null || (rootIdentity.attrs & FILE_ATTRIBUTE_DIRECTORY) === 0)
      refuse('HOST_OBSERVE_SCOPE_REFUSED');

    const lines: string[] = [`r\t${rootIdentity.index}`];
    let entries = 0;
    let files = 0;
    let visitedDirs = 0;
    let contentBytes = 0;
    type Frame = { handle: bigint; depth: number; rel: string };
    const stack: Frame[] = [{ handle: rootHandle, depth: 0, rel: '' }];
    while (stack.length > 0) {
      const frame = stack.pop();
      if (!frame) refuse('HOST_OBSERVE_MUTATION_REFUSED');
      if (++visitedDirs > MAX_DIRS) refuse('HOST_OBSERVE_BOUNDS_EXCEEDED');
      // Collect the whole directory stream first, then process it in sorted
      // name order: the traversal (and the content budget with it) becomes
      // deterministic for a given tree.
      const batch: EnumeratedEntry[] = [];
      let restart = true;
      for (;;) {
        const raw = native.enumerate(frame.handle, restart, ENUM_BUFFER_BYTES);
        restart = false;
        if (raw === null) refuse('HOST_OBSERVE_SCOPE_REFUSED');
        if (raw.status === NT_STATUS_NO_MORE_FILES) break;
        if (raw.status !== 0 && raw.status !== NT_STATUS_BUFFER_OVERFLOW)
          refuse('HOST_OBSERVE_SCOPE_REFUSED');
        if (
          !Number.isSafeInteger(raw.returned) ||
          raw.returned <= 0 ||
          raw.returned > ENUM_BUFFER_BYTES
        )
          refuse('HOST_OBSERVE_MUTATION_REFUSED');
        const decoded = decodeEnumerateBuffer(raw.data, raw.returned);
        if (decoded.length === 0) refuse('HOST_OBSERVE_MUTATION_REFUSED');
        // Bound BEFORE accumulation (R1 P1-02): the inventory budget must
        // gate the stream while it is being read — `entries` counts entries
        // already processed in earlier directories of this pass, `batch` the
        // decoded-but-unprocessed ones here. Refusing here keeps both the
        // batch memory and the enumeration progress bounded by MAX_ENTRIES
        // (every round decodes at least one entry), so a hostile huge
        // directory is refused without ever being fully read, hashed or
        // buffered; the per-entry check below remains as defense in depth.
        if (entries + batch.length + decoded.length > MAX_ENTRIES)
          refuse('HOST_OBSERVE_BOUNDS_EXCEEDED');
        for (const entry of decoded) batch.push(entry);
      }
      batch.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
      for (const entry of batch) {
        if (entry.name === '.' || entry.name === '..') continue;
        if (!validComponent(entry.name)) refuse('HOST_OBSERVE_SCOPE_REFUSED');
        // Defense in depth: the pre-accumulation bound above already keeps
        // every decoded batch inside the remaining budget, so this per-entry
        // count can no longer be crossed by a huge directory; it stays as a
        // hard cap on total inventory across all visited directories.
        if (++entries > MAX_ENTRIES) refuse('HOST_OBSERVE_BOUNDS_EXCEEDED');
        // A reparse entry is refused from enumeration metadata alone: its
        // target is never opened, not even for attributes.
        if ((entry.attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0)
          refuse('HOST_OBSERVE_ALIAS_REFUSED');
        const rel = frame.rel === '' ? entry.name : `${frame.rel}\\${entry.name}`;
        if ((entry.attrs & FILE_ATTRIBUTE_DIRECTORY) !== 0) {
          if (frame.depth >= MAX_DEPTH) refuse('HOST_OBSERVE_BOUNDS_EXCEEDED');
          lines.push(`d\t${rel}`);
          const child = native.openDir(frame.handle, entry.name);
          if (child === null) refuse('HOST_OBSERVE_SCOPE_REFUSED');
          openHandles.push(child);
          instrument.onDirOpen?.(frame.depth + 1, entry.name);
          const identity = native.entryId(child);
          if (identity === null) refuse('HOST_OBSERVE_SCOPE_REFUSED');
          if (
            (identity.attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0 ||
            (identity.attrs & FILE_ATTRIBUTE_DIRECTORY) === 0 ||
            identity.index !== entry.fileId
          ) {
            // Opened object is not the enumerated one: same-name swap.
            refuse('HOST_OBSERVE_MUTATION_REFUSED');
          }
          stack.push({ handle: child, depth: frame.depth + 1, rel });
        } else {
          files++;
          // A partial prefix hash is NOT proof: refuse before opening the
          // offending file if either content bound would be crossed.
          if (
            entry.size > BigInt(FILE_CONTENT_CAP_BYTES) ||
            entry.size > BigInt(WALK_CONTENT_BUDGET_BYTES - contentBytes)
          )
            refuse('HOST_OBSERVE_BOUNDS_EXCEEDED');
          lines.push(
            `f\t${rel}\t${entry.size}\t${entry.lastWriteMs}\t${entry.fileId}\t${digestAnchoredFileContent(
              native,
              frame.handle,
              entry,
              rel,
              instrument,
            )}`,
          );
          contentBytes += Number(entry.size);
        }
      }
    }
    lines.sort();
    return { lines, entries, files };
  } finally {
    for (const handle of openHandles.reverse()) native.close(handle);
  }
}

/**
 * Anchored content binding for one enumerated file: open the file through the
 * verified parent handle (never a path), cross-check the opened object's
 * 64-bit identity against the enumerated FileId, and only then read and hash
 * the content through that same handle. Any identity or size drift is a
 * refusal.
 */
function digestAnchoredFileContent(
  native: NativeAddon,
  parentHandle: bigint,
  entry: EnumeratedEntry,
  rel: string,
  instrument: HostObservationInstrument,
): string {
  const handle = native.openFile(parentHandle, entry.name);
  if (handle === null) {
    // Enumerated from the verified parent but unopenable: conservative
    // refusal, never a silently skipped entry.
    refuse('HOST_OBSERVE_MUTATION_REFUSED');
  }
  instrument.onFileOpen?.(rel);
  try {
    const identity = native.entryId(handle);
    if (identity === null) refuse('HOST_OBSERVE_MUTATION_REFUSED');
    if ((identity.attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0 || identity.index !== entry.fileId) {
      // The opened object is not the one enumerated from the verified parent
      // handle: refuse before a single content byte is read.
      refuse('HOST_OBSERVE_MUTATION_REFUSED');
    }
    const wantBytes = Number(entry.size);
    if (wantBytes === 0) return createHash('sha256').digest('hex');
    const read = native.readFile(handle, wantBytes);
    if (read === null) refuse('HOST_OBSERVE_MUTATION_REFUSED');
    if (read.status !== 0 && read.status !== NT_STATUS_END_OF_FILE)
      refuse('HOST_OBSERVE_MUTATION_REFUSED');
    if (!Number.isSafeInteger(read.returned) || read.returned < 0 || read.returned > wantBytes)
      refuse('HOST_OBSERVE_MUTATION_REFUSED');
    if (read.returned !== wantBytes) refuse('HOST_OBSERVE_MUTATION_REFUSED');
    return createHash('sha256').update(read.data.subarray(0, read.returned)).digest('hex');
  } finally {
    native.close(handle);
  }
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

/**
 * PACKAGE-INTERNAL test/audit seam (R1 P1-01/P2-01): direct `{scopeRoot}`
 * observation of a fixed-local scope with deterministic mutation hooks.
 * It exists so the in-package falsifiers can stage junction escapes,
 * interpass swaps and mid-scan mutations and prove zero IO beyond the
 * admitted prefix; src/index.ts does NOT re-export it, so code outside this
 * package (Recipe/model/HTTP) can never reach an unmediated scan. Production
 * access is exclusively `observeAuthorizedFileDuplicates` below, which takes
 * no callbacks and only an AuthorizedAction.
 */
export function observeVerifiedFileDuplicates(
  request: unknown,
  instrument: HostObservationInstrument = {},
): HostObservationResult {
  try {
    if (!plainWithExactKeys(request, ['scopeRoot'])) refuse('HOST_OBSERVE_SCOPE_REFUSED');
    const admission = staticScopeAdmission((request as Record<string, unknown>).scopeRoot);
    if (admission === null) refuse('HOST_OBSERVE_SCOPE_REFUSED');
    instrument.onStage?.('STATIC_ADMITTED', admission.drive);
    if (process.platform !== 'win32') refuse('HOST_OBSERVE_NATIVE_UNAVAILABLE');
    const native = loadNativeAddon();
    if (native === null) refuse('HOST_OBSERVE_NATIVE_UNAVAILABLE');

    // Drive attestation BEFORE any handle on that drive exists: two purely
    // local kernel questions. A mapped SMB root and a subst alias produce
    // zero opens here.
    const dosDeviceAnswer = native.dosDevice(admission.drive.slice(0, 2));
    const driveTypeAnswer = native.driveType(admission.drive);
    if (!attestsFixedLocalVolume(dosDeviceAnswer, driveTypeAnswer)) {
      instrument.onStage?.(
        'REFUSED',
        `drive-attestation dos=${String(dosDeviceAnswer)} type=${String(driveTypeAnswer)}`,
      );
      refuse('HOST_OBSERVE_DRIVE_REFUSED');
    }
    instrument.onStage?.('DRIVE_ATTESTED', admission.drive);

    const first = anchoredPass(native, admission, instrument);
    instrument.onPassCompleted?.(1);
    const second = anchoredPass(native, admission, instrument);
    instrument.onPassCompleted?.(2);

    // Independent post-state check: both passes must agree byte-for-byte on
    // every identity line (path, kind, size, mtime, file id, content digest).
    if (
      first.entries !== second.entries ||
      first.files !== second.files ||
      first.lines.length !== second.lines.length ||
      first.lines.some((line, index) => line !== second.lines[index])
    ) {
      refuse('HOST_OBSERVE_MUTATION_REFUSED');
    }

    // Groups come exclusively from content digests produced above; sizes
    // inside a digest-equal group are equal by construction.
    const byDigest = new Map<string, { sizeBytes: number; relativePaths: string[] }>();
    for (const line of first.lines) {
      if (!line.startsWith('f\t')) continue;
      const parts = line.split('\t');
      const rel = parts[1] ?? '';
      const size = parts[2] ?? '';
      const digest = parts[5] ?? '';
      const group = byDigest.get(digest) ?? { sizeBytes: Number(size), relativePaths: [] };
      group.relativePaths.push(rel);
      byDigest.set(digest, group);
    }
    const verifiedDuplicateGroups = [...byDigest]
      .filter(([, group]) => group.relativePaths.length > 1)
      .sort((left, right) => {
        const [leftDigest, leftGroup] = left;
        const [rightDigest, rightGroup] = right;
        return (
          leftGroup.sizeBytes - rightGroup.sizeBytes ||
          (leftDigest < rightDigest ? -1 : leftDigest > rightDigest ? 1 : 0)
        );
      })
      .map(([digest, group]) =>
        Object.freeze({
          sizeBytes: group.sizeBytes,
          contentDigestSha256: digest,
          relativePaths: Object.freeze(
            [...group.relativePaths].sort(
              (a, b) =>
                a.toLowerCase().localeCompare(b.toLowerCase(), 'en') || a.localeCompare(b, 'en'),
            ),
          ),
        }),
      );
    if (verifiedDuplicateGroups.length > MAX_DUPLICATE_GROUPS)
      refuse('HOST_OBSERVE_BOUNDS_EXCEEDED');

    return Object.freeze({
      ok: true as const,
      observation: Object.freeze({
        schema: 'shun.files.duplicate-verification.v02',
        status: 'HOST_OBSERVED_CONTENT_VERIFIED',
        trust: 'VERIFIED_HOST_OBSERVATION',
        scopeRoot: `${admission.drive}${admission.components.join('\\')}`,
        inspectedEntries: first.entries,
        observedFiles: first.files,
        verifiedDuplicateGroups: Object.freeze(verifiedDuplicateGroups),
        inventoryDigestSha256: createHash('sha256').update(first.lines.join('\n')).digest('hex'),
        filesystemObserved: true,
        duplicatesVerified: true,
        executionAuthorized: false,
        cloudDisclosure: false,
        completedTrustedChecks: COMPLETED_CHECKS,
      }),
    });
  } catch (error) {
    if (error instanceof Refusal) return Object.freeze({ ok: false as const, code: error.code });
    // Never disclose scope paths, native errors or partial observations.
    return Object.freeze({ ok: false as const, code: 'HOST_OBSERVE_MUTATION_REFUSED' });
  }
}

// ---------------------------------------------------------------------------
// R1 authorization mediation (review P1-01/P2-01). Mirrors how T04's trusted
// hosts consume the central ActionController's output: an AuthorizedAction
// whose shape follows @shun/contracts plan.ts AuthorizedActionSchema
// (re-validated structurally here — this package adds no runtime dependency
// on @shun/contracts), whose declared op is this capability's, whose only
// filesystem scope READ is exactly the root it will observe, and whose
// bounded expiry is still in the future when the scan starts. Grant
// integrity and per-effect currentness re-validation remain the wiring
// bootstrap's job (ActionController.authorizeEffect), exactly as for T04's
// executeTrustedWindowsR0Search.
// ---------------------------------------------------------------------------

const OBSERVATION_OP = 'files.duplicates.observe';
const AUTHORIZATION_KINDS = ['AUTOMATIC', 'EXPLICIT_APPROVAL', 'DURABLE_POLICY'] as const;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

function nonEmptyString(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

/**
 * Structural + semantic admission of one AuthorizedAction. Returns the
 * admitted scopeRoot, or null. Deliberately stricter than the schema on two
 * points, both fail-closed: `expiresAt` is REQUIRED (an action without a
 * bounded expiry can never authorize a scan) and must not have elapsed; and
 * optional PlanAction fields (timeoutMs/cancellation/expectedState) are not
 * accepted here — an action carrying them is refused rather than guessed at.
 */
function admittedObservationAction(value: unknown): string | null {
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
  // Currentness bound: the controller's bounded action validity must still
  // cover the moment the scan starts; an elapsed action authorizes nothing.
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
  // The authorized action identity must be the one the plan bound.
  if (typeof action.actionId !== 'string' || action.actionId !== top.actionId) return null;
  if (!nonEmptyString(action.bindingRef, 128)) return null;
  if (action.op !== OBSERVATION_OP) return null;
  if (action.sideEffectClass !== 'R0') return null;
  if (action.requiredPrivilege !== 'USER') return null;
  if (!plainWithExactKeys(action.parameters, ['scopeRoot'])) return null;
  const scopeRoot = action.parameters.scopeRoot;
  if (typeof scopeRoot !== 'string') return null;
  if (!plainWithExactKeys(action.filesystemScope, ['read', 'write'])) return null;
  const scope = action.filesystemScope as Record<string, unknown>;
  if (
    !Array.isArray(scope.read) ||
    scope.read.length !== 1 ||
    typeof scope.read[0] !== 'string' ||
    !Array.isArray(scope.write) ||
    scope.write.length !== 0
  )
    return null;
  // The authorization gate itself: the single granted read prefix must be
  // exactly the root the action wants observed — a grant for any other
  // scope, however valid, does not reach this scan.
  if (scope.read[0] !== scopeRoot) return null;
  return scopeRoot;
}

/**
 * The ONLY production entry into the physical duplicate observation: one
 * read-only, twice-verified, handle-anchored observation of the single
 * fixed-local scope an ActionController AuthorizedAction names. The caller
 * supplies no root, no file lists, no handles and NO callbacks — the scope
 * root comes exclusively from the authorized action's parameters, bound to
 * its single filesystem read scope, and nothing caller-supplied executes
 * during the scan. Authorization failures return
 * HOST_OBSERVE_AUTHORIZATION_REFUSED before any IO; physical refusals keep
 * their own codes.
 */
export function observeAuthorizedFileDuplicates(action: unknown): HostObservationResult {
  const scopeRoot = admittedObservationAction(action);
  if (scopeRoot === null) {
    return Object.freeze({ ok: false as const, code: 'HOST_OBSERVE_AUTHORIZATION_REFUSED' });
  }
  // The internal seam is invoked with NO instrument: the authorized path
  // never runs caller-visible callbacks (R1 P2-01).
  return observeVerifiedFileDuplicates({ scopeRoot }, {});
}
