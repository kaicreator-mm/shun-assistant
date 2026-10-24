// T04 independent R0 file.search post-state oracle. This module is the
// separately attested verifier demanded by frozen L2 §9.4.
//
// Confinement contract (R2 P1-01): the oracle performs ZERO pathname-based
// filesystem IO. Every directory and file is opened through the raw NT
// adapter with a single name component anchored at an ALREADY-VERIFIED
// parent handle, and FILE_OPEN_REPARSE_POINT so a junction/symlink yields
// the reparse point itself (refused from attributes) and never its target.
// Before the drive root is opened at all, the drive letter is attested as a
// fixed local volume by two purely-local kernel questions (QueryDosDeviceW
// device mapping must be \Device\HarddiskVolume*, GetDriveTypeW must be
// DRIVE_FIXED), so a mapped SMB or subst alias root is refused without any
// network or remote filesystem op. Every opened object is cross-checked
// against the FileId enumerated from its verified parent handle, so a
// same-name swap between enumeration and open is refused before content is
// read. No ancestor can redirect any open: path resolution never happens.
//
// Independence: this module shares NO parsing, NO traversal, NO matching,
// NO fingerprinting and NO refusal logic with the native walker in
// scoped-file-search.ts — only the raw-syscall adapter (which itself
// contains no parsing, bounds or policy). The enumeration buffer here is
// decoded with a separate DataView-based decoder, matches come from this
// module's own recursive-memo glob matcher, and the fingerprint binds
// relative path, kind, size, mtime, 64-bit file identity AND a content
// digest, so even a content swap that preserves superficial size/mtime
// cannot pass as "unchanged". Any anomaly degrades to refusal — never a
// seemingly complete PASS.
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import type { AuthorizedAction } from '@shun/contracts';

// Same envelope as the native walk; the oracle must refuse a scope the
// effect-level walk would have refused instead of verifying a wider world.
const MAX_ENTRIES = 4096;
const MAX_DIRS = 512;
const MAX_DEPTH = 8;
const MAX_MATCHES = 128;
// Per-file content digest cap and a whole-walk read budget: files beyond
// them are recorded with an explicit deterministic marker instead of
// silently weakening the mutation proof. Entries are processed in sorted
// order, so the budget cutoff is deterministic for a given tree.
const FILE_CONTENT_CAP_BYTES = 262144;
const WALK_CONTENT_BUDGET_BYTES = 32 << 20;
// Enumeration buffer: deliberately SMALL. Each raw call allocates a fresh
// buffer that only GC can reclaim, and the oracle walks whole directories
// across many batch round trips (the decoder merges them), so a compact
// buffer keeps the allocation pressure of a full tree walk bounded. Entries
// are ~600 bytes each; 16 KiB still batches ~26 entries per call.
const ENUM_BUFFER_BYTES = 16384;
const CONTENT_UNREAD = 'CONTENT_UNREAD_BUDGET';

const NT_STATUS_NO_MORE_FILES = 0x80000006;
const NT_STATUS_BUFFER_OVERFLOW = 0x80000005;
const NT_STATUS_END_OF_FILE = 0x80000004;
const FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
const FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
const DRIVE_FIXED = 3;
const FILETIME_TICKS_PER_MS = 10000n;
const FILETIME_UNIX_EPOCH_DELTA_MS = 11644473600000n;

export type OracleWalk = Readonly<{
  fingerprint: string;
  matches: readonly string[];
  inspectedEntries: number;
}>;

export type OracleWalkResult =
  | { ok: true; walk: OracleWalk }
  | { ok: false; code: 'ORACLE_SCOPE_REFUSED' | 'ORACLE_BOUNDS_EXCEEDED' | 'ORACLE_MUTATION_RISK' };

/**
 * Test/audit-only observation of what the oracle actually opened. The
 * negative controls use it to prove zero IO beyond the admitted prefix
 * (junction ancestors) and zero opens at all where drive attestation
 * refuses first (mapped SMB / subst aliases). Production callers never
 * pass it.
 */
export type OracleInstrument = Readonly<{
  onStage?: (stage: OracleAdmissionStage, detail: string) => void;
  onDirOpen?: (depth: number, name: string) => void;
  onFileOpen?: (rel: string) => void;
  /** Test-only: the exact sorted fingerprint preimage of a completed walk. */
  onWalkLines?: (lines: readonly string[]) => void;
}>;

export type OracleAdmissionStage =
  | 'STATIC_ADMITTED'
  | 'DRIVE_ATTESTED'
  | 'DRIVE_OPENED'
  | 'ANCESTOR_OPENED'
  | 'ADMITTED'
  | 'REFUSED';

// ---------------------------------------------------------------------------
// Raw NT adapter: an independent loader with its own interface. Failure to
// load fails closed (refuse), never falls back to pathname IO.
// ---------------------------------------------------------------------------

interface OracleNative {
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
  dosDevice(letter: string): string | null;
  driveType(root: string): number | null;
  close(handle: bigint): void;
}

let oracleNative: OracleNative | null | undefined;

function loadOracleNative(): OracleNative | null {
  if (oracleNative !== undefined) return oracleNative;
  try {
    oracleNative = createRequire(import.meta.url)(
      '../native/impl/shun_win32_impl.node',
    ) as OracleNative;
  } catch {
    // Fail closed: no addon, no oracle observation at all.
    oracleNative = null;
  }
  return oracleNative;
}

// ---------------------------------------------------------------------------
// Static root admission (zero IO) — independently written from the native
// walker's name checks: same Windows hazards, different code.
// ---------------------------------------------------------------------------

const RESERVED_DOS_NAMES = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|:|$)/i;

function validComponent(name: string): boolean {
  if (typeof name !== 'string' || !name || name.length > 255) return false;
  if (name === '.' || name === '..') return false;
  if (name.includes('\u0000')) return false;
  if (/[/\\:<>"|?]/.test(name)) return false;
  if (process.platform === 'win32') {
    // Win32 normalizes trailing spaces/dots away; reserved device names must
    // never be mistaken for real directories.
    if (/[. ]$/.test(name) || RESERVED_DOS_NAMES.test(name)) return false;
  }
  return true;
}

type StaticAdmission = Readonly<{ drive: string; components: readonly string[] }>;

function staticRootAdmission(root: string): StaticAdmission | null {
  if (typeof root !== 'string' || root.length === 0 || root.length > 2048) return null;
  if (root.includes('\u0000')) return null;
  const canonical = resolve(root);
  // Fixed-drive syntax only: no UNC shares, no device namespace, no rooted
  // paths — a mapped drive root is syntactically local, which is why the
  // device attestation below exists.
  if (!/^[a-zA-Z]:\\/.test(canonical)) return null;
  const drive = canonical.slice(0, 3);
  const components = canonical
    .slice(3)
    .split('\\')
    .filter((part) => part.length > 0);
  for (const component of components) {
    if (!validComponent(component)) return null;
  }
  return { drive, components };
}

/**
 * The OS-attested fixed-local-drive decision over the two raw attestation
 * answers. Exported for unit coverage of the mapped-SMB device form
 * (\Device\LanmanRedirector\...) without requiring a physical mapping.
 */
export function attestsFixedLocalDrive(
  dosDeviceAnswer: string | null,
  driveTypeAnswer: number | null,
): boolean {
  if (typeof dosDeviceAnswer !== 'string' || dosDeviceAnswer.length === 0) return false;
  // A fixed local volume device only. This refuses drive letters backed by
  // the network redirector (\Device\LanmanRedirector\;Q:...\server\share),
  // subst aliases (\??\C:\path) and every other non-volume device.
  if (!dosDeviceAnswer.toLowerCase().startsWith('\\device\\harddiskvolume')) return false;
  if (driveTypeAnswer !== DRIVE_FIXED) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Independent enumeration decoder (DataView-based; deliberately different
// structure from the native walker's byte-index parser).
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

function fileTimeToUnixMs(ticks: bigint): bigint {
  return ticks / FILETIME_TICKS_PER_MS - FILETIME_UNIX_EPOCH_DELTA_MS;
}

/** Decode one returned buffer; an empty result signals a malformed chain. */
function decodeEnumerateBuffer(data: Buffer, returned: number): EnumeratedEntry[] {
  const view = new DataView(data.buffer, data.byteOffset, returned);
  const entries: EnumeratedEntry[] = [];
  let offset = 0;
  for (;;) {
    const next = view.getUint32(offset + FIELD.nextEntryOffset, true);
    const attrs = view.getUint32(offset + FIELD.attributes, true);
    const nameLength = view.getUint32(offset + FIELD.fileNameLength, true);
    const nameStart = offset + FIELD.fileName;
    // A chain entry must cover the fixed header, stay 8-byte aligned and
    // never run past the returned byte count.
    if (nameLength % 2 !== 0 || nameStart + nameLength > returned) return [];
    const codes: number[] = [];
    for (let i = 0; i < nameLength / 2; i++) codes.push(view.getUint16(nameStart + i * 2, true));
    entries.push({
      name: String.fromCharCode(...codes),
      attrs,
      fileId: view.getBigUint64(offset + FIELD.fileId, true),
      size: view.getBigUint64(offset + FIELD.endOfFile, true),
      lastWriteMs: fileTimeToUnixMs(view.getBigUint64(offset + FIELD.lastWriteTime, true)),
    });
    if (next === 0) break;
    if (next < FIELD.fileName || next % 8 !== 0 || offset + next > returned) return [];
    offset += next;
  }
  return entries;
}

function sameDrivePath(a: string, b: string): boolean {
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

type WalkCode = 'ORACLE_SCOPE_REFUSED' | 'ORACLE_BOUNDS_EXCEEDED' | 'ORACLE_MUTATION_RISK';
type WalkFailure = { ok: false; code: WalkCode };

// ---------------------------------------------------------------------------
// The anchored walk. All handles are tracked and closed on every exit path.
// Entries are processed in sorted order, so the content budget is
// deterministic for a given tree.
// ---------------------------------------------------------------------------

function walkAnchored(
  root: string,
  query: string,
  instrument: OracleInstrument,
): { lines: string[]; matches: string[]; entries: number } | WalkFailure {
  const native = loadOracleNative();
  if (native === null) return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };

  const stage = (s: OracleAdmissionStage, detail: string) => instrument.onStage?.(s, detail);
  const staticAdmission = staticRootAdmission(root);
  if (staticAdmission === null) {
    stage('REFUSED', 'static');
    return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
  }
  stage('STATIC_ADMITTED', staticAdmission.drive);

  // Drive attestation BEFORE any handle on that drive exists: two purely
  // local kernel questions. A mapped SMB root produces zero opens and zero
  // network ops here.
  const dosDeviceAnswer = native.dosDevice(staticAdmission.drive.slice(0, 2));
  const driveTypeAnswer = native.driveType(staticAdmission.drive);
  if (!attestsFixedLocalDrive(dosDeviceAnswer, driveTypeAnswer)) {
    stage(
      'REFUSED',
      `drive-attestation dos=${String(dosDeviceAnswer)} type=${String(driveTypeAnswer)}`,
    );
    return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
  }
  stage('DRIVE_ATTESTED', staticAdmission.drive);

  const openHandles: bigint[] = [];
  try {
    const driveHandle = native.openDir(null, `\\??\\${staticAdmission.drive}`);
    if (driveHandle === null) {
      stage('REFUSED', 'drive-open');
      return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
    }
    openHandles.push(driveHandle);
    instrument.onDirOpen?.(0, staticAdmission.drive);
    stage('DRIVE_OPENED', staticAdmission.drive);
    const driveAttrs = native.entryInfo(driveHandle);
    if (
      driveAttrs === null ||
      (driveAttrs & FILE_ATTRIBUTE_DIRECTORY) === 0 ||
      (driveAttrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0
    )
      return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
    const finalPath = native.finalPath(driveHandle);
    if (finalPath === null) return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
    const stripped = finalPath.startsWith('\\\\?\\') ? finalPath.slice(4) : finalPath;
    if (!sameDrivePath(stripped, staticAdmission.drive))
      return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };

    // Anchored descent through the full ancestor chain: every open is one
    // component inside the previous verified handle, so no junction alias in
    // any ancestor can redirect resolution — the component opens inside the
    // object, not along a path. The junction component itself opens with
    // FILE_OPEN_REPARSE_POINT and is refused from its own attributes before
    // anything below it is touched.
    let rootHandle = driveHandle;
    for (const component of staticAdmission.components) {
      const child = native.openDir(rootHandle, component);
      if (child === null) {
        stage('REFUSED', `ancestor-open:${component}`);
        return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
      }
      openHandles.push(child);
      instrument.onDirOpen?.(openHandles.length, component);
      stage('ANCESTOR_OPENED', component);
      const attrs = native.entryInfo(child);
      if (
        attrs === null ||
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0 ||
        (attrs & FILE_ATTRIBUTE_DIRECTORY) === 0
      )
        return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
      rootHandle = child;
    }
    stage('ADMITTED', staticAdmission.drive);

    const lines: string[] = [];
    const matches: string[] = [];
    let entries = 0;
    let visitedDirs = 0;
    let contentBytes = 0;
    type Frame = { handle: bigint; depth: number; rel: string };
    const stack: Frame[] = [{ handle: rootHandle, depth: 0, rel: '' }];
    while (stack.length > 0) {
      const frame = stack.pop();
      if (!frame) return { ok: false, code: 'ORACLE_MUTATION_RISK' };
      if (++visitedDirs > MAX_DIRS) return { ok: false, code: 'ORACLE_BOUNDS_EXCEEDED' };
      // Collect the whole directory stream first, then process it in sorted
      // name order: the traversal (and with it the content budget) becomes
      // deterministic for a given tree, independent of kernel batch order.
      let batch: EnumeratedEntry[] = [];
      let restart = true;
      for (;;) {
        const raw = native.enumerate(frame.handle, restart, ENUM_BUFFER_BYTES);
        restart = false;
        if (raw === null) return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
        if (raw.status === NT_STATUS_NO_MORE_FILES) break;
        if (raw.status !== 0 && raw.status !== NT_STATUS_BUFFER_OVERFLOW)
          return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
        const decoded = decodeEnumerateBuffer(raw.data, raw.returned);
        if (decoded.length === 0) return { ok: false, code: 'ORACLE_MUTATION_RISK' };
        batch = batch.concat(decoded);
      }
      batch.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
      for (const entry of batch) {
        if (entry.name === '.' || entry.name === '..') continue;
        if (!validComponent(entry.name)) return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
        if (++entries > MAX_ENTRIES) return { ok: false, code: 'ORACLE_BOUNDS_EXCEEDED' };
        // A reparse entry is refused from enumeration metadata alone: its
        // target is never opened, not even for attributes.
        if ((entry.attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0)
          return { ok: false, code: 'ORACLE_MUTATION_RISK' };
        const rel = frame.rel === '' ? entry.name : `${frame.rel}\\${entry.name}`;
        if ((entry.attrs & FILE_ATTRIBUTE_DIRECTORY) !== 0) {
          if (frame.depth >= MAX_DEPTH) return { ok: false, code: 'ORACLE_BOUNDS_EXCEEDED' };
          lines.push(`d\t${rel}`);
          const child = native.openDir(frame.handle, entry.name);
          if (child === null) return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
          openHandles.push(child);
          instrument.onDirOpen?.(frame.depth + 1, entry.name);
          const identity = native.entryId(child);
          if (identity === null) return { ok: false, code: 'ORACLE_SCOPE_REFUSED' };
          if (
            (identity.attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0 ||
            (identity.attrs & FILE_ATTRIBUTE_DIRECTORY) === 0 ||
            BigInt(identity.index) !== entry.fileId
          ) {
            // Opened object is not the enumerated one: same-name swap.
            return { ok: false, code: 'ORACLE_MUTATION_RISK' };
          }
          stack.push({ handle: child, depth: frame.depth + 1, rel });
        } else {
          if (matches.length >= MAX_MATCHES && oracleGlobMatch(entry.name, query))
            return { ok: false, code: 'ORACLE_BOUNDS_EXCEEDED' };
          if (oracleGlobMatch(entry.name, query)) matches.push(rel);
          const unread = contentBytes >= WALK_CONTENT_BUDGET_BYTES;
          lines.push(
            `f\t${rel}\t${entry.size}\t${entry.lastWriteMs}\t${entry.fileId}\t${hashFileContent(
              native,
              frame.handle,
              entry,
              rel,
              instrument,
              unread,
            )}`,
          );
          if (!unread) contentBytes += Number(entry.size);
        }
      }
    }
    return { lines, matches, entries };
  } finally {
    for (const handle of openHandles.reverse()) native.close(handle);
  }
}

/**
 * Anchored content binding for one enumerated file: open the file through
 * the verified parent handle (never a path), cross-check the opened object's
 * identity against the enumerated FileId, and only then read and hash the
 * content. Any identity or size drift is thrown as a refusal.
 */
function hashFileContent(
  native: OracleNative,
  parentHandle: bigint,
  entry: EnumeratedEntry,
  rel: string,
  instrument: OracleInstrument,
  unread: boolean,
): string {
  if (unread) return CONTENT_UNREAD;
  const capped = entry.size > BigInt(FILE_CONTENT_CAP_BYTES);
  const wantBytes = capped ? FILE_CONTENT_CAP_BYTES : Number(entry.size);
  const handle = native.openFile(parentHandle, entry.name);
  if (handle === null) throw new Error('ORACLE_FILE_OPEN_REFUSED');
  instrument.onFileOpen?.(rel);
  try {
    const identity = native.entryId(handle);
    if (identity === null) throw new Error('ORACLE_FILE_IDENTITY_REFUSED');
    if (
      (identity.attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0 ||
      BigInt(identity.index) !== entry.fileId
    ) {
      // The opened object is not the one enumerated from the verified parent
      // handle: refuse before a single content byte is read.
      throw new Error('ORACLE_FILE_IDENTITY_MISMATCH');
    }
    if (wantBytes <= 0) return 'EMPTY';
    const read = native.readFile(handle, wantBytes);
    if (read === null) throw new Error('ORACLE_FILE_READ_REFUSED');
    if (read.status !== 0 && read.status !== NT_STATUS_END_OF_FILE)
      throw new Error('ORACLE_FILE_READ_STATUS');
    if (!Number.isSafeInteger(read.returned) || read.returned < 0 || read.returned > wantBytes)
      throw new Error('ORACLE_FILE_READ_BOUNDS');
    if (
      read.returned !== Number(entry.size) &&
      !(capped && read.returned === FILE_CONTENT_CAP_BYTES)
    )
      throw new Error('ORACLE_FILE_SIZE_DRIFT');
    const bytes = read.data.subarray(0, read.returned);
    const digest = createHash('sha256').update(bytes).digest('hex');
    return capped ? `${digest}+CAPPED` : digest;
  } finally {
    native.close(handle);
  }
}

/**
 * One bounded, independent observation of the scope: a whole-tree identity
 * fingerprint (relative path, kind, size, mtime, 64-bit file identity,
 * content digest) plus the oracle's own expected match set. Oversized scopes
 * are refused; any anomaly degrades to refusal, never an apparently
 * complete partial result.
 */
export function captureOracleWalk(
  root: string,
  query: string,
  instrument: OracleInstrument = {},
): OracleWalkResult {
  try {
    const walked = walkAnchored(root, query, instrument);
    if ('code' in walked) return walked;
    const lines = walked.lines.sort();
    instrument.onWalkLines?.(lines);
    const fingerprint = createHash('sha256').update(lines.join('\n')).digest('hex');
    return {
      ok: true,
      walk: {
        fingerprint,
        matches: walked.matches.sort(),
        inspectedEntries: walked.entries,
      },
    };
  } catch {
    return { ok: false, code: 'ORACLE_MUTATION_RISK' };
  }
}

export function oracleWalksEqual(before: OracleWalk, after: OracleWalk): boolean {
  return (
    before.fingerprint === after.fingerprint &&
    before.inspectedEntries === after.inspectedEntries &&
    before.matches.length === after.matches.length &&
    before.matches.every((path, index) => path === after.matches[index])
  );
}

/** Root-relative match paths use the platform separator; compare exactly. */
export function oracleMatchesObservation(
  walk: OracleWalk,
  observedPaths: readonly string[],
): boolean {
  if (walk.matches.length !== observedPaths.length) return false;
  const sorted = [...observedPaths].sort();
  return walk.matches.every((path, index) => path === sorted[index]);
}

/**
 * Trusted-host-only integrity check tying a positive receipt to the durable
 * journal row: the receipt digest recorded by the journal must match the
 * receipt the verifier was handed. The verifier cannot mint or alter rows.
 */
export function oracleReceiptDigestMatches(
  journalReceiptSha256: string | null,
  receiptCanonicalJson: string,
): boolean {
  if (journalReceiptSha256 === null) return false;
  return createHash('sha256').update(receiptCanonicalJson).digest('hex') === journalReceiptSha256;
}

export function isR0SearchAction(action: AuthorizedAction): boolean {
  return (
    action.action.op === 'file.search' &&
    action.action.sideEffectClass === 'R0' &&
    action.action.requiredPrivilege === 'USER' &&
    typeof action.action.parameters.root === 'string' &&
    typeof action.action.parameters.query === 'string' &&
    Object.keys(action.action.parameters).length === 2
  );
}

// Deliberately NOT the DP loop used by the native walk's matcher: the oracle
// must stay a separate implementation so a common-mode matcher bug cannot
// self-confirm. Depth is bounded by the 128 character grammar limit admitted
// upstream.
export function oracleGlobMatch(name: string, pattern: string): boolean {
  const n = process.platform === 'win32' ? name.toLowerCase() : name;
  const p = process.platform === 'win32' ? pattern.toLowerCase() : pattern;
  const memo = new Map<string, boolean>();
  const at = (ni: number, pi: number): boolean => {
    const key = `${ni}:${pi}`;
    const cached = memo.get(key);
    if (cached !== undefined) return cached;
    let result: boolean;
    if (pi === p.length) {
      result = ni === n.length;
    } else if (p[pi] === '*') {
      result = false;
      for (let k = ni; k <= n.length; k++) {
        if (at(k, pi + 1)) {
          result = true;
          break;
        }
      }
    } else if (ni >= n.length) {
      result = false;
    } else {
      const c = p[pi];
      result = c === '?' || c === n[ni] ? at(ni + 1, pi + 1) : false;
    }
    memo.set(key, result);
    return result;
  };
  return at(0, 0);
}
