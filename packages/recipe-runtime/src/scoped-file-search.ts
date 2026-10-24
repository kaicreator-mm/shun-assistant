// T04: bounded host-only R0 filesystem search. Never call this function
// from Recipe/model/HTTP without SqliteReadonlySearchAuthorizationBoundary.
// It does no grant verification, journaling, receipt or semantic verification.
//
// On Windows the walk is anchored to verified directory handles (P1-01 fix):
// every directory is opened through NtOpenFile with RootDirectory set to the
// already-verified parent handle and a single name component, with
// FILE_OPEN_REPARSE_POINT so a junction/symlink entry yields the reparse point
// itself (refused) instead of its target. Enumeration reads the same verified
// handle via NtQueryDirectoryFile, so a renamed/replaced ancestor name cannot
// redirect any open: resolution starts inside the parent object, and no
// outside-scope directory is ever opened, even under concurrent mutation.
import { lstatSync, opendirSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from 'node:path';
import type { AuthorizedAction } from '@shun/contracts';

const MAX_ENTRIES = 4096;
const MAX_DIRS = 512;
const MAX_MATCHES = 128;
const MAX_DEPTH = 8;

export type LocalFileSearchObservation = Readonly<{
  kind: 'R0_LOCAL_FILE_SEARCH_OBSERVATION';
  paths: readonly string[];
  inspectedEntries: number;
  truncated: false;
  semanticVerified: false;
  cloudDisclosure: false;
}>;

/** Test/audit-only synchronous barrier; never populated by production callers. */
export type ScopedSearchInstrumentation = Readonly<{
  onDirectoryOpened?: (relativePath: string) => void;
}>;

function assertName(name: string): void {
  if (
    !name ||
    name.length > 255 ||
    name === '.' ||
    name === '..' ||
    name.includes('/') ||
    name.includes('\\') ||
    name.includes(':') ||
    name.includes('\0')
  )
    throw new Error('REFUSED');
  if (process.platform === 'win32') {
    // Win32 normalizes trailing spaces/dots and reserves DOS device names.
    if (/[. ]$/.test(name) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name))
      throw new Error('REFUSED');
  }
}

function samePath(a: string, b: string): boolean {
  const left = normalize(a);
  const right = normalize(b);
  return process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right;
}

function containsPath(path: string, root: string): boolean {
  const rel = relative(root, path);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function assertCanonicalPath(path: string, root: string): string {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) throw new Error('REFUSED');
  const actual = realpathSync.native(path);
  // Never accept a file or directory redirected by a junction/reparse point,
  // including an alias in any ancestor. Host physical canaries remain required.
  if (!samePath(resolve(path), actual) || !containsPath(actual, root)) throw new Error('REFUSED');
  return actual;
}

function wildcardMatch(name: string, pattern: string): boolean {
  const n = process.platform === 'win32' ? name.toLowerCase() : name;
  const p = process.platform === 'win32' ? pattern.toLowerCase() : pattern;
  // Bounded DP; no model-controlled dynamic RegExp or shell glob expansion.
  let previous = new Array<boolean>(n.length + 1).fill(false);
  previous[0] = true;
  for (const ch of p) {
    const current = new Array<boolean>(n.length + 1).fill(false);
    if (ch === '*') current[0] = previous[0] ?? false;
    for (let i = 1; i <= n.length; i++) {
      current[i] =
        ch === '*'
          ? (previous[i] ?? false) || (current[i - 1] ?? false)
          : (previous[i - 1] ?? false) && (ch === '?' || ch === n[i - 1]);
    }
    previous = current;
  }
  return previous[n.length] ?? false;
}

// ---------------------------------------------------------------------------
// Windows handle-anchored traversal (NtOpenFile/NtQueryDirectoryFile through
// the native shun-win32-impl addon: windows-rs behind napi-rs, built per
// native/README.md). Only raw syscalls live in the addon; every status,
// attribute mask and byte count is validated here.
// ---------------------------------------------------------------------------

const NT_STATUS_NO_MORE_FILES = 0x80000006;
const NT_STATUS_BUFFER_OVERFLOW = 0x80000005;
const FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
const FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
// FILE_ID_BOTH_DIR_INFORMATION field offsets on x64.
const OFF_NEXT_ENTRY = 0;
const OFF_ATTRIBUTES = 56;
const OFF_NAME_LENGTH = 60;
const OFF_FILE_NAME = 104;
const ENUM_BUFFER_BYTES = 262144;

type EnumEntry = Readonly<{ name: string; isDirectory: boolean; isReparse: boolean }>;

interface NativeImplAddon {
  dosDevice(letter: string): string | null;
  driveType(root: string): number | null;
  openDir(parent: bigint | null, name: string): bigint | null;
  entryInfo(handle: bigint): number | null;
  finalPath(handle: bigint): string | null;
  enumerate(
    handle: bigint,
    restart: boolean,
    bufferBytes: number,
  ): { status: number; returned: number; data: Buffer } | null;
  close(handle: bigint): void;
}

interface Win32Handles {
  dosDevice(letter: string): string | null;
  driveType(root: string): number | null;
  openDir(parent: bigint | null, name: string): bigint | null;
  entryInfo(handle: bigint): { isDirectory: boolean; isReparse: boolean } | null;
  finalPath(handle: bigint): string | null;
  enumerate(handle: bigint, restart: boolean): { status: number; entries: EnumEntry[] };
  close(handle: bigint): void;
}

let win32Handles: Win32Handles | null = null;

let nativeImplAddon: NativeImplAddon | null = null;

function loadNativeImplAddon(): NativeImplAddon | null {
  if (nativeImplAddon !== null) return nativeImplAddon;
  try {
    nativeImplAddon = createRequire(import.meta.url)(
      '../native/impl/shun_win32_impl.node',
    ) as NativeImplAddon;
  } catch {
    // Fail closed: a missing or unloadable addon must refuse the walk, never
    // fall back to a path-based traversal.
    return null;
  }
  return nativeImplAddon;
}

function loadWin32(): Win32Handles | null {
  if (win32Handles !== null) return win32Handles;
  const addon = loadNativeImplAddon();
  if (addon === null) return null;
  win32Handles = {
    dosDevice: (letter) => addon.dosDevice(letter),
    driveType: (root) => addon.driveType(root),
    // The absolute bootstrap open resolves an NT pathname, so it must carry
    // the `\??\` Win32-namespace prefix; child opens stay single components
    // anchored at the parent handle.
    openDir: (parent, name) => addon.openDir(parent, parent === null ? `\\??\\${name}` : name),
    entryInfo: (handle) => {
      const attrs = addon.entryInfo(handle);
      if (attrs === null) return null;
      return {
        isDirectory: (attrs & FILE_ATTRIBUTE_DIRECTORY) !== 0,
        isReparse: (attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0,
      };
    },
    finalPath: (handle) => addon.finalPath(handle),
    enumerate: (handle, restart) => {
      const raw = addon.enumerate(handle, restart, ENUM_BUFFER_BYTES);
      if (raw === null) throw new Error('REFUSED');
      if (raw.status === NT_STATUS_NO_MORE_FILES) return { status: raw.status, entries: [] };
      if (raw.status !== 0 && raw.status !== NT_STATUS_BUFFER_OVERFLOW)
        return { status: raw.status, entries: [] };
      const returned = raw.returned;
      if (!Number.isSafeInteger(returned) || returned <= 0 || returned > ENUM_BUFFER_BYTES)
        throw new Error('REFUSED');
      const bytes = raw.data;
      const entries: EnumEntry[] = [];
      let offset = 0;
      while (offset < returned) {
        const read32 = (at: number): number =>
          ((bytes[at] ?? 0) |
            ((bytes[at + 1] ?? 0) << 8) |
            ((bytes[at + 2] ?? 0) << 16) |
            ((bytes[at + 3] ?? 0) << 24)) >>>
          0;
        const next = read32(offset + OFF_NEXT_ENTRY);
        const attrs = read32(offset + OFF_ATTRIBUTES);
        const nameLength = read32(offset + OFF_NAME_LENGTH);
        const nameStart = offset + OFF_FILE_NAME;
        if (nameLength % 2 !== 0 || nameStart + nameLength > returned) throw new Error('REFUSED');
        const nameBytes: number[] = [];
        for (let i = 0; i < nameLength; i++) nameBytes.push(bytes[nameStart + i] ?? 0);
        entries.push({
          name: Buffer.from(nameBytes).toString('utf16le'),
          isDirectory: (attrs & FILE_ATTRIBUTE_DIRECTORY) !== 0,
          isReparse: (attrs & FILE_ATTRIBUTE_REPARSE_POINT) !== 0,
        });
        if (!next) break;
        // A chain entry must at least cover the fixed header, stay 8-byte
        // aligned, and never run past the returned byte count.
        if (next < OFF_FILE_NAME || next % 8 !== 0 || offset + next > returned)
          throw new Error('REFUSED');
        offset += next;
      }
      return { status: raw.status, entries };
    },
    close: (handle) => {
      addon.close(handle);
    },
  };
  return win32Handles;
}

function refuse(): never {
  throw new Error('REFUSED');
}

function walkWin32(
  root: string,
  query: string,
  instrument: ScopedSearchInstrumentation,
): { matches: string[]; inspected: number } {
  const win = loadWin32();
  // No native capability on this host: refuse the whole action (fail closed).
  if (win === null) refuse();
  const openHandles: bigint[] = [];
  try {
    const resolvedRoot = resolve(root);
    // Never bootstrap by opening the full user-controlled pathname: an
    // ancestor replaced with a junction could give that first handle LIST
    // DIRECTORY rights outside the approved scope before we notice.
    // Instead open only the local drive root, establish its real provenance,
    // then descend using a *single component* relative to a verified handle.
    // This also accepts legitimate 8.3 short-name components (RUNNER~1):
    // kernel32 final-path normalization expands them to their long spellings.
    if (!/^[a-zA-Z]:\\/.test(resolvedRoot)) refuse();
    const driveRoot = resolvedRoot.slice(0, 3);
    // Native R0 can also be called by the older conservative Host adapter,
    // without an independent Oracle preflight. Its first open MUST NOT
    // touch a redirected SMB/subst volume. Both questions query local OS
    // device metadata only; on missing/old addon methods we fail closed.
    const targetDevice = win.dosDevice(driveRoot.slice(0, 2));
    if (
      typeof targetDevice !== 'string' ||
      !/^\\\\Device\\\\HarddiskVolume[0-9]+$/i.test(targetDevice) ||
      win.driveType(driveRoot) !== 3
    )
      refuse();
    const driveHandle = win.openDir(null, driveRoot);
    if (driveHandle === null) refuse();
    openHandles.push(driveHandle);
    const driveInfo = win.entryInfo(driveHandle);
    if (!driveInfo || driveInfo.isReparse || !driveInfo.isDirectory) refuse();
    const actualDrive = win.finalPath(driveHandle);
    if (actualDrive === null) refuse();
    const strippedDrive = actualDrive.startsWith('\\\\?\\') ? actualDrive.slice(4) : actualDrive;
    // Refuse UNC/mapped-drive and subst-style aliases BEFORE any descendant
    // is opened. A real drive-root handle must resolve to that same drive.
    if (!samePath(strippedDrive, driveRoot)) refuse();

    let rootHandle = driveHandle;
    for (const component of resolvedRoot.slice(3).split('\\').filter(Boolean)) {
      assertName(component);
      const child = win.openDir(rootHandle, component);
      if (child === null) refuse();
      openHandles.push(child);
      const childInfo = win.entryInfo(child);
      if (!childInfo || childInfo.isReparse || !childInfo.isDirectory) refuse();
      rootHandle = child;
    }
    // No potentially redirected multi-component pathname was followed.
    // The final root object is reached exclusively through anchored handles.

    const matches: string[] = [];
    let inspected = 0;
    let visitedDirs = 0;
    const stack: Array<{ handle: bigint; depth: number; rel: string }> = [
      { handle: rootHandle, depth: 0, rel: '' },
    ];
    while (stack.length > 0) {
      const frame = stack.pop();
      if (!frame) refuse();
      if (++visitedDirs > MAX_DIRS) refuse();
      let restart = true;
      for (;;) {
        const batch = win.enumerate(frame.handle, restart);
        restart = false;
        if (batch.status === NT_STATUS_NO_MORE_FILES) break;
        if (batch.status !== 0) refuse();
        for (const entry of batch.entries) {
          if (entry.name === '.' || entry.name === '..') continue;
          if (++inspected > MAX_ENTRIES) refuse();
          assertName(entry.name);
          // A reparse entry is refused from directory metadata alone: its
          // target is never opened, not even for attributes.
          if (entry.isReparse) refuse();
          if (entry.isDirectory) {
            if (frame.depth >= MAX_DEPTH) refuse();
            const child = win.openDir(frame.handle, entry.name);
            if (child === null) refuse();
            openHandles.push(child);
            const childInfo = win.entryInfo(child);
            if (!childInfo || childInfo.isReparse || !childInfo.isDirectory) refuse();
            const rel = join(frame.rel, entry.name);
            instrument.onDirectoryOpened?.(rel);
            stack.push({ handle: child, depth: frame.depth + 1, rel });
          } else if (wildcardMatch(entry.name, query)) {
            matches.push(join(frame.rel, entry.name));
            if (matches.length > MAX_MATCHES) refuse();
          }
        }
      }
    }
    return { matches, inspected };
  } finally {
    for (const handle of openHandles) win.close(handle);
  }
}

/**
 * Trusted OS capability only, invoked AFTER the real SQLite-backed grant gate.
 * This scans file *names* (not file contents), never writes or invokes tools,
 * returns only root-relative paths, and refuses any incomplete/unsafe walk
 * rather than returning an apparently complete partial result.
 */
export function observeScopedFileSearch(
  action: AuthorizedAction,
  instrument: ScopedSearchInstrumentation = {},
): LocalFileSearchObservation {
  try {
    const a = action.action;
    if (
      a.op !== 'file.search' ||
      a.sideEffectClass !== 'R0' ||
      a.requiredPrivilege !== 'USER' ||
      a.filesystemScope?.write.length !== 0 ||
      a.filesystemScope.read.length !== 1 ||
      a.networkScope !== undefined ||
      a.registryScope !== undefined ||
      (a.secretRefs?.length ?? 0) !== 0 ||
      Object.keys(a.parameters).length !== 2
    )
      throw new Error('REFUSED');

    const { root, query } = a.parameters;
    if (
      typeof root !== 'string' ||
      !isAbsolute(root) ||
      root.startsWith('\\\\') ||
      root.startsWith('//') ||
      root.includes('\0') ||
      root.split(/[\\/]/).includes('..') ||
      typeof query !== 'string' ||
      query.length > 128 ||
      !/^[a-zA-Z0-9._?* -]+$/.test(query) ||
      a.filesystemScope.read[0] !== root
    )
      throw new Error('REFUSED');

    let matches: string[];
    let inspected: number;
    if (process.platform === 'win32') {
      ({ matches, inspected } = walkWin32(root, query, instrument));
    } else {
      // Non-Windows hosts keep the simpler path-based walk; the Windows gate
      // host (the T04 deployment target) uses the handle-anchored walk above.
      const canonicalRoot = realpathSync.native(root);
      if (!samePath(resolve(root), canonicalRoot)) throw new Error('REFUSED');
      if (!lstatSync(root).isDirectory()) throw new Error('REFUSED');
      // Alias ancestors are refused even when they resolve back inside scope.
      let ancestor = root;
      for (;;) {
        if (lstatSync(ancestor).isSymbolicLink()) throw new Error('REFUSED');
        const parent = dirname(ancestor);
        if (parent === ancestor) break;
        ancestor = parent;
      }

      const dirs: Array<{ path: string; depth: number }> = [{ path: canonicalRoot, depth: 0 }];
      matches = [];
      inspected = 0;
      let visitedDirs = 0;
      while (dirs.length > 0) {
        const current = dirs.pop();
        if (!current) throw new Error('REFUSED');
        if (++visitedDirs > MAX_DIRS) throw new Error('REFUSED');
        assertCanonicalPath(current.path, canonicalRoot);
        const dir = opendirSync(current.path);
        try {
          let entry = dir.readSync();
          while (entry !== null) {
            inspected++;
            if (inspected > MAX_ENTRIES) throw new Error('REFUSED');
            assertName(entry.name);
            const candidate = join(current.path, entry.name);
            const checked = assertCanonicalPath(candidate, canonicalRoot);
            const stat = lstatSync(candidate);
            if (stat.isDirectory()) {
              if (current.depth >= MAX_DEPTH) throw new Error('REFUSED');
              dirs.push({ path: checked, depth: current.depth + 1 });
            } else if (stat.isFile() && wildcardMatch(entry.name, query)) {
              matches.push(relative(canonicalRoot, checked));
              if (matches.length > MAX_MATCHES) throw new Error('REFUSED');
            } else if (!stat.isFile()) {
              // Junctions, devices and special entries must not be traversed.
              throw new Error('REFUSED');
            }
            entry = dir.readSync();
          }
        } finally {
          dir.closeSync();
        }
      }
    }
    return {
      kind: 'R0_LOCAL_FILE_SEARCH_OBSERVATION',
      paths: matches.sort(),
      inspectedEntries: inspected,
      truncated: false,
      semanticVerified: false,
      cloudDisclosure: false,
    };
  } catch {
    // Never disclose native absolute paths or an apparently complete partial scan.
    throw new Error('R0_FILE_SEARCH_REFUSED');
  }
}
