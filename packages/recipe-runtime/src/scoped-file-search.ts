// T04: bounded host-only R0 filesystem search. Never call this function
// from Recipe/model/HTTP without SqliteReadonlySearchAuthorizationBoundary.
// It does no grant verification, journaling, receipt or semantic verification.
import { lstatSync, opendirSync, realpathSync } from 'node:fs';
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
    if (ch === '*') current[0] = previous[0];
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

/**
 * Trusted OS capability only, invoked AFTER the real SQLite-backed grant gate.
 * This scans file *names* (not file contents), never writes or invokes tools,
 * returns only root-relative paths, and refuses any incomplete/unsafe walk
 * rather than returning an apparently complete partial result.
 */
export function observeScopedFileSearch(action: AuthorizedAction): LocalFileSearchObservation {
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
    const matches: string[] = [];
    let visitedDirs = 0;
    let inspectedEntries = 0;
    while (dirs.length > 0) {
      const current = dirs.pop();
      if (!current) throw new Error('REFUSED');
      if (++visitedDirs > MAX_DIRS) throw new Error('REFUSED');
      assertCanonicalPath(current.path, canonicalRoot);
      const dir = opendirSync(current.path);
      try {
        let entry = dir.readSync();
        while (entry !== null) {
          if (++inspectedEntries > MAX_ENTRIES) throw new Error('REFUSED');
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
    return {
      kind: 'R0_LOCAL_FILE_SEARCH_OBSERVATION',
      paths: matches.sort(),
      inspectedEntries,
      truncated: false,
      semanticVerified: false,
      cloudDisclosure: false,
    };
  } catch {
    // Never disclose native absolute paths or an apparently complete partial scan.
    throw new Error('R0_FILE_SEARCH_REFUSED');
  }
}
