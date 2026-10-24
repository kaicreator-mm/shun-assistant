// T04 independent R0 file.search post-state oracle. This module is the
// separately attested verifier demanded by frozen L2 §9.4: it shares NO code,
// NO syscalls and NO implementation with the native handle-anchored walker in
// scoped-file-search.ts (NtOpenFile/NtQueryDirectoryFile). It observes the
// bounded scope afterwards using plain Node filesystem primitives through
// libuv, recomputes the expected match set with its own matcher, and
// fingerprints the whole tree so a read-only effect can be proven not to have
// mutated anything. Any anomaly degrades to "not verified" — never a PASS.
import { createHash } from 'node:crypto';
import { type Dir, lstatSync, opendirSync, type Stats } from 'node:fs';
import { isAbsolute, join, resolve, sep } from 'node:path';
import type { AuthorizedAction } from '@shun/contracts';

// Same envelope as the native walk; the oracle must refuse a scope the
// effect-level walk would have refused instead of verifying a wider world.
const MAX_ENTRIES = 4096;
const MAX_DIRS = 512;
const MAX_DEPTH = 8;

export type OracleWalk = Readonly<{
  fingerprint: string;
  matches: readonly string[];
  inspectedEntries: number;
}>;

export type OracleWalkResult =
  | { ok: true; walk: OracleWalk }
  | { ok: false; code: 'ORACLE_SCOPE_REFUSED' | 'ORACLE_BOUNDS_EXCEEDED' | 'ORACLE_MUTATION_RISK' };

function refuse(code: 'ORACLE_SCOPE_REFUSED' | 'ORACLE_BOUNDS_EXCEEDED'): OracleWalkResult {
  return { ok: false, code };
}

/**
 * Independently implemented bounded glob matcher for the frozen query grammar
 * (literal chars, '?' and '*'). Deliberately NOT the DP loop used by the
 * native walk's matcher: the oracle must stay a separate implementation so a
 * common-mode matcher bug cannot self-confirm. Depth is bounded by the 128
 * character grammar limit admitted upstream.
 */
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

type Fingerprints = { entries: number; matches: string[]; lines: string[] };

function walkScope(root: string, query: string): Fingerprints | OracleWalkResult {
  const canonicalRoot = resolve(root);
  if (!isAbsolute(canonicalRoot)) return refuse('ORACLE_SCOPE_REFUSED');
  let base: import('node:fs').Stats;
  try {
    base = lstatSync(canonicalRoot);
  } catch {
    return refuse('ORACLE_SCOPE_REFUSED');
  }
  if (!base.isDirectory()) return refuse('ORACLE_SCOPE_REFUSED');

  const fingerprints: Fingerprints = { entries: 0, matches: [], lines: [] };
  let visitedDirs = 0;
  const dirs: Array<{ path: string; depth: number; rel: string }> = [
    { path: canonicalRoot, depth: 0, rel: '' },
  ];
  while (dirs.length > 0) {
    const current = dirs.pop();
    if (!current) return { ok: false, code: 'ORACLE_MUTATION_RISK' };
    if (++visitedDirs > MAX_DIRS) return refuse('ORACLE_BOUNDS_EXCEEDED');
    let dir: Dir;
    try {
      dir = opendirSync(current.path);
    } catch {
      return refuse('ORACLE_SCOPE_REFUSED');
    }
    try {
      for (;;) {
        let entry: import('node:fs').Dirent | null;
        try {
          entry = dir.readSync();
        } catch {
          return refuse('ORACLE_SCOPE_REFUSED');
        }
        if (entry === null) break;
        if (entry.name === '.' || entry.name === '..') continue;
        if (++fingerprints.entries > MAX_ENTRIES) return refuse('ORACLE_BOUNDS_EXCEEDED');
        const childPath = join(current.path, entry.name);
        const rel = current.rel === '' ? entry.name : `${current.rel}${sep}${entry.name}`;
        let stat: Stats;
        try {
          stat = lstatSync(childPath);
        } catch {
          return refuse('ORACLE_SCOPE_REFUSED');
        }
        if (stat.isSymbolicLink()) {
          // Junction/symlink reparse entries make the world unstable for a
          // fingerprint comparison; the native walk refuses them too.
          return { ok: false, code: 'ORACLE_MUTATION_RISK' };
        }
        if (stat.isDirectory()) {
          if (current.depth >= MAX_DEPTH) return refuse('ORACLE_BOUNDS_EXCEEDED');
          fingerprints.lines.push(`d\t${rel}`);
          dirs.push({ path: childPath, depth: current.depth + 1, rel });
        } else if (stat.isFile()) {
          fingerprints.lines.push(`f\t${rel}\t${stat.size}\t${Math.floor(stat.mtimeMs)}`);
          if (oracleGlobMatch(entry.name, query)) fingerprints.matches.push(rel);
        } else {
          return { ok: false, code: 'ORACLE_MUTATION_RISK' };
        }
      }
    } finally {
      dir.closeSync();
    }
  }
  return fingerprints;
}

/**
 * One bounded, independent observation of the scope: a whole-tree fingerprint
 * (relative path, kind, size, mtime) plus the oracle's own expected match set.
 * Content bytes are intentionally not read; only the R0 search contract
 * (names and non-mutation) is verified, and oversized scopes are refused.
 */
export function captureOracleWalk(root: string, query: string): OracleWalkResult {
  try {
    const walked = walkScope(root, query);
    if ('ok' in walked) return walked;
    const lines = walked.lines.sort();
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
