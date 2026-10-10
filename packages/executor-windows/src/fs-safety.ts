// Filesystem safety surface for typed fs ops (L2 §8.2.1): grant-scope
// containment plus native realpath and reparse-point checks.
//
// contracts `pathWithin` is the lexical gate and explicitly does NOT replace
// this module: Win32 normalization can move a lexically-contained path
// outside its prefix, and reparse points (symlinks/junctions/mount points)
// redirect touches. So before any filesystem call the executor resolves the
// path natively and re-checks containment ON THE RESOLVED PATH, refusing any
// reparse point encountered along the way. TOCTOU on a local single-user host
// is acknowledged and bounded: the privileged helper re-runs these checks
// inside the elevated boundary immediately before the touch.
import { lstatSync, realpathSync } from 'node:fs';
import { dirname } from 'node:path';
import { pathWithin } from '@shun/contracts';

export type FsSafetyCheck = { ok: true; resolved: string } | { ok: false; reason: string };

function _isReparsePoint(path: string): boolean {
  const st = lstatSync(path, { throwIfNoEntry: false });
  if (!st) return false;
  // Symbolic links, junctions and mount points all surface as reparse; the
  // lstat-based symlink typing covers links/junctions on Win32.
  return st.isSymbolicLink();
}

/**
 * Resolve `target` without following reparse points and verify it lands
 * within one of `scopePrefixes`. `target` may not exist yet (fs.write of a
 * new file): the deepest existing ancestor is resolved natively and the
 * remaining segments are appended — every existing segment is reparse-checked
 * first, so a planted link cannot redirect the touch.
 *
 * Relative paths are refused by ops-layer validation before this runs; the
 * interpreter only ever hands over absolute, lexically-legal paths.
 */
export function resolveWithinScope(
  target: string,
  scopePrefixes: readonly string[],
): FsSafetyCheck {
  if (scopePrefixes.length === 0) {
    return {
      ok: false,
      reason: 'grant declares no filesystem scope but the action touches the filesystem',
    };
  }
  // Reparse check on EVERY existing ancestor of the raw target, first: a
  // link inside the scope that resolves INTO the scope would otherwise pass
  // containment while redirecting the touch.
  let walk: string | null = target;
  while (walk) {
    const st = lstatSync(walk, { throwIfNoEntry: false });
    if (st?.isSymbolicLink()) {
      return { ok: false, reason: `reparse point (symlink/junction) in path: ${walk}` };
    }
    const parent = dirname(walk);
    walk = parent === walk ? null : parent;
  }
  let resolved: string;
  try {
    resolved = realpathSync(target);
  } catch {
    // Target (partially) absent: resolve the deepest existing ancestor.
    const ancestor = deepestExistingAncestor(target);
    if (!ancestor) {
      return { ok: false, reason: `no existing ancestor to resolve: ${target}` };
    }
    try {
      const resolvedAncestor = realpathSync(ancestor);
      const rest = target.slice(ancestor.length);
      resolved = resolvedAncestor + rest;
    } catch (e) {
      return { ok: false, reason: `ancestor resolution failed: ${message(e)}` };
    }
  }
  for (const prefix of scopePrefixes) {
    if (pathWithin(resolved, prefix)) return { ok: true, resolved };
  }
  return { ok: false, reason: `resolved path ${resolved} is outside the grant filesystem scope` };
}

function deepestExistingAncestor(target: string): string | null {
  let current = target;
  for (;;) {
    if (lstatSync(current, { throwIfNoEntry: false })) return current;
    const parent = dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

/**
 * Resolve an I/O channel path against a trusted root on REAL paths (C07):
 * the root is realpath'd, the target is realpath'd (deepest existing
 * ancestor + literal tail for not-yet-created files), and containment is
 * checked on the resolved pair. A junction/symlink planted inside the root
 * therefore cannot redirect the elevated journal/receipt/evidence writes
 * outside it — the lexical path would pass `pathWithin` while the real
 * landing does not. In-root junctions above the root itself are fine: both
 * sides resolve through them consistently. TOCTOU on a local single-user
 * host is re-checked at helper startup immediately before the journal opens.
 */
export function resolveAgainstRoot(target: string, root: string): FsSafetyCheck {
  let resolvedRoot: string;
  try {
    resolvedRoot = realpathSync(root);
  } catch {
    return { ok: false, reason: `workspace root does not resolve to a real path: ${root}` };
  }
  let resolved: string;
  try {
    resolved = realpathSync(target);
  } catch {
    const ancestor = deepestExistingAncestor(target);
    if (!ancestor) {
      return { ok: false, reason: `no existing ancestor to resolve: ${target}` };
    }
    try {
      resolved = realpathSync(ancestor) + target.slice(ancestor.length);
    } catch (e) {
      return { ok: false, reason: `ancestor resolution failed: ${message(e)}` };
    }
  }
  if (pathWithin(resolved, resolvedRoot)) return { ok: true, resolved };
  return {
    ok: false,
    reason: `resolved I/O path ${resolved} escapes the pinned workspace root ${resolvedRoot} (junction/symlink escape refused)`,
  };
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
