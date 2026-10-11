// Manifest-restricted destructive effects (VJ-P1-01 R4 effect atomicity).
//
// A census — however strict — is only a snapshot. Content planted AFTER the
// last census (a caller-supplied trace hook, the async grant-issuance window
// inside runPrivileged, or any other seam) is invisible to it, and a
// whole-root uninstaller destroys it while the lifecycle reports REMOVED.
// The destructive privileged effect is therefore bound to the install-time
// owned manifest carried INSIDE the authorized action itself (plan-hash
// bound, ledger-revalidated at the boundary), in two layers:
//
//   1. Effect-time scope-exclusivity validation — runs INSIDE the privileged
//      effect executor, after the last caller-reachable seam, immediately
//      before destruction: every path currently present inside the declared
//      deletion scope must be manifest-recorded (entry-or-ancestor, the same
//      strict membership the preview census applies). Any unrecorded content
//      refuses the effect with zero deletions (fail closed, provider stays,
//      honest NO_EFFECT journaling).
//   2. Manifest-restricted deletion — the executor removes exactly the
//      manifest entries (deepest first, empty-directory-only). A path that
//      appeared after the manifest was recorded is structurally outside what
//      the effect can delete: no caller callback or await can repopulate the
//      deletion set, closing every remaining check-to-effect race by
//      construction.
//
// An EXTERNAL uninstaller (winget spawns the package's own removal program)
// cannot have its deletion set bounded by the manifest — for that path only
// (1) applies: the effect refuses unless exclusivity is proven at effect
// time, so an external uninstall that could remove unrecorded user files
// fails closed (provider retained, no REMOVED claim).
import { type PlanAction, pathWithin } from '@shun/contracts';
import type { FilesystemPort } from './ports.ts';

/** The manifest-restricted deletion spec an uninstall effect consumes. */
export interface ManifestDeletionSpec {
  /** Exact paths (files, directories, created roots) the install recorded. */
  readonly manifest: readonly string[];
  /** Declared deletion scope roots (the action's authorized write scope). */
  readonly scopeRoots: readonly string[];
}

/** One-node destructive primitive, owned by the effect executor. */
export interface EntryRemovalPort {
  /**
   * Remove exactly ONE node: a file, or a directory ONLY when it holds no
   * remaining children. Returns false when the node is absent or the
   * directory still holds content — unrecorded residue is never forced.
   */
  removeEntry(path: string): boolean | Promise<boolean>;
}

/**
 * Extract the manifest-restricted deletion spec from an uninstall action.
 * undefined = the action is not manifest-bound — a legacy whole-root shape
 * the effect must refuse (fail closed), never execute.
 */
export function manifestDeletionSpec(action: PlanAction): ManifestDeletionSpec | undefined {
  if (action.op !== 'software.uninstall') return undefined;
  const raw = (action.parameters as { deletionManifest?: unknown }).deletionManifest;
  if (!Array.isArray(raw) || raw.length === 0) return undefined;
  if (!raw.every((entry) => typeof entry === 'string' && entry.length > 0)) return undefined;
  const scopeRoots = action.filesystemScope?.write ?? [];
  if (scopeRoots.length === 0) return undefined;
  return { manifest: [...raw] as string[], scopeRoots: [...scopeRoots] };
}

/** Canonical comparison key: separator-normalized, case-insensitive (Windows truth). */
export function canonicalKey(path: string): string {
  return path
    .replaceAll('\\', '/')
    .replace(/^\/+|\/+$/g, '')
    .toLowerCase();
}

/**
 * Recursively enumerate every descendant path (directories and files) of a
 * root, with NO depth cap: a fixed depth bound would make content deeper
 * than the bound invisible to the removal gates, and content the gates
 * cannot see cannot block deletion (VJ-P1-01). A visited set keyed on the
 * canonical path guards against symlink/reparse-point cycles — a directory
 * graph that is not a tree — so the walk always terminates.
 */
export async function treeUnder(fs: FilesystemPort, root: string): Promise<string[]> {
  const found: string[] = [];
  const visited = new Set<string>();
  const walk = async (dir: string): Promise<void> => {
    const key = canonicalKey(dir);
    if (visited.has(key)) return;
    visited.add(key);
    if (!(await fs.isDirectory(dir))) return;
    for (const child of await fs.listChildren(dir)) {
      const path = joinPath(dir, child);
      found.push(path);
      await walk(path);
    }
  };
  await walk(root);
  return found;
}

function joinPath(root: string, child: string): string {
  return `${root.replace(/[\\/]+$/, '')}\\${child}`;
}

/**
 * Strict census membership (shared with the preview classifier): a path is
 * recorded when it IS a manifest entry or an ANCESTOR of one — a directory
 * holding installer-written content is itself installer-created, while
 * content dropped inside a recorded directory later is NOT covered.
 */
function isCensusRecorded(path: string, manifest: readonly string[]): boolean {
  return manifest.some((owned) => pathWithin(owned, path));
}

/**
 * Effect-time scope-exclusivity validation (VJ-P1-01 R4). The caller is the
 * privileged effect executor, AFTER its boundary validation and after every
 * caller-reachable seam (trace hooks, approval surfaces, grant issuance):
 * between this check and the destructive primitive the executor runs no
 * caller-supplied code. Returns undefined when every path currently present
 * inside the declared scope is manifest-recorded; otherwise a fail-closed
 * refusal note naming the first unrecorded paths. Also refuses a manifest
 * that escapes the declared scope — a plan defect the effect never executes.
 */
export async function effectTimeScopeRefusal(
  fs: FilesystemPort,
  spec: ManifestDeletionSpec,
): Promise<string | undefined> {
  for (const path of spec.manifest) {
    if (!spec.scopeRoots.some((root) => pathWithin(path, root))) {
      return `deletion manifest path escapes the action's filesystem scope: ${path}`;
    }
  }
  const offenders: string[] = [];
  for (const root of spec.scopeRoots) {
    if (!(await fs.exists(root))) continue;
    if (!isCensusRecorded(root, spec.manifest)) {
      offenders.push(root);
    }
    for (const path of await treeUnder(fs, root)) {
      if (offenders.length >= 8) break;
      if (!isCensusRecorded(path, spec.manifest)) {
        offenders.push(path);
      }
    }
    if (offenders.length >= 8) break;
  }
  if (offenders.length > 0) {
    const ellipsis = offenders.length >= 8 ? ' …' : '';
    return `deletion scope holds unrecorded content at effect time: ${offenders.join(', ')}${ellipsis}`;
  }
  return undefined;
}

/**
 * Manifest-restricted deletion (VJ-P1-01 R4): remove exactly the recorded
 * entries, deepest first so recorded directories collapse as their recorded
 * content is removed. A recorded directory that still holds children after
 * its recorded content is gone (defense in depth past the exclusivity gate)
 * is RETAINED — the destructive primitive is never aimed at content the
 * install did not record.
 */
export async function removeManifestEntries(
  removal: EntryRemovalPort,
  fs: FilesystemPort,
  spec: ManifestDeletionSpec,
): Promise<{ removed: string[]; retained: string[] }> {
  const ordered = [...spec.manifest].sort((a, b) => {
    const depthDelta = segmentCount(b) - segmentCount(a);
    if (depthDelta !== 0) return depthDelta;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  const removed: string[] = [];
  const retained: string[] = [];
  for (const path of ordered) {
    if (!(await fs.exists(path))) continue;
    if ((await fs.isDirectory(path)) && (await fs.listChildren(path)).length > 0) {
      retained.push(path);
      continue;
    }
    if (await removal.removeEntry(path)) removed.push(path);
    else retained.push(path);
  }
  return { removed, retained };
}

function segmentCount(path: string): number {
  return path.split(/[\\/]+/).length;
}
