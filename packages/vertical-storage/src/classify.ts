// Cleanup classification policy (Product C-003 / L2 §14.3): only policy-
// eligible disposable categories (CACHE, TEMP) may ever be removed; anything
// not provably disposable is USER_CREATED_UNKNOWN and fail-closed; declared
// protected assets are PROTECTED. Classification is path-policy based — never
// size-based: "big" is evidence for explaining growth, never a deletion
// criterion.
//
// Two frozen vocabularies meet here: cleanup TARGETS use the C-003 eligible
// category space (CACHE | TEMP), while the attribution record uses the frozen
// C-002 residue space (PROGRAM_OWNED | CACHE | CONFIGURATION |
// USER_CREATED_UNKNOWN | PROTECTED — no TEMP exists there). A TEMP-marked
// directory is disposable generated data: its residue label is CACHE, and the
// attribution explanation states the cleanup category explicitly so the
// mapping is auditable, never silent.
import * as path from 'node:path';
import { pathWithin, type ResidueClassification } from '@shun/contracts';

export type CleanupCategory = 'CACHE' | 'TEMP';

export interface ClassificationResult {
  path: string;
  /** Cleanup category when provably disposable; null when fail-closed or protected. */
  cleanupCategory: CleanupCategory | null;
  /** Frozen residue-space label (C-002) for the attribution record. */
  residue: ResidueClassification;
  /** Whole path segment that matched the disposable policy (null when fail-closed). */
  matchedMarker: string | null;
}

export interface ClassificationPolicy {
  /** Declared protected assets (canonical realpaths); they are PROTECTED and never disposable. */
  protectedRealPaths: readonly string[];
  /** Canonical scope roots: marker matching is confined to segments at or below a root. */
  scopeRoots: readonly string[];
}

/**
 * Conservative, reviewable marker list. A directory qualifies only when one
 * of these matches a whole path segment (case-insensitive). The list is
 * intentionally short: growing it is a policy decision, not a code accident.
 * Markers target universally-understood disposable semantics on Windows
 * (temp/cache vocabulary), never application-private heuristics.
 */
export const DISPOSABLE_SEGMENT_MARKERS: readonly string[] = [
  'cache',
  'caches',
  'temp',
  'tmp',
  'temporary',
  'temporary internet files',
  'cache2',
  'gpucache',
  'code cache',
  'shader-cache',
  'shadercache',
  'dawngraphitecache',
  'dawnwebgpucache',
  'crashpadreports',
];

const TEMP_MARKERS: ReadonlySet<string> = new Set(['temp', 'tmp']);

function segments(p: string): string[] {
  return p
    .replaceAll('\\', '/')
    .split('/')
    .filter((s) => s.length > 0);
}

/**
 * Segments used for marker matching: only those AT OR BELOW the containing
 * scope root. Ancestor segments above a scope root must never classify content
 * (a scan root that happens to live under %TEMP% would otherwise make every
 * observed directory "temp" — a scope is a boundary, not a classification).
 */
export function segmentsRelativeToScope(
  realPath: string,
  scopeRoots: readonly string[],
): string[] | null {
  const container = scopeRoots.find((root) => pathWithin(realPath, root));
  if (!container) return null;
  const all = segments(realPath);
  const rootSegCount = segments(container).length;
  return all.slice(rootSegCount);
}

/**
 * Classify one directory path (canonical realpath). Order is fixed and
 * fail-closed: PROTECTED beats any disposable marker (a folder named "cache"
 * under a protected tree stays protected); markers match only at or below the
 * containing scope root; anything without a matching marker is
 * USER_CREATED_UNKNOWN even inside the scan scope.
 */
export function classifyDirectory(
  realPath: string,
  policy: ClassificationPolicy,
): ClassificationResult {
  for (const protectedPath of policy.protectedRealPaths) {
    if (pathWithin(realPath, protectedPath)) {
      return { path: realPath, cleanupCategory: null, residue: 'PROTECTED', matchedMarker: null };
    }
  }
  const relative = segmentsRelativeToScope(realPath, policy.scopeRoots);
  if (relative === null) {
    return {
      path: realPath,
      cleanupCategory: null,
      residue: 'USER_CREATED_UNKNOWN',
      matchedMarker: null,
    };
  }
  for (const segment of relative.map((s) => s.toLowerCase())) {
    if (DISPOSABLE_SEGMENT_MARKERS.includes(segment)) {
      const category: CleanupCategory = TEMP_MARKERS.has(segment) ? 'TEMP' : 'CACHE';
      return {
        path: realPath,
        cleanupCategory: category,
        residue: 'CACHE',
        matchedMarker: segment,
      };
    }
  }
  return {
    path: realPath,
    cleanupCategory: null,
    residue: 'USER_CREATED_UNKNOWN',
    matchedMarker: null,
  };
}

/** True when a candidate target is or contains a declared protected asset (realpath aware). */
export function touchesProtectedAsset(
  candidateRealPath: string,
  protectedRealPaths: readonly string[],
): boolean {
  return protectedRealPaths.some(
    (p) => pathWithin(p, candidateRealPath) || pathWithin(candidateRealPath, p),
  );
}

/**
 * Loose files directly under a scope root: no directory policy covers them,
 * so they are fail-closed USER_CREATED_UNKNOWN. Deleting scattered root files
 * by size would be exactly the forbidden "delete by size alone".
 */
export function classifyLooseRootFile(filePath: string): ClassificationResult {
  return {
    path: path.resolve(filePath),
    cleanupCategory: null,
    residue: 'USER_CREATED_UNKNOWN',
    matchedMarker: null,
  };
}
