// Residue classification (Product C-002 gate step 2 — preview).
//
// Every candidate path discovered at removal time is classified into the
// frozen five-class taxonomy and given a fail-closed disposition:
//   PROGRAM_OWNED / CACHE            → DELETE eligible
//   CONFIGURATION                    → RETAIN (conservative default; backup
//                                      instead of deletion keeps restore
//                                      possible, C-002 checkpoint step)
//   USER_CREATED_UNKNOWN / PROTECTED → RETAIN, never auto-deleted
//                                        (schema-enforced: unknownOrProtectedDeleted
//                                        must stay false)
//
// Classification derives ONLY from the provider's declared install layout
// plus the protected-roots declaration. Anything the provider cannot claim is
// unknown — and unknown is never deleted.
import {
  NEVER_AUTO_DELETE_CLASSIFICATIONS,
  pathWithin,
  type ResidueClassification,
} from '@shun/contracts';
import type { ProviderInstallLayout } from './ports.ts';

export interface ResidueCandidate {
  readonly path: string;
  readonly classification: ResidueClassification;
  readonly disposition: 'DELETE' | 'RETAIN';
}

export interface ResidueClassificationInput {
  readonly layout: ProviderInstallLayout;
  /** Observed candidate paths (from the filesystem observer / uninstall plan). */
  readonly observed: readonly string[];
  /** Roots that are never deletable regardless of classification (user profile, documents, planted canaries). */
  readonly protectedRoots: readonly string[];
  /**
   * Paths known to pre-date the lifecycle run (benchmark canaries or observed
   * user files found inside provider roots). These are user-created/unknown
   * even when they sit inside a program directory.
   */
  readonly preExisting?: readonly string[];
  /**
   * Exact paths the provider's install recorded. When provided (strict /
   * benchmark mode), any other file inside a provider root is
   * USER_CREATED_UNKNOWN — the provider root claim cannot cover files the
   * installer never wrote. When absent, root-level trust applies and every
   * child inside a declared provider root is PROGRAM_OWNED.
   */
  readonly providerOwnedFiles?: readonly string[];
}

/**
 * Strict census membership (VJ-P1-01): the manifest names every path the
 * install recorded — files, directories and newly created roots alike. A
 * path is recorded when it IS a manifest entry or an ANCESTOR of one (a
 * directory holding installer-written content is itself installer-created).
 * Descendants of a recorded directory are NOT covered by that entry: the
 * installer creating a directory says nothing about files dropped inside it
 * later — each of those must be a manifest entry in its own right or it
 * stays unknown.
 */
function isCensusRecorded(path: string, providerOwnedFiles: readonly string[]): boolean {
  return providerOwnedFiles.some((owned) => pathWithin(owned, path));
}

/** Fail-closed disposition for a classification. */
export function dispositionFor(classification: ResidueClassification): 'DELETE' | 'RETAIN' {
  if ((NEVER_AUTO_DELETE_CLASSIFICATIONS as readonly string[]).includes(classification)) {
    return 'RETAIN';
  }
  return classification === 'CONFIGURATION' ? 'RETAIN' : 'DELETE';
}

/**
 * Classify one path against the declared layout. Provider roots are matched
 * with the contract's path-segment containment; the FIRST matching protected
 * root wins over program-owned claims (fail-closed precedence).
 */
export function classifyPath(
  path: string,
  input: ResidueClassificationInput,
): ResidueClassification {
  if (input.protectedRoots.some((root) => pathWithin(path, root))) {
    return 'PROTECTED';
  }
  if (input.preExisting?.some((asset) => pathWithin(path, asset))) {
    return 'USER_CREATED_UNKNOWN';
  }
  if (input.layout.configDirs.some((root) => pathWithin(path, root))) {
    return 'CONFIGURATION';
  }
  if (input.layout.cacheDirs.some((root) => pathWithin(path, root))) {
    // Strict census, same discipline as install roots (VJ-P1-01 cache
    // census): the cache-root claim covers exactly what the install
    // recorded. Cache roots sit inside the deletion scope, so anything
    // unrecorded dropped inside one is user-created/unknown and fails
    // closed — never root-trusted straight into CACHE/DELETE.
    if (input.providerOwnedFiles && !isCensusRecorded(path, input.providerOwnedFiles)) {
      return 'USER_CREATED_UNKNOWN';
    }
    return 'CACHE';
  }
  if (input.layout.installDirs.some((root) => pathWithin(path, root))) {
    // Strict census: provider-owned structure is exactly what the install
    // recorded — an owned path itself, or a directory containing one. Any
    // other file inside a program directory is user-created/unknown.
    if (input.providerOwnedFiles && !isCensusRecorded(path, input.providerOwnedFiles)) {
      return 'USER_CREATED_UNKNOWN';
    }
    return 'PROGRAM_OWNED';
  }
  // Outside every declared provider root: the provider cannot claim it.
  return 'USER_CREATED_UNKNOWN';
}

/**
 * Full preview classification. Deterministic: output order follows input
 * order; duplicates are collapsed; disposition is always the fail-closed
 * default for the class — the preview cannot invent deletions.
 */
export function classifyResidue(input: ResidueClassificationInput): ResidueCandidate[] {
  const seen = new Set<string>();
  const candidates: ResidueCandidate[] = [];
  for (const path of input.observed) {
    if (seen.has(path)) continue;
    seen.add(path);
    const classification = classifyPath(path, input);
    candidates.push({ path, classification, disposition: dispositionFor(classification) });
  }
  return candidates;
}

/**
 * Defense in depth before executing the bounded removal: the planned
 * deletions must not contain a single fail-closed class. Mirrors the frozen
 * output-schema invariant — a violation here means the classifier itself is
 * broken, so removal refuses rather than "fixing" the plan.
 */
export function assertNoProtectedDeletions(candidates: readonly ResidueCandidate[]): void {
  for (const candidate of candidates) {
    if (
      candidate.disposition === 'DELETE' &&
      (NEVER_AUTO_DELETE_CLASSIFICATIONS as readonly string[]).includes(candidate.classification)
    ) {
      throw new Error(
        `refusing removal plan: ${candidate.path} is ${candidate.classification} and must be RETAIN`,
      );
    }
  }
}
