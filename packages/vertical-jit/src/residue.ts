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
    return 'CACHE';
  }
  if (input.layout.installDirs.some((root) => pathWithin(path, root))) {
    // Strict mode: provider-owned structure is exactly what the install
    // recorded — an owned file itself, or a directory containing one. Any
    // other file inside a program directory is user-created/unknown.
    if (
      input.providerOwnedFiles &&
      !input.providerOwnedFiles.some((owned) => pathWithin(path, owned) || pathWithin(owned, path))
    ) {
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
