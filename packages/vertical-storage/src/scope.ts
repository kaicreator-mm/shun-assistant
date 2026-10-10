// Scoped filesystem roots for Loop C observation and cleanup (L2 §14.3 "read-
// only observation" and the DAG row "scoped Windows storage observation").
//
// Bounded-ness starts here: Shun never scans or cleans a whole volume. The
// runtime wiring declares explicit candidate roots (disposable-candidate
// directories on the target volume); everything this vertical ever touches
// must resolve inside them.
import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import { pathWithin } from '@shun/contracts';
import { z } from 'zod';
import { StorageVerticalError } from './errors.ts';

export const StorageScopeSchema = z.strictObject({
  /** Absolute candidate roots; every observation and every cleanup target stays inside them. */
  roots: z.array(z.string().min(1)).min(1),
});
export type StorageScope = z.infer<typeof StorageScopeSchema>;

export interface ResolvedScope {
  /** Canonical realpaths (Windows: native casing) of the accepted roots. */
  roots: readonly string[];
}

const WINDOWS_VOLUME = /^[a-zA-Z]:/;

/** True when `p` sits on `volume` (case-insensitive drive-letter match on Windows). */
export function pathOnVolume(p: string, volume: string): boolean {
  if (!WINDOWS_VOLUME.test(volume)) {
    throw new StorageVerticalError('ACTION_NOT_BOUNDED', `unsupported volume form: ${volume}`);
  }
  if (!WINDOWS_VOLUME.test(p)) return false;
  return p[0]?.toLowerCase() === volume[0]?.toLowerCase();
}

/**
 * Resolve and harden the declared scope. Rejects relative paths, `..`
 * segments, nonexistent roots, reparse points (symlinks/junctions must never
 * widen a scope behind the approver's back) and duplicate roots. Windows path
 * containment is case-insensitive and segment-boundary aware via the contracts
 * `pathWithin`; real containment on disk is re-checked by the executor before
 * any deletion (this module only establishes the trusted root set).
 */
export async function resolveScope(volume: string, declared: StorageScope): Promise<ResolvedScope> {
  const realRoots: string[] = [];
  for (const root of declared.roots) {
    if (!path.isAbsolute(root)) {
      throw new StorageVerticalError('ACTION_NOT_BOUNDED', `scope root is not absolute: ${root}`);
    }
    if (root.split(/[\\/]/).includes('..')) {
      throw new StorageVerticalError('ACTION_NOT_BOUNDED', `scope root contains '..': ${root}`);
    }
    if (!pathOnVolume(root, volume)) {
      throw new StorageVerticalError(
        'ACTION_NOT_BOUNDED',
        `scope root ${root} is not on target volume ${volume}`,
      );
    }
    // A reparse point as a root would let the real target live anywhere on
    // disk: check the DECLARED path (before resolution), then resolve.
    const declared = await fsp.lstat(root).catch(() => null);
    if (!declared) {
      throw new StorageVerticalError('ACTION_NOT_BOUNDED', `scope root does not exist: ${root}`);
    }
    if (declared.isSymbolicLink()) {
      throw new StorageVerticalError(
        'ACTION_NOT_BOUNDED',
        `scope root is a reparse point: ${root}`,
      );
    }
    if (!declared.isDirectory()) {
      throw new StorageVerticalError(
        'ACTION_NOT_BOUNDED',
        `scope root is not a directory: ${root}`,
      );
    }
    const real = await fsp.realpath(root);
    const dup = realRoots.find((existing) => existing.toLowerCase() === real.toLowerCase());
    if (dup) {
      throw new StorageVerticalError('ACTION_NOT_BOUNDED', `scope root ${root} duplicates ${dup}`);
    }
    realRoots.push(real);
  }
  // A root nested inside another root makes the effective scope ambiguous for
  // per-root attribution; refuse instead of silently overlapping.
  for (const a of realRoots) {
    for (const b of realRoots) {
      if (a !== b && pathWithin(a, b)) {
        throw new StorageVerticalError(
          'ACTION_NOT_BOUNDED',
          `scope roots overlap: ${a} is inside ${b}`,
        );
      }
    }
  }
  return { roots: realRoots };
}

/** Case-insensitive (Windows) segment-boundary containment against resolved scope roots. */
export function withinScope(candidateRealPath: string, scope: ResolvedScope): boolean {
  return scope.roots.some((root) => pathWithin(candidateRealPath, root));
}
