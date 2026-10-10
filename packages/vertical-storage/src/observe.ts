// R0 read-only observation (L2 §14.3): metadata only, never file contents
// (P0 data minimization; the B-040 canary depends on this — secret-shaped
// bytes inside scanned files must be structurally unreachable).
//
// Walks each resolved scope root, aggregates per-directory byte totals and
// records what could not be read (racing deletion, ACL denial) instead of
// failing the whole scan.
import { type Dirent, promises as fsp, type Stats } from 'node:fs';
import * as path from 'node:path';
import { z } from 'zod';
import type { ResolvedScope } from './scope.ts';

export const DirectoryStatSchema = z.strictObject({
  /** Canonical real directory path. */
  path: z.string().min(1),
  bytes: z.number().int().nonnegative(),
  files: z.number().int().nonnegative(),
  lastModifiedMs: z.number(),
  /** Directories/files that could not be read (ACL/race); observation stays honest about gaps. */
  inaccessibleEntries: z.array(z.string().min(1)),
});
export type DirectoryStat = z.infer<typeof DirectoryStatSchema>;

export const ObservationEvidenceSchema = z.strictObject({
  observedAt: z.string().min(1),
  roots: z.array(z.string().min(1)).min(1),
  /** One entry per direct child directory of each root (aggregated subtree totals). */
  directories: z.array(DirectoryStatSchema),
  /** Loose files directly under a root (never classified disposable by directory policy). */
  rootFiles: z.array(
    z.strictObject({
      path: z.string().min(1),
      bytes: z.number().int().nonnegative(),
    }),
  ),
  totalBytes: z.number().int().nonnegative(),
});
export type ObservationEvidence = z.infer<typeof ObservationEvidenceSchema>;

interface SubtreeAccumulator {
  bytes: number;
  files: number;
  lastModifiedMs: number;
  inaccessible: string[];
}

/**
 * Metadata-only walk. Reparse points are never followed (a junction inside a
 * cache directory must not pull outside content into the measurement, and the
 * executor refuses to delete through them); their own lstat size counts, their
 * target does not.
 */
export async function observeStorage(
  scope: ResolvedScope,
  clock: () => string,
): Promise<ObservationEvidence> {
  const directories: DirectoryStat[] = [];
  const rootFiles: ObservationEvidence['rootFiles'] = [];
  let totalBytes = 0;

  for (const root of scope.roots) {
    const rootEntries = await safeReaddir(root);
    for (const entry of rootEntries) {
      const entryPath = path.join(root, entry.name);
      if (entry.isDirectory()) {
        const acc: SubtreeAccumulator = {
          bytes: 0,
          files: 0,
          lastModifiedMs: 0,
          inaccessible: [],
        };
        await accumulate(entryPath, acc, 0);
        const stat = await safeStatDir(entryPath);
        directories.push({
          path: await realPathOrNull(entryPath).then((p) => p ?? entryPath),
          bytes: acc.bytes,
          files: acc.files,
          lastModifiedMs: Math.max(stat.mtimeMs, acc.lastModifiedMs),
          inaccessibleEntries: acc.inaccessible,
        });
        totalBytes += acc.bytes;
      } else {
        const st = await safeLstat(entryPath);
        if (st) {
          rootFiles.push({ path: entryPath, bytes: st.size });
          totalBytes += st.size;
        }
      }
    }
  }

  return ObservationEvidenceSchema.parse({
    observedAt: clock(),
    roots: [...scope.roots],
    directories,
    rootFiles,
    totalBytes,
  });
}

const MAX_DEPTH = 16;

async function accumulate(dir: string, acc: SubtreeAccumulator, depth: number): Promise<void> {
  if (depth > MAX_DEPTH) {
    acc.inaccessible.push(`${dir} (depth limit)`);
    return;
  }
  const entries = await safeReaddir(dir);
  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) {
      // Reparse point: measured by its own lstat size only, never followed.
      const st = await safeLstat(entryPath);
      if (st) acc.bytes += st.size;
      continue;
    }
    if (entry.isDirectory()) {
      const st = await safeStatDir(entryPath);
      acc.lastModifiedMs = Math.max(acc.lastModifiedMs, st.mtimeMs);
      await accumulate(entryPath, acc, depth + 1);
      continue;
    }
    const st = await safeLstat(entryPath);
    if (!st) {
      acc.inaccessible.push(entryPath);
      continue;
    }
    acc.bytes += st.size;
    acc.files += 1;
    acc.lastModifiedMs = Math.max(acc.lastModifiedMs, st.mtimeMs);
  }
}

async function safeReaddir(dir: string): Promise<Dirent[]> {
  try {
    return await fsp.readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

async function safeLstat(p: string): Promise<Stats | null> {
  try {
    return await fsp.lstat(p);
  } catch {
    return null;
  }
}

/** Only the fields callers rely on when the stat itself races away. */
interface MtimeOnly {
  mtimeMs: number;
}

async function safeStatDir(p: string): Promise<MtimeOnly> {
  try {
    return await fsp.stat(p);
  } catch {
    return { mtimeMs: 0 };
  }
}

async function realPathOrNull(p: string): Promise<string | null> {
  try {
    return await fsp.realpath(p);
  } catch {
    return null;
  }
}

/** Re-measure a directory subtree now (post-action honesty: regrowth is recorded, not hidden). */
export async function measureDirectoryNow(dir: string): Promise<DirectoryStat> {
  const acc: SubtreeAccumulator = { bytes: 0, files: 0, lastModifiedMs: 0, inaccessible: [] };
  const st = await safeStatDir(dir);
  await accumulate(dir, acc, 0);
  return DirectoryStatSchema.parse({
    path: (await realPathOrNull(dir)) ?? dir,
    bytes: acc.bytes,
    files: acc.files,
    lastModifiedMs: Math.max(st.mtimeMs, acc.lastModifiedMs),
    inaccessibleEntries: acc.inaccessible,
  });
}
