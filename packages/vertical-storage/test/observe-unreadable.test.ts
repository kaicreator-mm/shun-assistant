// VS-P2-07 negative controls (Issue #40): an unreadable directory must be
// recorded as unreadable — never silently counted as empty. An unreadable
// scope root fails the observation outright (an empty observation would be a
// fabricated one). Windows-native ACL denial provides the real mechanism
// evidence; other hosts skip the ACL controls honestly.
import { execSync } from 'node:child_process';
import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  attributeGrowth,
  buildCleanupPlan,
  observeStorage,
  resolveScope,
  StorageVerticalError,
} from '../src/index.ts';
import { makeFixtureRoot, plantFiles, volumeOf } from './helpers.ts';

const itWin = process.platform === 'win32' ? it : it.skip;

/** Deny directory listing (RD) for Everyone; returns false when unsupported. */
function denyRead(dir: string): boolean {
  try {
    execSync(`icacls "${dir}" /deny "*S-1-1-0:(RD)"`, { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function allowRead(dir: string): void {
  try {
    execSync(`icacls "${dir}" /reset`, { stdio: 'pipe' });
  } catch {
    // best-effort restore
  }
}

describe('VS-P2-07 — unreadable directories are explicit, never silently empty', () => {
  itWin('records an ACL-denied directory as inaccessible instead of measuring it as 0 bytes', async () => {
    const root = await makeFixtureRoot('observe-denied');
    const locked = path.join(root, 'lockedcache');
    await plantFiles(locked, [{ relativePath: 'secret.bin', bytes: 4096 }]);
    if (!denyRead(locked)) return; // host cannot apply ACLs: skip honestly
    try {
      const scope = await resolveScope(volumeOf(root), { roots: [root] });
      const observation = await observeStorage(scope, () => '2026-10-10T10:00:00.000Z');
      const lockedReal = await fsp.realpath(locked);
      const stat = observation.directories.find((d) => d.path === lockedReal);
      expect(stat).toBeDefined();
      // The directory EXISTS and holds 4096 bytes: silence would claim 0/0.
      expect(stat?.bytes).toBe(0); // unmeasured, not "empty on disk"
      expect(stat?.files).toBe(0);
      expect(stat?.inaccessibleEntries.length).toBeGreaterThan(0);
      expect(stat?.inaccessibleEntries.join(';')).toMatch(/unreadable/);
    } finally {
      allowRead(locked);
    }
  });

  itWin('never attributes or plans a cleanup target from an unreadable directory', async () => {
    const root = await makeFixtureRoot('observe-plan-denied');
    const locked = path.join(root, 'lockedcache');
    await plantFiles(locked, [{ relativePath: 'big.bin', bytes: 8192 }]);
    const open = path.join(root, 'cache');
    await plantFiles(open, [{ relativePath: 'small.bin', bytes: 1024 }]);
    if (!denyRead(locked)) return;
    try {
      const scope = await resolveScope(volumeOf(root), { roots: [root] });
      const observation = await observeStorage(scope, () => '2026-10-10T10:00:00.000Z');
      // Size alone would pick the locked 8192-byte directory; honesty must not.
      const attribution = attributeGrowth({
        observation,
        eligibleCategories: ['CACHE'],
        classificationPolicy: { protectedRealPaths: [], scopeRoots: scope.roots },
        observationEvidenceRef: 'evidence://t/observation.json',
      });
      expect(attribution.growthSourcePath).toBe(await fsp.realpath(open));
      const proposal = await buildCleanupPlan({
        taskId: 'task-t07-obs',
        targetVolume: volumeOf(root),
        attribution,
        observation,
        observationEvidenceRef: 'evidence://t/observation.json',
        scope,
        protectedRealPaths: [],
        eligibleCategories: ['CACHE'],
        policySnapshotRevision: 'policy-rev-1',
        rankingPolicyRevision: 'ranking-rev-1',
        environmentId: 'env-t07',
        evidenceDir: path.join(root, 'evidence'),
        clock: () => '2026-10-10T10:00:00.000Z',
      });
      expect(proposal.targets.map((t) => t.path)).toEqual([await fsp.realpath(open)]);
    } finally {
      allowRead(locked);
    }
  });

  itWin('fails the observation outright when a scope root itself is unreadable', async () => {
    const root = await makeFixtureRoot('observe-root-denied');
    await plantFiles(path.join(root, 'cache'), [{ relativePath: 'a.bin', bytes: 64 }]);
    if (!denyRead(root)) return;
    try {
      const scope = await resolveScope(volumeOf(root), { roots: [root] });
      await expect(observeStorage(scope, () => '2026-10-10T10:00:00.000Z')).rejects.toThrow(
        StorageVerticalError,
      );
    } finally {
      allowRead(root);
    }
  });
});
