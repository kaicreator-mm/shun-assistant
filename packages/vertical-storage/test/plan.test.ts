// Plan/preview tests: bounded target enumeration, protected refusals, stable
// plan identity, and a readable R2 preview that carries no file content.
import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';

/* Required platform evidence is the local Windows build host; other hosts run the static checks only. */
const d = process.platform === 'win32' ? describe : describe.skip;

import {
  attributeGrowth,
  buildCleanupPlan,
  observeStorage,
  resolveScope,
  StorageVerticalError,
} from '../src/index.ts';
import { makeFixtureRoot, plantFiles, volumeOf } from './helpers.ts';

async function build(
  root: string,
  options: { protectedRealPaths?: string[]; eligible?: ('CACHE' | 'TEMP')[] } = {},
) {
  const scope = await resolveScope(volumeOf(root), { roots: [root] });
  const observation = await observeStorage(scope, () => '2026-10-10T10:00:00.000Z');
  const evidenceDir = path.join(root, 'evidence');
  const protectedRealPaths = options.protectedRealPaths ?? [];
  const attribution = attributeGrowth({
    observation,
    eligibleCategories: options.eligible ?? ['CACHE'],
    classificationPolicy: { protectedRealPaths, scopeRoots: scope.roots },
    observationEvidenceRef: 'evidence://t/observation.json',
  });
  return buildCleanupPlan({
    taskId: 'task-t07-plan',
    targetVolume: volumeOf(root),
    attribution,
    observation,
    observationEvidenceRef: 'evidence://t/observation.json',
    scope,
    protectedRealPaths,
    eligibleCategories: options.eligible ?? ['CACHE'],
    policySnapshotRevision: 'policy-rev-1',
    rankingPolicyRevision: 'ranking-rev-1',
    environmentId: 'env-t07',
    evidenceDir,
    clock: () => '2026-10-10T10:00:00.000Z',
  });
}

d('buildCleanupPlan', () => {
  it('enumerates exactly the eligible directories with measured bytes', async () => {
    const root = await makeFixtureRoot('plan-enum');
    await plantFiles(path.join(root, 'cache'), [{ relativePath: 'a.bin', bytes: 1024 }]);
    await plantFiles(path.join(root, 'tmp'), [{ relativePath: 'b.bin', bytes: 256 }]);
    await plantFiles(path.join(root, 'keep'), [{ relativePath: 'c.bin', bytes: 8192 }]);
    const proposal = await build(root, { eligible: ['CACHE', 'TEMP'] });
    const paths = proposal.targets.map((t) => t.path);
    expect(paths).toHaveLength(2);
    expect(paths).toContain(await real(path.join(root, 'cache')));
    expect(paths).toContain(await real(path.join(root, 'tmp')));
    const cacheTarget = proposal.targets.find((t) => t.path.endsWith('cache'));
    expect(cacheTarget?.expectedReclaimBytes).toBe(1024);
    expect(proposal.plan.actions).toHaveLength(2);
    expect(proposal.plan.actions.every((a) => a.sideEffectClass === 'R2')).toBe(true);
    expect(proposal.plan.actions.every((a) => a.networkScope?.allowed === false)).toBe(true);
  });

  it('produces a stable plan identity for identical state (exact plan hashing)', async () => {
    const root = await makeFixtureRoot('plan-stable');
    await plantFiles(path.join(root, 'cache'), [{ relativePath: 'a.bin', bytes: 512 }]);
    const p1 = await build(root);
    const p2 = await build(root);
    expect(p1.plan.planHash).toBe(p2.plan.planHash);
  });

  it('refuses a target containing a declared protected asset (PROTECTED_ASSET_TOUCHED)', async () => {
    const root = await makeFixtureRoot('plan-protected');
    const protectedInside = path.join(root, 'cache', 'precious');
    await fsp.mkdir(protectedInside, { recursive: true });
    await plantFiles(path.join(root, 'cache'), [{ relativePath: 'a.bin', bytes: 256 }]);
    await expect(build(root, { protectedRealPaths: [protectedInside] })).rejects.toThrow(
      /PROTECTED_ASSET_TOUCHED/,
    );
  });

  it('refuses when nothing eligible survived classification', async () => {
    const root = await makeFixtureRoot('plan-none');
    await plantFiles(path.join(root, 'docs'), [{ relativePath: 'a.bin', bytes: 256 }]);
    // attributeGrowth throws first (nothing eligible); build requires attribution.
    const scope = await resolveScope(volumeOf(root), { roots: [root] });
    const observation = await observeStorage(scope, () => '2026-10-10T10:00:00.000Z');
    expect(() =>
      attributeGrowth({
        observation,
        eligibleCategories: ['CACHE'],
        classificationPolicy: { protectedRealPaths: [], scopeRoots: scope.roots },
        observationEvidenceRef: 'evidence://t',
      }),
    ).toThrow(StorageVerticalError);
  });

  it('writes a checkpoint manifest enumerating every target file before approval', async () => {
    const root = await makeFixtureRoot('plan-checkpoint');
    await plantFiles(path.join(root, 'cache'), [
      { relativePath: 'a.bin', bytes: 128 },
      { relativePath: 'nested/b.bin', bytes: 64 },
    ]);
    const proposal = await build(root);
    expect(proposal.checkpoint.checkpointRef).toMatch(/^evidence:\/\//);
    const manifestFile = path.join(
      root,
      'evidence',
      proposal.checkpoint.checkpointRef.split('/').pop() ?? '',
    );
    const manifest = JSON.parse(await fsp.readFile(manifestFile, 'utf8')) as {
      targets: { files: { path: string }[] }[];
    };
    const manifestPaths = manifest.targets[0]?.files.map((f) => f.path) ?? [];
    expect(manifestPaths).toHaveLength(2);
    expect(proposal.plan.recoveryPlan.checkpointRef).toBe(proposal.checkpoint.checkpointRef);
  });
});

d('renderPreview (R2 PREVIEW phase)', () => {
  it('is readable: names targets, classifications, protected assets and the R2 contract', async () => {
    const root = await makeFixtureRoot('plan-preview');
    await plantFiles(path.join(root, 'cache'), [{ relativePath: 'a.bin', bytes: 1024 }]);
    const photos = path.join(root, 'photos');
    await plantFiles(photos, [{ relativePath: 'p.jpg', bytes: 256 }]);
    const proposal = await build(root, { protectedRealPaths: [photos] });
    // Note: with photos protected, the plan refuses if photos live inside a target;
    // here photos is not inside the cache target, so the plan builds.
    const preview = proposal.preview;
    expect(preview).toMatch(/R2/);
    expect(preview).toMatch(/cache/);
    expect(preview).toMatch(/photos/);
    expect(preview).toMatch(/Network access: none/);
    expect(preview).toMatch(/1024 bytes/);
  });
});

async function real(p: string): Promise<string> {
  return fsp.realpath(p);
}
