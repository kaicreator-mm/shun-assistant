// B-039 integration on the real local Windows filesystem: injected hidden
// growth, protected decoys, full R2 gate, honest reclaim, and the B-040
// privacy canary. Also proves the benchmark envelope cannot leak into the
// production input path (L2 §4.2).
import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import { StorageBenchmarkInputSchema, StorageDiagnoseInputSchema } from '@shun/contracts';
import { describe, expect, it } from 'vitest';

/* Required platform evidence is the local Windows build host; other hosts run the static checks only. */
const d = process.platform === 'win32' ? describe : describe.skip;

import {
  fingerprintPath,
  runStorageDiagnose,
  runStorageDiagnoseBenchmark,
  StorageVerticalError,
} from '../src/index.ts';
import {
  CANARY_PRIVATE_KEY,
  CANARY_USERNAME,
  makeAuthorityDouble,
  makeClock,
  makeFixtureRoot,
  makeRuntime,
  plantFiles,
  volumeOf,
} from './helpers.ts';

async function setupInScope(label: string, options: { eligible?: ('CACHE' | 'TEMP')[] } = {}) {
  const root = await makeFixtureRoot(label);
  const scopeRoot = path.join(root, 'scope');
  await fsp.mkdir(scopeRoot, { recursive: true });
  const growth = path.join(scopeRoot, 'growth');

  const cacheDir = path.join(growth, 'cache');
  const tmpDir = path.join(growth, 'tmp');
  const decoyDir = path.join(growth, 'collect');
  const keep = path.join(scopeRoot, 'keep');
  const protectedPhotos = path.join(keep, 'photos');

  const cacheBytesPlanted = await plantFiles(cacheDir, [
    { relativePath: 'chunk-0001.bin', bytes: 4096 },
    { relativePath: 'chunk-0002.bin', bytes: 4096, content: `junk ${CANARY_PRIVATE_KEY}` },
    { relativePath: 'nested/chunk-0003.bin', bytes: 2048 },
  ]);
  const tmpBytesPlanted = await plantFiles(tmpDir, [{ relativePath: 'scratch.bin', bytes: 512 }]);
  const decoyBytesPlanted = await plantFiles(decoyDir, [
    { relativePath: 'notes.txt', bytes: 5120, content: `user notes for ${CANARY_USERNAME}` },
    { relativePath: 'export.bin', bytes: 5120 },
  ]);
  await plantFiles(protectedPhotos, [
    { relativePath: 'img-0001.jpg', bytes: 3072, content: `photo ${CANARY_PRIVATE_KEY}` },
    { relativePath: 'img-0002.jpg', bytes: 1536 },
  ]);

  const authority = makeAuthorityDouble(makeClock().now);
  // Scope policy declares the disposable-candidate roots themselves: growth
  // holds the candidates, keep holds protected user data (both on the volume).
  const runtime = makeRuntime({
    root,
    scopeRoots: [growth, keep],
    authority,
    clock: makeClock(),
  });
  const volume = volumeOf(scopeRoot);
  return {
    root,
    scopeRoot,
    cacheDir,
    tmpDir,
    decoyDir,
    protectedPhotos,
    cacheBytesPlanted,
    tmpBytesPlanted,
    decoyBytesPlanted,
    authority,
    runtime,
    volume,
    eligible: options.eligible ?? (['CACHE'] as ('CACHE' | 'TEMP')[]),
    productionInput: {
      taskId: 'task-t07-b039',
      targetVolume: volume,
      protectedAssets: [{ path: protectedPhotos }],
      cleanupPolicy: {
        eligibleCategories: options.eligible ?? (['CACHE'] as ('CACHE' | 'TEMP')[]),
      },
    },
  };
}

d('B-039 — diagnose → bounded cleanup → verify (real Windows filesystem)', () => {
  it('identifies injected growth, removes only disposable cache after approval, verifies reclaimed bytes and protected hashes', async () => {
    const ctx = await setupInScope('b039-happy');
    const photosBefore = await fingerprintPath(ctx.protectedPhotos);

    const result = await runStorageDiagnose(ctx.runtime, ctx.productionInput);
    const output = result.output;

    // Growth attributed to the injected cache source with evidence.
    expect(output.attribution.growthSourcePath).toBe(await fsp.realpath(ctx.cacheDir));
    expect(output.attribution.classifiedAs).toBe('CACHE');
    expect(output.attribution.evidenceRefs.length).toBeGreaterThanOrEqual(1);

    // One bounded plan with the full observable R2 gate and explicit approval.
    expect(output.cleanupPlan).not.toBeNull();
    expect(output.cleanupPlan?.bounded).toBe(true);
    expect(output.cleanupPlan?.r2Gate.phases).toEqual([
      'PLAN',
      'PREVIEW',
      'CHECKPOINT',
      'APPROVAL',
      'EXECUTE',
      'VERIFY',
    ]);
    expect(output.cleanupPlan?.r2Gate.approvedBy).toBe('USER_APPROVAL');

    // Only disposable cache removed; the user decoy and protected photos survive.
    expect(await fsp.readdir(ctx.cacheDir)).toEqual([]);
    expect((await fsp.readdir(ctx.decoyDir)).sort()).toEqual(['export.bin', 'notes.txt']);
    expect(await fsp.readdir(ctx.protectedPhotos)).toHaveLength(2);

    // Reclaimed bytes verified against the journal; post-action state recorded.
    expect(output.reclaimed?.grossBytes).toBe(ctx.cacheBytesPlanted);
    expect(output.reclaimed?.postActionStateBytes).toBe(0);

    // Protected asset integrity verified (hash unchanged).
    expect(output.protectedAssetVerification).toEqual([
      { path: ctx.protectedPhotos, unchanged: true },
    ]);
    expect(await fingerprintPath(ctx.protectedPhotos)).toBe(photosBefore);

    // Execution evidence present and schema-consistent.
    expect(output.executionEvidence?.terminal).toBe('SUCCEEDED');
    expect(output.executionEvidence?.sideEffectEvidence.sideEffectClass).toBe('R2');

    // The approval double received a readable summary bound to the plan hash.
    expect(ctx.runtime.approvals).toHaveLength(1);
    expect(ctx.runtime.approvals[0]?.summary).toMatch(/R2/);
  });

  it('refuses to execute when approval is declined and records the no-action state honestly', async () => {
    const ctx = await setupInScope('b039-declined');
    ctx.runtime.decision.approved = false;
    const result = await runStorageDiagnose(ctx.runtime, ctx.productionInput);
    expect(result.output.cleanupPlan).toBeNull();
    expect(result.output.executionEvidence).toBeUndefined();
    expect(result.output.reclaimed).toBeUndefined();
    expect(result.output.protectedAssetVerification).toEqual([
      { path: ctx.protectedPhotos, unchanged: true },
    ]);
    expect((await fsp.readdir(ctx.cacheDir)).length).toBe(3);
    expect(ctx.authority.grantCount()).toBe(0);
  });

  it('never selects the similarly sized protected/user decoy (no deletion by size alone)', async () => {
    const ctx = await setupInScope('b039-sizeonly');
    // The user decoy (10240 bytes) is exactly as large as the cache: size
    // alone cannot pick a target — policy classification must.
    const result = await runStorageDiagnose(ctx.runtime, ctx.productionInput);
    expect(result.output.attribution.growthSourcePath).toBe(await fsp.realpath(ctx.cacheDir));
    const plannedTargets = result.output.cleanupPlan?.targets.map((t) => t.path) ?? [];
    expect(plannedTargets).not.toContain(await fsp.realpath(ctx.decoyDir));
    expect((await fsp.readdir(ctx.decoyDir)).length).toBe(2);
  });

  it('handles cache recreation mid-flow inside the bounded target and deletes it with the plan', async () => {
    const ctx = await setupInScope('b039-race');
    // Deterministic race: while the flow is between scan and execute (at the
    // approval seam), the "cache app" recreates one file under the target.
    const originalApproval = ctx.runtime.ports.requestApproval.bind(ctx.runtime.ports);
    ctx.runtime.ports.requestApproval = async (request) => {
      await plantFiles(ctx.cacheDir, [{ relativePath: 'regrow-midflow.bin', bytes: 512 }]);
      return originalApproval(request);
    };
    const result = await runStorageDiagnose(ctx.runtime, ctx.productionInput);
    // The mid-flow file was inside the approved bounded target: reclaimed.
    expect(result.output.reclaimed?.grossBytes).toBe(ctx.cacheBytesPlanted + 512);
    expect(await fsp.readdir(ctx.cacheDir)).toEqual([]);
    expect(result.output.reclaimed?.postActionStateBytes).toBe(0);
  });

  it('records regrowth after execution honestly instead of claiming permanent recovery', async () => {
    const ctx = await setupInScope('b039-regrow', { eligible: ['CACHE', 'TEMP'] });
    // Deterministic regrowth: on the second privileged action (after the cache
    // target was already cleaned), the app recreates one cache file.
    let authorityCalls = 0;
    const originalAuthority = ctx.runtime.ports.currentAuthority.bind(ctx.runtime.ports);
    ctx.runtime.ports.currentAuthority = async () => {
      authorityCalls += 1;
      if (authorityCalls >= 2) {
        await plantFiles(ctx.cacheDir, [{ relativePath: 'regrow-postaction.bin', bytes: 512 }]);
      }
      return originalAuthority();
    };
    const result = await runStorageDiagnose(ctx.runtime, ctx.productionInput);
    expect(result.output.cleanupPlan?.targets).toHaveLength(2);
    // Gross reclaim counts every deleted byte; post-action state shows the 512
    // bytes that came back AFTER the action — both are recorded, neither hidden.
    expect(result.output.reclaimed?.grossBytes).toBe(ctx.cacheBytesPlanted + ctx.tmpBytesPlanted);
    expect(result.output.reclaimed?.postActionStateBytes).toBe(512);
  });

  it('fails verification when a protected canary baseline does not match (benchmark tamper)', async () => {
    const ctx = await setupInScope('b039-tamper');
    const envelope = {
      ...ctx.productionInput,
      protectedAssets: [{ path: ctx.protectedPhotos, baselineSha256: 'a'.repeat(64) }],
      growthFixture: { kind: 'SYNTHETIC' as const, injectorRef: 'harness/injector-1' },
    };
    await expect(runStorageDiagnoseBenchmark(ctx.runtime, envelope)).rejects.toThrow(
      StorageVerticalError,
    );
    // The protected photos were never touched even though verification failed.
    expect(await fsp.readdir(ctx.protectedPhotos)).toHaveLength(2);
  });
});

d('B-040 — privacy / local-only canary', () => {
  it('emits no secret-shaped content in any artifact and declares no network scope', async () => {
    const ctx = await setupInScope('b040-canary');
    const result = await runStorageDiagnose(ctx.runtime, ctx.productionInput);

    const artifacts: string[] = [];
    artifacts.push(result.preview ?? '');
    artifacts.push(JSON.stringify(result.output));
    const evidenceFiles = await fsp.readdir(ctx.runtime.evidenceDir);
    for (const f of evidenceFiles) {
      artifacts.push(await fsp.readFile(path.join(ctx.runtime.evidenceDir, f), 'utf8'));
    }
    const everything = artifacts.join('\n');
    expect(everything).not.toContain(CANARY_PRIVATE_KEY);
    expect(everything).not.toContain(CANARY_USERNAME);
    expect(everything).not.toContain('shun-canary-user');
    // Even protected file NAMES are not collected — metadata policy is scope-wide only.
    expect(everything).not.toContain('img-0001.jpg');

    // No network anywhere in the plan: the local-only policy is structural.
    for (const action of result.proposal?.plan.actions ?? []) {
      expect(action.networkScope?.allowed).toBe(false);
      expect(action.filesystemScope?.write.every((w) => !w.includes('http'))).toBe(true);
    }
  });
});

// The schema-separation guarantee is platform-independent evidence and runs
// everywhere; the end-to-end envelope run is Windows evidence.
describe('benchmark truth stays out of the production runtime (L2 §4.2)', () => {
  it('rejects the growth fixture envelope on the production entry (strict schema)', () => {
    const envelope = {
      taskId: 'task-t07-leak',
      targetVolume: 'C:',
      protectedAssets: [{ path: 'C:\\keep', baselineSha256: 'a'.repeat(64) }],
      cleanupPolicy: { eligibleCategories: ['CACHE'] },
      growthFixture: { kind: 'SYNTHETIC', injectorRef: 'harness/injector-1' },
    };
    const production = StorageDiagnoseInputSchema.safeParse(envelope);
    expect(production.success).toBe(false); // growthFixture/baselineSha256 are not production fields
    const benchmark = StorageBenchmarkInputSchema.safeParse(envelope);
    expect(benchmark.success).toBe(true);
  });

  const itWin = process.platform === 'win32' ? it : it.skip;
  itWin(
    'reduces the benchmark envelope to a pure production input and succeeds end-to-end',
    async () => {
      const ctx = await setupInScope('bench-happy');
      const photosHash = await fingerprintPath(ctx.protectedPhotos);
      const envelope = {
        ...ctx.productionInput,
        protectedAssets: [{ path: ctx.protectedPhotos, baselineSha256: photosHash }],
        growthFixture: { kind: 'REPRODUCIBLE' as const, injectorRef: 'harness/injector-2' },
      };
      const outcome = await runStorageDiagnoseBenchmark(ctx.runtime, envelope);
      expect(outcome.productionInput).toEqual(ctx.productionInput);
      expect(outcome.output.cleanupPlan).not.toBeNull();
      expect(outcome.output.reclaimed?.grossBytes).toBe(ctx.cacheBytesPlanted);
      expect(outcome.output.protectedAssetVerification).toEqual([
        { path: ctx.protectedPhotos, unchanged: true },
      ]);
    },
  );
});
