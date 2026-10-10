// Attribution tests: growth explanation is evidence-backed and size ranks
// only WITHIN the policy-eligible set — the no-size-only-delete guarantee at
// the attribution layer.
import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  attributeGrowth,
  type ObservationEvidence,
  observeStorage,
  StorageVerticalError,
} from '../src/index.ts';
import { makeFixtureRoot, plantFiles } from './helpers.ts';

async function observe(root: string): Promise<ObservationEvidence> {
  return observeStorage({ roots: [root] }, () => '2026-10-10T10:00:00.000Z');
}

describe('attributeGrowth', () => {
  it('attributes the largest eligible directory with evidence refs', async () => {
    const root = await makeFixtureRoot('attr-largest');
    await plantFiles(path.join(root, 'cache'), [
      { relativePath: 'a.bin', bytes: 4096 },
      { relativePath: 'b.bin', bytes: 2048 },
    ]);
    await plantFiles(path.join(root, 'cache-small'), [{ relativePath: 'c.bin', bytes: 512 }]);
    const observation = await observe(root);
    const ref = 'evidence://t/observation.json';
    const attribution = attributeGrowth({
      observation,
      eligibleCategories: ['CACHE'],
      classificationPolicy: { protectedRealPaths: [], scopeRoots: [root] },
      observationEvidenceRef: ref,
    });
    expect(attribution.growthSourcePath).toBe(await real(path.join(root, 'cache')));
    expect(attribution.classifiedAs).toBe('CACHE');
    expect(attribution.evidenceRefs).toContain(ref);
    expect(attribution.measuredBytes).toBe(6144);
  });

  it('never attributes a larger USER_CREATED_UNKNOWN directory (no size-only attribution)', async () => {
    const root = await makeFixtureRoot('attr-decoy');
    // Decoy is LARGER but not policy-eligible.
    await plantFiles(path.join(root, 'collect'), [{ relativePath: 'big.bin', bytes: 8192 }]);
    await plantFiles(path.join(root, 'cache'), [{ relativePath: 'a.bin', bytes: 1024 }]);
    const observation = await observe(root);
    const attribution = attributeGrowth({
      observation,
      eligibleCategories: ['CACHE'],
      classificationPolicy: { protectedRealPaths: [], scopeRoots: [root] },
      observationEvidenceRef: 'evidence://t/observation.json',
    });
    expect(attribution.growthSourcePath).toBe(await real(path.join(root, 'cache')));
    expect(attribution.explanation).toMatch(/NOT policy-eligible/);
  });

  it('skips directories whose entries could not be fully measured', async () => {
    const root = await makeFixtureRoot('attr-inaccessible');
    await plantFiles(path.join(root, 'cache'), [{ relativePath: 'a.bin', bytes: 1024 }]);
    const observation = await observe(root);
    const cachePath = await real(path.join(root, 'cache'));
    const tampered: ObservationEvidence = {
      ...observation,
      directories: observation.directories.map((d) =>
        d.path === cachePath ? { ...d, inaccessibleEntries: [path.join(cachePath, 'locked')] } : d,
      ),
    };
    expect(() =>
      attributeGrowth({
        observation: tampered,
        eligibleCategories: ['CACHE'],
        classificationPolicy: { protectedRealPaths: [], scopeRoots: [root] },
        observationEvidenceRef: 'evidence://t',
      }),
    ).toThrow(StorageVerticalError);
  });

  it('throws GROWTH_NOT_ATTRIBUTED when nothing eligible exists', async () => {
    const root = await makeFixtureRoot('attr-none');
    await plantFiles(path.join(root, 'docs'), [{ relativePath: 'a.txt', bytes: 1024 }]);
    const observation = await observe(root);
    try {
      attributeGrowth({
        observation,
        eligibleCategories: ['CACHE'],
        classificationPolicy: { protectedRealPaths: [], scopeRoots: [root] },
        observationEvidenceRef: 'evidence://t',
      });
      expect.unreachable('expected GROWTH_NOT_ATTRIBUTED');
    } catch (error) {
      expect(error).toBeInstanceOf(StorageVerticalError);
      expect((error as StorageVerticalError).code).toBe('GROWTH_NOT_ATTRIBUTED');
    }
  });

  it('reports the frozen residue taxonomy label with the cleanup category documented', async () => {
    const root = await makeFixtureRoot('attr-temp');
    await plantFiles(path.join(root, 'tmp'), [{ relativePath: 'a.bin', bytes: 256 }]);
    const observation = await observe(root);
    const attribution = attributeGrowth({
      observation,
      eligibleCategories: ['TEMP'],
      classificationPolicy: { protectedRealPaths: [], scopeRoots: [root] },
      observationEvidenceRef: 'evidence://t',
    });
    // TEMP is not a residue classification (C-002 space); the documented
    // mapping reports residue CACHE while the explanation names the category.
    expect(attribution.classifiedAs).toBe('CACHE');
    expect(attribution.explanation).toMatch(/cleanup category TEMP/);
  });
});

async function real(p: string): Promise<string> {
  return fsp.realpath(p);
}
