// Classification policy tests: the fail-closed matrix. Only path-policy
// markers make a directory disposable; protected assets win over markers;
// anything else — including similarly sized user data — is never eligible.
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import { classifyDirectory, classifyLooseRootFile, touchesProtectedAsset } from '../src/index.ts';
import { makeFixtureRoot } from './helpers.ts';

const NO_PROTECTED: string[] = [];

describe('classifyDirectory', () => {
  it('classifies cache and temp markers relative to the scope root', async () => {
    const root = await makeFixtureRoot('cls-basic');
    expect(
      classifyDirectory(path.join(root, 'cache'), {
        protectedRealPaths: NO_PROTECTED,
        scopeRoots: [root],
      }).cleanupCategory,
    ).toBe('CACHE');
    expect(
      classifyDirectory(path.join(root, 'tmp'), {
        protectedRealPaths: NO_PROTECTED,
        scopeRoots: [root],
      }).cleanupCategory,
    ).toBe('TEMP');
    expect(
      classifyDirectory(path.join(root, 'keep', 'gpucache'), {
        protectedRealPaths: NO_PROTECTED,
        scopeRoots: [root],
      }).cleanupCategory,
    ).toBe('CACHE');
  });

  it('never matches ancestor segments above the scope root (scope is a boundary, not a class)', async () => {
    const root = await makeFixtureRoot('cls-ancestor');
    // The root itself may live under .../Temp; children without their own marker are NOT temp.
    const child = path.join(root, 'user-data');
    const result = classifyDirectory(child, {
      protectedRealPaths: NO_PROTECTED,
      scopeRoots: [root],
    });
    expect(result.cleanupCategory).toBeNull();
    expect(result.residue).toBe('USER_CREATED_UNKNOWN');
  });

  it('is fail-closed for unmarked directories', async () => {
    const root = await makeFixtureRoot('cls-unknown');
    const result = classifyDirectory(path.join(root, 'documents'), {
      protectedRealPaths: NO_PROTECTED,
      scopeRoots: [root],
    });
    expect(result.cleanupCategory).toBeNull();
    expect(result.residue).toBe('USER_CREATED_UNKNOWN');
    expect(result.matchedMarker).toBeNull();
  });

  it('protected beats disposable markers (a protected folder named cache stays protected)', async () => {
    const root = await makeFixtureRoot('cls-protected');
    const protectedDir = path.join(root, 'cache');
    const result = classifyDirectory(protectedDir, {
      protectedRealPaths: [protectedDir],
      scopeRoots: [root],
    });
    expect(result.cleanupCategory).toBeNull();
    expect(result.residue).toBe('PROTECTED');
  });

  it('outside every scope root is not classifiable', async () => {
    const root = await makeFixtureRoot('cls-outside');
    const result = classifyDirectory(path.join(root, '..', 'elsewhere', 'cache'), {
      protectedRealPaths: NO_PROTECTED,
      scopeRoots: [root],
    });
    // Lexically this resolves outside the root; fail closed regardless.
    expect(result.cleanupCategory).toBeNull();
  });
});

describe('touchesProtectedAsset', () => {
  it('detects protected assets inside a candidate target and vice versa', async () => {
    const root = await makeFixtureRoot('cls-touch');
    const cacheDir = path.join(root, 'cache');
    const protectedInside = path.join(cacheDir, 'precious');
    expect(touchesProtectedAsset(cacheDir, [protectedInside])).toBe(true);
    expect(touchesProtectedAsset(protectedInside, [cacheDir])).toBe(true);
    const unrelated = path.join(root, 'other');
    expect(touchesProtectedAsset(unrelated, [protectedInside])).toBe(false);
  });
});

describe('classifyLooseRootFile', () => {
  it('is fail-closed USER_CREATED_UNKNOWN (no size-only delete of scattered files)', async () => {
    const result = classifyLooseRootFile('C:\\some\\root\\big-file.bin');
    expect(result.cleanupCategory).toBeNull();
    expect(result.residue).toBe('USER_CREATED_UNKNOWN');
  });
});
