// Scope hardening tests: bounded-ness begins at the scope boundary, so every
// escape shape (relative, .., reparse points, off-volume, overlap) must fail
// closed here, before any observation or plan exists.
import { promises as fsp, symlinkSync as fspSymlink } from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';

/* Required platform evidence is the local Windows build host; other hosts run the static checks only. */
const d = process.platform === 'win32' ? describe : describe.skip;

import { pathOnVolume, resolveScope, withinScope } from '../src/index.ts';
import { makeFixtureRoot, volumeOf } from './helpers.ts';

d('resolveScope', () => {
  it('resolves absolute existing roots to canonical realpaths', async () => {
    const root = await makeFixtureRoot('scope-ok');
    const resolved = await resolveScope(volumeOf(root), { roots: [root] });
    expect(resolved.roots).toHaveLength(1);
    expect(path.isAbsolute(resolved.roots[0] as string)).toBe(true);
  });

  it('rejects relative roots', async () => {
    await expect(resolveScope('C:', { roots: ['relative/dir'] })).rejects.toThrow(/not absolute/);
  });

  it('rejects traversal segments (raw, unnormalized)', async () => {
    const root = await makeFixtureRoot('scope-dotdot');
    // path.join would normalize '..' away; build the raw string instead.
    const escapePath = `${root}${path.sep}..${path.sep}escape`;
    await expect(resolveScope(volumeOf(root), { roots: [escapePath] })).rejects.toThrow(/\.\./);
  });

  it('rejects nonexistent roots', async () => {
    const root = await makeFixtureRoot('scope-missing');
    await expect(
      resolveScope(volumeOf(root), { roots: [path.join(root, 'does-not-exist')] }),
    ).rejects.toThrow(/does not exist/);
  });

  it('rejects a reparse-point root (junction must not widen the scope)', async () => {
    const root = await makeFixtureRoot('scope-junction');
    const target = path.join(root, 'real-target');
    await fsp.mkdir(target, { recursive: true });
    const link = path.join(root, 'link');
    fspSymlink(target, link, 'junction');
    await expect(resolveScope(volumeOf(root), { roots: [link] })).rejects.toThrow(/reparse point/);
  });

  it('rejects roots off the target volume', async () => {
    const root = await makeFixtureRoot('scope-volume');
    expect(pathOnVolume(root, 'Q:')).toBe(false);
    expect(pathOnVolume(root, volumeOf(root))).toBe(true);
    await expect(resolveScope('Q:', { roots: [root] })).rejects.toThrow(/not on target volume/);
  });

  it('rejects overlapping roots', async () => {
    const root = await makeFixtureRoot('scope-overlap');
    const inner = path.join(root, 'inner');
    await fsp.mkdir(inner, { recursive: true });
    await expect(resolveScope(volumeOf(root), { roots: [root, inner] })).rejects.toThrow(/overlap/);
  });
});

d('withinScope', () => {
  it('is case-insensitive and segment-boundary aware (Windows)', async () => {
    const root = await makeFixtureRoot('scope-case');
    const child = path.join(root, 'Cache', 'data');
    expect(withinScope(child, { roots: [root.toUpperCase()] })).toBe(true);
    // Segment-boundary: a sibling sharing a prefix is NOT inside.
    expect(withinScope(`${root}-sibling`, { roots: [root] })).toBe(false);
  });
});
