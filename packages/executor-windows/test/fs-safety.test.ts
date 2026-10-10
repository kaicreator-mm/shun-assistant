// Filesystem safety tests on a REAL Windows filesystem: reparse-point
// rejection, native realpath containment, scope segment boundaries.
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { resolveWithinScope } from '../src/fs-safety.ts';
import { createJunction } from './helpers.ts';

describe('resolveWithinScope (real fs)', () => {
  const root = mkdtempSync(join(tmpdir(), 'shun-fsafety-'));
  const scope = join(root, 'scope');
  const outside = join(root, 'outside');

  beforeAll(() => {
    mkdirSync(join(scope, 'sub'), { recursive: true });
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(scope, 'real.txt'), 'hello', 'utf8');
    writeFileSync(join(outside, 'secret.txt'), 'top', 'utf8');
  });

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('resolves and accepts a path inside the scope prefix', () => {
    const r = resolveWithinScope(join(scope, 'real.txt'), [scope]);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.resolved.toLowerCase()).toBe(join(scope, 'real.txt').toLowerCase());
  });

  it('refuses a lexically-legal path resolving OUTSIDE the scope (realpath check)', () => {
    // pathWithin refuses `..` lexically, so plant the escape via junction:
    const link = join(scope, 'hole');
    createJunction(link, outside);
    const r = resolveWithinScope(join(link, 'secret.txt'), [scope]);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('reparse point');
  });

  it('accepts a not-yet-existing file whose existing ancestors are in scope', () => {
    const r = resolveWithinScope(join(scope, 'sub', 'new-file.txt'), [scope]);
    expect(r.ok).toBe(true);
    expect(existsSync(join(scope, 'sub', 'new-file.txt'))).toBe(false);
  });

  it('refuses when no scope prefixes are declared (fail closed)', () => {
    expect(resolveWithinScope(join(scope, 'real.txt'), []).ok).toBe(false);
  });

  it('enforces whole-segment prefixes (C:\\a does not contain C:\\ab)', () => {
    const prefix = join(scope, 'sub');
    writeFileSync(join(scope, 'sub-evil.txt'), 'x', 'utf8');
    expect(resolveWithinScope(join(scope, 'sub-evil.txt'), [prefix]).ok).toBe(false);
  });
});
