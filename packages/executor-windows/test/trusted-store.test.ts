// Trusted substrate tests: currentness fail-closed reading, HMAC grant
// integrity (forgery refused, substrate failure fails closed), helper pin
// read/write, and the trusted plan/grant sources.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AuthorizationGrant } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import {
  FileCurrentnessSource,
  FileGrantSource,
  FilePlanSource,
  generateGrantHmacKey,
  hmacGrantIntegrityVerifier,
  readHelperPin,
  sha256Text,
  signGrantWithHmac,
  writeCurrentAuthority,
  writeGrantHmacKey,
  writeHelperPin,
} from '../src/trusted-store.ts';
import { currentAuthority } from './helpers.ts';

function tmpDir(): string {
  return mkdtempSync(join(tmpdir(), 'shun-store-'));
}

function grantFixture(): AuthorizationGrant {
  return {
    grantId: 'g1',
    issuer: { authorityId: 'a', authorityRevision: 'r' },
    taskId: 't',
    planHash: 'a'.repeat(64),
    policySnapshotRevision: 'p',
    actionScope: { actionIds: ['x'], privilegeLevel: 'USER' },
    issuedAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2027-01-01T00:00:00.000Z',
    integrity: { scheme: 'HMAC_SHA256', value: 'x' },
  };
}

describe('FileCurrentnessSource', () => {
  it('reads a CURRENT record', () => {
    const dir = tmpDir();
    writeCurrentAuthority(dir, currentAuthority());
    expect(new FileCurrentnessSource(join(dir, 'current-authority.json')).read()).toEqual(
      currentAuthority(),
    );
  });

  it('missing record → UNRESOLVABLE (never authentic-therefore-current)', () => {
    expect(new FileCurrentnessSource(join(tmpDir(), 'current-authority.json')).read().kind).toBe(
      'UNRESOLVABLE',
    );
  });

  it('corrupt record → UNRESOLVABLE', () => {
    const dir = tmpDir();
    writeCurrentAuthority(dir, currentAuthority());
    writeFileSync(join(dir, 'current-authority.json'), '{not json', 'utf8');
    expect(new FileCurrentnessSource(join(dir, 'current-authority.json')).read().kind).toBe(
      'UNRESOLVABLE',
    );
  });

  it('schema-invalid record (unknown status) → UNRESOLVABLE', () => {
    const dir = tmpDir();
    writeFileSync(
      join(dir, 'current-authority.json'),
      JSON.stringify({ ...currentAuthority(), policyStatus: 'WHATEVER' }),
      'utf8',
    );
    expect(new FileCurrentnessSource(join(dir, 'current-authority.json')).read().kind).toBe(
      'UNRESOLVABLE',
    );
  });
});

describe('HMAC grant integrity', () => {
  it('a signed grant verifies', () => {
    const dir = tmpDir();
    const key = generateGrantHmacKey();
    writeGrantHmacKey(dir, key);
    const grant = grantFixture();
    const envelope = signGrantWithHmac(key, grant);
    expect(hmacGrantIntegrityVerifier(dir)(grant, envelope)).toBe(true);
  });

  it('tampered grant content voids the envelope', () => {
    const dir = tmpDir();
    const key = generateGrantHmacKey();
    writeGrantHmacKey(dir, key);
    const grant = grantFixture();
    const envelope = signGrantWithHmac(key, grant);
    expect(hmacGrantIntegrityVerifier(dir)({ ...grant, taskId: 'evil-task' }, envelope)).toBe(
      false,
    );
  });

  it('envelope from a different (attacker) key fails', () => {
    const dir = tmpDir();
    writeGrantHmacKey(dir, generateGrantHmacKey());
    const grant = grantFixture();
    const forged = signGrantWithHmac(generateGrantHmacKey(), grant);
    expect(hmacGrantIntegrityVerifier(dir)(grant, forged)).toBe(false);
  });

  it('substrate failure (missing key file) fails closed to false', () => {
    const grant = grantFixture();
    const envelope = signGrantWithHmac(generateGrantHmacKey(), grant);
    expect(hmacGrantIntegrityVerifier(tmpDir())(grant, envelope)).toBe(false);
  });

  it('corrupt key file fails closed to false', () => {
    const dir = tmpDir();
    writeFileSync(join(dir, 'grant-hmac.key'), '!!!not-base64-32-bytes!!!', 'utf8');
    const grant = grantFixture();
    const envelope = signGrantWithHmac(generateGrantHmacKey(), grant);
    expect(hmacGrantIntegrityVerifier(dir)(grant, envelope)).toBe(false);
  });

  it('non-HMAC schemes are refused by the verifier', () => {
    const dir = tmpDir();
    writeGrantHmacKey(dir, generateGrantHmacKey());
    const grant = grantFixture();
    expect(
      hmacGrantIntegrityVerifier(dir)(grant, { scheme: 'TRUSTED_LOCAL_CHANNEL', value: 'x' }),
    ).toBe(false);
  });
});

describe('helper pin', () => {
  it('missing pin reads as undefined — never a default pin', () => {
    expect(readHelperPin(tmpDir())).toBeUndefined();
  });

  it('corrupt pin reads as undefined (fail closed)', () => {
    const dir = tmpDir();
    writeFileSync(join(dir, 'helper-pin.json'), '{"helperSha256": "nope"}', 'utf8');
    expect(readHelperPin(dir)).toBeUndefined();
  });

  it('pin roundtrips and carries the workspace root anchor', () => {
    const dir = tmpDir();
    const pin = {
      schemaVersion: 'shun.executor-windows.helper-pin/1' as const,
      helperRevision: 'rev-1',
      helperSha256: 'a'.repeat(64),
      relaySha256: 'b'.repeat(64),
      workspaceRoot: 'C:\\shun\\workspace',
      pinnedAt: '2026-01-01T00:00:00.000Z',
    };
    writeHelperPin(dir, pin);
    expect(readHelperPin(dir)).toEqual(pin);
  });
});

describe('trusted plan/grant sources', () => {
  it('plan source refuses missing/corrupt records', () => {
    const dir = join(tmpDir(), 'plans');
    mkdirSync(dir, { recursive: true });
    const src = new FilePlanSource(dir);
    expect(src.byPlanHash('f'.repeat(64))).toBeUndefined();
    writeFileSync(join(dir, `${'e'.repeat(64)}.json`), '{bad', 'utf8');
    expect(src.byPlanHash('e'.repeat(64))).toBeUndefined();
  });

  it('grant source refuses path-shaped grantIds (no traversal via authorizationRef)', () => {
    const src = new FileGrantSource(join(tmpDir(), 'grants'));
    expect(src.byGrantId('..\\evil')).toBeUndefined();
    expect(src.byGrantId('sub/dir')).toBeUndefined();
    expect(src.byGrantId('')).toBeUndefined();
  });
});

describe('sha256Text', () => {
  it('is a plain sha256 hex digest', () => {
    expect(sha256Text('abc')).toMatch(/^[0-9a-f]{64}$/);
    expect(sha256Text('abc')).toBe(sha256Text('abc'));
  });
});
