import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJson } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { CuratedProviderVerifier } from '../src/curated-provider.ts';

const contents = Buffer.from('pinned trusted rg fixture bytes', 'utf8');
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const { publicKey: attackerPub, privateKey: attackerPriv } = generateKeyPairSync('ed25519');
const issuer = 'trusted-curator-2026';
const scope = {
  providerId: 'rg',
  capabilityId: 'file.search',
  version: '14.1',
  catalogRevision: 'catalog-v1',
  bindingId: 'rg-search-binding',
  scopedVerifierId: 'shun-v02-curator',
  catalogManifestSha256: 'a'.repeat(64),
  bindingEvidenceSha256: 'b'.repeat(64),
  artifactSha256: hash(contents),
  origin: 'https://trusted.invalid/rg.exe',
  platform: 'windows-x64' as const,
  artifactKind: 'CLI' as const,
};

function signer(signed: Record<string, unknown>, key = privateKey) {
  return sign(null, Buffer.from(canonicalJson(signed)), key).toString('base64');
}

function makeArtifact(data: Record<string, unknown> = {}, key = privateKey) {
  const signed = {
    ...scope,
    entrypoint: 'rg.exe',
    abiRevision: undefined,
    signerKeyId: issuer,
    dependencySha256: [],
    ...data,
  };
  // Zod removes optional undefined fields on parse: absent for signature too.
  const { abiRevision: _unused, ...unsigned } = signed;
  return { ...unsigned, curatorSignature: signer(unsigned, key) };
}

function configured() {
  return new CuratedProviderVerifier(
    [{ keyId: issuer, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString() }],
    [scope],
  );
}

describe('T05 curated Provider trust-bound admission', () => {
  it('requires exact manifest signature, trusted binding and matching artifact bytes', () => {
    const verifier = configured();
    const verified = verifier.verify(makeArtifact());
    expect(verified.ok).toBe(true);
    expect(verifier.verifyBytes(verified, contents)).toBe(true);
    expect(verifier.verifyBytes(verified, Buffer.from('other bytes'))).toBe(false);
    expect(verifier.verifyBytes(verified, Buffer.alloc(64 * 1024 * 1024 + 1))).toBe(false);
  });

  it('refuses a model-supplied URL or changed manifest hash even with a valid key', () => {
    const verifier = configured();
    expect(verifier.verify(makeArtifact({
      origin: 'https://attacker.invalid/rg.exe',
    }))).toMatchObject({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
    expect(verifier.verify(makeArtifact({
      catalogManifestSha256: 'c'.repeat(64),
    }))).toMatchObject({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
    expect(verifier.verify(makeArtifact({
      bindingEvidenceSha256: 'd'.repeat(64),
    }))).toMatchObject({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
  });

  it('rejects an attacker signature under a legitimate signer ID', () => {
    const result = configured().verify(makeArtifact({}, attackerPriv));
    expect(result).toMatchObject({ ok: false, code: 'CATALOG_SIGNATURE_INVALID' });
  });

  it('rejects a tampered signed field without a valid new signature', () => {
    const before = makeArtifact();
    const changed = { ...before, dependencySha256: ['f'.repeat(64)] };
    expect(configured().verify(changed)).toMatchObject({
      ok: false, code: 'CATALOG_SIGNATURE_INVALID',
    });
  });

  it('rejects unsupported platform, untrusted signer, HTTPS downgrade and userinfo', () => {
    const verifier = configured();
    for (const input of [
      { platform: 'linux-x64' },
      { signerKeyId: 'unknown-curator' },
      { origin: 'http://trusted.invalid/rg.exe' },
      { origin: 'https://user:secret@trusted.invalid/rg.exe' },
    ]) {
      expect(verifier.verify(makeArtifact(input)).ok).toBe(false);
    }
    expect(new CuratedProviderVerifier(
      [{ keyId: 'attacker', publicKeyPem: attackerPub.export({ type: 'spki', format: 'pem' }).toString() }],
      [scope],
    ).verify(makeArtifact()).ok).toBe(false);
  });

  it('throws only stable configuration errors for duplicate roots/bindings', () => {
    const root = {
      keyId: issuer,
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    };
    expect(() => new CuratedProviderVerifier([root, root], [scope])).toThrow(
      'INVALID_TRUST_CONFIGURATION',
    );
    expect(() => new CuratedProviderVerifier([root], [scope, scope])).toThrow(
      'INVALID_TRUST_CONFIGURATION',
    );
  });
});
