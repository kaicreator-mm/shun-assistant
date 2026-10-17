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

  it('refuses caller-forged success receipts, modified signatures and cross-instance records', () => {
    const verifier = configured();
    const record = verifier.verify(makeArtifact());
    expect(record.ok).toBe(true);
    if (!record.ok) return;
    const forged = {
      ok: true as const,
      artifact: { ...record.artifact, artifactSha256: hash(Buffer.from('evil')) },
    };
    expect(verifier.verifyBytes(forged, Buffer.from('evil'))).toBe(false);
    expect(configured().verifyBytes(record, contents)).toBe(false);
    expect(Object.isFrozen(record)).toBe(true);
    expect(Object.isFrozen(record.artifact)).toBe(true);
    expect(Object.isFrozen(record.artifact.dependencySha256)).toBe(true);
  });

  it('refuses a model-supplied URL or changed manifest hash even with a valid key', () => {
    const verifier = configured();
    expect(
      verifier.verify(
        makeArtifact({
          origin: 'https://attacker.invalid/rg.exe',
        }),
      ),
    ).toMatchObject({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
    expect(
      verifier.verify(
        makeArtifact({
          catalogManifestSha256: 'c'.repeat(64),
        }),
      ),
    ).toMatchObject({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
    expect(
      verifier.verify(
        makeArtifact({
          bindingEvidenceSha256: 'd'.repeat(64),
        }),
      ),
    ).toMatchObject({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
  });

  it('rejects an attacker signature under a legitimate signer ID', () => {
    const result = configured().verify(makeArtifact({}, attackerPriv));
    expect(result).toMatchObject({ ok: false, code: 'CATALOG_SIGNATURE_INVALID' });
  });

  it('rejects a tampered signed field without a valid new signature', () => {
    const before = makeArtifact();
    // Tampering the dependency digest list now trips the name↔digest
    // bijection BEFORE the signature check — still refused, with the more
    // precise drift code.
    const changed = { ...before, dependencySha256: ['f'.repeat(64)] };
    expect(configured().verify(changed)).toMatchObject({
      ok: false,
      code: 'CATALOG_SCOPE_DRIFT',
    });
    // A tampered field that scope-pinning alone does not gate (the entrypoint
    // is not part of the scope comparison) still dies on the signature.
    const rehashed = { ...before, entrypoint: 'tampered.exe' };
    expect(configured().verify(rehashed)).toMatchObject({
      ok: false,
      code: 'CATALOG_SIGNATURE_INVALID',
    });
  });

  it('enforces the strict host-curated dependency name↔digest bijection', () => {
    const depSha = hash(Buffer.from('libvips fixture bytes', 'utf8'));
    const depScope = {
      ...scope,
      artifactKind: 'NATIVE_ADDON' as const,
      abiRevision: '137',
      dependencyEntries: [{ name: 'libvips-42.dll', artifactSha256: depSha }],
    };
    const makeVerifier = (trust: typeof depScope) =>
      new CuratedProviderVerifier(
        [
          {
            keyId: issuer,
            publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
          },
        ],
        [trust],
      );
    const makeNative = (trust: typeof depScope, data: Record<string, unknown> = {}) => {
      const signed = {
        ...trust,
        entrypoint: 'sharp-win32-x64.node',
        signerKeyId: issuer,
        dependencySha256: [depSha],
        ...data,
      };
      // Host-derived name pins are never part of the signed payload.
      const { dependencyEntries: _hostDerived, ...unsigned } = signed;
      return { ...unsigned, curatorSignature: signer(unsigned) };
    };
    // Valid closure: the verified artifact carries the resolved entries.
    const verified = makeVerifier(depScope).verify(makeNative(depScope));
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.artifact.dependencyEntries).toEqual([
        { name: 'libvips-42.dll', artifactSha256: depSha },
      ]);
      expect(Object.isFrozen(verified.artifact.dependencyEntries)).toBe(true);
    }
    // A digest without a pinned name cannot resolve.
    expect(
      makeVerifier(depScope).verify(makeNative(depScope, { dependencySha256: [depSha, 'f'.repeat(64)] })),
    ).toMatchObject({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
    // A pinned name without a matching digest cannot either.
    expect(
      makeVerifier(depScope).verify(makeNative(depScope, { dependencySha256: [] })),
    ).toMatchObject({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
    // Digest drift against the pinned name refuses.
    expect(
      makeVerifier(depScope).verify(makeNative(depScope, { dependencySha256: ['f'.repeat(64)] })),
    ).toMatchObject({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
    // Case-insensitive duplicate names refuse (loader name confusion).
    const dupScope = {
      ...depScope,
      dependencyEntries: [
        { name: 'libvips-42.dll', artifactSha256: depSha },
        { name: 'LIBVIPS-42.DLL', artifactSha256: 'f'.repeat(64) },
      ],
    };
    expect(
      makeVerifier(dupScope).verify(
        makeNative(dupScope, { dependencySha256: [depSha, 'f'.repeat(64)] }),
      ),
    ).toMatchObject({ ok: false, code: 'CATALOG_SCOPE_DRIFT' });
    // Path-shaped names refuse.
    const unsafeScope = {
      ...depScope,
      dependencyEntries: [{ name: 'sub/evil.dll', artifactSha256: depSha }],
    };
    expect(makeVerifier(unsafeScope).verify(makeNative(unsafeScope))).toMatchObject({
      ok: false,
      code: 'CATALOG_SCOPE_DRIFT',
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
    expect(
      new CuratedProviderVerifier(
        [
          {
            keyId: 'attacker',
            publicKeyPem: attackerPub.export({ type: 'spki', format: 'pem' }).toString(),
          },
        ],
        [scope],
      ).verify(makeArtifact()).ok,
    ).toBe(false);
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
