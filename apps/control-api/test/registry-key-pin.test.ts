import { createHash, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyPinnedRegistryPublicKey } from '../src/real-storage/registry-key-pin.ts';

const issuer = generateKeyPairSync('ed25519');
const pinnedPem = issuer.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const pinnedDigest = createHash('sha256')
  .update(issuer.publicKey.export({ type: 'spki', format: 'der' }))
  .digest('hex');

describe('separately operator-pinned Ed25519 Registry issuer', () => {
  it('accepts the original authority key with a correctly pinned SPKI DER SHA-256', () => {
    expect(() => verifyPinnedRegistryPublicKey(pinnedPem, pinnedDigest)).not.toThrow();
  });

  it('rejects a swapped issuer key, even if it could sign a new self-consistent Registry envelope', () => {
    const attacker = generateKeyPairSync('ed25519');
    const attackerPem = attacker.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    expect(() => verifyPinnedRegistryPublicKey(attackerPem, pinnedDigest)).toThrow(
      'REAL_STORAGE_REGISTRY_PUBLIC_KEY_PIN_MISMATCH',
    );
  });

  it('never accepts unconfigured, malformed or wrong-case operator fingerprints', () => {
    for (const bad of ['', 'a', 'z'.repeat(64), pinnedDigest.toUpperCase()]) {
      expect(() => verifyPinnedRegistryPublicKey(pinnedPem, bad)).toThrow(
        'REAL_STORAGE_REGISTRY_PUBLIC_KEY_PIN_REQUIRED',
      );
    }
  });

  it('rejects RSA keys and unparseable trust material', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaPem = rsa.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    expect(() => verifyPinnedRegistryPublicKey(rsaPem, pinnedDigest)).toThrow(
      'REAL_STORAGE_REGISTRY_PUBLIC_KEY_INVALID',
    );
    expect(() => verifyPinnedRegistryPublicKey('not a PEM key', pinnedDigest)).toThrow(
      'REAL_STORAGE_REGISTRY_PUBLIC_KEY_INVALID',
    );
  });
});
