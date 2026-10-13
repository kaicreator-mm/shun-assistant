// External trust anchor for a short-lived Registry issuer. A signed snapshot
// proves no authority when an attacker can replace BOTH the signature
// envelope and the public-key file. The expected fingerprint must originate
// in trusted operator configuration, never from the envelope or candidate.
import { createHash, createPublicKey, timingSafeEqual } from 'node:crypto';

export function verifyPinnedRegistryPublicKey(pem: string, operatorPinnedSpkiSha256: string): void {
  if (!/^[0-9a-f]{64}$/.test(operatorPinnedSpkiSha256)) {
    throw new Error('REAL_STORAGE_REGISTRY_PUBLIC_KEY_PIN_REQUIRED');
  }
  let actual: Buffer;
  try {
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== 'ed25519') {
      throw new Error('Not an Ed25519 verification key');
    }
    actual = createHash('sha256')
      .update(key.export({ type: 'spki', format: 'der' }))
      .digest();
  } catch {
    throw new Error('REAL_STORAGE_REGISTRY_PUBLIC_KEY_INVALID');
  }
  if (!timingSafeEqual(actual, Buffer.from(operatorPinnedSpkiSha256, 'hex'))) {
    throw new Error('REAL_STORAGE_REGISTRY_PUBLIC_KEY_PIN_MISMATCH');
  }
}
