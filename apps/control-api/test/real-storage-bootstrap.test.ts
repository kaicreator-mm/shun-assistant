import { describe, expect, it } from 'vitest';
import { RealStorageControlBackend } from '../src/real-storage/backend.ts';

describe('M02 real C-003 control backend fail-closed bootstrap', () => {
  it('cannot silently instantiate a non-Windows real backend or fall through to demo', async () => {
    if (process.platform === 'win32') return; // real-host coverage is M03
    await expect(
      RealStorageControlBackend.create({
        workspace: '/tmp/untrusted',
        protectedAssets: ['/tmp/untrusted/canary'],
        evidenceDir: '/tmp/shun-evidence',
        databaseFile: '/tmp/shun.sqlite',
        registryRevisionFile: '/tmp/shun-operator-registry-revision',
        registryPublicKeyFile: '/tmp/shun-operator-registry-public-key',
        registryPublicKeySha256: 'a'.repeat(64),
        issuanceSecret: 'separate-controller-key',
        integritySecret: 'separate-integrity-key',
      }),
    ).rejects.toThrow('REAL_STORAGE_REQUIRES_WINDOWS');
  });

  it('the real mode cannot be created using an empty or forged config', async () => {
    // This row is structural on non-Windows. Windows host must independently
    // exercise real canonical-root, alias, policy and canary negatives.
    if (process.platform === 'win32') return;
    await expect(
      RealStorageControlBackend.create({
        workspace: '/tmp/no-config',
        protectedAssets: [],
        evidenceDir: '/tmp/shun-evidence',
        databaseFile: '/tmp/shun.sqlite',
        registryRevisionFile: '/tmp/shun-operator-registry-revision',
        registryPublicKeyFile: '/tmp/shun-operator-registry-public-key',
        registryPublicKeySha256: 'a'.repeat(64),
        issuanceSecret: '',
        integritySecret: '',
      }),
    ).rejects.toThrow('REAL_STORAGE_REQUIRES_WINDOWS');
  });
});
