import type { RegistrySnapshot } from '@shun/resolver';
import { describe, expect, it } from 'vitest';
import { assertSignedHostFactsCurrent } from '../src/real-storage/registry-host-facts.ts';

type Environment = RegistrySnapshot['environment'];
const LIVE: Environment = {
  environmentId: 'shun-real-storage-x64',
  backendKind: 'LOCAL_WINDOWS',
  os: 'WINDOWS-10.0.26300',
  arch: 'X64',
  observationRevision: 'host-2026-10-13T00:00:00.000Z',
  runtimeCapabilities: ['windows-storage-metadata'],
  privilegeMode: 'FILTERED_ADMIN',
  guiSession: true,
  filesystemCapabilities: ['read', 'write'],
  networkPolicy: 'OFFLINE',
  resources: { cpuCores: 8, memoryMb: 16384, freeDiskMb: 4096 },
};
const ISSUED: Environment = { ...LIVE, observationRevision: 'issuer:2026-10-13T00:00:00.000Z' };

describe('source-issued host facts recensus before R2 effects', () => {
  it('accepts a matching source environment and a bounded disk-pressure difference', () => {
    expect(() => assertSignedHostFactsCurrent(ISSUED, LIVE)).not.toThrow();
    expect(() =>
      assertSignedHostFactsCurrent(ISSUED, {
        ...LIVE,
        resources: { ...LIVE.resources, freeDiskMb: LIVE.resources.freeDiskMb - 128 },
      }),
    ).not.toThrow();
  });

  it('refuses changed Windows privilege, OS, network state, scope or runtime', () => {
    for (const modified of [
      { ...LIVE, privilegeMode: 'ELEVATED_ADMIN' as const },
      { ...LIVE, os: 'WINDOWS-OTHER' },
      { ...LIVE, networkPolicy: 'OPEN' as const },
      { ...LIVE, environmentId: 'unexpected-host' },
      { ...LIVE, runtimeCapabilities: [] },
      { ...LIVE, filesystemCapabilities: ['read'] as Environment['filesystemCapabilities'] },
      { ...LIVE, resources: { ...LIVE.resources, cpuCores: 16 } },
      { ...LIVE, resources: { ...LIVE.resources, memoryMb: 8192 } },
      { ...LIVE, resources: { ...LIVE.resources, freeDiskMb: 3967 } },
    ]) {
      expect(() => assertSignedHostFactsCurrent(ISSUED, modified)).toThrow(
        'REAL_STORAGE_REGISTRY_HOST_FACTS_DRIFT',
      );
    }
  });

  it('does not trust self-described observation revisions or malformed resource numbers', () => {
    for (const malformed of [
      { ...ISSUED, observationRevision: 'host-candidate-self-issued' },
      { ...ISSUED, resources: { ...ISSUED.resources, freeDiskMb: -1 } },
      { ...ISSUED, resources: { ...ISSUED.resources, freeDiskMb: 1.5 } },
    ]) {
      expect(() => assertSignedHostFactsCurrent(malformed, LIVE)).toThrow(
        'REAL_STORAGE_REGISTRY_HOST_FACTS_DRIFT',
      );
    }
  });
});
