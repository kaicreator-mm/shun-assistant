// Bind source-issued environment facts to the actual host at every R2 gate.
// A signed snapshot is not permission to use stale Windows privilege or disk
// facts after the human preview. Any material host drift is fail-closed.
import { canonicalJson } from '@shun/contracts';
import type { RegistrySnapshot } from '@shun/resolver';

type Environment = RegistrySnapshot['environment'];

export function assertSignedHostFactsCurrent(issued: Environment, observed: Environment): void {
  if (
    issued.environmentId !== observed.environmentId ||
    issued.backendKind !== observed.backendKind ||
    issued.os !== observed.os ||
    issued.arch !== observed.arch ||
    issued.privilegeMode !== observed.privilegeMode ||
    issued.guiSession !== observed.guiSession ||
    issued.networkPolicy !== observed.networkPolicy ||
    canonicalJson(issued.runtimeCapabilities) !== canonicalJson(observed.runtimeCapabilities) ||
    canonicalJson(issued.filesystemCapabilities) !==
      canonicalJson(observed.filesystemCapabilities) ||
    !issued.observationRevision.startsWith('issuer:') ||
    !Number.isSafeInteger(issued.resources.freeDiskMb) ||
    issued.resources.freeDiskMb < 0 ||
    issued.resources.cpuCores !== observed.resources.cpuCores ||
    issued.resources.memoryMb !== observed.resources.memoryMb ||
    !Number.isSafeInteger(observed.resources.freeDiskMb) ||
    observed.resources.freeDiskMb < 0 ||
    Math.abs(issued.resources.freeDiskMb - observed.resources.freeDiskMb) > 128
  ) {
    throw new Error('REAL_STORAGE_REGISTRY_HOST_FACTS_DRIFT');
  }
}
