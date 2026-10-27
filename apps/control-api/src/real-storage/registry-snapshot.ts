// The production C-003 trusted catalog is fixed by source, not provided by
// a browser Goal. The independent Windows issuer signs these exact facts.
import type { RegistrySnapshot } from '@shun/resolver';

const CAPABILITY = 'system.storage.diagnose_bounded_action';
const BINDING = 'binding/shun-storage-local-windows';

export function createStorageRegistrySnapshot(
  environment: RegistrySnapshot['environment'],
): RegistrySnapshot {
  const arch = environment.arch;
  if (arch !== 'X64' && arch !== 'ARM64') {
    throw new Error('REAL_STORAGE_REGISTRY_UNSUPPORTED_ARCH');
  }
  const capability: RegistrySnapshot['capabilities'][number] = {
    capabilityId: CAPABILITY,
    revision: 'r1',
    inputSchema: { type: 'object' },
    outputSchema: { type: 'object' },
    sideEffectClass: 'R0',
    allowedInterfaceClasses: ['I0'],
    verificationContract: {
      verifierId: 'verifier.storage-c003',
      verifierRevision: 'r1',
      checks: [
        { checkId: 'protected-assets-unchanged', required: true },
        { checkId: 'reclaimed-bytes-verified', required: true },
      ],
    },
    requiredPolicyFacts: [],
  };
  const provider: RegistrySnapshot['providers'][number] = {
    providerId: 'storage.cleaner.local-windows',
    revision: '0.1.0',
    acquisition: {
      mechanism: 'PREINSTALLED',
      source: '@shun/vertical-storage',
      official: true,
      version: '0.1.0',
    },
    provenanceFacts: { trustState: 'TRUSTED' },
    licenseFacts: { license: 'INTERNAL' },
    supportedPlatforms: [{ os: 'WINDOWS', arch }],
    lifecycle: { supportedOperations: ['CONFIGURE'] },
    interfaces: [
      {
        interfaceId: 'storage-local-i0',
        interfaceClass: 'I0',
        invocation: '@shun/vertical-storage runStorageDiagnose',
      },
    ],
  };
  const binding: RegistrySnapshot['bindings'][number] = {
    bindingId: BINDING,
    providerId: provider.providerId,
    capabilityId: CAPABILITY,
    capabilityRevisionRange: { min: 'r1', max: 'r1' },
    adapterId: 'adapter.storage.local-windows',
    interfaceClass: 'I0',
    environmentRequirements: {
      backendKind: 'LOCAL_WINDOWS',
      os: 'WINDOWS',
      networkAccess: 'FORBIDDEN',
    },
    verifierId: 'verifier.storage-c003',
  };
  return {
    capabilities: [capability],
    providers: [provider],
    bindings: [binding],
    environment,
  };
}

// T08 C07R: a second *fixed* operator-issued catalog shape. The issuer must
// deliberately sign its exact bytes; Shun never upgrades an existing signed
// storage-only snapshot or computes its own authority revision.
export function createInventoryRegistrySnapshot(
  environment: RegistrySnapshot['environment'],
): RegistrySnapshot {
  const storage = createStorageRegistrySnapshot(environment);
  const arch = environment.arch;
  const capability: RegistrySnapshot['capabilities'][number] = {
    capabilityId: 'system.inventory',
    revision: 'r1',
    inputSchema: { type: 'object' },
    outputSchema: { type: 'object' },
    sideEffectClass: 'R0',
    allowedInterfaceClasses: ['I0'],
    verificationContract: {
      verifierId: 'verifier.system-inventory.local-readonly',
      verifierRevision: '1',
      checks: [{ checkId: 'real-windows-local-snapshot-schema', required: true }],
    },
    requiredPolicyFacts: [],
  };
  const provider: RegistrySnapshot['providers'][number] = {
    providerId: 'system.inventory.local-windows',
    revision: '0.2.0',
    acquisition: {
      mechanism: 'PREINSTALLED',
      source: '@shun/vertical-system',
      official: true,
      version: '0.2.0',
    },
    provenanceFacts: { trustState: 'TRUSTED' },
    licenseFacts: { license: 'INTERNAL' },
    supportedPlatforms: [{ os: 'WINDOWS', arch }],
    lifecycle: { supportedOperations: ['CONFIGURE'] },
    interfaces: [
      {
        interfaceId: 'system-inventory-readonly-i0',
        interfaceClass: 'I0',
        invocation: '@shun/vertical-system collectWindowsSystemInventory',
      },
    ],
  };
  const binding: RegistrySnapshot['bindings'][number] = {
    bindingId: 'binding/shun-local-system-inventory',
    providerId: provider.providerId,
    capabilityId: capability.capabilityId,
    capabilityRevisionRange: { min: 'r1', max: 'r1' },
    adapterId: 'adapter.system-inventory.local-windows',
    interfaceClass: 'I0',
    environmentRequirements: {
      backendKind: 'LOCAL_WINDOWS',
      os: 'WINDOWS',
      networkAccess: 'FORBIDDEN',
    },
    verifierId: 'verifier.system-inventory.local-readonly',
  };
  return {
    capabilities: [...storage.capabilities, capability],
    providers: [...storage.providers, provider],
    bindings: [...storage.bindings, binding],
    environment,
  };
}
