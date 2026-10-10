// Shared scenario builders for resolver tests. Data shapes mirror the frozen
// contracts fixtures; every builder returns schema-valid contract data.
import type {
  CapabilityDefinition,
  EnvironmentFacts,
  EnvironmentRequirements,
  GoalRequest,
  ProviderCapabilityBinding,
  ProviderDefinition,
} from '@shun/contracts';

export const ENV_LOCAL: EnvironmentFacts = {
  environmentId: 'env-local-windows-01',
  backendKind: 'LOCAL_WINDOWS',
  os: 'WINDOWS',
  arch: 'X64',
  observationRevision: 'obs-0042',
  runtimeCapabilities: ['node-24', 'powershell-7'],
  privilegeMode: 'FILTERED_ADMIN',
  guiSession: true,
  filesystemCapabilities: ['user-profile-read', 'user-profile-write', 'temp-write'],
  networkPolicy: 'POLICY_CONTROLLED',
  resources: { cpuCores: 16, memoryMb: 32768, freeDiskMb: 204800 },
};

export function envFacts(overrides: Partial<EnvironmentFacts>): EnvironmentFacts {
  return { ...ENV_LOCAL, ...overrides };
}

export function providerDef(
  overrides: Partial<ProviderDefinition> & { providerId: string },
): ProviderDefinition {
  return {
    revision: 'r1',
    acquisition: {
      mechanism: 'PREINSTALLED',
      source: 'local install maintained by owner',
      official: true,
      version: '1.0.0',
    },
    provenanceFacts: { trustState: 'TRUSTED', publisher: 'scenario publisher' },
    licenseFacts: { license: 'MIT' },
    supportedPlatforms: [{ os: 'WINDOWS', arch: 'X64' }],
    lifecycle: { supportedOperations: ['CONFIGURE'] },
    interfaces: [
      {
        interfaceId: `${overrides.providerId}-if`,
        interfaceClass: 'I1',
        invocation: `${overrides.providerId} <typed-args>`,
      },
    ],
    ...overrides,
  };
}

export function capabilityDef(
  overrides: Partial<CapabilityDefinition> & { capabilityId: string },
): CapabilityDefinition {
  return {
    revision: 'r1',
    inputSchema: { type: 'object' },
    outputSchema: { type: 'object' },
    sideEffectClass: 'R1',
    allowedInterfaceClasses: ['I0', 'I1', 'I2'],
    verificationContract: {
      verifierId: 'verifier.generic',
      verifierRevision: 'r1',
      checks: [{ checkId: 'outcome-declared', required: true }],
    },
    requiredPolicyFacts: [],
    ...overrides,
  };
}

export function requirements(overrides: Partial<EnvironmentRequirements>): EnvironmentRequirements {
  return { backendKind: 'LOCAL_WINDOWS', ...overrides };
}

export function bindingDef(
  overrides: Partial<ProviderCapabilityBinding> & {
    bindingId: string;
    providerId: string;
    capabilityId: string;
  },
): ProviderCapabilityBinding {
  return {
    capabilityRevisionRange: { min: 'r1' },
    adapterId: `adapter.${overrides.bindingId}`,
    interfaceClass: 'I1',
    environmentRequirements: requirements({}),
    verifierId: 'verifier.generic',
    ...overrides,
  };
}

export function goalRequest(overrides: Partial<GoalRequest> & { goal: string }): GoalRequest {
  return {
    taskId: 'task-t01-001',
    objects: [{ kind: 'DIRECTORY', ref: 'C:\\fixtures\\images' }],
    constraints: { format: 'JPG' },
    policyContext: {
      privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
      environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
    },
    ...overrides,
  };
}
