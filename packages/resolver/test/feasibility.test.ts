// Typed Provider × Environment feasibility derivation: every frozen rejection
// reason is produced by exactly its condition, in deterministic order.
import { describe, expect, it } from 'vitest';
import { deriveFeasibility } from '../src/feasibility.ts';
import {
  bindingDef,
  capabilityDef,
  ENV_LOCAL,
  envFacts,
  providerDef,
  requirements,
} from './scenarios.ts';

const capability = capabilityDef({ capabilityId: 'image.batch_process' });
const provider = providerDef({ providerId: 'imageProvider.imagemagick' });

function feasibilityFor(
  reqOverrides: Parameters<typeof requirements>[0],
  opts?: {
    env?: ReturnType<typeof envFacts>;
    providerPlatforms?: typeof provider.supportedPlatforms;
  },
) {
  const binding = bindingDef({
    bindingId: 'b-test',
    providerId: provider.providerId,
    capabilityId: capability.capabilityId,
    environmentRequirements: requirements(reqOverrides),
  });
  return deriveFeasibility({
    binding,
    provider: opts?.providerPlatforms
      ? { ...provider, supportedPlatforms: opts.providerPlatforms }
      : provider,
    environment: opts?.env ?? ENV_LOCAL,
    environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
  });
}

describe('binding feasibility derivation', () => {
  it('a well-posed local binding is feasible with no rejection reasons', () => {
    expect(feasibilityFor({})).toEqual({ feasible: true, rejectionReasons: [] });
  });

  it('BACKEND_KIND_INELIGIBLE when the binding targets another backend kind', () => {
    const result = feasibilityFor({ backendKind: 'LOCAL_POSIX' });
    expect(result).toEqual({ feasible: false, rejectionReasons: ['BACKEND_KIND_INELIGIBLE'] });
  });

  it('BACKEND_KIND_INELIGIBLE when the observed backend is not an allowed kind', () => {
    const binding = bindingDef({
      bindingId: 'b-remote',
      providerId: provider.providerId,
      capabilityId: capability.capabilityId,
      environmentRequirements: requirements({}),
    });
    const result = deriveFeasibility({
      binding,
      provider,
      environment: ENV_LOCAL,
      environmentPolicy: { allowedBackendKinds: ['REMOTE_ECF'], allowElevation: false },
    });
    expect(result.rejectionReasons).toContain('BACKEND_KIND_INELIGIBLE');
  });

  it('PLATFORM_UNSUPPORTED when the provider declares no Windows support', () => {
    const result = feasibilityFor({}, { providerPlatforms: [{ os: 'LINUX' }] });
    expect(result).toEqual({ feasible: false, rejectionReasons: ['PLATFORM_UNSUPPORTED'] });
  });

  it('PLATFORM_UNSUPPORTED when the binding requires another OS', () => {
    const result = feasibilityFor({ os: 'LINUX' });
    expect(result.rejectionReasons).toContain('PLATFORM_UNSUPPORTED');
  });

  it('ARCH_UNSUPPORTED when the binding requires another architecture', () => {
    const result = feasibilityFor({ arch: 'ARM64' });
    expect(result).toEqual({ feasible: false, rejectionReasons: ['ARCH_UNSUPPORTED'] });
  });

  it('PRIVILEGE_INSUFFICIENT when the requirement exceeds observed privilege', () => {
    const result = feasibilityFor({ privilegeMode: 'ELEVATED_ADMIN' });
    expect(result.rejectionReasons).toEqual(['PRIVILEGE_INSUFFICIENT']);
  });

  it('PRIVILEGE_INSUFFICIENT is not raised for equal-or-lower requirements', () => {
    expect(feasibilityFor({ privilegeMode: 'FILTERED_ADMIN' }).feasible).toBe(true);
    expect(feasibilityFor({ privilegeMode: 'STANDARD_USER' }).feasible).toBe(true);
  });

  it('GUI_SESSION_UNAVAILABLE when a GUI binding meets a headless environment', () => {
    const result = feasibilityFor(
      { guiSessionRequired: true },
      { env: envFacts({ guiSession: false }) },
    );
    expect(result.rejectionReasons).toEqual(['GUI_SESSION_UNAVAILABLE']);
  });

  it('NETWORK_POLICY_FORBIDDEN when a network-required binding meets an offline environment', () => {
    const result = feasibilityFor(
      { networkAccess: 'REQUIRED' },
      { env: envFacts({ networkPolicy: 'OFFLINE' }) },
    );
    expect(result.rejectionReasons).toEqual(['NETWORK_POLICY_FORBIDDEN']);
  });

  it('RESOURCE_INSUFFICIENT when free disk is below the requirement', () => {
    const result = feasibilityFor({ minFreeDiskMb: 999_999 });
    expect(result.rejectionReasons).toEqual(['RESOURCE_INSUFFICIENT']);
  });

  it('RUNTIME_CAPABILITY_MISSING when observed facts lack a required runtime', () => {
    const result = feasibilityFor({ runtimeCapabilities: ['gpu-nvenc', 'node-24'] });
    expect(result.rejectionReasons).toEqual(['RUNTIME_CAPABILITY_MISSING']);
  });

  it('rejection reasons are emitted in the frozen enum order, deterministically', () => {
    const result = feasibilityFor(
      {
        arch: 'ARM64',
        privilegeMode: 'ELEVATED_ADMIN',
        guiSessionRequired: true,
        minFreeDiskMb: 999_999,
      },
      { env: envFacts({ guiSession: false }) },
    );
    expect(result.rejectionReasons).toEqual([
      'ARCH_UNSUPPORTED',
      'PRIVILEGE_INSUFFICIENT',
      'GUI_SESSION_UNAVAILABLE',
      'RESOURCE_INSUFFICIENT',
    ]);
  });
});
