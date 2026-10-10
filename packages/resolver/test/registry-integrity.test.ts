// Registry integrity: identity uniqueness and trusted snapshot currentness.
// One stable identity must designate exactly one fact (P1-05), and the
// resolver only resolves over a currentness-verifiable snapshot (P1-06).
import { type RegistryReadModelPort, ShunContractError } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { type RegistrySnapshot, ShunRegistry, sealRegistrySnapshot } from '../src/registry.ts';
import { resolveGoal } from '../src/resolve.ts';
import {
  bindingDef,
  capabilityDef,
  ENV_LOCAL,
  goalRequest,
  providerDef,
  requirements,
} from './scenarios.ts';

function baseSnapshot() {
  const capability = capabilityDef({ capabilityId: 'image.batch_process' });
  const provider = providerDef({ providerId: 'imageProvider.imagemagick' });
  const binding = bindingDef({
    bindingId: 'b-im',
    providerId: provider.providerId,
    capabilityId: 'image.batch_process',
    // Scenario policy is local-only/FORBIDDEN — declare the no-network
    // posture explicitly (P1-02 disclosure evidence).
    environmentRequirements: requirements({ networkAccess: 'FORBIDDEN' }),
  });
  return {
    capabilities: [capability],
    providers: [provider],
    bindings: [binding],
    environment: ENV_LOCAL,
  };
}

describe('registry identity uniqueness fails closed (P1-05)', () => {
  it('a duplicate capabilityId is rejected even when the revision conflicts', () => {
    const snapshot = baseSnapshot();
    snapshot.capabilities.push(
      capabilityDef({ capabilityId: 'image.batch_process', revision: 'r2' }),
    );
    expect(() => ShunRegistry.fromSnapshot(snapshot)).toThrow(ShunContractError);
    expect(() => ShunRegistry.fromSnapshot(snapshot)).toThrow(/duplicate capabilityId/);
    expect(() => ShunRegistry.fromSnapshot(snapshot)).toThrow(/r1/);
    expect(() => ShunRegistry.fromSnapshot(snapshot)).toThrow(/r2/);
  });

  it('a duplicate providerId with a conflicting revision is rejected, not silently overwritten', () => {
    const snapshot = baseSnapshot();
    snapshot.providers.push(
      providerDef({
        providerId: 'imageProvider.imagemagick',
        revision: 'r9',
        acquisition: {
          mechanism: 'DIRECT_DOWNLOAD',
          source: 'unofficial mirror',
          official: false,
          version: '9.9.9',
        },
      }),
    );
    expect(() => ShunRegistry.fromSnapshot(snapshot)).toThrow(ShunContractError);
    expect(() => ShunRegistry.fromSnapshot(snapshot)).toThrow(
      /duplicate providerId "imageProvider\.imagemagick"/,
    );
  });

  it('a duplicate bindingId within one capability is rejected instead of appended', () => {
    const snapshot = baseSnapshot();
    snapshot.bindings.push(
      bindingDef({
        bindingId: 'b-im',
        providerId: 'imageProvider.imagemagick',
        capabilityId: 'image.batch_process',
        adapterId: 'adapter.other',
      }),
    );
    expect(() => ShunRegistry.fromSnapshot(snapshot)).toThrow(/duplicate bindingId "b-im"/);
  });

  it('a bindingId colliding across two capabilities is rejected — one binding identity cannot designate two Provider/adapter bindings', () => {
    const snapshot = baseSnapshot();
    snapshot.capabilities.push(capabilityDef({ capabilityId: 'software.uninstall_safe' }));
    const other = providerDef({ providerId: 'softwareProvider.safer-uninstaller' });
    snapshot.providers.push(other);
    // Alias/collision scenario: the same bindingId is registered for a second
    // capability backed by a different provider and adapter. Left unchecked,
    // selectedBindingId could designate two different bindings.
    snapshot.bindings.push(
      bindingDef({
        bindingId: 'b-im',
        providerId: other.providerId,
        capabilityId: 'software.uninstall_safe',
      }),
    );
    expect(() => ShunRegistry.fromSnapshot(snapshot)).toThrow(ShunContractError);
    expect(() => ShunRegistry.fromSnapshot(snapshot)).toThrow(/duplicate bindingId "b-im"/);
  });

  it('a provider bound under several capabilities is not a duplicate — legitimate reuse stays constructible', () => {
    const snapshot = baseSnapshot();
    snapshot.capabilities.push(capabilityDef({ capabilityId: 'software.uninstall_safe' }));
    snapshot.bindings.push(
      bindingDef({
        bindingId: 'b-im-uninstall',
        providerId: 'imageProvider.imagemagick',
        capabilityId: 'software.uninstall_safe',
      }),
    );
    expect(() => ShunRegistry.fromSnapshot(snapshot)).not.toThrow();
  });
});

function portOf(snapshot: RegistrySnapshot): RegistryReadModelPort {
  return {
    listCapabilities: async () => [...snapshot.capabilities],
    listProviders: async () => [...snapshot.providers],
    providerCapabilityBindings: async (capabilityId) =>
      snapshot.bindings.filter((binding) => binding.capabilityId === capabilityId),
    providerEnvironmentBindings: async () => [],
    observedFacts: async () => snapshot.environment,
  };
}

function resolvingRequest() {
  const request = goalRequest({ goal: 'image.batch_process: batch resize my photos offline' });
  request.constraints.other = { offline: true };
  return request;
}

describe('trusted snapshot currentness seam (P1-06)', () => {
  it('a registry collected via sequential async reads without a snapshot seal fails closed at resolution', async () => {
    const registry = await ShunRegistry.fromPort(portOf(baseSnapshot()));
    expect(registry.currentnessAttested).toBe(false);
    const result = resolveGoal({
      request: resolvingRequest(),
      registry,
      objectExists: () => true,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBeNull();
    expect(result.record.failureDisposition?.failureCode).toBe('REGISTRY_CURRENTNESS_INSUFFICIENT');
    expect(result.record.failureDisposition?.detail).toContain('snapshot seal');
  });

  it('a port-built registry with a matching snapshot seal is currentness-attested and resolves', async () => {
    const snapshot = baseSnapshot();
    const registry = await ShunRegistry.fromPort(portOf(snapshot), {
      snapshotSeal: sealRegistrySnapshot(snapshot),
    });
    expect(registry.currentnessAttested).toBe(true);
    const result = resolveGoal({
      request: resolvingRequest(),
      registry,
      objectExists: () => true,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBe('b-im');
  });

  it('reads-between-changed: a seal that does not bind to the collected facts is rejected at construction', async () => {
    // The collector sealed an atomic read of snapshot A; the port then served
    // facts in which the environment changed mid-collection (snapshot B).
    const sealed = baseSnapshot();
    const served = baseSnapshot();
    served.environment = { ...served.environment, observationRevision: 'obs-0043' };
    await expect(
      ShunRegistry.fromPort(portOf(served), { snapshotSeal: sealRegistrySnapshot(sealed) }),
    ).rejects.toThrow(/stale or altered|does not bind/);
  });

  it('stale snapshot: facts mutated after sealing are rejected by fromSnapshot', () => {
    const snapshot = baseSnapshot();
    const seal = sealRegistrySnapshot(snapshot);
    snapshot.environment = { ...snapshot.environment, networkPolicy: 'OPEN' };
    expect(() => ShunRegistry.fromSnapshot(snapshot, { snapshotSeal: seal })).toThrow(
      ShunContractError,
    );
    expect(() => ShunRegistry.fromSnapshot(snapshot, { snapshotSeal: seal })).toThrow(
      /stale or was altered/,
    );
  });

  it('a matching fromSnapshot seal verifies and resolution proceeds over the attested snapshot', () => {
    const snapshot = baseSnapshot();
    const registry = ShunRegistry.fromSnapshot(snapshot, {
      snapshotSeal: sealRegistrySnapshot(snapshot),
    });
    expect(registry.currentnessAttested).toBe(true);
    const result = resolveGoal({
      request: resolvingRequest(),
      registry,
      objectExists: () => true,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBe('b-im');
  });
});
