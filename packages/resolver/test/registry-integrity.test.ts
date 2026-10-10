// Registry integrity: identity uniqueness and trusted snapshot currentness.
// One stable identity must designate exactly one fact (P1-05), and the
// resolver only resolves over a currentness-verifiable snapshot (P1-06).
import { ShunContractError } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { ShunRegistry } from '../src/registry.ts';
import { bindingDef, capabilityDef, ENV_LOCAL, providerDef } from './scenarios.ts';

function baseSnapshot() {
  const capability = capabilityDef({ capabilityId: 'image.batch_process' });
  const provider = providerDef({ providerId: 'imageProvider.imagemagick' });
  const binding = bindingDef({
    bindingId: 'b-im',
    providerId: provider.providerId,
    capabilityId: 'image.batch_process',
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
