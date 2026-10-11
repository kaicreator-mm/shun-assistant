// Registry integrity: identity uniqueness and trusted snapshot currentness.
// One stable identity must designate exactly one fact (P1-05), and the
// resolver only resolves over a currentness-verifiable snapshot (P1-06).
//
// R1 (Issue #33 fresh review blockers 1–2): a caller-computable content
// digest is NOT currentness evidence — attestation requires a trusted
// source-issued revision/currentness authority compared against the CURRENT
// authority state, and attested facts are immutable after construction.
import { type RegistryReadModelPort, ShunContractError } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import {
  type RegistryCurrentnessAuthority,
  type RegistrySnapshot,
  ShunRegistry,
  snapshotFactsRevision,
} from '../src/registry.ts';
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

/** Test double standing in for the TRUSTED registry currentness authority. */
function authorityFor(snapshot: RegistrySnapshot): RegistryCurrentnessAuthority {
  return { currentRevision: async () => snapshotFactsRevision(snapshot) };
}

describe('trusted currentness authority seam (P1-06, R1 blocker 1)', () => {
  it('a registry collected via sequential async reads without a trusted currentness authority fails closed at resolution', async () => {
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
    expect(result.record.failureDisposition?.detail).toContain('currentness authority');
  });

  it('a port-built registry whose trusted authority confirms the collected revision is currentness-attested and resolves', async () => {
    const snapshot = baseSnapshot();
    const registry = await ShunRegistry.fromPort(portOf(snapshot), {
      currentnessAuthority: authorityFor(snapshot),
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

  it('the review counterexample: the port keeps serving stale snapshot A after the authority moved to revision B — resolution fails closed and A is never selected', async () => {
    // The trusted authority has already issued a new revision (provider trust
    // revoked); the async port keeps returning the superseded snapshot A.
    const stale = baseSnapshot();
    const current = baseSnapshot();
    current.providers[0] = providerDef({
      providerId: 'imageProvider.imagemagick',
      provenanceFacts: { trustState: 'UNTRUSTED' },
    });
    const registry = await ShunRegistry.fromPort(portOf(stale), {
      currentnessAuthority: authorityFor(current),
    });
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
    expect(result.record.failureDisposition?.detail).toContain('reads-between-changed');
  });

  it('a currentness authority that cannot be consulted leaves the registry unattested — resolution fails closed', async () => {
    const registry = await ShunRegistry.fromPort(portOf(baseSnapshot()), {
      currentnessAuthority: {
        currentRevision: async () => {
          throw new Error('authority unreachable');
        },
      },
    });
    expect(registry.currentnessAttested).toBe(false);
    const result = resolveGoal({
      request: resolvingRequest(),
      registry,
      objectExists: () => true,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.failureDisposition?.failureCode).toBe('REGISTRY_CURRENTNESS_INSUFFICIENT');
    expect(result.record.failureDisposition?.detail).toContain('authority unreachable');
  });

  it('a synchronous snapshot is NOT attested by default — an arbitrary stale snapshot cannot masquerade as current (R1)', () => {
    // Premise tightened (R1 review blocker 1): R0 attested fromSnapshot by
    // default, so any self-consistent stale snapshot resolved. A snapshot
    // without a source-issued authority revision has unverifiable currentness.
    const registry = ShunRegistry.fromSnapshot(baseSnapshot());
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
  });

  it('a trusted authority confirming the collected facts attests a synchronous snapshot and resolution proceeds (R2 — trusted path replaces the removed self-attestation option)', async () => {
    // Premise migrated (R2 review blocker 1): the R1
    // `fromSnapshot(snapshot, {authorityRevision: <caller-computed>})` form
    // was self-attestation and is gone. A snapshot attests only through
    // fromAttestedSnapshot against the trusted authority's CURRENT revision.
    const snapshot = baseSnapshot();
    const registry = await ShunRegistry.fromAttestedSnapshot(snapshot, {
      currentnessAuthority: authorityFor(snapshot),
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

  it('stale snapshot: facts mutated after the authority confirmed the original facts are no longer attested (R2)', () => {
    // Premise migrated (R2 review blocker 1): the R1 form threw at
    // construction on a caller-passed revision mismatch. Under the trusted
    // path the mismatch is a currentness verdict: the mutated snapshot never
    // attests and resolution fails closed (see the stale-A/current-B
    // regression in adversarial-r2.test.ts for the end-to-end form).
    const snapshot = baseSnapshot();
    const issued = snapshotFactsRevision(snapshot);
    snapshot.environment = { ...snapshot.environment, networkPolicy: 'OPEN' };
    // Content mutation changes the exact revision the facts bind — and no
    // caller-supplied revision string can attest the mutated snapshot anyway.
    expect(snapshotFactsRevision(snapshot)).not.toBe(issued);
    const registry = ShunRegistry.fromSnapshot(snapshot);
    expect(registry.currentnessAttested).toBe(false);
    expect(registry.currentnessExplanation).toContain('currentness authority');
  });
});

describe('attested registry facts are immutable after construction (R1 blocker 2)', () => {
  async function attestedRegistry(snapshot: RegistrySnapshot): Promise<ShunRegistry> {
    // R2 (review blocker 1): attestation goes through the trusted authority
    // comparison — the self-computed authorityRevision option is removed.
    return ShunRegistry.fromAttestedSnapshot(snapshot, {
      currentnessAuthority: authorityFor(snapshot),
    });
  }

  it('the review counterexample: a post-construction trust upgrade is refused — resolution still fails the provider closed', async () => {
    const snapshot = baseSnapshot();
    snapshot.providers[0] = providerDef({
      providerId: 'imageProvider.imagemagick',
      provenanceFacts: { trustState: 'UNKNOWN', formatSupport: ['JPG'] },
    });
    const registry = await attestedRegistry(snapshot);
    const provider = registry.provider('imageProvider.imagemagick');
    expect(provider?.provenanceFacts.trustState).toBe('UNKNOWN');
    expect(() => {
      if (!provider) throw new Error('provider missing from registry');
      (provider.provenanceFacts as { trustState: string }).trustState = 'TRUSTED';
    }).toThrow(TypeError);
    expect(registry.provider('imageProvider.imagemagick')?.provenanceFacts.trustState).toBe(
      'UNKNOWN',
    );
    const result = resolveGoal({
      request: resolvingRequest(),
      registry,
      objectExists: () => true,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBeNull();
    expect(result.record.failureDisposition?.failureCode).toBe('NO_TRUSTED_PROVIDER');
  });

  it('observed environment facts, bindings and capability policy declarations are equally frozen', async () => {
    const snapshot = baseSnapshot();
    snapshot.capabilities[0] = capabilityDef({
      capabilityId: 'image.batch_process',
      requiredPolicyFacts: ['userApprovedDelete'],
    });
    const registry = await attestedRegistry(snapshot);
    expect(() => {
      (registry.observedEnvironment() as { observationRevision: string }).observationRevision =
        'obs-forged';
    }).toThrow(TypeError);
    const binding = registry.bindingsForCapability('image.batch_process')[0];
    expect(() => {
      if (!binding) throw new Error('binding missing from registry');
      const requirement = binding.environmentRequirements as { networkAccess: string };
      requirement.networkAccess = 'REQUIRED';
    }).toThrow(TypeError);
    expect(() => {
      const capability = registry.capability('image.batch_process');
      if (!capability) throw new Error('capability missing from registry');
      capability.requiredPolicyFacts.push('another-fact');
    }).toThrow(TypeError);
    expect(registry.observedEnvironment().observationRevision).toBe('obs-0042');
    expect(binding?.environmentRequirements.networkAccess).toBe('FORBIDDEN');
    expect(registry.capability('image.batch_process')?.requiredPolicyFacts).toEqual([
      'userApprovedDelete',
    ]);
  });
});
