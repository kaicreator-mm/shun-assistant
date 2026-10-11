// Capability/Provider registry view over the T00 read model (L2 §7.1).
//
// The resolver consumes a validated snapshot of the registry fact classes
// (curated provider facts, observed machine facts — outcome evidence is NOT
// part of the P0 resolver input). Snapshot entries are re-parsed with the
// frozen contract parsers, so malformed registry data fails closed at
// construction instead of leaking into resolution.
//
// R1 (Issue #33 review blocker 1): a caller-computable content digest is NOT
// currentness evidence — it proves self-consistency only, never source
// authority, atomicity or freshness. Attestation therefore requires a trusted
// source-issued revision/currentness authority whose CURRENT revision binds to
// the exact collected facts; anything else is unattested and resolution fails
// closed with REGISTRY_CURRENTNESS_INSUFFICIENT.
//
// R1 (review blocker 2): validated facts are deeply frozen at construction —
// an attested registry can no longer be mutated after attestation.
//
// R2 (fresh review blocker 1): synchronous self-attestation is impossible —
// fromSnapshot accepts no attestation input at all (a caller-computed revision
// is self-attestation; a pre-attestation flag is a bypass), and the only
// attested snapshot path is fromAttestedSnapshot, which compares the snapshot
// against a trusted RegistryCurrentnessAuthority's CURRENT revision.
import { createHash } from 'node:crypto';
import {
  type CapabilityDefinition,
  canonicalJson,
  type EnvironmentFacts,
  type ProviderCapabilityBinding,
  type ProviderDefinition,
  parseCapabilityDefinition,
  parseEnvironmentFacts,
  parseProviderCapabilityBinding,
  parseProviderDefinition,
  type RegistryReadModelPort,
  ShunContractError,
} from '@shun/contracts';
import { matchCapabilityIds, OBJECTIVE_MATCHERS, type ObjectiveMatcherTable } from './matchers.ts';

/** Identity of the resolver implementation itself (durable identity input, L2 §11.2). */
export const RESOLVER_REVISION = 'shun.resolver/0.1';

/**
 * Prefix of a registry snapshot fact revision (P1-06, R1): the suffix is a
 * SHA-256 content digest over the exact snapshot facts. This revision is the
 * unit the trusted authority ISSUES — deriving it locally proves nothing
 * about currentness; only the authority's confirmation does.
 */
export const REGISTRY_SNAPSHOT_REVISION_PREFIX = 'shun.registry-snapshot/1:sha256:';

/**
 * Trusted currentness authority seam (P1-06, R1). The frozen
 * RegistryReadModelPort collects its fact classes through separate async calls
 * and cannot express an atomic read, so the resolver requires a source-side
 * authority that issues revision identities. A snapshot is currentness-attested
 * ONLY when the authority's current revision binds to the exact collected
 * facts — attestation is always a comparison against the authority's current
 * state, so a stale-but-self-consistent snapshot fails closed.
 *
 * The trust anchor is the wiring of this port: the integration layer is
 * responsible for injecting a genuine authority (the same trust boundary as
 * injecting the RegistryReadModelPort itself).
 */
export interface RegistryCurrentnessAuthority {
  /** Revision identity the trusted authority currently serves for the registry fact classes. */
  currentRevision(): Promise<string>;
}

/** Deterministic content revision of a snapshot (the unit an authority issues). */
export function snapshotFactsRevision(snapshot: RegistrySnapshot): string {
  const digest = createHash('sha256')
    .update(
      canonicalJson({
        capabilities: snapshot.capabilities,
        providers: snapshot.providers,
        bindings: snapshot.bindings,
        environment: snapshot.environment,
      }),
      'utf8',
    )
    .digest('hex');
  return `${REGISTRY_SNAPSHOT_REVISION_PREFIX}${digest}`;
}

/** Deeply freeze a validated fact object; mutation attempts throw in strict mode. */
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const entry of Object.values(value as Record<string, unknown>)) {
      deepFreeze(entry);
    }
    Object.freeze(value);
  }
  return value;
}

export type { ObjectiveMatcherTable };

export interface RegistrySnapshot {
  capabilities: readonly CapabilityDefinition[];
  providers: readonly ProviderDefinition[];
  bindings: readonly ProviderCapabilityBinding[];
  environment: EnvironmentFacts;
}

export interface RegistryOptions {
  /**
   * Additional curated objective matchers beyond the built-in table — the
   * registry is data-driven, so a curated registry may register the
   * vocabulary of capabilities it ships (e.g. benchmark fixture
   * capabilities). Entries extend, never silently replace, the built-ins.
   *
   * R2 (review blocker 1): this is the ONLY synchronous-snapshot option.
   * There is no caller-supplied attestation input of any kind — a revision
   * string the caller computes or asserts is self-attestation, and a boolean
   * pre-attestation flag is a bypass. A snapshot attests exclusively through
   * {@link ShunRegistry.fromAttestedSnapshot} against a trusted
   * {@link RegistryCurrentnessAuthority}.
   */
  additionalObjectiveMatchers?: ObjectiveMatcherTable;
}

export interface RegistryFromPortOptions extends RegistryOptions {
  /**
   * Trusted source-side currentness authority (P1-06, R1). After collecting
   * the fact classes, the computed content revision is compared against the
   * authority's CURRENT revision: only a binding revision attests. An
   * unreachable or disagreeing authority leaves the registry unattested —
   * resolution fails closed instead of trusting an unbound collection.
   */
  currentnessAuthority?: RegistryCurrentnessAuthority;
}

export class ShunRegistry {
  private readonly matchers: ObjectiveMatcherTable;

  private constructor(
    private readonly capabilities: ReadonlyMap<string, CapabilityDefinition>,
    private readonly providers: ReadonlyMap<string, ProviderDefinition>,
    private readonly bindingsByCapability: ReadonlyMap<string, ProviderCapabilityBinding[]>,
    private readonly environment: EnvironmentFacts,
    matchers: ObjectiveMatcherTable,
    /**
     * True when the snapshot's currentness is verifiably attested: the
     * snapshot's content revision is confirmed current by a trusted
     * source-issued authority revision (P1-06, R1). Resolution over an
     * unattested registry fails closed in resolveGoal.
     */
    private readonly attested: boolean,
    /** Audit note stating why currentness is (un)attested; carried into resolution records. */
    private readonly currentnessNote: string,
  ) {
    this.matchers = { ...matchers };
  }

  /**
   * Whether this registry's snapshot currentness is verifiably attested
   * (P1-06, R1): the source-issued authority revision binds to the exact
   * facts. Unattested registries fail closed at resolution.
   */
  get currentnessAttested(): boolean {
    return this.attested;
  }

  /** Why currentness is (un)attested — resolution failure details carry this verbatim. */
  get currentnessExplanation(): string {
    return this.currentnessNote;
  }

  /** Build from the async T00 read model port (the async boundary of resolution). */
  static async fromPort(
    port: RegistryReadModelPort,
    options?: RegistryFromPortOptions,
  ): Promise<ShunRegistry> {
    const capabilities = await port.listCapabilities();
    const [providers, bindings, environment] = await Promise.all([
      port.listProviders(),
      Promise.all(
        capabilities.map((capability) => port.providerCapabilityBindings(capability.capabilityId)),
      ).then((lists) => lists.flat()),
      port.observedFacts(),
    ]);
    const snapshot: RegistrySnapshot = { capabilities, providers, bindings, environment };
    // Currentness attestation (P1-06, R1; R2 blocker 1): the collected facts
    // attest only against the trusted authority's CURRENT revision, through
    // the same trusted path as an explicitly held snapshot.
    return ShunRegistry.fromAttestedSnapshot(snapshot, options);
  }

  /**
   * Synchronous construction from already-collected facts (tests, callers
   * holding a snapshot). R2 (review blocker 1): a synchronous snapshot is
   * ALWAYS a local view — there is no caller-supplied attestation input
   * (revision string or pre-attestation flag), because a caller-computed
   * revision is self-attestation. Resolution over it fails closed with
   * REGISTRY_CURRENTNESS_INSUFFICIENT; attest through
   * {@link ShunRegistry.fromAttestedSnapshot} instead.
   */
  static fromSnapshot(snapshot: RegistrySnapshot, options?: RegistryOptions): ShunRegistry {
    // Identity uniqueness fails closed (P1-05): one stable identity must
    // designate exactly one fact. A duplicate capabilityId/providerId would
    // silently overwrite its predecessor here, and a duplicate bindingId
    // would make selectedBindingId designate two different Provider/adapter
    // bindings — ambiguous selection is refused at construction instead.
    const capabilities = new Map<string, CapabilityDefinition>();
    for (const capability of snapshot.capabilities) {
      const parsed = parseCapabilityDefinition(capability);
      const existing = capabilities.get(parsed.capabilityId);
      if (existing !== undefined) {
        throw new ShunContractError(
          'SCHEMA_VIOLATION',
          `duplicate capabilityId "${parsed.capabilityId}" in registry snapshot (existing revision ${existing.revision}, duplicate revision ${parsed.revision}) — one stable identity must designate exactly one capability; fail closed`,
        );
      }
      capabilities.set(parsed.capabilityId, deepFreeze(parsed));
    }
    const providers = new Map<string, ProviderDefinition>();
    for (const provider of snapshot.providers) {
      const parsed = parseProviderDefinition(provider);
      const existing = providers.get(parsed.providerId);
      if (existing !== undefined) {
        throw new ShunContractError(
          'SCHEMA_VIOLATION',
          `duplicate providerId "${parsed.providerId}" in registry snapshot (existing revision ${existing.revision}, duplicate revision ${parsed.revision}) — a repeated identity with a conflicting revision must not be silently accepted; fail closed`,
        );
      }
      providers.set(parsed.providerId, deepFreeze(parsed));
    }
    const bindingsByCapability = new Map<string, ProviderCapabilityBinding[]>();
    const seenBindingIds = new Set<string>();
    for (const binding of snapshot.bindings) {
      const parsed = parseProviderCapabilityBinding(binding);
      if (seenBindingIds.has(parsed.bindingId)) {
        throw new ShunContractError(
          'SCHEMA_VIOLATION',
          `duplicate bindingId "${parsed.bindingId}" in registry snapshot (provider ${parsed.providerId}, capability ${parsed.capabilityId}) — one binding identity must designate exactly one Provider/adapter binding or selection becomes ambiguous; fail closed`,
        );
      }
      seenBindingIds.add(parsed.bindingId);
      const list = bindingsByCapability.get(parsed.capabilityId) ?? [];
      list.push(deepFreeze(parsed));
      bindingsByCapability.set(parsed.capabilityId, list);
    }
    for (const list of bindingsByCapability.values()) {
      Object.freeze(list);
    }
    // R1 (review blocker 2): the validated environment facts are frozen with
    // the rest of the attested snapshot.
    const environment = deepFreeze(parseEnvironmentFacts(snapshot.environment));
    const matchers: Record<string, readonly RegExp[]> = { ...OBJECTIVE_MATCHERS };
    for (const [capabilityId, patterns] of Object.entries(
      options?.additionalObjectiveMatchers ?? {},
    )) {
      matchers[capabilityId] = [...(matchers[capabilityId] ?? []), ...patterns];
    }
    return new ShunRegistry(
      capabilities,
      providers,
      bindingsByCapability,
      environment,
      matchers,
      // R2 (review blocker 1): an unattested local view by construction — no
      // caller-supplied input can flip this.
      false,
      'synchronous snapshot not bound to a trusted registry currentness authority — no source-issued revision proves these facts current',
    );
  }

  /**
   * Trusted snapshot attestation (R2, review blocker 1): the ONLY way a
   * synchronously-held snapshot becomes currentness-attested. The computed
   * content revision of the exact snapshot facts is compared against the
   * trusted authority's CURRENT revision — attestation is always a comparison
   * against live authority state, so a stale-but-self-consistent snapshot
   * (or one altered after collection) never attests, and an unreachable
   * authority leaves the registry unattested. The trust anchor is the wiring
   * of the authority: the integration layer injects it exactly like the
   * RegistryReadModelPort itself.
   */
  static async fromAttestedSnapshot(
    snapshot: RegistrySnapshot,
    options?: RegistryFromPortOptions,
  ): Promise<ShunRegistry> {
    let attested = false;
    let note: string;
    if (options?.currentnessAuthority !== undefined) {
      try {
        const authorityRevision = await options.currentnessAuthority.currentRevision();
        const collectedRevision = snapshotFactsRevision(snapshot);
        attested = authorityRevision === collectedRevision;
        note = attested
          ? `the trusted registry authority confirms revision ${authorityRevision} is current for the collected facts`
          : `the trusted registry authority serves revision ${authorityRevision}, which does not bind the collected facts (${collectedRevision}) — reads-between-changed: the collection is stale or was altered`;
      } catch (error) {
        note = `the trusted registry currentness authority could not be consulted: ${
          error instanceof Error ? error.message : String(error)
        }`;
      }
    } else {
      note =
        'no trusted registry currentness authority provided — attestation requires a comparison against the authority’s current revision, not a caller-asserted one';
    }
    const registry = ShunRegistry.fromSnapshot(snapshot, {
      additionalObjectiveMatchers: options?.additionalObjectiveMatchers,
    });
    // Re-wrap with the computed attestation state: fromSnapshot always builds
    // the unattested local view; this method owns the trusted attestation
    // verdict derived from the authority comparison above.
    return new ShunRegistry(
      registry.capabilities,
      registry.providers,
      registry.bindingsByCapability,
      registry.environment,
      registry.matchers,
      attested,
      note,
    );
  }

  capability(capabilityId: string): CapabilityDefinition | undefined {
    return this.capabilities.get(capabilityId);
  }

  provider(providerId: string): ProviderDefinition | undefined {
    return this.providers.get(providerId);
  }

  bindingsForCapability(capabilityId: string): ProviderCapabilityBinding[] {
    return [...(this.bindingsByCapability.get(capabilityId) ?? [])];
  }

  /** Observed machine facts of the single P0 local environment (L2 §7.1 fact class 2). */
  observedEnvironment(): EnvironmentFacts {
    return this.environment;
  }

  /**
   * Deterministic objective matching: only capabilities whose registered id or
   * alias the objective names can be resolved without a planner.
   */
  matchCapabilities(objective: string): CapabilityDefinition[] {
    return matchCapabilityIds(objective, this.matchers)
      .map((id) => this.capabilities.get(id))
      .filter((capability): capability is CapabilityDefinition => capability !== undefined);
  }
}
