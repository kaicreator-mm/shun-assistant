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
   */
  additionalObjectiveMatchers?: ObjectiveMatcherTable;
  /**
   * Source-issued revision of the trusted registry authority for the
   * synchronous snapshot path (P1-06, R1). Present and binding to the exact
   * snapshot facts → currentness-attested; present but NOT binding → the
   * snapshot is stale or was altered and construction fails closed; absent →
   * the snapshot is a local view with unverifiable currentness and resolution
   * fails closed (REGISTRY_CURRENTNESS_INSUFFICIENT).
   */
  authorityRevision?: string;
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
    // Currentness attestation (P1-06, R1): compare the collected facts against
    // the authority's CURRENT revision. A content match with an outdated
    // revision (stale-but-self-consistent snapshot) does not attest.
    let attested = false;
    let note: string;
    if (options?.currentnessAuthority !== undefined) {
      try {
        const authorityRevision = await options.currentnessAuthority.currentRevision();
        const collectedRevision = snapshotFactsRevision(snapshot);
        attested = authorityRevision === collectedRevision;
        note = attested
          ? `the trusted registry authority confirms revision ${authorityRevision} is current for the collected facts`
          : `the trusted registry authority serves revision ${authorityRevision}, which does not bind the collected facts (${collectedRevision}) — reads-between-changed: the collection is stale`;
      } catch (error) {
        note = `the trusted registry currentness authority could not be consulted: ${
          error instanceof Error ? error.message : String(error)
        }`;
      }
    } else {
      note =
        'snapshot collected through sequential async reads without a trusted currentness authority — no source-issued revision binds the collected facts';
    }
    return ShunRegistry.fromSnapshot(snapshot, {
      additionalObjectiveMatchers: options?.additionalObjectiveMatchers,
      // Sequential async reads are only currentness-attested when the trusted
      // authority's current revision binds the collected facts (P1-06, R1).
      asyncCollectionAttested: attested,
      asyncCollectionNote: note,
    });
  }

  /** Synchronous construction from already-collected facts (tests, callers holding a snapshot). */
  static fromSnapshot(
    snapshot: RegistrySnapshot,
    options?: RegistryOptions & {
      /** Internal: attestation pre-verified by the async port path. */
      asyncCollectionAttested?: boolean;
      /** Internal: audit note from the async port path. */
      asyncCollectionNote?: string;
    },
  ): ShunRegistry {
    // Authority revision binding (P1-06, R1): a provided source-issued
    // revision that does not bind to THESE facts proves the snapshot is stale
    // or was altered — fail closed at construction. Without any authority
    // revision the snapshot is a local view: it is NOT attested by default and
    // resolution fails closed.
    let attested: boolean;
    let note: string;
    const collectedRevision = snapshotFactsRevision(snapshot);
    if (options?.authorityRevision !== undefined) {
      if (options.authorityRevision !== collectedRevision) {
        throw new ShunContractError(
          'SCHEMA_VIOLATION',
          `registry snapshot is not the revision the trusted authority issued (source-issued ${options.authorityRevision}, snapshot binds ${collectedRevision}) — the snapshot is stale or was altered; fail closed`,
        );
      }
      attested = true;
      note = `snapshot binds the source-issued authority revision ${options.authorityRevision}`;
    } else {
      attested = options?.asyncCollectionAttested ?? false;
      note =
        options?.asyncCollectionNote ??
        'synchronous snapshot not bound to a trusted registry currentness authority — no source-issued revision proves these facts current';
    }
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
    return new ShunRegistry(capabilities, providers, bindingsByCapability, environment, matchers, attested, note);
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
