// Capability/Provider registry view over the T00 read model (L2 §7.1).
//
// The resolver consumes a validated snapshot of the registry fact classes
// (curated provider facts, observed machine facts — outcome evidence is NOT
// part of the P0 resolver input). Snapshot entries are re-parsed with the
// frozen contract parsers, so malformed registry data fails closed at
// construction instead of leaking into resolution.
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
 * Prefix of a verifiable snapshot seal revision (P1-06): the suffix is a
 * SHA-256 content digest over the exact sealed facts, computed by
 * sealRegistrySnapshot — the seal binds to the facts, it is not a label a
 * caller can assert independently.
 */
export const REGISTRY_SNAPSHOT_SEAL_REVISION_PREFIX = 'shun.registry-snapshot/1:sha256:';

/**
 * Trusted currentness seam for registry snapshots (P1-06). The frozen
 * RegistryReadModelPort collects its fact classes through separate async
 * calls and cannot express an atomic read, so the resolver requires an
 * explicit seal whose revision verifiably binds to the collected facts.
 */
export interface RegistrySnapshotSeal {
  readonly snapshotRevision: string;
}

function snapshotFactsRevision(snapshot: RegistrySnapshot): string {
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
  return `${REGISTRY_SNAPSHOT_SEAL_REVISION_PREFIX}${digest}`;
}

/** Seal a collected snapshot: the returned revision binds to these exact facts. */
export function sealRegistrySnapshot(snapshot: RegistrySnapshot): RegistrySnapshotSeal {
  return { snapshotRevision: snapshotFactsRevision(snapshot) };
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
   * Optional trusted snapshot seal (P1-06). When provided it is verified
   * against the snapshot facts; a mismatch means the snapshot is stale or was
   * altered after sealing and construction fails closed.
   */
  snapshotSeal?: RegistrySnapshotSeal;
}

export interface RegistryFromPortOptions extends RegistryOptions {}

export class ShunRegistry {
  private readonly matchers: ObjectiveMatcherTable;

  private constructor(
    private readonly capabilities: ReadonlyMap<string, CapabilityDefinition>,
    private readonly providers: ReadonlyMap<string, ProviderDefinition>,
    private readonly bindingsByCapability: ReadonlyMap<string, ProviderCapabilityBinding[]>,
    private readonly environment: EnvironmentFacts,
    matchers: ObjectiveMatcherTable,
    /**
     * True when the snapshot's currentness is verifiably attested: either the
     * synchronous in-memory path (atomic by construction) or an async port
     * collection bound by a verified snapshot seal (P1-06). Resolution over
     * an unattested registry fails closed in resolveGoal.
     */
    private readonly attested: boolean,
  ) {
    this.matchers = { ...matchers };
  }

  /**
   * Whether this registry's snapshot currentness is verifiably attested
   * (P1-06). Unattested registries (sequential async reads without a
   * snapshot seal) fail closed at resolution.
   */
  get currentnessAttested(): boolean {
    return this.attested;
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
    return ShunRegistry.fromSnapshot(
      { capabilities, providers, bindings, environment },
      {
        additionalObjectiveMatchers: options?.additionalObjectiveMatchers,
        snapshotSeal: options?.snapshotSeal,
        // Sequential async reads are only currentness-attested when a
        // verifiable snapshot seal binds the collected facts (P1-06).
        asyncCollectionAttested: options?.snapshotSeal !== undefined,
      },
    );
  }

  /** Synchronous construction from already-collected facts (tests, callers holding a snapshot). */
  static fromSnapshot(
    snapshot: RegistrySnapshot,
    options?: RegistryOptions & { asyncCollectionAttested?: boolean },
  ): ShunRegistry {
    // Seal verification binds the trusted currentness facts (P1-06): a seal
    // whose revision does not bind to THESE facts means the snapshot is stale
    // or was altered after sealing — fail closed at construction.
    if (options?.snapshotSeal !== undefined) {
      const expected = snapshotFactsRevision(snapshot);
      if (options.snapshotSeal.snapshotRevision !== expected) {
        throw new ShunContractError(
          'SCHEMA_VIOLATION',
          `registry snapshot seal does not bind to the provided facts (seal ${options.snapshotSeal.snapshotRevision}, expected ${expected}) — the snapshot is stale or was altered after sealing; fail closed`,
        );
      }
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
      capabilities.set(parsed.capabilityId, parsed);
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
      providers.set(parsed.providerId, parsed);
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
      list.push(parsed);
      bindingsByCapability.set(parsed.capabilityId, list);
    }
    const environment = parseEnvironmentFacts(snapshot.environment);
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
      // Synchronous construction over an in-memory snapshot is atomic by
      // construction (attested by default); the async port path overrides
      // this with its seal-based attestation.
      options?.asyncCollectionAttested ?? true,
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
