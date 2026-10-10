// Capability/Provider registry view over the T00 read model (L2 §7.1).
//
// The resolver consumes a validated snapshot of the registry fact classes
// (curated provider facts, observed machine facts — outcome evidence is NOT
// part of the P0 resolver input). Snapshot entries are re-parsed with the
// frozen contract parsers, so malformed registry data fails closed at
// construction instead of leaking into resolution.
import {
  type CapabilityDefinition,
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
}

export class ShunRegistry {
  private readonly matchers: ObjectiveMatcherTable;

  private constructor(
    private readonly capabilities: ReadonlyMap<string, CapabilityDefinition>,
    private readonly providers: ReadonlyMap<string, ProviderDefinition>,
    private readonly bindingsByCapability: ReadonlyMap<string, ProviderCapabilityBinding[]>,
    private readonly environment: EnvironmentFacts,
    matchers: ObjectiveMatcherTable,
  ) {
    this.matchers = { ...matchers };
  }

  /** Build from the async T00 read model port (the async boundary of resolution). */
  static async fromPort(port: RegistryReadModelPort): Promise<ShunRegistry> {
    const capabilities = await port.listCapabilities();
    const [providers, bindings, environment] = await Promise.all([
      port.listProviders(),
      Promise.all(
        capabilities.map((capability) => port.providerCapabilityBindings(capability.capabilityId)),
      ).then((lists) => lists.flat()),
      port.observedFacts(),
    ]);
    return ShunRegistry.fromSnapshot({ capabilities, providers, bindings, environment });
  }

  /** Synchronous construction from already-collected facts (tests, callers holding a snapshot). */
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
    return new ShunRegistry(capabilities, providers, bindingsByCapability, environment, matchers);
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
