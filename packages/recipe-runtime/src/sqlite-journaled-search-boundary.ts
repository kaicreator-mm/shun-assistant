// T04 restricted private host composition. All authorization verification,
// cross-process duplicate refusal and pre-effect commit belong to separately
// reviewed components; do NOT expose this factory to Recipe/model/HTTP.
// Actual native R0 file.search and trusted post-state receipt provenance
// remain a separate host-owned capability and Windows qualification.
import { ActionController } from '@shun/authorization';
import type { AuthorizedAction } from '@shun/contracts';
import { ShunStore } from '@shun/store';
import { JournaledR0SearchCapability } from './journaled-r0-search.ts';
import { SqliteReadonlySearchAuthorizationBoundary } from './sqlite-effect-boundary.ts';
import { SqliteR0EffectJournal } from './sqlite-r0-effect-journal.ts';

export type SqliteJournaledSearchBoundaryConfig = Readonly<{
  store: ShunStore;
  controller: ActionController;
  /** Trusted host loads an immutable expected ActionPlan by its exact hash. */
  loadPlanByHash: (hash: string) => Promise<unknown>;
  /** Trusted private Windows host: must produce genuine independent effect receipts. */
  executeScopedSearch: (action: AuthorizedAction) => Promise<unknown>;
}>;

/**
 * Revalidates real persisted grant+plan+current policy before writing a
 * durable one-shot STARTED to the same SQLite store. On any ambiguity the
 * dispatcher rejects without replaying; it does not confer semantic PASS.
 *
 * This class intentionally does not turn an arbitrary injected callback into
 * a trusted OS primitive. Its caller must be the fixed private host bootstrap.
 */
export class SqliteJournaledSearchAuthorizationBoundary {
  private readonly gate: SqliteReadonlySearchAuthorizationBoundary;

  constructor(config: SqliteJournaledSearchBoundaryConfig) {
    try {
      if (
        !(config?.store instanceof ShunStore) ||
        !(config?.controller instanceof ActionController) ||
        typeof config.loadPlanByHash !== 'function' ||
        typeof config.executeScopedSearch !== 'function'
      )
        throw new Error('R0_PRIVATE_BOOTSTRAP_REFUSED');
      const journal = new SqliteR0EffectJournal(config.store);
      const journaled = new JournaledR0SearchCapability({
        journal,
        effect: config.executeScopedSearch.bind(config),
      });
      this.gate = new SqliteReadonlySearchAuthorizationBoundary({
        store: config.store,
        controller: config.controller,
        loadPlanByHash: config.loadPlanByHash.bind(config),
        executeScopedSearch: (action) => journaled.execute(action),
      });
    } catch {
      throw new Error('R0_PRIVATE_BOOTSTRAP_REFUSED');
    }
  }

  execute(action: AuthorizedAction): Promise<unknown> {
    return this.gate.execute(action);
  }
}
