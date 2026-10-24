// T04 fixed native-only bootstrap for Shun's trusted Windows Host.
// This module is deliberately NOT exported from the package root.
// Recipe/model/UI code cannot substitute a callback in the host's R0 port.
// Independent post-state and semantic Task verification remain NOT IMPLEMENTED.
import { createSqliteAuthorizedRecipeEffectHost, type SqliteRecipeHostOptions } from './index.ts';
import { executeConservativeNativeR0Search } from './native-r0-effect.ts';
import type { SqliteReadonlySearchGateConfig } from './sqlite-effect-boundary.ts';

type FixedNativeR0HostOptions = SqliteRecipeHostOptions &
  Readonly<{
    loadPlanByHash: SqliteReadonlySearchGateConfig['loadPlanByHash'];
  }>;

/**
 * Only trusted local bootstrap supplies the REAL SQLite store, ActionController,
 * immutable plan loader and currentness. The effect port is fixed by this
 * module, not selected by a Recipe, LLM, UI or plugin.
 *
 * Grant + current policy reentry and durable STARTED always precede the OS
 * call. Until an independent Host post-state oracle exists, the fixed OS port
 * returns UNCERTAIN, never COMPLETED_VERIFIED or Task PASS, and the durable
 * journal forbids automatic duplicate dispatch.
 */
export function createSqliteNativeR0RecipeEffectHost(options: FixedNativeR0HostOptions) {
  try {
    return createSqliteAuthorizedRecipeEffectHost({
      store: options.store,
      controller: options.controller,
      currentness: options.currentness,
      loadExpectedPlan: options.loadExpectedPlan,
      loadPlanByHash: options.loadPlanByHash,
      executeScopedSearch: executeConservativeNativeR0Search,
    });
  } catch {
    throw new Error('R0_NATIVE_HOST_BOOTSTRAP_REFUSED');
  }
}
