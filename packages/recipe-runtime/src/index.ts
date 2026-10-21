// T04 concrete private host composition: real T03 SQLite revision repository
// and the real, policy-backed ActionController. This is not an HTTP endpoint,
// Recipe promotion surface, grant issuer or execution service.
import { ActionController } from '@shun/authorization';
import {
  type TrustedRecipeHost,
  TrustedRecipeReadService,
} from '@shun/resolver';
import { ImmutableRecipeRepository, ShunStore } from '@shun/store';

/** Actual host-only ports: trusted currentness and a host-derived plan. */
export type SqliteRecipeHostOptions = Readonly<{
  store: ShunStore;
  controller: ActionController;
  currentness: TrustedRecipeHost['currentness'];
  loadExpectedPlan: TrustedRecipeHost['loadExpectedPlan'];
}>;

/**
 * Wires real immutable SQLite bytes and real controller method identity.
 * The caller MUST be the trusted private host. A browser/model/Recipe cannot
 * inject currentness or a plan. A separate T04 effect runner and Windows host
 * integration must prove per-effect reentry and durable recovery.
 */
export function createSqliteRecipeReadService(
  options: SqliteRecipeHostOptions,
): TrustedRecipeReadService {
  try {
    const store = options?.store;
    const controller = options?.controller;
    const currentness = options?.currentness;
    const loadExpectedPlan = options?.loadExpectedPlan;
    if (
      !(store instanceof ShunStore) ||
      !(controller instanceof ActionController) ||
      typeof currentness !== 'function' ||
      typeof loadExpectedPlan !== 'function'
    ) {
      throw new Error('RECIPE_SQLITE_HOST_CONFIGURATION_REFUSED');
    }
    const repo = new ImmutableRecipeRepository(store);
    return new TrustedRecipeReadService({
      repository: {
        append: (revision) => repo.append(revision),
        get: (recipeId, revisionSha256) => repo.get(recipeId, revisionSha256),
      },
      currentness: currentness.bind(options),
      loadExpectedPlan: loadExpectedPlan.bind(options),
      controller: {
        authorizePlan: (input) => controller.authorizePlan(input),
      },
    });
  } catch {
    // No internal DB path, HMAC key, policy or model content leaks.
    throw new Error('RECIPE_SQLITE_HOST_CONFIGURATION_REFUSED');
  }
}
