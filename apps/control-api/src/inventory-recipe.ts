// T08 C04: a high-ROI built-in, immutable, read-only Recipe CANDIDATE.
// Reuse T04's strict literal compiler and T03's SQLite revision store.
// This module does NOT grant or execute system.inventory, promote ACTIVE,
// run user/model-supplied JS, or call DeepSeek.
import { canonicalJson } from '@shun/contracts';
import { compileLiteralRecipe, type TrustedRecipeReadService } from '@shun/resolver';

export const BUILTIN_INVENTORY_RECIPE_ID = 'shun.builtin.system-inventory.readonly.v02';

const SOURCE = `export default defineRecipe(${canonicalJson({
  nodes: [
    {
      actionId: 'read-system-inventory',
      op: 'system.inventory',
      parameters: { includeProcesses: false },
    },
  ],
  edges: [],
})});`;

const PIN = Object.freeze({
  recipeId: BUILTIN_INVENTORY_RECIPE_ID,
  contractRevision: 'v0.2',
  verifierId: 'verifier.system-inventory.local-readonly',
  verifierRevision: '1',
});

/**
 * Private trusted-host registration only. Existing T04 compiler validates
 * the exact frozen one-node graph, and the existing T03 repository persists
 * its SHA identity. The caller injects its already trusted Recipe service;
 * no new writer, interpreter or caller-selected graph is admitted here.
 */
export function registerBuiltinInventoryCandidate(
  host: Pick<TrustedRecipeReadService, 'registerLiteral'>,
): ReturnType<TrustedRecipeReadService['registerLiteral']> {
  try {
    if (typeof host?.registerLiteral !== 'function') {
      return { ok: false, code: 'RECIPE_SOURCE_REFUSED' };
    }
    return host.registerLiteral(SOURCE, PIN);
  } catch {
    return { ok: false, code: 'RECIPE_STORE_REFUSED' };
  }
}

/** Pure identity of the built-in source; never reads or writes local storage. */
export function expectedBuiltinInventoryIdentity() {
  const compiled = compileLiteralRecipe(SOURCE, PIN);
  if (!compiled.ok) throw new Error('BUILTIN_RECIPE_INVALID');
  return compiled.compiled.identity;
}
