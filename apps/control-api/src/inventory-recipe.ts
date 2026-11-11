// T08 C04: a high-ROI built-in, immutable, read-only Recipe CANDIDATE.
// Reuse T04's strict literal compiler and T03's SQLite revision store.
// This module does NOT grant or execute system.inventory, promote ACTIVE,
// run user/model-supplied JS, or call DeepSeek.
import { canonicalJson } from '@shun/contracts';
import type { TrustedRecipeReadService } from '@shun/resolver';
import type { ImmutableRecipeRepository } from '@shun/store';

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

export type BuiltinInventoryReadResult =
  | {
      ok: true;
      saved: boolean;
      state: 'PERSISTED_CANDIDATE_ONLY' | 'NOT_SAVED';
      recipeId: string;
      revisionSha256: string | null;
      executionAuthorized: false;
      modelCalls: 0;
    }
  | { ok: false; code: 'RECIPE_READ_UNAVAILABLE' };

/**
 * Read-only inspection of the existing immutable SQLite records.
 * Existing repository.get validates full revision SHA and payload integrity.
 * We require the exact trusted source/pin; an older or unrelated revision is
 * never represented as the current built-in definition.
 */
export function readBuiltinInventoryCandidate(
  repository: Pick<ImmutableRecipeRepository, 'get'>,
  revisionShas: readonly string[],
): BuiltinInventoryReadResult {
  try {
    if (!Array.isArray(revisionShas) || revisionShas.length > 32) {
      return { ok: false, code: 'RECIPE_READ_UNAVAILABLE' };
    }
    for (const revisionSha256 of revisionShas) {
      if (!/^[a-f0-9]{64}$/.test(revisionSha256)) {
        return { ok: false, code: 'RECIPE_READ_UNAVAILABLE' };
      }
      const actual = repository.get(BUILTIN_INVENTORY_RECIPE_ID, revisionSha256);
      if (!actual) continue;
      if (
        actual.sourceText !== SOURCE ||
        actual.identity.contractRevision !== PIN.contractRevision ||
        actual.identity.verifierId !== PIN.verifierId ||
        actual.identity.verifierRevision !== PIN.verifierRevision
      ) {
        continue;
      }
      const [action] = actual.actionGraph.nodes;
      if (
        actual.actionGraph.nodes.length !== 1 ||
        actual.actionGraph.edges.length !== 0 ||
        action?.op !== 'system.inventory' ||
        action.actionId !== 'read-system-inventory' ||
        action.parameters.includeProcesses !== false ||
        actual.declaredEffects.length !== 1 ||
        actual.declaredEffects[0] !== 'system.inventory'
      ) {
        return { ok: false, code: 'RECIPE_READ_UNAVAILABLE' };
      }
      return {
        ok: true,
        saved: true,
        state: 'PERSISTED_CANDIDATE_ONLY',
        recipeId: BUILTIN_INVENTORY_RECIPE_ID,
        revisionSha256,
        executionAuthorized: false,
        modelCalls: 0,
      };
    }
    return {
      ok: true,
      saved: false,
      state: 'NOT_SAVED',
      recipeId: BUILTIN_INVENTORY_RECIPE_ID,
      revisionSha256: null,
      executionAuthorized: false,
      modelCalls: 0,
    };
  } catch {
    return { ok: false, code: 'RECIPE_READ_UNAVAILABLE' };
  }
}
