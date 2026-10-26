import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TrustedRecipeReadService } from '@shun/resolver';
import { ImmutableRecipeRepository, ShunStore } from '@shun/store';
import { describe, expect, it } from 'vitest';
import {
  BUILTIN_INVENTORY_RECIPE_ID,
  registerBuiltinInventoryCandidate,
} from '../src/inventory-recipe.ts';

describe('T08 C04 fixed R0 inventory candidate (no LLM, no auto-execution)', () => {
  it('compiles through existing T04 and durably reuses exact T03 SQLite revision', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-inventory-recipe-'));
    const file = join(dir, 'store.sqlite');
    let authorizationCalls = 0;
    try {
      const store = new ShunStore({ file });
      try {
        const revisions = new ImmutableRecipeRepository(store);
        const service = new TrustedRecipeReadService({
          repository: {
            append: (value) => revisions.append(value),
            get: (recipeId, sha) => revisions.get(recipeId, sha),
          },
          currentness: () => ({ kind: 'UNRESOLVABLE' }),
          loadExpectedPlan: () => {
            throw new Error('NO_ACTIVE_PLAN_IN_CANDIDATE_ONLY');
          },
          controller: {
            authorizePlan: async () => {
              authorizationCalls++;
              return { ok: false };
            },
          },
        });
        const first = registerBuiltinInventoryCandidate(service);
        expect(first).toMatchObject({
          ok: true,
          state: 'PERSISTED_CANDIDATE_ONLY',
          recipeId: BUILTIN_INVENTORY_RECIPE_ID,
          inserted: true,
          modelCalls: 0,
          executionAuthorized: false,
        });
        if (!first.ok) throw new Error('candidate must be immutable');
        const saved = revisions.get(first.recipeId, first.revisionSha256);
        expect(saved?.actionGraph).toEqual({
          nodes: [
            {
              actionId: 'read-system-inventory',
              op: 'system.inventory',
              parameters: { includeProcesses: false },
            },
          ],
          edges: [],
        });
        expect(saved?.declaredEffects).toEqual(['system.inventory']);
        const again = registerBuiltinInventoryCandidate(service);
        expect(again).toMatchObject({
          ok: true,
          state: 'PERSISTED_CANDIDATE_ONLY',
          revisionSha256: first.revisionSha256,
          inserted: false,
          modelCalls: 0,
          executionAuthorized: false,
        });
        // In the absence of trusted live policy/currentness, not even the
        // R0 immutable candidate is automatically preview-current.
        expect(
          service.previewExact({
            taskId: 'r0-diagnosis',
            recipeId: first.recipeId,
            revisionSha256: first.revisionSha256,
          }),
        ).toEqual({ ok: false, code: 'RECIPE_CURRENTNESS_UNKNOWN' });
        expect(authorizationCalls).toBe(0);
      } finally {
        await store.close();
      }

      // A fresh store instance (same physical SQLite file) sees the identical
      // immutable SHA; no model request or new source compilation is needed.
      const reopened = new ShunStore({ file });
      try {
        const repo = new ImmutableRecipeRepository(reopened);
        const rows = reopened.database
          .prepare('SELECT recipe_id, revision_sha256 FROM recipe_revisions_v02')
          .all() as Array<{ recipe_id: string; revision_sha256: string }>;
        expect(rows).toHaveLength(1);
        expect(rows[0]?.recipe_id).toBe(BUILTIN_INVENTORY_RECIPE_ID);
        const saved = repo.get(rows[0]!.recipe_id, rows[0]!.revision_sha256);
        expect(saved?.actionGraph.nodes[0]?.op).toBe('system.inventory');
      } finally {
        await reopened.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails closed on missing trusted Recipe host; cannot promote or dispatch', () => {
    expect(registerBuiltinInventoryCandidate({} as TrustedRecipeReadService)).toEqual({
      ok: false,
      code: 'RECIPE_SOURCE_REFUSED',
    });
  });
});
