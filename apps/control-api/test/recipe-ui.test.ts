import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TrustedRecipeReadService } from '@shun/resolver';
import { ImmutableRecipeRepository, ShunStore } from '@shun/store';
import { describe, expect, it } from 'vitest';
import { DemoShunBackend } from '../src/demo/backend.ts';
import {
  BUILTIN_INVENTORY_RECIPE_ID,
  readBuiltinInventoryCandidate,
  registerBuiltinInventoryCandidate,
} from '../src/inventory-recipe.ts';
import { createControlServer } from '../src/server.ts';
import { startHarness } from './helpers.ts';

describe('T08 C05 — real immutable Recipe candidate save via local UI API', () => {
  it('never advertises a durable Recipe writer in default Demo mode', async () => {
    const h = await startHarness();
    try {
      const denied = await h.post('/api/recipes/builtin/system-inventory/save', {});
      expect(denied).toEqual({
        status: 503,
        body: { ok: false, code: 'RECIPE_STORAGE_UNAVAILABLE' },
      });
      expect(await h.get('/api/recipes/builtin/system-inventory')).toEqual({
        status: 503,
        body: { ok: false, code: 'RECIPE_STORAGE_UNAVAILABLE' },
      });
      expect((await h.get('/api/tasks')).body).toEqual({ tasks: [] });
    } finally {
      await h.close();
    }
  });

  it('saves only the fixed graph in real SQLite with no caller script or grant', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-recipe-ui-'));
    const store = new ShunStore({ file: join(dir, 'recipes.sqlite') });
    let controllerCalls = 0;
    let saveCalls = 0;
    try {
      const repo = new ImmutableRecipeRepository(store);
      const recipeService = new TrustedRecipeReadService({
        repository: {
          append: (item) => repo.append(item),
          get: (recipeId, sha) => repo.get(recipeId, sha),
        },
        currentness: () => ({ kind: 'UNRESOLVABLE' }),
        loadExpectedPlan: () => {
          throw new Error('NO_USER_RECIPE_EXECUTION_IN_C05');
        },
        controller: {
          authorizePlan: async () => {
            controllerCalls++;
            return { ok: false };
          },
        },
      });
      const server = createControlServer({
        backend: new DemoShunBackend(),
        saveBuiltinInventoryCandidate: () => {
          saveCalls++;
          return registerBuiltinInventoryCandidate(recipeService);
        },
        readBuiltinInventoryCandidate: () => {
          const rows = store.database
            .prepare('SELECT revision_sha256 FROM recipe_revisions_v02 WHERE recipe_id = ?')
            .all(BUILTIN_INVENTORY_RECIPE_ID) as Array<{ revision_sha256: string }>;
          return readBuiltinInventoryCandidate(repo, rows.map((row) => row.revision_sha256));
        },
      });
      const port = await server.start();
      const post = async (body: unknown) => {
        const response = await fetch(
          `http://127.0.0.1:${port}/api/recipes/builtin/system-inventory/save`,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
          },
        );
        return {
          status: response.status,
          json: (await response.json()) as Record<string, unknown>,
        };
      };
      try {
        for (const forged of [
          { source: 'export default defineRecipe({evil:true})' },
          { actionGraph: { nodes: [{ op: 'shell.exec' }] } },
          { grant: true },
          ['model-provided-code'],
        ]) {
          const refused = await post(forged);
          expect(refused.status).toBe(400);
          expect(refused.json).toEqual({ ok: false, code: 'RECIPE_INPUT_REFUSED' });
        }
        expect(saveCalls).toBe(0);
        const view = async () => {
          const res = await fetch(`http://127.0.0.1:${port}/api/recipes/builtin/system-inventory`);
          return { status: res.status, body: (await res.json()) as Record<string, unknown> };
        };
        const unsaved = await view();
        expect(unsaved.status).toBe(200);
        expect(unsaved.body).toMatchObject({
          ok: true,
          state: 'NOT_SAVED',
          saved: false,
          revisionSha256: null,
          executionAuthorized: false,
          modelCalls: 0,
        });
        const saved = await post({});
        expect(saved.status).toBe(200);
        expect(saved.json).toMatchObject({
          ok: true,
          state: 'PERSISTED_CANDIDATE_ONLY',
          inserted: true,
          modelCalls: 0,
          executionAuthorized: false,
        });
        const again = await post({});
        expect(again.status).toBe(200);
        expect(again.json).toMatchObject({
          ok: true,
          state: 'PERSISTED_CANDIDATE_ONLY',
          inserted: false,
          modelCalls: 0,
          executionAuthorized: false,
          revisionSha256: saved.json.revisionSha256,
        });
        const verified = await view();
        expect(verified.status).toBe(200);
        expect(verified.body).toEqual({
          ok: true,
          saved: true,
          state: 'PERSISTED_CANDIDATE_ONLY',
          recipeId: saved.json.recipeId,
          revisionSha256: saved.json.revisionSha256,
          executionAuthorized: false,
          modelCalls: 0,
        });
        expect(verified.body).not.toHaveProperty('sourceText');
        expect(verified.body).not.toHaveProperty('actionGraph');
        expect(verified.body).not.toHaveProperty('grant');
        expect(saveCalls).toBe(2);
        expect(controllerCalls).toBe(0);
        const savedSha = saved.json.revisionSha256;
        expect(typeof savedSha).toBe('string');
        const rows = store.database
          .prepare('SELECT recipe_id,revision_sha256 FROM recipe_revisions_v02')
          .all() as Array<{ recipe_id: string; revision_sha256: string }>;
        expect(rows).toHaveLength(1);
        expect(rows[0]?.revision_sha256).toBe(savedSha);
        expect(
          repo.get(rows[0]!.recipe_id, rows[0]!.revision_sha256)?.actionGraph.nodes[0]?.op,
        ).toBe('system.inventory');
      } finally {
        await server.close();
      }
    } finally {
      await store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
