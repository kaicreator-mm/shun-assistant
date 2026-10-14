import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalJson, computeRecipeRevision } from '@shun/contracts';
import { afterEach, describe, expect, it } from 'vitest';
import { ImmutableRecipeRepository, RecipeStoreError } from '../src/recipe-repository.ts';
import { ShunStore } from '../src/shun-store.ts';

const dirs: string[] = [];
const stores: ShunStore[] = [];
afterEach(async () => {
  for (const store of stores.splice(0)) await store.close();
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function digest(s: string): string {
  return createHash('sha256').update(s).digest('hex');
}

function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'shun-recipe-v02-'));
  dirs.push(dir);
  const file = join(dir, 'business.sqlite');
  const store = new ShunStore({ file });
  stores.push(store);
  return { store, repo: new ImmutableRecipeRepository(store), file };
}

function fixture(sourceText = 'user selected file operation: report only') {
  const actionGraph = {
    nodes: [
      {
        actionId: 'discover',
        op: 'file.search' as const,
        parameters: { root: 'C:/approved', query: '*.txt' },
      },
    ],
    edges: [],
  };
  const compiledArtifact = 'opaque-typed-artifact-v02-never-executable';
  const declaredEffects = ['file.search'];
  const identityBase = {
    recipeId: 'recipe-1',
    sourceSha256: digest(sourceText),
    actionGraphSha256: digest(canonicalJson(actionGraph)),
    compiledSha256: digest(compiledArtifact),
    declaredEffectsSha256: digest(canonicalJson(declaredEffects)),
    compilerRevision: 'compiler-1',
    contractRevision: 'contract-1',
    verifierId: 'safe-verifier',
    verifierRevision: 'v1',
  };
  return {
    identity: { ...identityBase, revisionSha256: computeRecipeRevision(identityBase) },
    sourceText,
    actionGraph,
    compiledArtifact,
    declaredEffects,
  };
}

describe('T03 immutable Recipe revisions', () => {
  it('appends exact revision once; survives clean restart without model/provider calls', async () => {
    const { store, repo, file } = setup();
    const revision = fixture();
    expect(repo.append(revision)).toMatchObject({ inserted: true });
    expect(repo.append(revision)).toMatchObject({ inserted: false });
    expect(repo.get(revision.identity.recipeId, revision.identity.revisionSha256)).toEqual(
      revision,
    );
    await store.close();
    stores.splice(stores.indexOf(store), 1);
    const reopened = new ShunStore({ file });
    stores.push(reopened);
    const later = new ImmutableRecipeRepository(reopened);
    expect(later.get(revision.identity.recipeId, revision.identity.revisionSha256)).toEqual(
      revision,
    );
  });

  it('rejects changed source, graph, compiled artifact and declared effects under the same digest', () => {
    const { repo } = setup();
    const base = fixture();
    expect(repo.append(base).inserted).toBe(true);
    const drifts = [
      { ...base, sourceText: 'changed source' },
      { ...base, compiledArtifact: 'modified compiled bytes' },
      {
        ...base,
        actionGraph: {
          ...base.actionGraph,
          nodes: [
            { ...base.actionGraph.nodes[0], parameters: { root: 'C:/elsewhere', query: '*.txt' } },
          ],
        },
      },
      { ...base, declaredEffects: ['file.copy'] },
      { ...base, identity: { ...base.identity, verifierRevision: 'attacker' } },
    ];
    for (const drift of drifts) {
      expect(() => repo.append(drift)).toThrow(RecipeStoreError);
    }
    expect(repo.get(base.identity.recipeId, base.identity.revisionSha256)).toEqual(base);
  });

  it('allows a successor immutable revision under the same logical recipe id', () => {
    const { repo } = setup();
    const one = fixture();
    const two = fixture('changed source makes a distinct revision');
    repo.append(one);
    repo.append(two);
    expect(one.identity.revisionSha256).not.toBe(two.identity.revisionSha256);
    expect(repo.get(one.identity.recipeId, one.identity.revisionSha256)).toEqual(one);
    expect(repo.get(two.identity.recipeId, two.identity.revisionSha256)).toEqual(two);
  });

  it('fails closed on UPDATE/DELETE/REPLACE and detects journal tampering', () => {
    const { store, repo } = setup();
    const f = fixture();
    repo.append(f);
    // SQLite REPLACE otherwise bypasses DELETE triggers when recursive_triggers=OFF.
    store.database.exec('PRAGMA recursive_triggers=OFF');
    expect(() =>
      store.database
        .prepare(`INSERT OR REPLACE INTO recipe_revisions_v02
          (recipe_id, revision_sha256, payload, payload_sha256, created_at)
          VALUES (?, ?, ?, ?, ?)`)
        .run(f.identity.recipeId, f.identity.revisionSha256, 'forged', '0'.repeat(64), '2026-10-15T00:00:00.000Z'),
    ).toThrow();
    expect(repo.get(f.identity.recipeId, f.identity.revisionSha256)).toEqual(f);
    expect(() =>
      store.database
        .prepare('UPDATE recipe_revisions_v02 SET payload = ? WHERE recipe_id = ?')
        .run('forged', f.identity.recipeId),
    ).toThrow();
    expect(() =>
      store.database
        .prepare('DELETE FROM recipe_revisions_v02 WHERE recipe_id = ?')
        .run(f.identity.recipeId),
    ).toThrow();
    // Underlying trust model excludes a privileged attacker that removes DB
    // guards, but corruption must NEVER be interpreted as an enabled Recipe.
    store.database.exec('DROP TRIGGER recipe_revisions_v02_no_update');
    store.database
      .prepare('UPDATE recipe_revisions_v02 SET payload = ? WHERE recipe_id = ?')
      .run('forged', f.identity.recipeId);
    expect(() => repo.get(f.identity.recipeId, f.identity.revisionSha256)).toThrow(
      'RECIPE_CORRUPT',
    );
  });

  it('rolls back on commit failure; never leaves a partial revision', () => {
    const { store, repo } = setup();
    const f = fixture();
    store.database.exec(`
      CREATE TRIGGER recipe_block_insert BEFORE INSERT ON recipe_revisions_v02
      BEGIN SELECT RAISE(ABORT, 'simulated disk fault'); END
    `);
    expect(() => repo.append(f)).toThrow('RECIPE_STORE_UNAVAILABLE');
    expect(repo.get(f.identity.recipeId, f.identity.revisionSha256)).toBeNull();
    store.database.exec('DROP TRIGGER recipe_block_insert');
    expect(repo.append(f).inserted).toBe(true);
  });
});
