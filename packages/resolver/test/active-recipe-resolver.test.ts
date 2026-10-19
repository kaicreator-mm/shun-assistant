import { createHash } from 'node:crypto';
import { canonicalJson, type RecipeCandidates, type RecipeDefinition } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { BoundedActiveRecipeResolver } from '../src/active-recipe-resolver.ts';
import type { RecipeReplayPreview } from '../src/recipe-resolver.ts';

const sha = 'a'.repeat(64);
const graphSha = 'b'.repeat(64);
const recipe: RecipeDefinition = {
  recipeId: 'r1',
  revision: sha,
  capabilityId: 'file.search',
  capabilityRevisionRange: { min: '1' },
  applicabilityPredicate: { objective: 'search documents' },
  parameterSchema: {},
  providerBindingConstraints: {},
  policyRequirements: {},
  riskFloor: 'R0',
  actionTemplate: {
    actionGraphSha256: graphSha,
    verificationPlan: {
      verifierId: 'v',
      verifierRevision: '1',
      checks: [{ checkId: 'search-result' }],
    },
  },
  verifierId: 'v',
  verifierRevision: '1',
  recoveryTemplate: {
    classificationStrategy: 'JOURNAL_AND_POST_STATE',
    reconcileBeforeRetry: true,
    retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
  },
  currentnessInputs: ['registryRevision'],
  provenance: { source: 'trusted-promoted-catalog' },
};
function fixture() {
  let state: RecipeCandidates['candidates'][number]['lifecycle']['state'] = 'ACTIVE';
  let registryRevision = 'reg-1';
  let previews = 0;
  let mutateGraph = false;
  let catalogVerifier = 'v';
  let catalogVerifierRevision = '1';
  const authority = {
    list: () => {
      const definition = {
        ...recipe,
        verifierId: catalogVerifier,
        verifierRevision: catalogVerifierRevision,
        actionTemplate: {
          ...recipe.actionTemplate,
          verificationPlan: {
            ...(recipe.actionTemplate.verificationPlan as Record<string, unknown>),
            verifierId: catalogVerifier,
            verifierRevision: catalogVerifierRevision,
          },
        },
      };
      return [{ recipe: definition, lifecycle: { recipeId: 'r1', revision: sha, state } }];
    },
    taskId: () => 't1',
    currentFacts: () => ({ registryRevision }),
    previewExact: (_input: {
      taskId: string;
      recipeId: string;
      revisionSha256: string;
    }): RecipeReplayPreview => {
      previews++;
      return {
        ok: true,
        state: 'PREVIEW_ONLY',
        taskId: 't1',
        recipeId: 'r1',
        revisionSha256: sha,
        actionGraphSha256: mutateGraph ? 'c'.repeat(64) : graphSha,
        // These are the independently validated T03 stored revision pins.
        verifierId: 'v',
        verifierRevision: '1',
        actionGraph: {
          nodes: [
            {
              actionId: 's1',
              op: 'file.search',
              parameters: { root: 'C:/selected', query: '*.txt' },
            },
          ],
          edges: [],
        },
        declaredEffects: ['file.search'],
        modelCalls: 0,
        requiresActionControllerRevalidation: true,
        executionAuthorized: false,
      };
    },
  };
  return {
    resolver: new BoundedActiveRecipeResolver(authority),
    setState: (next: typeof state) => {
      state = next;
    },
    setRevision: (next: string) => {
      registryRevision = next;
    },
    tamperGraph: () => {
      mutateGraph = true;
    },
    tamperCatalogVerifier: () => {
      catalogVerifier = 'attacker-verifier';
      catalogVerifierRevision = '2';
    },
    previews: () => previews,
  };
}
const facts = { registryRevision: 'reg-1' };
const intent = { objective: 'search documents', objects: [], constraints: {} };

describe('T04 active RecipeResolverPort exact-source R0 proposal', () => {
  it('matches only eligible ACTIVE narrow search definition, never promotes candidates', async () => {
    const h = fixture();
    expect(await h.resolver.match(intent)).toMatchObject({
      candidates: [{ lifecycle: { state: 'ACTIVE' } }],
    });
    expect((await h.resolver.match({ ...intent, objects: ['private-file'] })).candidates).toEqual(
      [],
    );
    h.setState('CANDIDATE');
    expect((await h.resolver.match(intent)).candidates).toEqual([]);
    h.setState('QUARANTINED');
    expect((await h.resolver.match(intent)).candidates).toEqual([]);
  });

  it('rechecks trusted facts and exact graph SHA before a no-effect plan proposal', async () => {
    const h = fixture();
    expect(await h.resolver.checkCurrentness(recipe, facts)).toEqual({
      outcome: 'CURRENT',
      inputs: { factsSha256: createHash('sha256').update(canonicalJson(facts)).digest('hex') },
    });
    expect(await h.resolver.instantiate(recipe, {}, facts)).toMatchObject({
      capabilityId: 'file.search',
      recipeRef: `r1@${sha}`,
      candidateActions: [
        { actionId: 's1', op: 'file.search', parameters: { root: 'C:/selected' } },
      ],
    });
    expect(h.previews()).toBe(2);
  });

  it('refuses forged Recipe revision, changed live fact, candidate state and tampered graph', async () => {
    const h = fixture();
    expect(
      (await h.resolver.checkCurrentness({ ...recipe, revision: 'c'.repeat(64) }, facts)).outcome,
    ).toBe('UNKNOWN');
    expect((await h.resolver.checkCurrentness(recipe, { registryRevision: 'fake' })).outcome).toBe(
      'UNKNOWN',
    );
    h.setRevision('reg-2');
    await expect(h.resolver.instantiate(recipe, {}, facts)).rejects.toThrow(
      'RECIPE_INSTANTIATION_REFUSED',
    );
    h.setRevision('reg-1');
    h.tamperGraph();
    await expect(h.resolver.instantiate(recipe, {}, facts)).rejects.toThrow(
      'RECIPE_INSTANTIATION_REFUSED',
    );
    h.setState('RETIRED');
    await expect(h.resolver.instantiate(recipe, {}, facts)).rejects.toThrow(
      'RECIPE_INSTANTIATION_REFUSED',
    );
  });

  it('rejects dynamic parameters or unsupported policy gates rather than silently skipping', async () => {
    const h = fixture();
    await expect(h.resolver.instantiate(recipe, { root: 'C:/private' }, facts)).rejects.toThrow(
      'RECIPE_INSTANTIATION_REFUSED',
    );
    expect(
      (await h.resolver.checkCurrentness({ ...recipe, policyRequirements: { admin: true } }, facts))
        .outcome,
    ).toBe('UNKNOWN');
    expect(
      (
        await h.resolver.checkCurrentness(
          { ...recipe, verifierRevision: 'wrong-verifier-revision' },
          facts,
        )
      ).outcome,
    ).toBe('UNKNOWN');
    expect((await h.resolver.match({ ...intent, objective: 'different task' })).candidates).toEqual(
      [],
    );
  });

  it('rejects catalog verifier drift against the unchanged T03 revision identity', async () => {
    const h = fixture();
    // Exact R and graph SHA remain unchanged; the catalog changes BOTH its
    // verifier fields and embedded VerificationPlan consistently.
    h.tamperCatalogVerifier();
    const catalog = (await h.resolver.match(intent)).candidates[0]?.recipe;
    expect(catalog).toBeDefined();
    if (!catalog) throw new Error('fixture');
    expect((await h.resolver.checkCurrentness(catalog, facts)).outcome).toBe('UNKNOWN');
    await expect(h.resolver.instantiate(catalog, {}, facts)).rejects.toThrow(
      'RECIPE_INSTANTIATION_REFUSED',
    );
  });

  it('refuses a catalog capability that is not file.search even with an R0 search graph', async () => {
    const catalog = { ...recipe, capabilityId: 'software.jit_capability_lifecycle' };
    const source = new BoundedActiveRecipeResolver({
      list: () => [
        { recipe: catalog, lifecycle: { recipeId: 'r1', revision: sha, state: 'ACTIVE' } },
      ],
      taskId: () => 't1',
      currentFacts: () => facts,
      previewExact: () => ({
        ok: true,
        state: 'PREVIEW_ONLY',
        taskId: 't1',
        recipeId: 'r1',
        revisionSha256: sha,
        actionGraphSha256: graphSha,
        verifierId: 'v',
        verifierRevision: '1',
        actionGraph: {
          nodes: [
            {
              actionId: 's1',
              op: 'file.search',
              parameters: { root: 'C:/selected', query: '*.txt' },
            },
          ],
          edges: [],
        },
        declaredEffects: ['file.search'],
        modelCalls: 0,
        requiresActionControllerRevalidation: true,
        executionAuthorized: false,
      }),
    });
    expect((await source.match(intent)).candidates).toEqual([]);
    expect((await source.checkCurrentness(catalog, facts)).outcome).toBe('UNKNOWN');
  });

  it('redacts host getters and refuses malformed/duplicate trusted registry', async () => {
    expect(
      () =>
        new BoundedActiveRecipeResolver({
          get list(): never {
            throw new Error('Bearer secret');
          },
        } as never),
    ).toThrow(/^RECIPE_RESOLVER_CONFIGURATION_REFUSED$/);
    const bad = new BoundedActiveRecipeResolver({
      list: () => [
        { recipe, lifecycle: { recipeId: 'r1', revision: sha, state: 'ACTIVE' } },
        { recipe, lifecycle: { recipeId: 'r1', revision: sha, state: 'ACTIVE' } },
      ],
      taskId: () => 't1',
      currentFacts: () => facts,
      previewExact: () => ({ ok: false, code: 'RECIPE_UNAVAILABLE' }),
    });
    await expect(bad.match(intent)).rejects.toThrow(/^RECIPE_RESOLVER_UNAVAILABLE$/);
  });
});
