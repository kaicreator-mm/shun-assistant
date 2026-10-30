import { describe, expect, it } from 'vitest';
import type { RecipeDefinition } from '../../../../packages/contracts/src/ports.ts';
import type { RecipeActionGraph } from '../../../../packages/contracts/src/v02.ts';
import { DomainComputerRecipeReplayAdapter } from '../../../../packages/domain-computer/src/recipes/recipe-replay.ts';
import type { TrustedActiveRecipeAuthority } from '../../../../packages/resolver/src/active-recipe-resolver.ts';
import type { RecipeReplayPreview } from '../../../../packages/resolver/src/recipe-resolver.ts';

const REVISION = 'a'.repeat(64);
const GRAPH_SHA = 'b'.repeat(64);

function recipe(): RecipeDefinition {
  return {
    recipeId: 'recipe-search-01',
    revision: REVISION,
    capabilityId: 'file.search',
    capabilityRevisionRange: { min: '1' },
    applicabilityPredicate: { objective: 'search documents' },
    parameterSchema: {},
    providerBindingConstraints: {},
    policyRequirements: {},
    riskFloor: 'R0',
    actionTemplate: {
      actionGraphSha256: GRAPH_SHA,
      verificationPlan: {
        verifierId: 'bounded-search-verifier',
        verifierRevision: 'r1',
        checks: [{ checkId: 'search-result-present' }],
      },
    },
    verifierId: 'bounded-search-verifier',
    verifierRevision: 'r1',
    recoveryTemplate: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
    currentnessInputs: ['registryRevision'],
    provenance: { source: 'trusted-promoted-catalog' },
  };
}

type Mode = 'valid' | 'corrupt-source' | 'tampered-graph' | 'unknown-effect' | 'stale-currentness';

function harness(
  options: {
    mode?: Mode;
    lifecycle?: 'ACTIVE' | 'CANDIDATE' | 'RETIRED';
    duplicate?: boolean;
  } = {},
) {
  const selected = recipe();
  const mode = options.mode ?? 'valid';
  let listCalls = 0;
  let previewCalls = 0;
  const modelCalls = 0;
  const previewInputs: Array<{ taskId: string; recipeId: string; revisionSha256: string }> = [];
  const candidate = {
    recipe: selected,
    lifecycle: {
      recipeId: selected.recipeId,
      revision: selected.revision,
      state: options.lifecycle ?? 'ACTIVE',
    },
  };
  const authority: TrustedActiveRecipeAuthority = {
    list: () => {
      listCalls++;
      if (!options.duplicate) return [candidate];
      const secondRecipe = {
        ...selected,
        recipeId: 'recipe-search-02',
        revision: 'c'.repeat(64),
        actionTemplate: { ...selected.actionTemplate, actionGraphSha256: 'd'.repeat(64) },
      };
      return [
        candidate,
        {
          recipe: secondRecipe,
          lifecycle: {
            recipeId: secondRecipe.recipeId,
            revision: secondRecipe.revision,
            state: 'ACTIVE',
          },
        },
      ];
    },
    taskId: () => 'task-01',
    currentFacts: () => ({ registryRevision: 'registry-01' }),
    previewExact: (input): RecipeReplayPreview => {
      previewCalls++;
      previewInputs.push(input);
      if (mode === 'corrupt-source') return { ok: false, code: 'RECIPE_CORRUPT' };
      if (mode === 'stale-currentness') return { ok: false, code: 'RECIPE_CURRENTNESS_STALE' };
      const actionGraph =
        mode === 'unknown-effect'
          ? {
              nodes: [
                {
                  actionId: 'unknown-01',
                  op: 'file.move',
                  parameters: {
                    sourcePath: 'C:/selected/a.txt',
                    destinationPath: 'C:/other/a.txt',
                  },
                },
              ],
              edges: [],
            }
          : {
              nodes: [
                {
                  actionId: 'search-01',
                  op: 'file.search' as const,
                  parameters: { root: 'C:/selected', query: '*.txt' },
                },
              ],
              edges: [],
            };
      return {
        ok: true,
        state: 'PREVIEW_ONLY',
        taskId: 'task-01',
        recipeId: selected.recipeId,
        revisionSha256: selected.revision,
        actionGraphSha256: mode === 'tampered-graph' ? 'c'.repeat(64) : GRAPH_SHA,
        verifierId: selected.verifierId,
        verifierRevision: selected.verifierRevision,
        actionGraph: actionGraph as unknown as RecipeActionGraph,
        declaredEffects: mode === 'unknown-effect' ? ['file.move'] : ['file.search'],
        modelCalls: modelCalls as 0,
        requiresActionControllerRevalidation: true,
        executionAuthorized: false,
      };
    },
  };
  const adapter = new DomainComputerRecipeReplayAdapter(authority);
  return {
    adapter,
    previewInputs,
    listCalls: () => listCalls,
    previewCalls: () => previewCalls,
    modelCalls: () => modelCalls,
  };
}

const intent = {
  objective: 'search documents',
  objects: [],
  constraints: {},
};

describe('T07 deterministic exact-identity Recipe replay adapter', () => {
  it('returns a deterministic proposal pinned to recipe revision and graph hash with zero model calls', async () => {
    const h = harness();
    const first = await h.adapter.proposeExactReplay(intent);
    const second = await h.adapter.proposeExactReplay(intent);

    expect(first).toMatchObject({
      status: 'PROPOSAL_ONLY',
      recipeIdentity: {
        recipeId: 'recipe-search-01',
        revisionSha256: REVISION,
        actionGraphSha256: GRAPH_SHA,
      },
      proposal: {
        proposalId: `recipe:recipe-search-01@${REVISION}`,
        recipeRef: `recipe-search-01@${REVISION}`,
        capabilityId: 'file.search',
        candidateActions: [
          {
            actionId: 'search-01',
            op: 'file.search',
            parameters: { root: 'C:/selected', query: '*.txt' },
          },
        ],
      },
      declaredEffects: ['file.search'],
      modelCalls: 0,
      deterministic: true,
      executionAuthorized: false,
      requiresActionControllerRevalidation: true,
      effectRoute: 'KERNEL_ACTION_CONTROLLER_ONLY',
    });
    expect(second).toEqual(first);
    expect(h.previewInputs).toEqual([
      { taskId: 'task-01', recipeId: 'recipe-search-01', revisionSha256: REVISION },
      { taskId: 'task-01', recipeId: 'recipe-search-01', revisionSha256: REVISION },
      { taskId: 'task-01', recipeId: 'recipe-search-01', revisionSha256: REVISION },
      { taskId: 'task-01', recipeId: 'recipe-search-01', revisionSha256: REVISION },
    ]);
    expect(h.modelCalls()).toBe(0);
    expect('execute' in h.adapter).toBe(false);
    expect(first.status === 'PROPOSAL_ONLY' && Object.isFrozen(first.proposal)).toBe(true);
  });

  it('refuses tampered source, changed graph identity and stale currentness before proposal', async () => {
    for (const mode of ['corrupt-source', 'tampered-graph', 'stale-currentness'] as const) {
      const h = harness({ mode });
      const result = await h.adapter.proposeExactReplay(intent);
      expect(result).toMatchObject({
        status: 'REFUSED',
        code: 'RECIPE_NOT_CURRENT',
        modelCalls: 0,
      });
      expect(h.previewCalls()).toBe(1);
    }
  });

  it('rejects unknown effects rather than widening the registered capability', async () => {
    const h = harness({ mode: 'unknown-effect' });
    expect(await h.adapter.proposeExactReplay(intent)).toMatchObject({
      status: 'REFUSED',
      code: 'REPLAY_REFUSED',
      modelCalls: 0,
    });
  });

  it('refuses ambiguous active recipes and never chooses by display name or order', async () => {
    const h = harness({ duplicate: true });
    expect(await h.adapter.proposeExactReplay(intent)).toMatchObject({
      status: 'REFUSED',
      code: 'AMBIGUOUS_RECIPE',
      modelCalls: 0,
    });
    expect(h.previewCalls()).toBe(0);
  });

  it('returns NO_MATCH for a non-ACTIVE candidate without attempting replay', async () => {
    const h = harness({ lifecycle: 'CANDIDATE' });
    expect(await h.adapter.proposeExactReplay(intent)).toEqual({
      status: 'NO_MATCH',
      modelCalls: 0,
    });
    expect(h.previewCalls()).toBe(0);
  });

  it('rejects caller-supplied approvals, grants, raw graphs and unsupported parameters', async () => {
    const h = harness();
    for (const input of [
      { ...intent, approval: { approved: true } },
      { ...intent, grant: { granted: true } },
      { ...intent, actionGraph: { nodes: [], edges: [] } },
      { ...intent, constraints: { includeHiddenFiles: true } },
      { ...intent, objects: ['C:/private'] },
    ]) {
      expect(await h.adapter.proposeExactReplay(input)).toMatchObject({
        status: 'REFUSED',
        code: 'INVALID_REQUEST',
        modelCalls: 0,
      });
    }
    expect(h.listCalls()).toBe(0);
    expect(h.previewCalls()).toBe(0);
  });

  it('fails closed if the trusted currentness source is unavailable', async () => {
    const authority: TrustedActiveRecipeAuthority = {
      list: () => [
        {
          recipe: recipe(),
          lifecycle: { recipeId: 'recipe-search-01', revision: REVISION, state: 'ACTIVE' },
        },
      ],
      taskId: () => 'task-01',
      currentFacts: () => {
        throw new Error('private authority detail');
      },
      previewExact: () => ({ ok: false, code: 'RECIPE_UNAVAILABLE' }),
    };
    const adapter = new DomainComputerRecipeReplayAdapter(authority);
    await expect(adapter.proposeExactReplay(intent)).resolves.toMatchObject({
      status: 'REFUSED',
      code: 'CURRENTNESS_UNKNOWN',
      modelCalls: 0,
    });
  });

  it('snapshots trusted host methods once and refuses hostile configuration getters', () => {
    expect(
      () =>
        new DomainComputerRecipeReplayAdapter({
          get list(): never {
            throw new Error('private host secret');
          },
        } as never),
    ).toThrow('DOMAIN_RECIPE_CONFIGURATION_REFUSED');
  });
});
