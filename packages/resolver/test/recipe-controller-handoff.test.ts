import { type ActionPlan, computePlanHash } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { ReadonlyRecipeControllerHandoff } from '../src/recipe-controller-handoff.ts';
import type { RecipeReplayPreview } from '../src/recipe-resolver.ts';

const sha = 'a'.repeat(64);
function samplePlan(): ActionPlan {
  const draft: ActionPlan = {
    taskId: 'task1',
    capabilityId: 'file.search',
    bindingRefs: ['b1'],
    recipeRef: `r1@${sha}`,
    rankingPolicyRevision: 'rank-1',
    policySnapshotRevision: 'policy-1',
    actions: [
      {
        actionId: 's1',
        bindingRef: 'b1',
        op: 'file.search',
        parameters: { root: 'C:/approved', query: '*.txt' },
        sideEffectClass: 'R0',
        requiredPrivilege: 'USER',
        filesystemScope: { read: ['C:/approved'], write: [] },
      },
    ],
    verificationPlan: {
      verifierId: 'v1',
      verifierRevision: '1',
      checks: [{ checkId: 'bounded-results' }],
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
    planHash: sha,
  };
  draft.planHash = computePlanHash(draft);
  return draft;
}
function preview(): RecipeReplayPreview {
  return {
    ok: true,
    state: 'PREVIEW_ONLY',
    taskId: 'task1',
    recipeId: 'r1',
    revisionSha256: sha,
    actionGraphSha256: 'b'.repeat(64),
    actionGraph: {
      nodes: [
        {
          actionId: 's1',
          op: 'file.search',
          parameters: { root: 'C:/approved', query: '*.txt' },
        },
      ],
      edges: [],
    },
    declaredEffects: ['file.search'],
    modelCalls: 0,
    requiresActionControllerRevalidation: true,
    executionAuthorized: false,
  };
}
function harness(nextPreview: RecipeReplayPreview = preview(), decision = true) {
  const calls: ActionPlan[] = [];
  const trusted = samplePlan();
  const bridge = new ReadonlyRecipeControllerHandoff({
    previewer: { preview: () => nextPreview },
    controller: {
      authorizePlan: async ({ plan }) => {
        calls.push(plan as ActionPlan);
        return { ok: decision };
      },
    },
    trustedPlan: { loadExpectedPlan: () => trusted },
  });
  const input = { taskId: 'task1', recipeId: 'r1', revisionSha256: sha };
  return { bridge, calls, input };
}

describe('T04 R0 Recipe preview → ActionController authorization-only join', () => {
  it('passes only exact canonical single-action read search to controller, never executes', async () => {
    const h = harness();
    const result = await h.bridge.authorizeReadonlySearch({
      ...h.input,
      candidatePlan: samplePlan(),
    });
    expect(result).toEqual({
      ok: true,
      stage: 'CONTROLLER_AUTHORIZED_NO_EXECUTION',
      actionCount: 1,
      requiresPerEffectRevalidation: true,
      effectExecuted: false,
    });
    expect(h.calls).toHaveLength(1);
  });

  it('refuses changed search path, wider read scope and wrong plan hash before controller', async () => {
    const poison = [
      (p: ActionPlan) => {
        p.actions[0]!.parameters.root = 'C:/private';
      },
      (p: ActionPlan) => {
        p.actions[0]!.filesystemScope!.read = ['C:/'];
      },
      (p: ActionPlan) => {
        p.planHash = '0'.repeat(64);
      },
      (p: ActionPlan) => {
        p.recipeRef = `r1@${'f'.repeat(64)}`;
      },
      (p: ActionPlan) => {
        p.actions[0]!.requiredPrivilege = 'ELEVATED';
      },
      (p: ActionPlan) => {
        p.actions[0]!.sideEffectClass = 'R2';
      },
      (p: ActionPlan) => {
        p.actions[0]!.networkScope = { allowed: true, domains: ['evil.invalid'] };
      },
    ];
    for (const change of poison) {
      const h = harness();
      const candidatePlan = samplePlan();
      change(candidatePlan);
      expect(await h.bridge.authorizeReadonlySearch({ ...h.input, candidatePlan })).toEqual({
        ok: false,
        code: 'RECIPE_PLAN_MISMATCH',
      });
      expect(h.calls).toHaveLength(0);
    }
  });

  it('denies a self-rehashed but forged binding/verifier/ranking/options plan', async () => {
    const mutations = [
      (p: ActionPlan) => {
        p.bindingRefs = ['attacker-binding'];
        p.actions[0]!.bindingRef = 'attacker-binding';
      },
      (p: ActionPlan) => {
        p.rankingPolicyRevision = 'attacker-rank';
      },
      (p: ActionPlan) => {
        p.verificationPlan.verifierId = 'attacker-verifier';
      },
      (p: ActionPlan) => {
        p.verificationPlan.verifierRevision = 'stale-verifier-revision';
      },
      (p: ActionPlan) => {
        p.actions[0]!.timeoutMs = 999999;
      },
      (p: ActionPlan) => {
        p.actions[0]!.expectedState = { ignoredByRecipe: true };
      },
    ];
    for (const mutate of mutations) {
      const h = harness();
      const forged = samplePlan();
      mutate(forged);
      forged.planHash = computePlanHash(forged);
      expect(
        await h.bridge.authorizeReadonlySearch({
          ...h.input,
          candidatePlan: forged,
        }),
      ).toEqual({ ok: false, code: 'RECIPE_PLAN_MISMATCH' });
      expect(h.calls).toHaveLength(0);
    }
  });

  it('refuses missing trusted expected-plan identity before controller callback', async () => {
    const calls: unknown[] = [];
    const bridge = new ReadonlyRecipeControllerHandoff({
      previewer: { preview },
      controller: {
        authorizePlan: async (plan) => {
          calls.push(plan);
          return { ok: true };
        },
      },
      trustedPlan: { loadExpectedPlan: () => null },
    });
    const result = await bridge.authorizeReadonlySearch({
      taskId: 'task1',
      recipeId: 'r1',
      revisionSha256: sha,
      candidatePlan: samplePlan(),
    });
    expect(result).toEqual({ ok: false, code: 'RECIPE_PLAN_MISMATCH' });
    expect(calls).toHaveLength(0);
  });

  it('redacts constructor getter/proxy errors before any plan can be authorized', () => {
    const injected = new Error('Bearer private-credential');
    expect(
      () =>
        new ReadonlyRecipeControllerHandoff({
          previewer: {
            get preview(): never {
              throw injected;
            },
          },
          controller: { authorizePlan: async () => ({ ok: true }) },
          trustedPlan: { loadExpectedPlan: () => samplePlan() },
        }),
    ).toThrow(/^RECIPE_CONTROLLER_CONFIGURATION_REFUSED$/);
    expect(
      () =>
        new ReadonlyRecipeControllerHandoff({
          previewer: { preview },
          controller: new Proxy(
            { authorizePlan: async () => ({ ok: true }) },
            {
              get() {
                throw injected;
              },
            },
          ),
          trustedPlan: { loadExpectedPlan: () => samplePlan() },
        }),
    ).toThrow(/^RECIPE_CONTROLLER_CONFIGURATION_REFUSED$/);
  });

  it('refuses changed Recipe operations and dependency edges before controller', async () => {
    const changed = preview();
    if (!changed.ok) throw new Error('fixture');
    changed.actionGraph.nodes[0]!.op = 'file.move' as 'file.search';
    const h = harness(changed);
    expect(
      await h.bridge.authorizeReadonlySearch({ ...h.input, candidatePlan: samplePlan() }),
    ).toEqual({ ok: false, code: 'RECIPE_PLAN_MISMATCH' });
    expect(h.calls).toHaveLength(0);
    const edged = preview();
    if (!edged.ok) throw new Error('fixture');
    edged.actionGraph.edges.push({ from: 's1', to: 's1' });
    const h2 = harness(edged);
    expect(
      await h2.bridge.authorizeReadonlySearch({ ...h2.input, candidatePlan: samplePlan() }),
    ).toEqual({ ok: false, code: 'RECIPE_PLAN_MISMATCH' });
    expect(h2.calls).toHaveLength(0);
  });

  it('cannot turn a preview-only refusal or controller rejection into authorization', async () => {
    const no = harness({ ok: false, code: 'RECIPE_CURRENTNESS_STALE' });
    expect(
      await no.bridge.authorizeReadonlySearch({ ...no.input, candidatePlan: samplePlan() }),
    ).toEqual({ ok: false, code: 'RECIPE_PREVIEW_UNAVAILABLE' });
    expect(no.calls).toHaveLength(0);
    const rejected = harness(preview(), false);
    expect(
      await rejected.bridge.authorizeReadonlySearch({
        ...rejected.input,
        candidatePlan: samplePlan(),
      }),
    ).toEqual({ ok: false, code: 'RECIPE_CONTROLLER_REFUSED' });
  });

  it('redacts throwing host ports and caller accessors with fixed refusal', async () => {
    const h = new ReadonlyRecipeControllerHandoff({
      previewer: {
        preview: () => {
          throw new Error('Bearer private');
        },
      },
      controller: { authorizePlan: async () => ({ ok: true }) },
      trustedPlan: { loadExpectedPlan: () => samplePlan() },
    });
    expect(
      await h.authorizeReadonlySearch({
        taskId: 'task1',
        recipeId: 'r1',
        revisionSha256: sha,
        candidatePlan: samplePlan(),
      }),
    ).toEqual({ ok: false, code: 'RECIPE_HANDOFF_REFUSED' });
  });
});
