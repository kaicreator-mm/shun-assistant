import { type ActionPlan, computePlanHash } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { TrustedRecipeReadService } from '../src/trusted-recipe-host.ts';
import type { RecipeReplayCurrentness, RecipeReplaySnapshot } from '../src/recipe-resolver.ts';

const cfg = {
  recipeId: 'recipe-1',
  contractRevision: 'v02-recipe',
  verifierId: 'real-verifier',
  verifierRevision: '1',
};
const source = 'export default defineRecipe({"nodes":[{"actionId":"read","op":"file.search","parameters":{"root":"C:/approved","query":"*.txt"}}],"edges":[]});';

function makeFixture() {
  const revisions = new Map<string, RecipeReplaySnapshot>();
  let planCalls = 0;
  let loads = 0;
  let authorized = 0;
  let policyIsCurrent = true;
  let mutateOnSecond = false;

  const expectedPlan = (revisionSha256: string): ActionPlan => {
    const plan: ActionPlan = {
      taskId: 'task1',
      capabilityId: 'file.search',
      bindingRefs: ['binding1'],
      recipeRef: `recipe-1@${revisionSha256}`,
      rankingPolicyRevision: 'rank-1',
      policySnapshotRevision: 'policy-1',
      actions: [
        {
          actionId: 'read',
          bindingRef: 'binding1',
          op: 'file.search',
          parameters: { root: 'C:/approved', query: '*.txt' },
          sideEffectClass: 'R0',
          requiredPrivilege: 'USER',
          filesystemScope: { read: ['C:/approved'], write: [] },
        },
      ],
      verificationPlan: { verifierId: 'v1', verifierRevision: '1', checks: [{ checkId: 'c1' }] },
      recoveryPlan: {
        classificationStrategy: 'JOURNAL_AND_POST_STATE',
        reconcileBeforeRetry: true,
        retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
      },
      planHash: 'a'.repeat(64),
    };
    plan.planHash = computePlanHash(plan);
    return plan;
  };

  const service = new TrustedRecipeReadService({
    repository: {
      append: (saved) => {
        const key = saved.identity.revisionSha256;
        const existing = revisions.has(key);
        if (!existing) revisions.set(key, saved);
        return {
          recipeId: saved.identity.recipeId,
          revisionSha256: key,
          inserted: !existing,
        };
      },
      get: (_, sha) => {
        loads++;
        return revisions.get(sha) ?? null;
      },
    },
    currentness: (taskId, recipeId): RecipeReplayCurrentness => {
      const saved = [...revisions.values()][0];
      if (!policyIsCurrent || !saved) return { kind: 'UNRESOLVABLE' };
      return {
        kind: 'CURRENT',
        taskId,
        recipeId,
        revisionSha256: saved.identity.revisionSha256,
        actionGraphSha256: saved.identity.actionGraphSha256,
        compilerRevision: saved.identity.compilerRevision,
        contractRevision: saved.identity.contractRevision,
        verifierId: saved.identity.verifierId,
        verifierRevision: saved.identity.verifierRevision,
        registryRevision: 'registry-1',
        policyRevision: 'policy-1',
        scopeRevision: 'scope-1',
        revocationEpoch: 0,
        capability: 'PREVIEW_RECIPE',
      };
    },
    loadExpectedPlan: ({ revisionSha256 }) => {
      planCalls++;
      const plan = expectedPlan(revisionSha256);
      if (mutateOnSecond && planCalls % 2 === 0) {
        plan.rankingPolicyRevision = 'stale-rank';
        plan.planHash = computePlanHash(plan);
      }
      return plan;
    },
    controller: {
      authorizePlan: async () => {
        authorized++;
        return { ok: true };
      },
    },
  });
  return {
    service,
    source,
    cfg,
    loads: () => loads,
    planCalls: () => planCalls,
    authorized: () => authorized,
    invalidate: () => { policyIsCurrent = false; },
    changeBetweenReads: () => { mutateOnSecond = true; },
  };
}

describe('T04 trusted source→T03 exact store→ActionController read-only composition', () => {
  it('persists one immutable candidate and replays the same exact revision without any model call', () => {
    const h = makeFixture();
    const first = h.service.registerLiteral(h.source, h.cfg);
    expect(first).toMatchObject({
      ok: true,
      state: 'PERSISTED_CANDIDATE_ONLY',
      inserted: true,
      modelCalls: 0,
      executionAuthorized: false,
    });
    expect(h.service.registerLiteral(h.source, h.cfg)).toMatchObject({
      ok: true,
      inserted: false,
      executionAuthorized: false,
    });
    if (!first.ok) throw new Error('fixture');
    const preview = h.service.previewExact({
      taskId: 'task1',
      recipeId: first.recipeId,
      revisionSha256: first.revisionSha256,
    });
    expect(preview).toMatchObject({
      ok: true,
      state: 'PREVIEW_ONLY',
      modelCalls: 0,
      executionAuthorized: false,
    });
    expect(h.loads()).toBe(1);
    expect(h.authorized()).toBe(0);
  });

  it('routes exactly trusted read search through authorization with zero execution', async () => {
    const h = makeFixture();
    const record = h.service.registerLiteral(h.source, h.cfg);
    if (!record.ok) throw new Error('fixture');
    const result = await h.service.authorizeReadonlySearch({
      taskId: 'task1',
      recipeId: record.recipeId,
      revisionSha256: record.revisionSha256,
    });
    expect(result).toEqual({
      ok: true,
      stage: 'CONTROLLER_AUTHORIZED_NO_EXECUTION',
      actionCount: 1,
      requiresPerEffectRevalidation: true,
      effectExecuted: false,
    });
    expect(h.loads()).toBe(2);
    expect(h.planCalls()).toBe(2);
    expect(h.authorized()).toBe(1);
  });

  it('refuses changed trusted plan between reads and never reaches controller', async () => {
    const h = makeFixture();
    const record = h.service.registerLiteral(h.source, h.cfg);
    if (!record.ok) throw new Error('fixture');
    h.changeBetweenReads();
    expect(await h.service.authorizeReadonlySearch({
      taskId: 'task1',
      recipeId: record.recipeId,
      revisionSha256: record.revisionSha256,
    })).toEqual({ ok: false, code: 'RECIPE_PLAN_MISMATCH' });
    expect(h.authorized()).toBe(0);
  });

  it('refuses stale policy, missing revision, unsupported source without authority use', async () => {
    const h = makeFixture();
    expect(h.service.registerLiteral('export default eval("bad");', h.cfg)).toEqual({
      ok: false,
      code: 'RECIPE_SOURCE_REFUSED',
    });
    const record = h.service.registerLiteral(h.source, h.cfg);
    if (!record.ok) throw new Error('fixture');
    expect(await h.service.authorizeReadonlySearch({
      taskId: 'task1', recipeId: record.recipeId, revisionSha256: 'a'.repeat(64),
    })).toEqual({ ok: false, code: 'RECIPE_PREVIEW_REFUSED' });
    h.invalidate();
    expect(await h.service.authorizeReadonlySearch({
      taskId: 'task1', recipeId: record.recipeId, revisionSha256: record.revisionSha256,
    })).toEqual({ ok: false, code: 'RECIPE_PREVIEW_REFUSED' });
    expect(h.authorized()).toBe(0);
  });

  it('redacts hostile getter failures during trusted host configuration', () => {
    expect(() => new TrustedRecipeReadService({
      get repository(): never {
        throw new Error('Bearer private-value');
      },
    } as never)).toThrow(/^RECIPE_HOST_CONFIGURATION_REFUSED$/);
  });
});
