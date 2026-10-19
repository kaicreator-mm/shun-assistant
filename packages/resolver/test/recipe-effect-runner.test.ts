import { type ActionPlan, computePlanHash } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import {
  type TrustedReadonlyEffectHost,
  TrustedReadonlyRecipeEffectRunner,
} from '../src/recipe-effect-runner.ts';
import type { RecipeReplayPreview } from '../src/recipe-resolver.ts';

const sha = 'a'.repeat(64);
const ids = { taskId: 'task-1', recipeId: 'recipe-1', revisionSha256: sha };
const now = '2026-10-19T00:00:00.000Z';

function plan(): ActionPlan {
  const value: ActionPlan = {
    taskId: ids.taskId,
    capabilityId: 'file.search',
    bindingRefs: ['binding-1'],
    recipeRef: `recipe-1@${sha}`,
    rankingPolicyRevision: 'rank-1',
    policySnapshotRevision: 'policy-1',
    actions: [
      {
        actionId: 'search-1',
        bindingRef: 'binding-1',
        op: 'file.search',
        parameters: { root: 'C:/safe', query: '*.txt' },
        sideEffectClass: 'R0',
        requiredPrivilege: 'USER',
        filesystemScope: { read: ['C:/safe'], write: [] },
      },
    ],
    verificationPlan: { verifierId: 'v1', verifierRevision: '1', checks: [{ checkId: 'found' }] },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
    planHash: sha,
  };
  value.planHash = computePlanHash(value);
  return value;
}
function preview(): RecipeReplayPreview {
  return {
    ok: true,
    state: 'PREVIEW_ONLY',
    ...ids,
    actionGraphSha256: 'b'.repeat(64),
    verifierId: 'v1',
    verifierRevision: '1',
    actionGraph: {
      nodes: [
        {
          actionId: 'search-1',
          op: 'file.search',
          parameters: { root: 'C:/safe', query: '*.txt' },
        },
      ],
      edges: [],
    },
    declaredEffects: ['file.search'],
    modelCalls: 0,
    executionAuthorized: false,
    requiresActionControllerRevalidation: true,
  };
}
function fixture() {
  const events: string[] = [];
  let policyRevoked = false;
  let recipeRevoked = false;
  let changedPlan = false;
  let expectedReads = 0;
  let wrongGrant = false;
  let crashBackend = false;
  let blockAuthorization: (() => void) | undefined;
  const gate = new Promise<void>((resolve) => {
    blockAuthorization = resolve;
  });
  let delay = false;
  const host: TrustedReadonlyEffectHost = {
    previewExact: () => {
      events.push('preview');
      return recipeRevoked ? { ok: false, code: 'RECIPE_CURRENTNESS_STALE' } : preview();
    },
    loadExpectedPlan: () => {
      events.push('expected');
      expectedReads++;
      const proposed = plan();
      // First read matches what ActionController granted. After the await,
      // its second read changes ranking-policy revision with a fresh hash.
      if (changedPlan && expectedReads === 2) {
        proposed.rankingPolicyRevision = 'changed';
        proposed.planHash = computePlanHash(proposed);
      }
      return proposed;
    },
    controller: {
      authorizePlan: async ({ plan: proposed }) => {
        events.push('plan');
        if (delay) await gate;
        const p = proposed as ActionPlan;
        const action = {
          taskId: p.taskId,
          actionId: p.actions[0]!.actionId,
          planHash: p.planHash,
          policySnapshotRevision: p.policySnapshotRevision,
          authorizationKind: 'AUTOMATIC' as const,
          authorizationRef: 'grant-1',
          expiresAt: '2026-10-20T00:00:00.000Z',
          action: p.actions[0]!,
        };
        const grant = {
          grantId: wrongGrant ? 'forged' : 'grant-1',
          issuer: { authorityId: 'auth-1', authorityRevision: '1' },
          taskId: p.taskId,
          planHash: p.planHash,
          policySnapshotRevision: p.policySnapshotRevision,
          actionScope: {
            actionIds: [action.actionId],
            privilegeLevel: 'USER' as const,
            filesystem: { read: ['C:/safe'], write: [] },
          },
          issuedAt: now,
          expiresAt: '2026-10-20T00:00:00.000Z',
          integrity: { scheme: 'HMAC_SHA256' as const, value: 'test-integrity' },
        };
        return {
          ok: true as const,
          authorization: { plan: p, actions: [action], grants: [grant] },
        };
      },
      authorizeEffect: async () => {
        events.push('effect');
        return { ok: !policyRevoked };
      },
    },
    backend: {
      execute: async (action) => {
        events.push('execute');
        if (crashBackend) throw new Error('Bearer private');
        return {
          actionId: action.actionId,
          environmentId: 'win-1',
          providerId: 'windows',
          providerVersion: '1',
          startedAt: now,
          finishedAt: now,
          terminal: 'SUCCEEDED' as const,
          outputRefs: [],
          sideEffectEvidence: {
            sideEffectClass: 'R0' as const,
            recoveryClassification: 'COMPLETED_VERIFIED' as const,
            postStateVerified: true,
          },
        };
      },
    },
  };
  return {
    runner: new TrustedReadonlyRecipeEffectRunner(host),
    events,
    revokePolicy: () => {
      policyRevoked = true;
    },
    revokeRecipe: () => {
      recipeRevoked = true;
    },
    driftPlan: () => {
      changedPlan = true;
    },
    forgeGrant: () => {
      wrongGrant = true;
    },
    crash: () => {
      crashBackend = true;
    },
    delayAuth: () => {
      delay = true;
    },
    releaseAuth: () => blockAuthorization?.(),
  };
}

describe('T04 real authorization reentry before read-only Recipe effect', () => {
  it('performs preview→trusted plan→authorizePlan→fresh replay→authorizeEffect→executor in order', async () => {
    const x = fixture();
    expect(await x.runner.run(ids)).toEqual({
      ok: true,
      state: 'EXECUTED_NOT_SEMANTICALLY_VERIFIED',
      actionCount: 1,
      taskPass: false,
    });
    expect(x.events).toEqual([
      'preview',
      'expected',
      'plan',
      'preview',
      'expected',
      'effect',
      'execute',
    ]);
  });

  it('refuses revoked policy at per-effect check with ZERO backend dispatch', async () => {
    const x = fixture();
    x.revokePolicy();
    expect(await x.runner.run(ids)).toEqual({ ok: false, code: 'RECIPE_EFFECT_REFUSED' });
    expect(x.events).not.toContain('execute');
  });

  it('refuses stale Recipe after async plan approval with ZERO backend dispatch', async () => {
    const x = fixture();
    x.delayAuth();
    const active = x.runner.run(ids);
    await Promise.resolve();
    x.revokeRecipe();
    x.releaseAuth();
    expect(await active).toEqual({ ok: false, code: 'RECIPE_NOT_CURRENT' });
    expect(x.events).not.toContain('effect');
    expect(x.events).not.toContain('execute');
  });

  it('refuses forged grant/action binding before per-effect gate', async () => {
    const x = fixture();
    x.forgeGrant();
    expect(await x.runner.run(ids)).toEqual({ ok: false, code: 'RECIPE_AUTHORIZATION_REFUSED' });
    expect(x.events).not.toContain('effect');
    expect(x.events).not.toContain('execute');
  });

  it('serializes same exact Recipe invocation in-process', async () => {
    const x = fixture();
    x.delayAuth();
    const pending = x.runner.run(ids);
    await Promise.resolve();
    expect(await x.runner.run(ids)).toEqual({ ok: false, code: 'RECIPE_AUTHORIZATION_REFUSED' });
    x.releaseAuth();
    await pending;
    expect(x.events.filter((s) => s === 'execute')).toHaveLength(1);
  });

  it('records uncertain effect instead of claiming false zero-effect success', async () => {
    const x = fixture();
    x.crash();
    expect(await x.runner.run(ids)).toEqual({ ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN' });
    expect(x.events).toContain('execute');
  });

  it('refuses input, throwing host constructor getters, and plan drift', async () => {
    const x = fixture();
    expect(await x.runner.run({ ...ids, revisionSha256: 'bad' })).toEqual({
      ok: false,
      code: 'RECIPE_INPUT_REFUSED',
    });
    x.driftPlan();
    expect(await x.runner.run(ids)).toMatchObject({ ok: false });
    expect(
      () =>
        new TrustedReadonlyRecipeEffectRunner({
          get controller(): never {
            throw new Error('Bearer private');
          },
        } as never),
    ).toThrow(/^RECIPE_EFFECT_HOST_CONFIGURATION_REFUSED$/);
  });
});
