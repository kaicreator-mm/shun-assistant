import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import {
  type ActionPlan,
  type AuthorizedAction,
  computePlanHash,
} from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteReadonlySearchAuthorizationBoundary } from '../src/sqlite-effect-boundary.ts';

const now = '2026-10-22T02:00:00.000Z';
const root = 'C:\\approved';
const dispose: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const f of dispose.splice(0).reverse()) await f();
});

function validPlan(): ActionPlan {
  const plan: ActionPlan = {
    taskId: 'task-1',
    capabilityId: 'file.search',
    bindingRefs: ['binding-1'],
    recipeRef: `r1@${'b'.repeat(64)}`,
    rankingPolicyRevision: 'rank-1',
    policySnapshotRevision: 'policy-1',
    actions: [{
      actionId: 'search-1',
      bindingRef: 'binding-1',
      op: 'file.search',
      parameters: { root, query: '*.txt' },
      sideEffectClass: 'R0',
      requiredPrivilege: 'USER',
      filesystemScope: { read: [root], write: [] },
    }],
    verificationPlan: {
      verifierId: 'v1',
      verifierRevision: '1',
      checks: [{ checkId: 'read' }],
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
    planHash: 'a'.repeat(64),
  };
  plan.planHash = computePlanHash(plan);
  return plan;
}

async function world() {
  const folder = mkdtempSync(join(tmpdir(), 'shun-recipe-sqlite-boundary-'));
  const store = new ShunStore({ file: join(folder, 'db.sqlite') });
  dispose.push(async () => {
    await store.close();
    rmSync(folder, { recursive: true, force: true });
  });
  const adapter = new ShunStoreAuthorizationAdapter(store);
  await adapter.saveAuthorityRecord({
    authorityId: 'auth-1',
    authorityRevision: 'rev-1',
    updatedAt: now,
    policyInitialized: true,
  });
  await adapter.savePolicySnapshot({
    policySnapshotRevision: 'policy-1',
    status: 'ACTIVE',
    authorityId: 'auth-1',
    authorityRevision: 'rev-1',
    revokedGrantIds: [],
    rules: [{
      ruleId: 'rule-search-1',
      capabilityId: 'file.search',
      op: 'file.search',
      maxRiskClass: 'R0',
      privilegeLevel: 'USER',
      filesystem: { read: [root], write: [] },
    }],
    riskGuards: [],
    updatedAt: now,
  });
  const authority = new AuthorizationAuthority({
    state: adapter,
    grants: adapter,
    integritySecret: 'private-auth-key',
    issuanceSecret: 'private-issuance-key',
    clock: () => now,
  });
  const controller = new ActionController({
    authority,
    policyState: adapter,
    approvals: { requestApproval: async () => { throw new Error('approval not allowed'); } },
    issuanceSecret: 'private-issuance-key',
    clock: () => now,
  });
  const plan = validPlan();
  const authorized = await controller.authorizePlan({ plan });
  if (!authorized.ok) throw new Error('fixture failed to authorize valid policy');
  const action = authorized.authorization.actions[0];
  if (!action) throw new Error('fixture has no authorized action');
  let dispatches = 0;
  let brokenPlan = false;
  const backend = new SqliteReadonlySearchAuthorizationBoundary({
    store,
    controller,
    loadPlanByHash: async () => brokenPlan ? { ...plan, planHash: '0'.repeat(64) } : plan,
    executeScopedSearch: async () => {
      dispatches++;
      return { source: 'trusted private effect port' };
    },
  });
  return {
    store,adapter,plan,action,backend,
    count: () => dispatches,
    wrongPlan: () => { brokenPlan = true; },
  };
}

describe('T04 real SQLite durable effect authorization before read-only dispatch', () => {
  it('rehydrates the REAL issued SQLite grant and re-enters REAL current ActionController', async () => {
    const v = await world();
    expect(await v.backend.execute(v.action)).toEqual({ source: 'trusted private effect port' });
    expect(v.count()).toBe(1);
    expect((await v.adapter.get(v.action.authorizationRef))).toMatchObject({
      grantId: v.action.authorizationRef,
    });
  });

  it('fails closed on missing stored grant with zero effect dispatch', async () => {
    const v = await world();
    const forged = { ...v.action, authorizationRef: 'nonexistent-grant' };
    await expect(v.backend.execute(forged)).rejects.toThrow('RECIPE_EFFECT_BOUNDARY_REFUSED');
    expect(v.count()).toBe(0);
  });

  it('fails closed on changed/corrupt independent plan hash with zero dispatch', async () => {
    const v = await world();
    v.wrongPlan();
    await expect(v.backend.execute(v.action)).rejects.toThrow('RECIPE_EFFECT_BOUNDARY_REFUSED');
    expect(v.count()).toBe(0);
  });

  it('fails closed on revoked policy after grant issuance and before dispatch', async () => {
    const v = await world();
    const policy = await v.adapter.loadCurrentPolicy();
    if (policy === null || typeof policy !== 'object') throw new Error('fixture has no policy');
    await v.adapter.savePolicySnapshot({ ...policy, status: 'REVOKED' } as never);
    await expect(v.backend.execute(v.action)).rejects.toThrow('RECIPE_EFFECT_BOUNDARY_REFUSED');
    expect(v.count()).toBe(0);
  });

  it('fails closed on wider privilege and switched op after legit issuance', async () => {
    const v = await world();
    const escalated: AuthorizedAction = {
      ...v.action,
      action: { ...v.action.action, op: 'windows.proc.exec', requiredPrivilege: 'ELEVATED' },
    };
    await expect(v.backend.execute(escalated)).rejects.toThrow('RECIPE_EFFECT_BOUNDARY_REFUSED');
    expect(v.count()).toBe(0);
  });

  it('fails closed on missing true host controller/store instead of trusting structural fakes', async () => {
    const v = await world();
    expect(() => new SqliteReadonlySearchAuthorizationBoundary({
      store: v.store,
      controller: {} as ActionController,
      loadPlanByHash: async () => v.plan,
      executeScopedSearch: async () => null,
    })).toThrow(/^RECIPE_BOUNDARY_CONFIGURATION_REFUSED$/);
  });
});
