import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import { type ActionPlan, computePlanHash } from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SqliteJournaledSearchAuthorizationBoundary } from '../src/sqlite-journaled-search-boundary.ts';
import { SqliteR0EffectJournal } from '../src/sqlite-r0-effect-journal.ts';

const timestamp = '2026-10-22T02:00:00.000Z';
const root = 'C:\\approved';
const disposers: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const dispose of disposers.splice(0).reverse()) await dispose();
});

function validPlan(): ActionPlan {
  const plan: ActionPlan = {
    taskId: 'task-1',
    capabilityId: 'file.search',
    bindingRefs: ['binding-1'],
    recipeRef: `r1@${'b'.repeat(64)}`,
    rankingPolicyRevision: 'rank-1',
    policySnapshotRevision: 'policy-1',
    actions: [
      {
        actionId: 'search-1',
        bindingRef: 'binding-1',
        op: 'file.search',
        parameters: { root, query: '*.txt' },
        sideEffectClass: 'R0',
        requiredPrivilege: 'USER',
        filesystemScope: { read: [root], write: [] },
      },
    ],
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

async function setup() {
  const folder = mkdtempSync(join(tmpdir(), 'shun-t04-composed-'));
  const file = join(folder, 'business.sqlite');
  const store = new ShunStore({ file });
  disposers.push(async () => {
    await store.close();
    rmSync(folder, { recursive: true, force: true });
  });
  const adapter = new ShunStoreAuthorizationAdapter(store);
  await adapter.saveAuthorityRecord({
    authorityId: 'auth-1',
    authorityRevision: 'rev-1',
    updatedAt: timestamp,
    policyInitialized: true,
  });
  await adapter.savePolicySnapshot({
    policySnapshotRevision: 'policy-1',
    status: 'ACTIVE',
    authorityId: 'auth-1',
    authorityRevision: 'rev-1',
    revokedGrantIds: [],
    rules: [
      {
        ruleId: 'allow-single-search',
        capabilityId: 'file.search',
        op: 'file.search',
        maxRiskClass: 'R0',
        privilegeLevel: 'USER',
        filesystem: { read: [root], write: [] },
      },
    ],
    riskGuards: [],
    updatedAt: timestamp,
  });
  const authority = new AuthorizationAuthority({
    state: adapter,
    grants: adapter,
    integritySecret: 'private-test-integrity',
    issuanceSecret: 'private-test-issuance',
    clock: () => timestamp,
  });
  const controller = new ActionController({
    authority,
    policyState: adapter,
    approvals: {
      requestApproval: async () => {
        throw new Error('approval cannot be reached');
      },
    },
    issuanceSecret: 'private-test-issuance',
    clock: () => timestamp,
  });
  const plan = validPlan();
  const authorized = await controller.authorizePlan({ plan });
  if (!authorized.ok) throw new Error('no real persisted grant');
  const action = authorized.authorization.actions[0];
  if (!action) throw new Error('missing issued action');
  const receipt = {
    actionId: action.actionId,
    environmentId: 'synthetic-private-host',
    providerId: 'test-native-port',
    providerVersion: 'test-only',
    startedAt: timestamp,
    finishedAt: timestamp,
    terminal: 'SUCCEEDED',
    outputRefs: [],
    sideEffectEvidence: {
      sideEffectClass: 'R0',
      recoveryClassification: 'COMPLETED_VERIFIED',
      postStateVerified: true,
    },
  };
  return { store, adapter, controller, plan, action, receipt };
}

describe('T04 composed real SQLite grant gate + durable journal (synthetic OS receipt)', () => {
  it('runs one persisted-grant current-policy checked R0 effect, then refuses replay across two objects', async () => {
    const x = await setup();
    const executeScopedSearch = vi.fn(async () => x.receipt);
    const options = {
      store: x.store,
      controller: x.controller,
      loadPlanByHash: async () => x.plan,
      executeScopedSearch,
    };
    const first = new SqliteJournaledSearchAuthorizationBoundary(options);
    expect(await first.execute(x.action)).toMatchObject({ terminal: 'SUCCEEDED' });
    expect(executeScopedSearch).toHaveBeenCalledTimes(1);
    expect(new SqliteR0EffectJournal(x.store).lookup(x.action)).toMatchObject({
      ok: true,
      state: 'OBSERVED_NOT_SEMANTICALLY_VERIFIED',
      semanticVerified: false,
    });
    const second = new SqliteJournaledSearchAuthorizationBoundary(options);
    await expect(second.execute(x.action)).rejects.toThrow('RECIPE_EFFECT_BOUNDARY_REFUSED');
    expect(executeScopedSearch).toHaveBeenCalledTimes(1);
  });

  it('revoked policy or corrupt plan refuses before journal reservation or OS execution', async () => {
    const x = await setup();
    const executeScopedSearch = vi.fn(async () => x.receipt);
    let broken = true;
    const gate = new SqliteJournaledSearchAuthorizationBoundary({
      store: x.store,
      controller: x.controller,
      loadPlanByHash: async () => (broken ? { ...x.plan, planHash: '0'.repeat(64) } : x.plan),
      executeScopedSearch,
    });
    await expect(gate.execute(x.action)).rejects.toThrow('RECIPE_EFFECT_BOUNDARY_REFUSED');
    expect(new SqliteR0EffectJournal(x.store).lookup(x.action)).toEqual({
      ok: false,
      code: 'NOT_FOUND',
    });
    broken = false;
    const policy = await x.adapter.loadCurrentPolicy();
    if (!policy) throw new Error('fixture lacks policy');
    await x.adapter.savePolicySnapshot({ ...policy, status: 'REVOKED' });
    await expect(gate.execute(x.action)).rejects.toThrow('RECIPE_EFFECT_BOUNDARY_REFUSED');
    expect(executeScopedSearch).not.toHaveBeenCalled();
    expect(new SqliteR0EffectJournal(x.store).lookup(x.action)).toEqual({
      ok: false,
      code: 'NOT_FOUND',
    });
  });

  it('ambiguous synthetically reported recovery remains persistently uncertain and is never re-dispatched', async () => {
    const x = await setup();
    const executeScopedSearch = vi.fn(async () => ({
      ...x.receipt,
      sideEffectEvidence: {
        ...x.receipt.sideEffectEvidence,
        recoveryClassification: 'NOT_STARTED',
        postStateVerified: false,
      },
    }));
    const gate = new SqliteJournaledSearchAuthorizationBoundary({
      store: x.store,
      controller: x.controller,
      loadPlanByHash: async () => x.plan,
      executeScopedSearch,
    });
    await expect(gate.execute(x.action)).rejects.toThrow('RECIPE_EFFECT_BOUNDARY_REFUSED');
    expect(new SqliteR0EffectJournal(x.store).lookup(x.action)).toMatchObject({
      ok: true,
      state: 'UNCERTAIN',
      semanticVerified: false,
    });
    await expect(gate.execute(x.action)).rejects.toThrow('RECIPE_EFFECT_BOUNDARY_REFUSED');
    expect(executeScopedSearch).toHaveBeenCalledTimes(1);
  });

  it('cannot construct on an in-memory SQLite store or a fake ActionController', async () => {
    const ephemeral = new ShunStore({ file: ':memory:' });
    try {
      const x = await setup();
      expect(
        () =>
          new SqliteJournaledSearchAuthorizationBoundary({
            store: ephemeral,
            controller: x.controller,
            loadPlanByHash: async () => x.plan,
            executeScopedSearch: async () => x.receipt,
          }),
      ).toThrow('R0_PRIVATE_BOOTSTRAP_REFUSED');
      expect(
        () =>
          new SqliteJournaledSearchAuthorizationBoundary({
            store: x.store,
            controller: {} as ActionController,
            loadPlanByHash: async () => x.plan,
            executeScopedSearch: async () => x.receipt,
          }),
      ).toThrow('R0_PRIVATE_BOOTSTRAP_REFUSED');
    } finally {
      await ephemeral.close();
    }
  });
});
