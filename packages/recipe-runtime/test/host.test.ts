import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import { type ActionPlan, computePlanHash } from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createSqliteAuthorizedRecipeEffectHost,
  createSqliteRecipeReadService,
  type SqliteRecipeHostOptions,
} from '../src/index.ts';
import { createSqliteNativeR0RecipeEffectHost } from '../src/sqlite-native-r0-host.ts';

const config = {
  recipeId: 'recipe-1',
  contractRevision: 'contract-1',
  verifierId: 'verifier-1',
  verifierRevision: '1',
};
const source =
  'export default defineRecipe({"nodes":[{"actionId":"read","op":"file.search","parameters":{"root":"C:/approved","query":"*.txt"}}],"edges":[]});';

const cleanup: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const task of cleanup.splice(0).reverse()) await task();
});

function fixture(root = 'C:/approved') {
  const dir = mkdtempSync(join(tmpdir(), 'shun-v02-real-recipe-'));
  const dbPath = join(dir, 'business.sqlite');
  let store = new ShunStore({ file: dbPath });
  cleanup.push(async () => {
    await store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  let stale = false;
  let planLoads = 0;
  const now = '2026-10-22T00:00:00.000Z';

  function attach(currentStore: ShunStore) {
    const adapter = new ShunStoreAuthorizationAdapter(currentStore);
    const issuer = new AuthorizationAuthority({
      state: adapter,
      grants: adapter,
      integritySecret: 'private-integrity-fixture',
      issuanceSecret: 'private-issuance-fixture',
      clock: () => now,
    });
    const controller = new ActionController({
      authority: issuer,
      policyState: adapter,
      approvals: {
        requestApproval: async () => {
          throw new Error('approval must be unreachable with no ACTIVE policy');
        },
      },
      issuanceSecret: 'private-issuance-fixture',
      clock: () => now,
    });
    let revision:
      | {
          recipeId: string;
          revisionSha256: string;
        }
      | undefined;
    const host: SqliteRecipeHostOptions = {
      store: currentStore,
      controller,
      currentness: (taskId, recipeId) => {
        if (stale || !revision) return { kind: 'UNRESOLVABLE' };
        const saved = currentStore.database
          .prepare(
            'SELECT payload FROM recipe_revisions_v02 WHERE recipe_id = ? AND revision_sha256 = ?',
          )
          .get(recipeId, revision.revisionSha256) as { payload: string } | undefined;
        if (!saved) return { kind: 'UNRESOLVABLE' };
        const identity = (
          JSON.parse(saved.payload) as {
            identity: {
              revisionSha256: string;
              actionGraphSha256: string;
              compilerRevision: string;
              contractRevision: string;
              verifierId: string;
              verifierRevision: string;
            };
          }
        ).identity;
        return {
          kind: 'CURRENT',
          taskId,
          recipeId,
          revisionSha256: identity.revisionSha256,
          actionGraphSha256: identity.actionGraphSha256,
          compilerRevision: identity.compilerRevision,
          contractRevision: identity.contractRevision,
          verifierId: identity.verifierId,
          verifierRevision: identity.verifierRevision,
          registryRevision: 'registry-1',
          policyRevision: 'policy-1',
          scopeRevision: 'scope-1',
          revocationEpoch: 0,
          capability: 'PREVIEW_RECIPE',
        };
      },
      loadExpectedPlan: ({ taskId, recipeId, revisionSha256 }) => {
        planLoads++;
        const plan: ActionPlan = {
          taskId,
          capabilityId: 'file.search',
          bindingRefs: ['binding-1'],
          recipeRef: `${recipeId}@${revisionSha256}`,
          rankingPolicyRevision: 'rank-1',
          policySnapshotRevision: 'policy-1',
          actions: [
            {
              actionId: 'read',
              bindingRef: 'binding-1',
              op: 'file.search',
              parameters: { root, query: '*.txt' },
              sideEffectClass: 'R0',
              requiredPrivilege: 'USER',
              filesystemScope: { read: [root], write: [] },
            },
          ],
          verificationPlan: {
            verifierId: 'verifier-1',
            verifierRevision: '1',
            checks: [{ checkId: 'valid' }],
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
      },
    };
    const service = createSqliteRecipeReadService(host);
    return {
      service,
      controller,
      host,
      adapter,
      attachRevision: (id: typeof revision) => {
        revision = id;
      },
    };
  }

  return {
    attach,
    getStore: () => store,
    restart: async () => {
      await store.close();
      store = new ShunStore({ file: dbPath });
      return attach(store);
    },
    invalidate: () => {
      stale = true;
    },
    planLoads: () => planLoads,
  };
}

describe('T04 real SQLite Recipe host + actual ActionController read-only boundary', () => {
  it('persists immutable literal candidate across SQLite restart without model or grant', async () => {
    const f = fixture();
    const first = f.attach(f.getStore());
    const saved = first.service.registerLiteral(source, config);
    expect(saved).toMatchObject({
      ok: true,
      state: 'PERSISTED_CANDIDATE_ONLY',
      inserted: true,
      modelCalls: 0,
      executionAuthorized: false,
    });
    if (!saved.ok) throw new Error('fixture register failed');
    first.attachRevision(saved);
    expect(first.service.previewExact({ taskId: 'task-1', ...saved })).toMatchObject({
      ok: true,
      state: 'PREVIEW_ONLY',
      executionAuthorized: false,
      modelCalls: 0,
    });
    const reopened = await f.restart();
    reopened.attachRevision(saved);
    expect(reopened.service.registerLiteral(source, config)).toMatchObject({
      ok: true,
      inserted: false,
    });
    const exact = reopened.service.previewExact({
      taskId: 'task-1',
      recipeId: saved.recipeId,
      revisionSha256: saved.revisionSha256,
    });
    expect(exact).toMatchObject({
      ok: true,
      state: 'PREVIEW_ONLY',
      recipeId: saved.recipeId,
      revisionSha256: saved.revisionSha256,
      verifierId: config.verifierId,
    });
  });

  it('fails closed through REAL ActionController when no ACTIVE policy, no grant/effect', async () => {
    const f = fixture();
    const host = f.attach(f.getStore());
    const saved = host.service.registerLiteral(source, config);
    if (!saved.ok) throw new Error('fixture register failed');
    host.attachRevision(saved);
    const decision = await host.service.authorizeReadonlySearch({
      taskId: 'task-1',
      recipeId: saved.recipeId,
      revisionSha256: saved.revisionSha256,
    });
    expect(decision).toEqual({ ok: false, code: 'RECIPE_CONTROLLER_REFUSED' });
    expect(f.planLoads()).toBeGreaterThan(0);
    expect(await host.adapter.hasAnyGrant()).toBe(false);
    f.invalidate();
    expect(
      host.service.previewExact({
        taskId: 'task-1',
        recipeId: saved.recipeId,
        revisionSha256: saved.revisionSha256,
      }),
    ).toMatchObject({ ok: false, code: 'RECIPE_CURRENTNESS_UNKNOWN' });
  });

  it('routes actual SQLite Recipe preview to real ActionController before ANY backend effect', async () => {
    const f = fixture();
    const h = f.attach(f.getStore());
    const saved = h.service.registerLiteral(source, config);
    if (!saved.ok) throw new Error('fixture register failed');
    h.attachRevision(saved);
    let dispatched = 0;
    const live = createSqliteAuthorizedRecipeEffectHost({
      ...h.host,
      loadPlanByHash: async () => null,
      executeScopedSearch: async () => {
        dispatched++;
        throw new Error('unexpected execution');
      },
    });
    expect(
      await live.runner.run({
        taskId: 'task-1',
        recipeId: saved.recipeId,
        revisionSha256: saved.revisionSha256,
      }),
    ).toEqual({ ok: false, code: 'RECIPE_AUTHORIZATION_REFUSED' });
    expect(dispatched).toBe(0);
    expect(await h.adapter.hasAnyGrant()).toBe(false);
    f.invalidate();
    expect(
      await live.runner.run({
        taskId: 'task-1',
        recipeId: saved.recipeId,
        revisionSha256: saved.revisionSha256,
      }),
    ).toEqual({ ok: false, code: 'RECIPE_NOT_CURRENT' });
    expect(dispatched).toBe(0);
  });

  it('composes actual SQLite grant reentry before private R0 operation (synthetic receipt only)', async () => {
    const f = fixture();
    const h = f.attach(f.getStore());
    const saved = h.service.registerLiteral(source, config);
    if (!saved.ok) throw new Error('fixture register failed');
    h.attachRevision(saved);
    const identity = {
      taskId: 'task-1',
      recipeId: saved.recipeId,
      revisionSha256: saved.revisionSha256,
    };
    const preview = h.service.previewExact(identity);
    if (!preview.ok) throw new Error('fixture preview failed');
    const plan = h.host.loadExpectedPlan({
      ...identity,
      actionGraphSha256: preview.actionGraphSha256,
    }) as ActionPlan;

    await h.adapter.saveAuthorityRecord({
      authorityId: 'auth-1',
      authorityRevision: 'rev-1',
      updatedAt: '2026-10-22T00:00:00.000Z',
      policyInitialized: true,
    });
    await h.adapter.savePolicySnapshot({
      policySnapshotRevision: 'policy-1',
      status: 'ACTIVE',
      authorityId: 'auth-1',
      authorityRevision: 'rev-1',
      revokedGrantIds: [],
      rules: [
        {
          ruleId: 'allow-single-R0',
          capabilityId: 'file.search',
          op: 'file.search',
          maxRiskClass: 'R0',
          privilegeLevel: 'USER',
          filesystem: { read: ['C:/approved'], write: [] },
        },
      ],
      riskGuards: [],
      updatedAt: '2026-10-22T00:00:00.000Z',
    });
    let calls = 0;
    let corruptPlan = false;
    const live = createSqliteAuthorizedRecipeEffectHost({
      ...h.host,
      loadPlanByHash: async (hash) =>
        hash !== plan.planHash ? null : corruptPlan ? { ...plan, planHash: '0'.repeat(64) } : plan,
      executeScopedSearch: async (action) => {
        calls++;
        // Deliberately synthetic: NOT an installed Windows filesystem receipt.
        return {
          actionId: action.actionId,
          environmentId: 'synthetic-host',
          providerId: 'test-readonly',
          providerVersion: '0.2.0',
          startedAt: '2026-10-22T00:00:00.000Z',
          finishedAt: '2026-10-22T00:00:00.000Z',
          terminal: 'SUCCEEDED',
          outputRefs: [],
          sideEffectEvidence: {
            sideEffectClass: 'R0',
            recoveryClassification: 'COMPLETED_VERIFIED',
            postStateVerified: true,
            journalRef: 'synthetic-only',
          },
        };
      },
    });
    expect(await live.runner.run(identity)).toEqual({
      ok: true,
      state: 'EXECUTED_NOT_SEMANTICALLY_VERIFIED',
      actionCount: 1,
      taskPass: false,
    });
    expect(calls).toBe(1);
    expect(await h.adapter.hasAnyGrant()).toBe(true);
    expect(
      f
        .getStore()
        .database.prepare(
          'SELECT state FROM recipe_r0_effect_journal_v02 WHERE task_id=? AND action_id=?',
        )
        .get('task-1', 'read'),
    ).toMatchObject({ state: 'OBSERVED_NOT_SEMANTICALLY_VERIFIED' });

    // No unjournaled Host entry: a second execution with the same
    // task/action identity cannot repeat an effect even with fresh approval.
    expect(await live.runner.run(identity)).toEqual({
      ok: false,
      code: 'RECIPE_EXECUTION_UNCERTAIN',
    });
    expect(calls).toBe(1);

    // The runner's earlier approval cannot bypass the second independent
    // immutable-plan read in the SQLite authority boundary.
    corruptPlan = true;
    expect(await live.runner.run(identity)).toEqual({
      ok: false,
      code: 'RECIPE_EXECUTION_UNCERTAIN',
    });
    expect(calls).toBe(1);
  });

  it('rejects a missing restricted native search port instead of exposing a raw backend', () => {
    const f = fixture();
    const h = f.attach(f.getStore());
    expect(() =>
      createSqliteAuthorizedRecipeEffectHost({
        ...h.host,
        loadPlanByHash: async () => null,
        executeScopedSearch: undefined as never,
      }),
    ).toThrow(/^RECIPE_EFFECT_HOST_CONFIGURATION_REFUSED$/);
  });

  it('refuses fake store/controller and hostile getters without leaking details', () => {
    const f = fixture();
    const real = f.attach(f.getStore());
    expect(() =>
      createSqliteRecipeReadService({
        store: {} as ShunStore,
        controller: {} as ActionController,
        currentness: () => ({ kind: 'UNRESOLVABLE' }),
        loadExpectedPlan: () => null,
      }),
    ).toThrow(/^RECIPE_SQLITE_HOST_CONFIGURATION_REFUSED$/);
    expect(() =>
      createSqliteRecipeReadService({
        get store(): never {
          throw new Error('Bearer private');
        },
        controller: {} as ActionController,
        currentness: () => ({ kind: 'UNRESOLVABLE' }),
        loadExpectedPlan: () => null,
      }),
    ).toThrow(/^RECIPE_SQLITE_HOST_CONFIGURATION_REFUSED$/);
    expect(real.service.registerLiteral('export default eval("x");', config)).toEqual({
      ok: false,
      code: 'RECIPE_SOURCE_REFUSED',
    });
  });
  it('fixed native bootstrap cannot use injected Recipe search callbacks and fails closed without policy', async () => {
    const f = fixture();
    const h = f.attach(f.getStore());
    const saved = h.service.registerLiteral(source, config);
    if (!saved.ok) throw new Error('fixture register failed');
    h.attachRevision(saved);
    let injectedCalls = 0;
    // A malicious extra property cannot be used to replace the compile-time
    // fixed native port, even though JavaScript callers may supply it.
    const options = {
      ...h.host,
      loadPlanByHash: async () => null,
      executeScopedSearch: async () => {
        injectedCalls++;
        throw new Error('UNTRUSTED_OVERRIDE');
      },
    };
    const live = createSqliteNativeR0RecipeEffectHost(options);
    expect(
      await live.runner.run({
        taskId: 'task-1',
        recipeId: saved.recipeId,
        revisionSha256: saved.revisionSha256,
      }),
    ).toEqual({ ok: false, code: 'RECIPE_AUTHORIZATION_REFUSED' });
    expect(injectedCalls).toBe(0);
    expect(await h.adapter.hasAnyGrant()).toBe(false);
    expect(
      f.getStore().database.prepare('SELECT COUNT(*) AS n FROM recipe_r0_effect_journal_v02').get(),
    ).toMatchObject({ n: 0 });
  });

  it('fixed native bootstrap refuses fake SQLite store before any side effect', () => {
    const f = fixture();
    const h = f.attach(f.getStore());
    expect(() =>
      createSqliteNativeR0RecipeEffectHost({
        ...h.host,
        store: {} as ShunStore,
        loadPlanByHash: async () => null,
      }),
    ).toThrow(/^R0_NATIVE_HOST_BOOTSTRAP_REFUSED$/);
  });
  it.skipIf(process.platform !== 'win32')(
    'executes real Win32 read-only port only after persisted SQLite grant and STARTED, never auto-replays UNCERTAIN',
    async () => {
      const dir = mkdtempSync(join(tmpdir(), 'shun-t04-native-host-real-'));
      cleanup.push(async () => rmSync(dir, { recursive: true, force: true }));
      const root = join(dir, 'approved');
      mkdirSync(root);
      writeFileSync(join(root, 'note.txt'), 'NEVER_DISCLOSE_CONTENT');
      const f = fixture(root);
      const h = f.attach(f.getStore());
      const literal = `export default defineRecipe(${JSON.stringify({
        nodes: [{ actionId: 'read', op: 'file.search', parameters: { root, query: '*.txt' } }],
        edges: [],
      })});`;
      const saved = h.service.registerLiteral(literal, config);
      if (!saved.ok) throw new Error('native fixture register failed');
      h.attachRevision(saved);
      const identity = {
        taskId: 'task-1',
        recipeId: saved.recipeId,
        revisionSha256: saved.revisionSha256,
      };
      const preview = h.service.previewExact(identity);
      if (!preview.ok) throw new Error('native fixture preview failed');
      const plan = h.host.loadExpectedPlan({
        ...identity,
        actionGraphSha256: preview.actionGraphSha256,
      }) as ActionPlan;
      await h.adapter.saveAuthorityRecord({
        authorityId: 'auth-1',
        authorityRevision: 'rev-1',
        updatedAt: '2026-10-22T00:00:00.000Z',
        policyInitialized: true,
      });
      await h.adapter.savePolicySnapshot({
        policySnapshotRevision: 'policy-1',
        status: 'ACTIVE',
        authorityId: 'auth-1',
        authorityRevision: 'rev-1',
        revokedGrantIds: [],
        rules: [{
          ruleId: 'allow-native-r0',
          capabilityId: 'file.search',
          op: 'file.search',
          maxRiskClass: 'R0',
          privilegeLevel: 'USER',
          filesystem: { read: [root], write: [] },
        }],
        riskGuards: [],
        updatedAt: '2026-10-22T00:00:00.000Z',
      });
      const live = createSqliteNativeR0RecipeEffectHost({
        ...h.host,
        loadPlanByHash: async (hash) => hash === plan.planHash ? plan : null,
      });
      const first = await live.runner.run(identity);
      // Native execution is a genuine Windows OS scan, but there is no
      // independent post-state oracle, therefore never claim Task PASS.
      expect(first).toEqual({ ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN' });
      expect(await h.adapter.hasAnyGrant()).toBe(true);
      expect(
        f.getStore().database.prepare(
          'SELECT state FROM recipe_r0_effect_journal_v02 WHERE task_id=? AND action_id=?',
        ).get('task-1', 'read'),
      ).toMatchObject({ state: 'UNCERTAIN' });
      // Re-enter through the actual full Recipe runner: no second OS dispatch
      // is permitted with an existing journal row for the same task/action.
      expect(await live.runner.run(identity)).toEqual({
        ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN',
      });
      expect(JSON.stringify(first)).not.toContain(root);
      expect(JSON.stringify(first)).not.toContain('NEVER_DISCLOSE_CONTENT');
      expect(JSON.stringify(first)).not.toContain('note.txt');
    },
    45_000,
  );

});
