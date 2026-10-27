import { describe, expect, it } from 'vitest';
import { DemoShunBackend } from '../src/demo/backend.ts';
import { BUILTIN_INVENTORY_RECIPE_ID } from '../src/inventory-recipe.ts';
import { runAuthorizedInventoryRecipe } from '../src/recipe-inventory-run.ts';
import { createControlServer } from '../src/server.ts';
import { startHarness } from './helpers.ts';

const REVISION = 'b'.repeat(64);
const CURRENT = {
  kind: 'CURRENT',
  policyRevision: 'operator-policy-r1',
  registryRevision: 'registry-r1',
} as const;
const SNAPSHOT = {
  schema: 'shun.system-inventory.v02',
  localOnly: true,
  externalDisclosures: [],
  provenance: 'node:os+node:fs:statfs',
  platform: 'win32',
  cpuLogicalCount: 8,
  memoryTotalBytes: 8000000,
  memoryFreeBytes: 1000000,
  diskTotalBytes: 12000000,
  diskFreeBytes: 7000000,
  uptimeSeconds: 300,
} as const;
const candidate = {
  ok: true,
  saved: true,
  state: 'PERSISTED_CANDIDATE_ONLY',
  recipeId: BUILTIN_INVENTORY_RECIPE_ID,
  revisionSha256: REVISION,
  modelCalls: 0,
  executionAuthorized: false,
} as const;

describe('T08 C07R — zero-model, real T02-gated Recipe replay', () => {
  it('rejects empty/not-saved candidate before any controller or Windows collector', async () => {
    let planCalls = 0;
    let observations = 0;
    const output = await runAuthorizedInventoryRecipe({
      readCandidate: () => ({
        ...candidate,
        saved: false,
        state: 'NOT_SAVED',
        revisionSha256: null,
      }),
      current: async () => CURRENT,
      controller: {
        authorizePlan: async () => {
          planCalls++;
          return { ok: false, code: 'POLICY_BLOCKED', detail: 'no matching operator rule' };
        },
        authorizeEffect: async () => ({
          ok: false,
          code: 'GRANT_NOT_AUTHENTIC',
          detail: 'refused',
        }),
      },
      collect: () => {
        observations++;
        return { ok: true, snapshot: SNAPSHOT };
      },
    });
    expect(output).toEqual({ ok: false, code: 'RECIPE_NOT_SAVED' });
    expect(planCalls).toBe(0);
    expect(observations).toBe(0);
  });

  it('a default missing R0 operator rule is denied before any real inventory call', async () => {
    let planCalls = 0;
    let observations = 0;
    const result = await runAuthorizedInventoryRecipe({
      readCandidate: () => candidate,
      current: async () => CURRENT,
      controller: {
        authorizePlan: async ({ plan }) => {
          planCalls++;
          expect(plan).toMatchObject({
            capabilityId: 'system.inventory',
            recipeRef: `${BUILTIN_INVENTORY_RECIPE_ID}@${REVISION}`,
            policySnapshotRevision: CURRENT.policyRevision,
            actions: [
              {
                actionId: 'read-system-inventory',
                op: 'system.inventory',
                parameters: { includeProcesses: false },
                sideEffectClass: 'R0',
                requiredPrivilege: 'USER',
              },
            ],
          });
          return { ok: false, code: 'POLICY_BLOCKED', detail: 'no durable exact R0 rule' };
        },
        authorizeEffect: async () => {
          throw new Error('effect gate must not be reached without operator R0 rule');
        },
      },
      collect: () => {
        observations++;
        return { ok: true, snapshot: SNAPSHOT };
      },
    });
    expect(result).toEqual({ ok: false, code: 'RECIPE_AUTHORIZATION_REFUSED' });
    expect(planCalls).toBe(1);
    expect(observations).toBe(0);
  });

  it('refuses currentness drift between plan and effect, without Windows reads', async () => {
    let checked = 0;
    let observations = 0;
    const output = await runAuthorizedInventoryRecipe({
      readCandidate: () => candidate,
      current: async () => {
        checked++;
        return checked === 1 ? CURRENT : { ...CURRENT, policyRevision: 'operator-policy-revoked' };
      },
      controller: {
        authorizePlan: async ({ plan }) => {
          const p = plan as { planHash: string; actions: unknown[] };
          return {
            ok: true,
            authorization: {
              plan,
              actions: [
                {
                  ...(p.actions[0] as object),
                  actionId: 'read-system-inventory',
                  authorizationRef: 'g1',
                  authorizationKind: 'AUTOMATIC',
                  planHash: p.planHash,
                  action: { op: 'system.inventory', sideEffectClass: 'R0' },
                },
              ],
              grants: [{ grantId: 'g1' }],
            },
          } as never;
        },
        authorizeEffect: async () => {
          throw new Error('effect gate must not be reached after policy drift');
        },
      },
      collect: () => {
        observations++;
        return { ok: true, snapshot: SNAPSHOT };
      },
    });
    expect(output).toEqual({ ok: false, code: 'RECIPE_AUTHORITY_UNAVAILABLE' });
    expect(checked).toBe(2);
    expect(observations).toBe(0);
  });

  it('requires successful private effect grant before exactly one real observation', async () => {
    let effectCalls = 0;
    let observations = 0;
    const makeController = (allow: boolean) => ({
      authorizePlan: async ({ plan }: { plan: unknown }) => {
        const p = plan as { planHash: string; actions: unknown[] };
        return {
          ok: true,
          authorization: {
            plan,
            disposition: { kind: 'AUTOMATIC', ruleIds: ['operator-approved-inventory-r0'] },
            grants: [{ grantId: 'operator-signed-grant' }],
            actions: [
              {
                actionId: 'read-system-inventory',
                authorizationRef: 'operator-signed-grant',
                authorizationKind: 'AUTOMATIC',
                planHash: p.planHash,
                action: { op: 'system.inventory', sideEffectClass: 'R0' },
              },
            ],
          },
        } as never;
      },
      authorizeEffect: async () => {
        effectCalls++;
        return allow
          ? ({ ok: true, grant: { grantId: 'operator-signed-grant' } } as never)
          : ({ ok: false, code: 'GRANT_REVOKED', detail: 'revoked' } as never);
      },
    });
    const host = {
      readCandidate: () => candidate,
      current: async () => CURRENT,
      collect: () => {
        observations++;
        return { ok: true as const, snapshot: SNAPSHOT };
      },
    };
    const denied = await runAuthorizedInventoryRecipe({
      ...host,
      controller: makeController(false),
    });
    expect(denied).toEqual({ ok: false, code: 'RECIPE_AUTHORIZATION_REFUSED' });
    expect(observations).toBe(0);
    const passed = await runAuthorizedInventoryRecipe({
      ...host,
      controller: makeController(true),
    });
    expect(passed).toMatchObject({
      ok: true,
      status: 'VERIFIED_READONLY_OBSERVATION',
      recipeExecuted: true,
      modelCalls: 0,
      revisionSha256: REVISION,
    });
    expect(observations).toBe(1);
    expect(effectCalls).toBe(2);
    expect(passed).not.toHaveProperty('grant');
    expect(passed).not.toHaveProperty('authorization');
  });

  it('never offers a runnable Recipe from the shipped Demo server or accepts arbitrary browser plans', async () => {
    const h = await startHarness();
    try {
      expect(await h.post('/api/recipes/builtin/system-inventory/run', {})).toEqual({
        status: 503,
        body: { ok: false, code: 'RECIPE_EXECUTION_UNAVAILABLE' },
      });
    } finally {
      await h.close();
    }
    let invoked = 0;
    const server = createControlServer({
      backend: new DemoShunBackend(),
      executeBuiltinInventoryRecipe: async () => {
        invoked++;
        return { ok: false, code: 'RECIPE_AUTHORIZATION_REFUSED' };
      },
    });
    const port = await server.start();
    try {
      for (const body of [
        { grant: true },
        { source: 'shell.exec' },
        { plan: { op: 'system.inventory' } },
        ['injected'],
      ]) {
        const res = await fetch(
          `http://127.0.0.1:${port}/api/recipes/builtin/system-inventory/run`,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
          },
        );
        expect(res.status).toBe(400);
        expect(await res.json()).toEqual({ ok: false, code: 'RECIPE_INPUT_REFUSED' });
      }
      expect(invoked).toBe(0);
    } finally {
      await server.close();
    }
  });
});
