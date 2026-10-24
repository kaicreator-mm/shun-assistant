// T04 deployed private composition, not a test-owned injected native callback.
import { describe, expect, it } from 'vitest';
import {
  createSqliteVerifiedWindowsR0RecipeEffectHost,
} from '../src/sqlite-verified-windows-r0-host.ts';
import {
  buildAuthorityStack,
  buildCurrentness,
  buildLoadExpectedPlan,
  makeHostFixture,
} from './helpers/win-e2e-fixture.ts';

describe.skipIf(process.platform !== 'win32')(
  'T04 fixed verified Windows Host real SQLite+native OS chain',
  () => {
    it('admits fixed native+independent Oracle, persists phase and verifies semantics once, never replays', async () => {
      const fixture = await makeHostFixture('fixed-deployed-host');
      try {
        const { plan } = fixture.compose();
        const controller = buildAuthorityStack(fixture.store).controller;
        let injectedCalls = 0;
        const host = createSqliteVerifiedWindowsR0RecipeEffectHost({
          store: fixture.store,
          controller,
          currentness: buildCurrentness(fixture.store),
          loadExpectedPlan: buildLoadExpectedPlan(fixture.tree.rootForward),
          loadPlanByHash: async (hash) => (hash === plan.planHash ? plan : null),
          // An untrusted extra property at runtime must be ignored.
          executeScopedSearch: async () => {
            injectedCalls++;
            throw new Error('INJECTED_CALLBACK_MUST_NOT_RUN');
          },
        });
        expect(await host.runner.run(fixture.identity)).toEqual({
          ok: true,
          state: 'EXECUTED_NOT_SEMANTICALLY_VERIFIED',
          actionCount: 1,
          taskPass: false,
        });
        expect(injectedCalls).toBe(0);
        expect(host.verifyTaskSemantics(fixture.identity.taskId)).toMatchObject({
          ok: true,
          taskSemantic: 'PASS',
        });
        // A second caller cannot reuse an in-memory proof to mint a new PASS.
        expect(host.verifyTaskSemantics(fixture.identity.taskId)).toMatchObject({
          ok: false,
          taskSemantic: 'UNCERTAIN',
          code: 'SEMANTIC_EVIDENCE_INCOMPLETE',
        });
        expect(await host.runner.run(fixture.identity)).toEqual({
          ok: false,
          code: 'RECIPE_EXECUTION_UNCERTAIN',
        });
      } finally {
        await fixture.dispose();
      }
    }, 45_000);
  },
);
