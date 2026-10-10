// T03 — RecipeResolverPort seam: interfaces only (frozen scope). The P0
// reference ships a fail-closed seam; automatic recipe promotion/replay is P1
// and is NOT implemented here (L2 §6.5/§6.9, Issue #14 scope note).
import { describe, expect, it } from 'vitest';
import { FailClosedRecipeResolver, RecipeSeamUnavailableError } from '../src/index.ts';

describe('FailClosedRecipeResolver', () => {
  const resolver = new FailClosedRecipeResolver();

  it('refuses match with a typed error (escalates upward, never silently empty)', async () => {
    await expect(resolver.match({ objective: 'x', objects: [], constraints: {} })).rejects.toHaveProperty(
      'code',
      'RECIPE_SEAM_UNAVAILABLE',
    );
  });

  it('refuses checkCurrentness with a typed error', async () => {
    await expect(
      resolver.checkCurrentness(
        {
          recipeId: 'r',
          revision: '1',
          capabilityId: 'c',
          capabilityRevisionRange: { min: '1', max: '2' },
          applicabilityPredicate: {},
          parameterSchema: {},
          providerBindingConstraints: {},
          policyRequirements: {},
          riskFloor: 'R0',
          actionTemplate: {},
          verifierId: 'v',
          verifierRevision: '1',
          recoveryTemplate: {},
          currentnessInputs: ['fact'],
          provenance: {},
        },
        {},
      ),
    ).rejects.toBeInstanceOf(RecipeSeamUnavailableError);
  });

  it('refuses instantiate with a typed error', async () => {
    await expect(resolver.instantiate({} as never, {}, {})).rejects.toBeInstanceOf(
      RecipeSeamUnavailableError,
    );
  });
});
