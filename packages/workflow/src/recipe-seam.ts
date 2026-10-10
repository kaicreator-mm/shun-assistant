// RecipeResolverPort seam — interfaces only (frozen T03 scope).
//
// The recipe port and its state space are frozen architecture (L2 §6.5/§6.9),
// but automatic recipe promotion/replay is P1 and NOT part of the first
// executable proof. The P0 reference therefore ships a fail-closed seam: any
// resolution attempt escalates upward with a typed error instead of silently
// returning empty candidates or faking recipe behavior.
import type {
  ActionPlanProposal,
  RecipeCandidates,
  RecipeCurrentnessResult,
  RecipeDefinition,
  RecipeResolverPort,
} from '@shun/contracts';
import { RecipeSeamUnavailableError } from './errors.ts';

export class FailClosedRecipeResolver implements RecipeResolverPort {
  async match(_intent: {
    objective: string;
    objects: string[];
    constraints: Record<string, unknown>;
  }): Promise<RecipeCandidates> {
    throw new RecipeSeamUnavailableError('match');
  }

  async checkCurrentness(
    _recipe: RecipeDefinition,
    _currentFacts: Record<string, unknown>,
  ): Promise<RecipeCurrentnessResult> {
    throw new RecipeSeamUnavailableError('checkCurrentness');
  }

  async instantiate(
    _recipe: RecipeDefinition,
    _parameters: Record<string, unknown>,
    _currentFacts: Record<string, unknown>,
  ): Promise<ActionPlanProposal> {
    throw new RecipeSeamUnavailableError('instantiate');
  }
}
