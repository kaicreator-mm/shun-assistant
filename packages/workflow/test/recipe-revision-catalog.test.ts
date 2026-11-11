import { describe, expect, it } from 'vitest';
import { ReadonlyRecipeRevisionCatalog } from '../src/recipe-seam.ts';

describe('v0.2 immutable Recipe read-only workflow seam', () => {
  it('queries only exact recipe + revision; never promotes, executes or invokes planner', () => {
    const invoked: string[] = [];
    const reader = {
      get(recipeId: string, revisionSha256: string) {
        invoked.push(`${recipeId}:${revisionSha256}`);
        return null;
      },
    };
    const lookup = new ReadonlyRecipeRevisionCatalog(reader);
    const sha = 'a'.repeat(64);
    expect(lookup.getExact('recipe-1', sha)).toBeNull();
    expect(invoked).toEqual([`recipe-1:${sha}`]);
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(lookup))).toEqual([
      'constructor',
      'getExact',
    ]);
  });
});
