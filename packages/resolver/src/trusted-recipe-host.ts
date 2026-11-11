// v0.2 T04 trusted-host composition for T03 immutable source → compiler
// → exact replay preview → ActionController's read-only plan gate.
// This service is intentionally NOT exposed through a web/Recipe/model port.
// It cannot execute effects, promote recipes, mint approval or skip R2 reentry.
import { ActionPlanSchema, computePlanHash } from '@shun/contracts';
import {
  compileLiteralRecipe,
  type TrustedRecipeCompilerConfig,
} from './literal-recipe-compiler.ts';
import {
  ReadonlyRecipeControllerHandoff,
  type RecipeControllerHandoffResult,
} from './recipe-controller-handoff.ts';
import {
  ClosedWorldRecipePreview,
  type RecipeReplayCurrentness,
  type RecipeReplayPreview,
  type RecipeReplaySnapshot,
} from './recipe-resolver.ts';

export type TrustedRecipeHost = Readonly<{
  /** The actual T03 ImmutableRecipeRepository structural seam. */
  repository: Readonly<{
    append: (revision: RecipeReplaySnapshot) => {
      recipeId: string;
      revisionSha256: string;
      inserted: boolean;
    };
    get: (recipeId: string, revisionSha256: string) => RecipeReplaySnapshot | null;
  }>;
  /** Trusted Shun authority currentness; re-read for EVERY preview. */
  currentness: (taskId: string, recipeId: string) => RecipeReplayCurrentness;
  /** Host policy-derived whole ActionPlan, NEVER sourced from the browser or LLM. */
  loadExpectedPlan: (identity: {
    taskId: string;
    recipeId: string;
    revisionSha256: string;
    actionGraphSha256: string;
  }) => unknown;
  /** Actual ActionController.authorizePlan port, not a caller-owned boolean. */
  controller: Readonly<{
    authorizePlan: (input: { plan: unknown }) => Promise<{ ok: boolean }>;
  }>;
}>;

export type RecipeRegistrationResult =
  | {
      ok: true;
      state: 'PERSISTED_CANDIDATE_ONLY';
      recipeId: string;
      revisionSha256: string;
      inserted: boolean;
      modelCalls: 0;
      executionAuthorized: false;
    }
  | {
      ok: false;
      code: 'RECIPE_SOURCE_REFUSED' | 'RECIPE_STORE_REFUSED';
    };

export type TrustedRecipeReadResult =
  | RecipeControllerHandoffResult
  | { ok: false; code: 'RECIPE_PREVIEW_REFUSED' | 'RECIPE_PLAN_REFUSED' };

/** Construct only in a private trusted host where all four ports are trusted. */
export class TrustedRecipeReadService {
  private readonly store: TrustedRecipeHost['repository'];
  private readonly previewer: ClosedWorldRecipePreview;
  private readonly handoff: ReadonlyRecipeControllerHandoff;
  private readonly loadExpectedPlan: TrustedRecipeHost['loadExpectedPlan'];

  constructor(host: TrustedRecipeHost) {
    try {
      const repository = host?.repository;
      const get = repository?.get;
      const append = repository?.append;
      const currentness = host?.currentness;
      const loadExpectedPlan = host?.loadExpectedPlan;
      const controller = host?.controller;
      const authorizePlan = controller?.authorizePlan;
      if (
        typeof get !== 'function' ||
        typeof append !== 'function' ||
        typeof currentness !== 'function' ||
        typeof loadExpectedPlan !== 'function' ||
        typeof authorizePlan !== 'function'
      ) {
        throw new Error('RECIPE_HOST_CONFIGURATION_REFUSED');
      }
      // Snapshot and bind every trusted method once. Never re-read Proxy
      // properties after construction or expose them to Recipe source.
      this.store = {
        get: get.bind(repository),
        append: append.bind(repository),
      };
      this.loadExpectedPlan = loadExpectedPlan.bind(host);
      this.previewer = new ClosedWorldRecipePreview({
        loadExact: this.store.get,
        currentness: currentness.bind(host),
      });
      this.handoff = new ReadonlyRecipeControllerHandoff({
        previewer: this.previewer,
        trustedPlan: { loadExpectedPlan: this.loadExpectedPlan },
        controller: { authorizePlan: authorizePlan.bind(controller) },
      });
    } catch {
      throw new Error('RECIPE_HOST_CONFIGURATION_REFUSED');
    }
  }

  /** Only append immutable candidates; automatic ACTIVE promotion is absent. */
  registerLiteral(
    source: unknown,
    trustedConfig: TrustedRecipeCompilerConfig,
  ): RecipeRegistrationResult {
    const compiled = compileLiteralRecipe(source, trustedConfig);
    if (!compiled.ok) return { ok: false, code: 'RECIPE_SOURCE_REFUSED' };
    try {
      const expected = compiled.compiled.identity;
      const result = this.store.append(compiled.compiled);
      if (
        result.recipeId !== expected.recipeId ||
        result.revisionSha256 !== expected.revisionSha256 ||
        typeof result.inserted !== 'boolean'
      ) {
        return { ok: false, code: 'RECIPE_STORE_REFUSED' };
      }
      return {
        ok: true,
        state: 'PERSISTED_CANDIDATE_ONLY',
        recipeId: expected.recipeId,
        revisionSha256: expected.revisionSha256,
        inserted: result.inserted,
        modelCalls: 0,
        executionAuthorized: false,
      };
    } catch {
      return { ok: false, code: 'RECIPE_STORE_REFUSED' };
    }
  }

  /** Resolve an exact SHA from T03, verify identity/currentness and preview. */
  previewExact(input: {
    taskId: string;
    recipeId: string;
    revisionSha256: string;
  }): RecipeReplayPreview {
    return this.previewer.preview(input);
  }

  /**
   * Public method takes ONLY identities. It deliberately does not accept a
   * plan, action graph, execution decision, raw shell arguments or authority.
   * A fresh trusted plan must match the independently re-fetched host plan,
   * and ActionController always re-reads policy/currentness.
   * No authorized action/grant is exposed as an execution capability.
   */
  async authorizeReadonlySearch(input: {
    taskId: string;
    recipeId: string;
    revisionSha256: string;
  }): Promise<TrustedRecipeReadResult> {
    try {
      const preview = this.previewer.preview(input);
      if (!preview.ok) return { ok: false, code: 'RECIPE_PREVIEW_REFUSED' };
      const expected = ActionPlanSchema.safeParse(
        this.loadExpectedPlan({
          taskId: preview.taskId,
          recipeId: preview.recipeId,
          revisionSha256: preview.revisionSha256,
          actionGraphSha256: preview.actionGraphSha256,
        }),
      );
      if (!expected.success || computePlanHash(expected.data) !== expected.data.planHash) {
        return { ok: false, code: 'RECIPE_PLAN_REFUSED' };
      }
      return this.handoff.authorizeReadonlySearch({
        ...input,
        candidatePlan: expected.data,
      });
    } catch {
      return { ok: false, code: 'RECIPE_PLAN_REFUSED' };
    }
  }
}
