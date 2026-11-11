// v0.2 T04: signed Recipe preview to the REAL ActionController's plan gate.
// Narrow read-only file.search path; no generic compiled JS executor and no
// effect dispatch. Authorization grants are never returned from this adapter.
import { type ActionPlan, ActionPlanSchema, canonicalJson, computePlanHash } from '@shun/contracts';
import type { ClosedWorldRecipePreview } from './recipe-resolver.ts';

type PreviewPort = Pick<ClosedWorldRecipePreview, 'preview'>;
type ControllerPort = Readonly<{
  authorizePlan: (input: { plan: unknown }) => Promise<{ ok: boolean }>;
}>;
type TrustedRecipePlanPort = Readonly<{
  /**
   * Shun-owned trusted host derives the FULL expected immutable ActionPlan
   * for the exact Recipe/graph and current authority snapshot, each call.
   * Planner, browser and Recipe JS cannot supply or replace this port.
   */
  loadExpectedPlan: (identity: {
    taskId: string;
    recipeId: string;
    revisionSha256: string;
    actionGraphSha256: string;
  }) => unknown;
}>;

export type RecipeControllerHandoffResult =
  | {
      ok: true;
      stage: 'CONTROLLER_AUTHORIZED_NO_EXECUTION';
      actionCount: 1;
      requiresPerEffectRevalidation: true;
      effectExecuted: false;
    }
  | {
      ok: false;
      code:
        | 'RECIPE_HANDOFF_REFUSED'
        | 'RECIPE_PREVIEW_UNAVAILABLE'
        | 'RECIPE_PLAN_MISMATCH'
        | 'RECIPE_CONTROLLER_REFUSED';
    };

/**
 * Compose ONLY inside Shun's trusted host, using the actual
 * ActionController and T03-backed ClosedWorldRecipePreview; a browser/Recipe
 * must never supply these ports. This bridge has no execution port.
 */
export class ReadonlyRecipeControllerHandoff {
  private readonly previewer: PreviewPort;
  private readonly controller: ControllerPort;
  private readonly trustedPlan: TrustedRecipePlanPort;

  constructor(input: {
    previewer: PreviewPort;
    controller: ControllerPort;
    trustedPlan: TrustedRecipePlanPort;
  }) {
    // Constructor accessors are not exempt from redaction. Snapshot and bind
    // methods ONCE: a Proxy getter cannot substitute a different method later.
    try {
      const previewer = input?.previewer;
      const controller = input?.controller;
      const trustedPlan = input?.trustedPlan;
      const preview = previewer?.preview;
      const authorizePlan = controller?.authorizePlan;
      const loadExpectedPlan = trustedPlan?.loadExpectedPlan;
      if (
        typeof preview !== 'function' ||
        typeof authorizePlan !== 'function' ||
        typeof loadExpectedPlan !== 'function'
      ) {
        throw new Error('RECIPE_CONTROLLER_CONFIGURATION_REFUSED');
      }
      this.previewer = { preview: preview.bind(previewer) };
      this.controller = { authorizePlan: authorizePlan.bind(controller) };
      this.trustedPlan = { loadExpectedPlan: loadExpectedPlan.bind(trustedPlan) };
    } catch {
      throw new Error('RECIPE_CONTROLLER_CONFIGURATION_REFUSED');
    }
  }

  async authorizeReadonlySearch(input: {
    taskId: string;
    recipeId: string;
    revisionSha256: string;
    candidatePlan: unknown;
  }): Promise<RecipeControllerHandoffResult> {
    const refused = (code: RecipeControllerHandoffResult & { ok: false }) => code;
    try {
      const { taskId, recipeId, revisionSha256, candidatePlan } = input;
      if (
        typeof taskId !== 'string' ||
        !taskId ||
        typeof recipeId !== 'string' ||
        !recipeId ||
        typeof revisionSha256 !== 'string' ||
        !/^[a-f0-9]{64}$/.test(revisionSha256)
      ) {
        return refused({ ok: false, code: 'RECIPE_HANDOFF_REFUSED' });
      }
      const preview = this.previewer.preview({ taskId, recipeId, revisionSha256 });
      if (
        !preview.ok ||
        preview.state !== 'PREVIEW_ONLY' ||
        preview.executionAuthorized !== false ||
        preview.requiresActionControllerRevalidation !== true ||
        preview.modelCalls !== 0 ||
        preview.taskId !== taskId ||
        preview.recipeId !== recipeId ||
        preview.revisionSha256 !== revisionSha256
      ) {
        return refused({ ok: false, code: 'RECIPE_PREVIEW_UNAVAILABLE' });
      }
      // A multi-node/edge graph cannot be flattened into a sequential plan
      // until dependency-preserving DAG execution/recovery is implemented.
      const [node] = preview.actionGraph.nodes;
      if (
        preview.actionGraph.nodes.length !== 1 ||
        preview.actionGraph.edges.length !== 0 ||
        !node ||
        node.op !== 'file.search' ||
        canonicalJson(preview.declaredEffects) !== canonicalJson(['file.search'])
      ) {
        return refused({ ok: false, code: 'RECIPE_PLAN_MISMATCH' });
      }
      const parsed = ActionPlanSchema.safeParse(candidatePlan);
      if (!parsed.success) return refused({ ok: false, code: 'RECIPE_PLAN_MISMATCH' });
      const plan: ActionPlan = parsed.data;
      const [action] = plan.actions;
      // A recomputed hash is only integrity of the caller's chosen plan.
      // Compare the ENTIRE plan against a fresh, independently host-derived
      // expected ActionPlan before delegating to ActionController. This pins
      // bindingRefs, verifier, rank-policy, options and all action fields.
      const expected = ActionPlanSchema.safeParse(
        this.trustedPlan.loadExpectedPlan({
          taskId,
          recipeId,
          revisionSha256,
          actionGraphSha256: preview.actionGraphSha256,
        }),
      );
      if (
        !expected.success ||
        computePlanHash(expected.data) !== expected.data.planHash ||
        canonicalJson(plan) !== canonicalJson(expected.data)
      ) {
        return refused({ ok: false, code: 'RECIPE_PLAN_MISMATCH' });
      }
      if (
        plan.taskId !== taskId ||
        plan.recipeRef !== `${recipeId}@${revisionSha256}` ||
        plan.capabilityId !== 'file.search' ||
        plan.actions.length !== 1 ||
        !action ||
        action.actionId !== node.actionId ||
        action.op !== node.op ||
        canonicalJson(action.parameters) !== canonicalJson(node.parameters) ||
        action.sideEffectClass !== 'R0' ||
        action.requiredPrivilege !== 'USER' ||
        action.filesystemScope?.read.length !== 1 ||
        action.filesystemScope.read[0] !== node.parameters.root ||
        action.filesystemScope.write.length !== 0 ||
        action.networkScope !== undefined ||
        action.registryScope !== undefined ||
        (action.secretRefs?.length ?? 0) !== 0 ||
        computePlanHash(plan) !== plan.planHash
      ) {
        return refused({ ok: false, code: 'RECIPE_PLAN_MISMATCH' });
      }
      // Existing controller MUST load current policy/grants and authorize
      // against the canonical plan. No output here is an execution credential.
      const approved = await this.controller.authorizePlan({ plan });
      if (!approved || approved.ok !== true) {
        return refused({ ok: false, code: 'RECIPE_CONTROLLER_REFUSED' });
      }
      return {
        ok: true,
        stage: 'CONTROLLER_AUTHORIZED_NO_EXECUTION',
        actionCount: 1,
        requiresPerEffectRevalidation: true,
        effectExecuted: false,
      };
    } catch {
      return refused({ ok: false, code: 'RECIPE_HANDOFF_REFUSED' });
    }
  }
}
