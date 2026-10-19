// T04 source-level real ActionController reentry for a SINGLE R0 Recipe
// search, not a general-purpose executor, grant issuer or release proof.
// This is private-host composition only. The trusted backend MUST independently
// check its persisted grant/plan/currentness at its own effect boundary.
import {
  type ActionPlan,
  ActionPlanSchema,
  type AuthorizationGrant,
  AuthorizationGrantSchema,
  type AuthorizedAction,
  AuthorizedActionSchema,
  canonicalJson,
  computePlanHash,
  ExecutionReceiptSchema,
} from '@shun/contracts';
import type { RecipeReplayPreview } from './recipe-resolver.ts';

type Identity = Readonly<{ taskId: string; recipeId: string; revisionSha256: string }>;
type ExpectedPlanIdentity = Identity & Readonly<{ actionGraphSha256: string }>;
type AuthorizedBundle = Readonly<{
  plan: ActionPlan;
  actions: AuthorizedAction[];
  grants: AuthorizationGrant[];
}>;

export type TrustedReadonlyEffectHost = Readonly<{
  /** T03 saved exact SHA and currentness, never a browser-supplied preview. */
  previewExact: (input: Identity) => RecipeReplayPreview;
  /** Fresh canonical expected plan: policy/binding/verifier owned by Shun host. */
  loadExpectedPlan: (input: ExpectedPlanIdentity) => unknown;
  /** Actual ActionController: its plan gate issues grants and effect gate rechecks them. */
  controller: Readonly<{
    authorizePlan: (input: { plan: unknown }) => Promise<
      { ok: true; authorization: AuthorizedBundle } | { ok: false }
    >;
    authorizeEffect: (input: {
      plan: ActionPlan;
      action: AuthorizedAction;
      grant: unknown;
    }) => Promise<{ ok: boolean }>;
  }>;
  /** Actual EnvironmentBackend, which revalidates its own durable authority. */
  backend: Readonly<{ execute: (action: AuthorizedAction) => Promise<unknown> }>;
}>;

export type ReadonlyRecipeEffectOutcome =
  | { ok: true; state: 'EXECUTED_NOT_SEMANTICALLY_VERIFIED'; actionCount: 1; taskPass: false }
  | {
      ok: false;
      code:
        | 'RECIPE_INPUT_REFUSED'
        | 'RECIPE_NOT_CURRENT'
        | 'RECIPE_PLAN_REFUSED'
        | 'RECIPE_AUTHORIZATION_REFUSED'
        | 'RECIPE_EFFECT_REFUSED'
        | 'RECIPE_EXECUTION_UNCERTAIN';
    };

function safePlan(candidate: unknown, identity: Identity, preview: RecipeReplayPreview): ActionPlan | null {
  if (!preview.ok || preview.state !== 'PREVIEW_ONLY') return null;
  const parsed = ActionPlanSchema.safeParse(candidate);
  if (!parsed.success) return null;
  const plan = parsed.data;
  const [action] = plan.actions;
  const [node] = preview.actionGraph.nodes;
  if (
    computePlanHash(plan) !== plan.planHash ||
    plan.taskId !== identity.taskId ||
    plan.recipeRef !== `${identity.recipeId}@${identity.revisionSha256}` ||
    plan.capabilityId !== 'file.search' ||
    plan.actions.length !== 1 ||
    !action ||
    preview.actionGraph.nodes.length !== 1 ||
    preview.actionGraph.edges.length !== 0 ||
    !node ||
    node.op !== 'file.search' ||
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
    (action.secretRefs?.length ?? 0) !== 0
  ) return null;
  return plan;
}

function validPreview(preview: RecipeReplayPreview, identity: Identity): boolean {
  return (
    preview.ok &&
    preview.state === 'PREVIEW_ONLY' &&
    preview.taskId === identity.taskId &&
    preview.recipeId === identity.recipeId &&
    preview.revisionSha256 === identity.revisionSha256 &&
    preview.executionAuthorized === false &&
    preview.requiresActionControllerRevalidation === true &&
    preview.modelCalls === 0
  );
}

/**
 * The only public input is exact Recipe identity. An approved grant is NEVER
 * returned to callers. No mutable generic operation can be selected.
 */
export class TrustedReadonlyRecipeEffectRunner {
  private readonly host: TrustedReadonlyEffectHost;
  private readonly inflight = new Set<string>();

  constructor(input: TrustedReadonlyEffectHost) {
    try {
      const preview = input?.previewExact;
      const load = input?.loadExpectedPlan;
      const controller = input?.controller;
      const authorizePlan = controller?.authorizePlan;
      const authorizeEffect = controller?.authorizeEffect;
      const backend = input?.backend;
      const execute = backend?.execute;
      if (
        typeof preview !== 'function' ||
        typeof load !== 'function' ||
        typeof authorizePlan !== 'function' ||
        typeof authorizeEffect !== 'function' ||
        typeof execute !== 'function'
      ) throw new Error('RECIPE_EFFECT_HOST_CONFIGURATION_REFUSED');
      this.host = {
        previewExact: preview.bind(input),
        loadExpectedPlan: load.bind(input),
        controller: {
          authorizePlan: authorizePlan.bind(controller),
          authorizeEffect: authorizeEffect.bind(controller),
        },
        backend: { execute: execute.bind(backend) },
      };
    } catch {
      throw new Error('RECIPE_EFFECT_HOST_CONFIGURATION_REFUSED');
    }
  }

  async run(input: Identity): Promise<ReadonlyRecipeEffectOutcome> {
    let key: string;
    try {
      if (
        !input ||
        typeof input.taskId !== 'string' ||
        !input.taskId ||
        typeof input.recipeId !== 'string' ||
        !input.recipeId ||
        typeof input.revisionSha256 !== 'string' ||
        !/^[a-f0-9]{64}$/.test(input.revisionSha256)
      ) return { ok: false, code: 'RECIPE_INPUT_REFUSED' };
      key = JSON.stringify([input.taskId, input.recipeId, input.revisionSha256]);
    } catch {
      return { ok: false, code: 'RECIPE_INPUT_REFUSED' };
    }
    if (this.inflight.has(key)) return { ok: false, code: 'RECIPE_AUTHORIZATION_REFUSED' };
    this.inflight.add(key);
    try {
      const first = this.host.previewExact(input);
      if (!validPreview(first, input) || !first.ok) return { ok: false, code: 'RECIPE_NOT_CURRENT' };
      const identity = { ...input, actionGraphSha256: first.actionGraphSha256 };
      const firstPlan = safePlan(this.host.loadExpectedPlan(identity), input, first);
      if (!firstPlan) return { ok: false, code: 'RECIPE_PLAN_REFUSED' };
      const approved = await this.host.controller.authorizePlan({ plan: firstPlan });
      if (!approved || approved.ok !== true) {
        return { ok: false, code: 'RECIPE_AUTHORIZATION_REFUSED' };
      }
      // AuthorizePlan can suspend while the catalog/policy/verifier changes.
      // Re-read T03 AND the independent trusted expected plan before touching
      // any executor. Full snapshot equality detects even same-SHA drift.
      const second = this.host.previewExact(input);
      if (!validPreview(second, input) || !second.ok || canonicalJson(first) !== canonicalJson(second)) {
        return { ok: false, code: 'RECIPE_NOT_CURRENT' };
      }
      const secondPlan = safePlan(this.host.loadExpectedPlan(identity), input, second);
      if (!secondPlan || canonicalJson(firstPlan) !== canonicalJson(secondPlan)) {
        return { ok: false, code: 'RECIPE_PLAN_REFUSED' };
      }
      const bundle = approved.authorization;
      const authorizedPlan = ActionPlanSchema.safeParse(bundle?.plan);
      const action = AuthorizedActionSchema.safeParse(bundle?.actions?.[0]);
      const grant = AuthorizationGrantSchema.safeParse(bundle?.grants?.[0]);
      if (
        !authorizedPlan.success ||
        computePlanHash(authorizedPlan.data) !== authorizedPlan.data.planHash ||
        canonicalJson(authorizedPlan.data) !== canonicalJson(firstPlan) ||
        bundle.actions.length !== 1 ||
        bundle.grants.length !== 1 ||
        !action.success ||
        !grant.success ||
        action.data.taskId !== firstPlan.taskId ||
        action.data.actionId !== firstPlan.actions[0]?.actionId ||
        action.data.planHash !== firstPlan.planHash ||
        action.data.authorizationRef !== grant.data.grantId ||
        canonicalJson(action.data.action) !== canonicalJson(firstPlan.actions[0]) ||
        grant.data.taskId !== firstPlan.taskId ||
        grant.data.planHash !== firstPlan.planHash ||
        grant.data.actionScope.privilegeLevel !== 'USER' ||
        canonicalJson(grant.data.actionScope.actionIds) !== canonicalJson([action.data.actionId]) ||
        canonicalJson(grant.data.actionScope.filesystem) !==
          canonicalJson({ read: firstPlan.actions[0]?.filesystemScope?.read, write: [] })
      ) return { ok: false, code: 'RECIPE_AUTHORIZATION_REFUSED' };
      const verdict = await this.host.controller.authorizeEffect({
        plan: firstPlan,
        action: action.data,
        grant: grant.data,
      });
      if (!verdict || verdict.ok !== true) return { ok: false, code: 'RECIPE_EFFECT_REFUSED' };
      // Effect may now have started. ANY throw/invalid receipt is UNKNOWN,
      // never a proof of zero effects or Task PASS. Backend's own grant check,
      // journal and reconcile-first recovery remain mandatory.
      let receipt: unknown;
      try {
        receipt = await this.host.backend.execute(action.data);
      } catch {
        return { ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN' };
      }
      const parsedReceipt = ExecutionReceiptSchema.safeParse(receipt);
      if (
        !parsedReceipt.success ||
        parsedReceipt.data.actionId !== action.data.actionId ||
        parsedReceipt.data.sideEffectEvidence.sideEffectClass !== 'R0' ||
        parsedReceipt.data.terminal !== 'SUCCEEDED'
      ) return { ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN' };
      // Success at the execution surface is not a semantic verifier PASS.
      return {
        ok: true,
        state: 'EXECUTED_NOT_SEMANTICALLY_VERIFIED',
        actionCount: 1,
        taskPass: false,
      };
    } catch {
      // Conservative after an async boundary: might have issued a grant or
      // dispatched an effect; never assert "no effect" from this catch.
      return { ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN' };
    } finally {
      this.inflight.delete(key);
    }
  }
}
