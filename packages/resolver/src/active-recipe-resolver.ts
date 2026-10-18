// T04 P0 narrow RecipeResolverPort: only a host-attested ACTIVE exact
// Recipe revision, with a single R0 file.search action, can produce a plan
// PROPOSAL. No model call, source execution, grant issuance or file effects.
import { createHash } from 'node:crypto';
import {
  type ActionPlanProposal,
  ActionPlanProposalSchema,
  canonicalJson,
  type RecipeCandidates,
  RecipeCandidatesSchema,
  type RecipeCurrentnessResult,
  type RecipeDefinition,
  RecipeDefinitionSchema,
  type RecipeResolverPort,
  RecoveryPlanSchema,
  VerificationPlanSchema,
} from '@shun/contracts';
import type { RecipeReplayPreview } from './recipe-resolver.ts';

type Intent = Parameters<RecipeResolverPort['match']>[0];
type Candidate = RecipeCandidates['candidates'][number];

export type TrustedActiveRecipeAuthority = Readonly<{
  /** Trusted persisted lifecycle view. A candidate cannot self-promote. */
  list(): readonly Candidate[];
  /** Current principal's authenticated task id: never an input parameter. */
  taskId(): string;
  /** Source-issued registry/policy/scope revisions, not caller assertions. */
  currentFacts(): Readonly<Record<string, unknown>>;
  /** Wired to TrustedRecipeReadService.previewExact / T03 exact SHA. */
  previewExact(input: {
    taskId: string;
    recipeId: string;
    revisionSha256: string;
  }): RecipeReplayPreview;
}>;

function isEmptyRecord(value: unknown): boolean {
  return (
    !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0
  );
}

function isSafeR0Definition(recipe: RecipeDefinition): boolean {
  const template = recipe.actionTemplate;
  const predicate = recipe.applicabilityPredicate;
  return (
    recipe.riskFloor === 'R0' &&
    /^[a-f0-9]{64}$/.test(recipe.revision) &&
    Object.keys(predicate).length === 1 &&
    typeof predicate.objective === 'string' &&
    !!predicate.objective &&
    isEmptyRecord(recipe.parameterSchema) &&
    isEmptyRecord(recipe.policyRequirements) &&
    isEmptyRecord(recipe.providerBindingConstraints) &&
    recipe.environmentRequirements === undefined &&
    Object.keys(template).length === 2 &&
    typeof template.actionGraphSha256 === 'string' &&
    /^[a-f0-9]{64}$/.test(template.actionGraphSha256) &&
    VerificationPlanSchema.safeParse(template.verificationPlan).success &&
    (template.verificationPlan as { verifierId: string }).verifierId === recipe.verifierId &&
    (template.verificationPlan as { verifierRevision: string }).verifierRevision ===
      recipe.verifierRevision &&
    RecoveryPlanSchema.safeParse(recipe.recoveryTemplate).success &&
    recipe.currentnessInputs.length > 0 &&
    new Set(recipe.currentnessInputs).size === recipe.currentnessInputs.length
  );
}

function refusal(outcome: RecipeCurrentnessResult['outcome']): RecipeCurrentnessResult {
  return { outcome, inputs: {}, reason: 'RECIPE_NOT_ELIGIBLE_OR_CURRENT' };
}

/**
 * Narrow exact-matching pilot: unsupported predicate, dynamic parameters,
 * environment/policy/binding constraints and mutating graphs are NOT silently
 * ignored. Those Recipes are not eligible until separately mediated.
 */
export class BoundedActiveRecipeResolver implements RecipeResolverPort {
  private readonly host: TrustedActiveRecipeAuthority;

  constructor(authority: TrustedActiveRecipeAuthority) {
    try {
      const list = authority?.list;
      const taskId = authority?.taskId;
      const facts = authority?.currentFacts;
      const preview = authority?.previewExact;
      if ([list, taskId, facts, preview].some((fn) => typeof fn !== 'function')) {
        throw new Error('RECIPE_RESOLVER_CONFIGURATION_REFUSED');
      }
      this.host = {
        list: list.bind(authority),
        taskId: taskId.bind(authority),
        currentFacts: facts.bind(authority),
        previewExact: preview.bind(authority),
      };
    } catch {
      throw new Error('RECIPE_RESOLVER_CONFIGURATION_REFUSED');
    }
  }

  private active(): Candidate[] {
    try {
      const entries = this.host.list();
      if (!Array.isArray(entries) || entries.length > 32) {
        throw new Error('RECIPE_RESOLVER_UNAVAILABLE');
      }
      const parsed = RecipeCandidatesSchema.safeParse({ candidates: entries });
      if (!parsed.success) throw new Error('RECIPE_RESOLVER_UNAVAILABLE');
      const unique = new Set<string>();
      for (const entry of parsed.data.candidates) {
        const key = `${entry.recipe.recipeId}@${entry.recipe.revision}`;
        if (unique.has(key)) throw new Error('RECIPE_RESOLVER_UNAVAILABLE');
        unique.add(key);
      }
      return parsed.data.candidates.filter(
        (entry) =>
          entry.lifecycle.state === 'ACTIVE' &&
          entry.lifecycle.recipeId === entry.recipe.recipeId &&
          entry.lifecycle.revision === entry.recipe.revision &&
          isSafeR0Definition(entry.recipe),
      );
    } catch {
      throw new Error('RECIPE_RESOLVER_UNAVAILABLE');
    }
  }

  async match(intent: Intent): Promise<RecipeCandidates> {
    try {
      if (
        typeof intent?.objective !== 'string' ||
        !Array.isArray(intent.objects) ||
        !intent.objects.every((v) => typeof v === 'string') ||
        !isEmptyRecord(intent.constraints)
      ) {
        throw new Error('RECIPE_RESOLVER_UNAVAILABLE');
      }
      // A non-empty objects set demands a separately specified mapping. Never
      // claim the generic recipe is eligible for unknown selected objects.
      if (intent.objects.length > 0) return { candidates: [] };
      return {
        candidates: this.active().filter(
          (entry) => entry.recipe.applicabilityPredicate.objective === intent.objective,
        ),
      };
    } catch {
      throw new Error('RECIPE_RESOLVER_UNAVAILABLE');
    }
  }

  private async eligible(
    input: RecipeDefinition,
    facts: Record<string, unknown>,
  ): Promise<{
    recipe: RecipeDefinition;
    preview: Extract<RecipeReplayPreview, { ok: true }>;
  } | null> {
    try {
      const parsed = RecipeDefinitionSchema.safeParse(input);
      if (!parsed.success || !isSafeR0Definition(parsed.data)) return null;
      const verified = this.active().find(
        (item) =>
          item.recipe.recipeId === parsed.data.recipeId &&
          item.recipe.revision === parsed.data.revision &&
          canonicalJson(item.recipe) === canonicalJson(parsed.data),
      );
      if (!verified) return null;
      const trustedFacts = this.host.currentFacts();
      if (!trustedFacts || typeof trustedFacts !== 'object' || Array.isArray(trustedFacts))
        return null;
      const allowed = verified.recipe.currentnessInputs;
      const keys = Object.keys(trustedFacts);
      if (
        keys.length !== allowed.length ||
        !keys.every((key) => allowed.includes(key)) ||
        keys.some((key) => {
          const value = trustedFacts[key];
          return !(
            typeof value === 'string' ||
            typeof value === 'number' ||
            typeof value === 'boolean'
          );
        }) ||
        canonicalJson(facts) !== canonicalJson(trustedFacts)
      )
        return null;
      const taskId = this.host.taskId();
      if (typeof taskId !== 'string' || !taskId) return null;
      const preview = this.host.previewExact({
        taskId,
        recipeId: verified.recipe.recipeId,
        revisionSha256: verified.recipe.revision,
      });
      if (
        !preview.ok ||
        preview.state !== 'PREVIEW_ONLY' ||
        preview.taskId !== taskId ||
        preview.recipeId !== verified.recipe.recipeId ||
        preview.revisionSha256 !== verified.recipe.revision ||
        preview.actionGraphSha256 !== verified.recipe.actionTemplate.actionGraphSha256 ||
        preview.executionAuthorized !== false ||
        preview.requiresActionControllerRevalidation !== true ||
        preview.modelCalls !== 0
      )
        return null;
      return { recipe: verified.recipe, preview };
    } catch {
      return null;
    }
  }

  async checkCurrentness(
    recipe: RecipeDefinition,
    currentFacts: Record<string, unknown>,
  ): Promise<RecipeCurrentnessResult> {
    const found = await this.eligible(recipe, currentFacts);
    if (!found) return refusal('UNKNOWN');
    const digest = createHash('sha256').update(canonicalJson(currentFacts)).digest('hex');
    return { outcome: 'CURRENT', inputs: { factsSha256: digest } };
  }

  async instantiate(
    recipe: RecipeDefinition,
    parameters: Record<string, unknown>,
    currentFacts: Record<string, unknown>,
  ): Promise<ActionPlanProposal> {
    try {
      // Parameter substitutions, arbitrary template language and multi-node
      // effects require a separate T04 proof. Never infer applicability.
      if (!isEmptyRecord(parameters)) throw new Error('RECIPE_INSTANTIATION_REFUSED');
      const found = await this.eligible(recipe, currentFacts);
      if (!found) throw new Error('RECIPE_INSTANTIATION_REFUSED');
      const graph = found.preview.actionGraph;
      const [action] = graph.nodes;
      if (
        graph.nodes.length !== 1 ||
        graph.edges.length !== 0 ||
        !action ||
        action.op !== 'file.search' ||
        canonicalJson(found.preview.declaredEffects) !== canonicalJson(['file.search'])
      )
        throw new Error('RECIPE_INSTANTIATION_REFUSED');
      const vp = VerificationPlanSchema.safeParse(found.recipe.actionTemplate.verificationPlan);
      const recovery = RecoveryPlanSchema.safeParse(found.recipe.recoveryTemplate);
      if (!vp.success || !recovery.success) throw new Error('RECIPE_INSTANTIATION_REFUSED');
      const result = ActionPlanProposalSchema.safeParse({
        proposalId: `recipe:${found.recipe.recipeId}@${found.recipe.revision}`,
        capabilityId: found.recipe.capabilityId,
        candidateActions: [
          { actionId: action.actionId, op: action.op, parameters: action.parameters },
        ],
        verificationPlan: vp.data,
        recoveryPlan: recovery.data,
        recipeRef: `${found.recipe.recipeId}@${found.recipe.revision}`,
      });
      if (!result.success) throw new Error('RECIPE_INSTANTIATION_REFUSED');
      // Even CURRENT and ACTIVE are ONLY a plan proposal; no grant/effects.
      return result.data;
    } catch {
      throw new Error('RECIPE_INSTANTIATION_REFUSED');
    }
  }
}
