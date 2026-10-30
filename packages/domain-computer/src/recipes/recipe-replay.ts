/**
 * T07 Domain Computer Recipe adapter.
 *
 * This adapter reuses the existing T04 BoundedActiveRecipeResolver and T03
 * immutable-revision preview seam. It never compiles source, chooses a mutable
 * "latest" revision, calls an LLM, issues an approval/grant, or executes an
 * action. Its only successful result is a typed proposal for the existing
 * Kernel / ActionController path to revalidate independently.
 */
import {
  ActionPlanProposalSchema,
  RecipeCandidatesSchema,
  RecipeCurrentnessResultSchema,
  RecipeDefinitionSchema,
  type ActionPlanProposal,
  type RecipeResolverPort,
} from '../../../contracts/src/ports.ts';
import {
  BoundedActiveRecipeResolver,
  type TrustedActiveRecipeAuthority,
} from '../../../resolver/src/active-recipe-resolver.ts';

const SHA256 = /^[a-f0-9]{64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

export type DomainRecipeReplayRefusal =
  | 'INVALID_REQUEST'
  | 'RESOLVER_UNAVAILABLE'
  | 'NO_CURRENT_RECIPE'
  | 'AMBIGUOUS_RECIPE'
  | 'CURRENTNESS_UNKNOWN'
  | 'RECIPE_NOT_CURRENT'
  | 'REPLAY_REFUSED';

export type DomainRecipeReplayResult =
  | Readonly<{ status: 'NO_MATCH'; modelCalls: 0 }>
  | Readonly<{ status: 'REFUSED'; code: DomainRecipeReplayRefusal; modelCalls: 0 }>
  | Readonly<{
      status: 'PROPOSAL_ONLY';
      recipeIdentity: Readonly<{
        recipeId: string;
        revisionSha256: string;
        actionGraphSha256: string;
      }>;
      proposal: ActionPlanProposal;
      declaredEffects: readonly ['file.search'];
      modelCalls: 0;
      deterministic: true;
      executionAuthorized: false;
      requiresActionControllerRevalidation: true;
      effectRoute: 'KERNEL_ACTION_CONTROLLER_ONLY';
    }>;

type ReplayIntent = Readonly<{
  objective: string;
  objects: readonly string[];
  constraints: Readonly<Record<string, unknown>>;
}>;

function isRecord(value: unknown): value is Record<string, unknown> {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function safeText(value: unknown, maxLength: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxLength &&
    value.trim() === value &&
    !CONTROL.test(value)
  );
}

function parseIntent(value: unknown): ReplayIntent | null {
  try {
    if (!isRecord(value)) return null;
    const keys = Object.keys(value).sort();
    if (keys.join(',') !== 'constraints,objective,objects') return null;
    if (!safeText(value.objective, 256) || !Array.isArray(value.objects) || value.objects.length > 32) {
      return null;
    }
    if (!value.objects.every((item) => safeText(item, 256))) return null;
    if (new Set(value.objects).size !== value.objects.length) return null;
    if (!isRecord(value.constraints) || Object.keys(value.constraints).length !== 0) return null;
    return {
      objective: value.objective,
      objects: [...value.objects],
      constraints: {},
    };
  } catch {
    return null;
  }
}

function snapshotFacts(value: unknown): Record<string, unknown> | null {
  try {
    if (!isRecord(value)) return null;
    const entries = Object.entries(value);
    if (entries.length === 0 || entries.length > 32) return null;
    const copy: Record<string, unknown> = {};
    for (const [key, item] of entries) {
      if (
        !safeText(key, 128) ||
        !(
          (typeof item === 'string' && item.length <= 256 && !CONTROL.test(item)) ||
          typeof item === 'boolean' ||
          (typeof item === 'number' && Number.isFinite(item))
        )
      ) return null;
      copy[key] = item;
    }
    return copy;
  } catch {
    return null;
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function validProposal(
  raw: unknown,
  recipeId: string,
  revisionSha256: string,
  capabilityId: string,
): ActionPlanProposal | null {
  const parsed = ActionPlanProposalSchema.safeParse(raw);
  if (!parsed.success) return null;
  const proposal = parsed.data;
  const exactRef = `${recipeId}@${revisionSha256}`;
  if (
    proposal.proposalId !== `recipe:${exactRef}` ||
    proposal.recipeRef !== exactRef ||
    proposal.capabilityId !== capabilityId ||
    capabilityId !== 'file.search' ||
    proposal.candidateActions.length !== 1
  ) return null;

  const action = proposal.candidateActions[0];
  if (
    !isRecord(action) ||
    Object.keys(action).sort().join(',') !== 'actionId,op,parameters' ||
    !safeText(action.actionId, 128) ||
    action.op !== 'file.search' ||
    !isRecord(action.parameters) ||
    Object.keys(action.parameters).sort().join(',') !== 'query,root' ||
    !safeText(action.parameters.root, 32768) ||
    !safeText(action.parameters.query, 256)
  ) return null;

  return parsed.data;
}

/**
 * Host-only bounded adapter. The supplied authority must be the private T04
 * composition over T03's exact immutable Recipe repository/currentness. All
 * method references are snapshotted once so mutable getters cannot swap ports
 * between checks. No execution-capability port is accepted by this class.
 */
export class DomainComputerRecipeReplayAdapter {
  private readonly resolver: RecipeResolverPort;
  private readonly currentFacts: TrustedActiveRecipeAuthority['currentFacts'];

  constructor(authority: TrustedActiveRecipeAuthority) {
    try {
      const list = authority?.list;
      const taskId = authority?.taskId;
      const currentFacts = authority?.currentFacts;
      const previewExact = authority?.previewExact;
      if (
        typeof list !== 'function' ||
        typeof taskId !== 'function' ||
        typeof currentFacts !== 'function' ||
        typeof previewExact !== 'function'
      ) throw new Error('DOMAIN_RECIPE_CONFIGURATION_REFUSED');

      const stableAuthority: TrustedActiveRecipeAuthority = Object.freeze({
        list: list.bind(authority),
        taskId: taskId.bind(authority),
        currentFacts: currentFacts.bind(authority),
        previewExact: previewExact.bind(authority),
      });
      this.currentFacts = stableAuthority.currentFacts;
      this.resolver = new BoundedActiveRecipeResolver(stableAuthority);
    } catch {
      throw new Error('DOMAIN_RECIPE_CONFIGURATION_REFUSED');
    }
  }

  /**
   * Match one trusted ACTIVE Recipe and return only a deterministic proposal.
   * Unknown/ambiguous identity, unsupported effects, stale currentness or any
   * resolver failure is a typed refusal. This method never dispatches effects.
   */
  async proposeExactReplay(input: unknown): Promise<DomainRecipeReplayResult> {
    const intent = parseIntent(input);
    if (!intent) return { status: 'REFUSED', code: 'INVALID_REQUEST', modelCalls: 0 };

    let candidates: unknown;
    try {
      candidates = await this.resolver.match({
        objective: intent.objective,
        objects: [...intent.objects],
        constraints: { ...intent.constraints },
      });
    } catch {
      return { status: 'REFUSED', code: 'RESOLVER_UNAVAILABLE', modelCalls: 0 };
    }

    const parsedCandidates = RecipeCandidatesSchema.safeParse(candidates);
    if (!parsedCandidates.success) {
      return { status: 'REFUSED', code: 'RESOLVER_UNAVAILABLE', modelCalls: 0 };
    }
    if (parsedCandidates.data.candidates.length === 0) {
      return { status: 'NO_MATCH', modelCalls: 0 };
    }
    if (parsedCandidates.data.candidates.length !== 1) {
      return { status: 'REFUSED', code: 'AMBIGUOUS_RECIPE', modelCalls: 0 };
    }

    const selected = parsedCandidates.data.candidates[0];
    if (!selected) return { status: 'NO_MATCH', modelCalls: 0 };
    const parsedRecipe = RecipeDefinitionSchema.safeParse(selected.recipe);
    if (
      !parsedRecipe.success ||
      selected.lifecycle.state !== 'ACTIVE' ||
      selected.lifecycle.recipeId !== parsedRecipe.data.recipeId ||
      selected.lifecycle.revision !== parsedRecipe.data.revision ||
      !SHA256.test(parsedRecipe.data.revision) ||
      parsedRecipe.data.capabilityId !== 'file.search' ||
      !isRecord(parsedRecipe.data.actionTemplate) ||
      typeof parsedRecipe.data.actionTemplate.actionGraphSha256 !== 'string' ||
      !SHA256.test(parsedRecipe.data.actionTemplate.actionGraphSha256)
    ) {
      return { status: 'REFUSED', code: 'REPLAY_REFUSED', modelCalls: 0 };
    }
    const recipe = parsedRecipe.data;
    const actionGraphSha256 = recipe.actionTemplate.actionGraphSha256;
    if (typeof actionGraphSha256 !== 'string' || !SHA256.test(actionGraphSha256)) {
      return { status: 'REFUSED', code: 'REPLAY_REFUSED', modelCalls: 0 };
    }
    let rawFacts: unknown;
    try {
      rawFacts = this.currentFacts();
    } catch {
      return { status: 'REFUSED', code: 'CURRENTNESS_UNKNOWN', modelCalls: 0 };
    }
    const facts = snapshotFacts(rawFacts);
    if (!facts) return { status: 'REFUSED', code: 'CURRENTNESS_UNKNOWN', modelCalls: 0 };

    let currentness: unknown;
    try {
      currentness = await this.resolver.checkCurrentness(recipe, facts);
    } catch {
      return { status: 'REFUSED', code: 'CURRENTNESS_UNKNOWN', modelCalls: 0 };
    }
    const parsedCurrentness = RecipeCurrentnessResultSchema.safeParse(currentness);
    if (!parsedCurrentness.success) {
      return { status: 'REFUSED', code: 'CURRENTNESS_UNKNOWN', modelCalls: 0 };
    }
    if (parsedCurrentness.data.outcome !== 'CURRENT') {
      return { status: 'REFUSED', code: 'RECIPE_NOT_CURRENT', modelCalls: 0 };
    }

    let rawProposal: unknown;
    try {
      rawProposal = await this.resolver.instantiate(recipe, {}, facts);
    } catch {
      return { status: 'REFUSED', code: 'REPLAY_REFUSED', modelCalls: 0 };
    }
    const proposal = validProposal(
      rawProposal,
      recipe.recipeId,
      recipe.revision,
      recipe.capabilityId,
    );
    if (!proposal) return { status: 'REFUSED', code: 'REPLAY_REFUSED', modelCalls: 0 };

    return deepFreeze({
      status: 'PROPOSAL_ONLY',
      recipeIdentity: {
        recipeId: recipe.recipeId,
        revisionSha256: recipe.revision,
        actionGraphSha256,
      },
      proposal,
      declaredEffects: ['file.search'] as const,
      modelCalls: 0 as const,
      deterministic: true as const,
      executionAuthorized: false as const,
      requiresActionControllerRevalidation: true as const,
      effectRoute: 'KERNEL_ACTION_CONTROLLER_ONLY' as const,
    });
  }
}
