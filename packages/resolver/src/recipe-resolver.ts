// v0.2 T04 closed-world Recipe replay *preview*. An immutable revision can
// propose only the frozen typed ActionGraph, never execute arbitrary JS,
// PowerShell, shell commands, imports or side effects. Runtime permission/R2
// reentry remains the sole responsibility of the host ActionController.
import { createHash } from 'node:crypto';
import {
  canonicalJson,
  type RecipeActionGraph,
  RecipeActionGraphSchema,
  type RecipeRevisionIdentity,
  RecipeRevisionIdentitySchema,
  verifyRecipeRevision,
} from '@shun/contracts';

const SHA = /^[a-f0-9]{64}$/;
function digest(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export type RecipeReplaySnapshot = Readonly<{
  identity: RecipeRevisionIdentity;
  sourceText: string;
  compiledArtifact: string;
  actionGraph: RecipeActionGraph;
  declaredEffects: readonly string[];
}>;

export type RecipeReplayCurrentness =
  | Readonly<{
      kind: 'CURRENT';
      taskId: string;
      recipeId: string;
      revisionSha256: string;
      actionGraphSha256: string;
      compilerRevision: string;
      contractRevision: string;
      verifierId: string;
      verifierRevision: string;
      registryRevision: string;
      policyRevision: string;
      scopeRevision: string;
      revocationEpoch: number;
      capability: 'PREVIEW_RECIPE';
    }>
  | Readonly<{ kind: 'UNRESOLVABLE' }>;

export type RecipeReplayHost = Readonly<{
  /** T03 immutable revision lookup, NEVER a caller-provided source body. */
  loadExact: (recipeId: string, revisionSha256: string) => RecipeReplaySnapshot | null;
  /**
   * Trusted local host/ActionController produces facts on every preview.
   * This is NOT a replay/execute grant and cannot replace action-level R2.
   */
  currentness: (taskId: string, recipeId: string) => RecipeReplayCurrentness;
}>;

export type RecipeReplayRefusal =
  | 'RECIPE_INVALID'
  | 'RECIPE_UNAVAILABLE'
  | 'RECIPE_CORRUPT'
  | 'RECIPE_CURRENTNESS_UNKNOWN'
  | 'RECIPE_CURRENTNESS_STALE';

export type RecipeReplayPreview =
  | {
      ok: true;
      state: 'PREVIEW_ONLY';
      taskId: string;
      recipeId: string;
      revisionSha256: string;
      actionGraphSha256: string;
      /** Exact verifier pins independently checked against T03 saved identity. */
      verifierId?: string;
      verifierRevision?: string;
      actionGraph: RecipeActionGraph;
      declaredEffects: readonly string[];
      /** True means no new model call was needed for this exact lookup. */
      modelCalls: 0;
      requiresActionControllerRevalidation: true;
      executionAuthorized: false;
    }
  | { ok: false; code: RecipeReplayRefusal };

export class ClosedWorldRecipePreview {
  private readonly host: RecipeReplayHost;

  constructor(host: RecipeReplayHost) {
    if (!host || typeof host.loadExact !== 'function' || typeof host.currentness !== 'function') {
      throw new Error('RECIPE_PREVIEW_CONFIGURATION_REFUSED');
    }
    this.host = host;
  }

  /**
   * Does not accept source JS, a graph from user input, a shell string, a
   * permission flag or a fake "current" statement from the planner/UI.
   */
  preview(input: {
    taskId: string;
    recipeId: string;
    revisionSha256: string;
  }): RecipeReplayPreview {
    let taskId: string;
    let recipeId: string;
    let revisionSha256: string;
    try {
      taskId = input.taskId;
      recipeId = input.recipeId;
      revisionSha256 = input.revisionSha256;
    } catch {
      return { ok: false, code: 'RECIPE_INVALID' };
    }
    if (
      typeof taskId !== 'string' ||
      taskId.length < 1 ||
      typeof recipeId !== 'string' ||
      recipeId.length < 1 ||
      typeof revisionSha256 !== 'string' ||
      !SHA.test(revisionSha256)
    ) {
      return { ok: false, code: 'RECIPE_INVALID' };
    }

    let saved: RecipeReplaySnapshot | null;
    try {
      saved = this.host.loadExact(recipeId, revisionSha256);
    } catch {
      return { ok: false, code: 'RECIPE_UNAVAILABLE' };
    }
    if (!saved) return { ok: false, code: 'RECIPE_UNAVAILABLE' };

    let identity: RecipeRevisionIdentity;
    let graph: RecipeActionGraph;
    let effects: readonly string[];
    try {
      const parsedId = RecipeRevisionIdentitySchema.safeParse(saved.identity);
      const parsedGraph = RecipeActionGraphSchema.safeParse(saved.actionGraph);
      if (
        !parsedId.success ||
        !parsedGraph.success ||
        !verifyRecipeRevision(parsedId.data) ||
        parsedId.data.recipeId !== recipeId ||
        parsedId.data.revisionSha256 !== revisionSha256 ||
        typeof saved.sourceText !== 'string' ||
        typeof saved.compiledArtifact !== 'string' ||
        !Array.isArray(saved.declaredEffects) ||
        saved.declaredEffects.some((e) => typeof e !== 'string') ||
        parsedGraph.data.nodes.length > 128 ||
        parsedGraph.data.edges.length > 256
      ) {
        return { ok: false, code: 'RECIPE_CORRUPT' };
      }
      identity = parsedId.data;
      graph = parsedGraph.data;
      effects = [...new Set(graph.nodes.map((node) => node.op))].sort();
      if (
        digest(saved.sourceText) !== identity.sourceSha256 ||
        digest(saved.compiledArtifact) !== identity.compiledSha256 ||
        digest(canonicalJson(graph)) !== identity.actionGraphSha256 ||
        digest(canonicalJson(effects)) !== identity.declaredEffectsSha256 ||
        canonicalJson(saved.declaredEffects) !== canonicalJson(effects)
      ) {
        return { ok: false, code: 'RECIPE_CORRUPT' };
      }
    } catch {
      return { ok: false, code: 'RECIPE_CORRUPT' };
    }

    let facts: RecipeReplayCurrentness;
    try {
      facts = this.host.currentness(taskId, recipeId);
    } catch {
      return { ok: false, code: 'RECIPE_CURRENTNESS_UNKNOWN' };
    }
    try {
      if (!facts || facts.kind !== 'CURRENT') {
        return { ok: false, code: 'RECIPE_CURRENTNESS_UNKNOWN' };
      }
      if (
        facts.taskId !== taskId ||
        facts.recipeId !== recipeId ||
        facts.revisionSha256 !== revisionSha256 ||
        facts.actionGraphSha256 !== identity.actionGraphSha256 ||
        facts.compilerRevision !== identity.compilerRevision ||
        facts.contractRevision !== identity.contractRevision ||
        facts.verifierId !== identity.verifierId ||
        facts.verifierRevision !== identity.verifierRevision ||
        typeof facts.registryRevision !== 'string' ||
        !facts.registryRevision ||
        typeof facts.policyRevision !== 'string' ||
        !facts.policyRevision ||
        typeof facts.scopeRevision !== 'string' ||
        !facts.scopeRevision ||
        !Number.isSafeInteger(facts.revocationEpoch) ||
        facts.revocationEpoch < 0 ||
        facts.capability !== 'PREVIEW_RECIPE'
      ) {
        return { ok: false, code: 'RECIPE_CURRENTNESS_STALE' };
      }
    } catch {
      return { ok: false, code: 'RECIPE_CURRENTNESS_UNKNOWN' };
    }

    // Returned graph is a typed proposal only: it never becomes a grant, a
    // promoted recipe, a process invocation or a filesystem effect here.
    return {
      ok: true,
      state: 'PREVIEW_ONLY',
      taskId,
      recipeId,
      revisionSha256,
      actionGraphSha256: identity.actionGraphSha256,
      verifierId: identity.verifierId,
      verifierRevision: identity.verifierRevision,
      actionGraph: graph,
      declaredEffects: effects,
      modelCalls: 0,
      requiresActionControllerRevalidation: true,
      executionAuthorized: false,
    };
  }
}
