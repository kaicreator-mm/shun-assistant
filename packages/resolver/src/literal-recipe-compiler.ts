// T04 narrow closed-world JS/TS Recipe mediation. Only a single literal
// defineRecipe(<strict JSON>) expression is accepted. There is NO interpreter,
// import loader, transpiler, Function/eval, shell or effect dispatch.
import { createHash } from 'node:crypto';
import {
  canonicalJson,
  computeRecipeRevision,
  RecipeActionGraphSchema,
  type RecipeActionGraph,
  type RecipeRevisionIdentity,
} from '@shun/contracts';
import type { RecipeReplaySnapshot } from './recipe-resolver.ts';

const MAX_SOURCE_BYTES = 64 * 1024;
const MAX_ACTIONS = 128;
const MAX_EDGES = 256;
/** Required wrapper is valid TS; the argument is a strict JSON literal subset. */
const LITERAL_ONLY_RECIPE =
  /^\s*export\s+default\s+defineRecipe\s*\(\s*([\s\S]*?)\s*\)\s*;\s*$/u;

function hash(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export const LITERAL_RECIPE_COMPILER_REVISION = 'v0.2-literal-json-1';
export type LiteralRecipeCompileResult =
  | {
      ok: true;
      state: 'COMPILED_NOT_EXECUTED';
      compiled: RecipeReplaySnapshot;
      modelCalls: 0;
      effectExecuted: false;
      requiresActionControllerRevalidation: true;
    }
  | {
      ok: false;
      code: 'SOURCE_INVALID' | 'UNSUPPORTED_CODE' | 'GRAPH_INVALID' | 'COMPILER_CONFIG_INVALID';
    };

export type TrustedRecipeCompilerConfig = Readonly<{
  recipeId: string;
  contractRevision: string;
  verifierId: string;
  verifierRevision: string;
}>;

/**
 * Compiles a *literal-only* TS source subset to a hashed, immutable graph
 * representation. All other JS/TS constructs intentionally fail closed.
 * This never promotes a Recipe revision or returns an execution grant.
 */
export function compileLiteralRecipe(
  source: unknown,
  hostConfig: TrustedRecipeCompilerConfig,
): LiteralRecipeCompileResult {
  try {
    if (
      !hostConfig ||
      typeof hostConfig.recipeId !== 'string' ||
      !hostConfig.recipeId ||
      typeof hostConfig.contractRevision !== 'string' ||
      !hostConfig.contractRevision ||
      typeof hostConfig.verifierId !== 'string' ||
      !hostConfig.verifierId ||
      typeof hostConfig.verifierRevision !== 'string' ||
      !hostConfig.verifierRevision
    ) {
      return { ok: false, code: 'COMPILER_CONFIG_INVALID' };
    }
    if (typeof source !== 'string' || !source || Buffer.byteLength(source, 'utf8') > MAX_SOURCE_BYTES) {
      return { ok: false, code: 'SOURCE_INVALID' };
    }
    const match = LITERAL_ONLY_RECIPE.exec(source);
    if (!match) return { ok: false, code: 'UNSUPPORTED_CODE' };
    let raw: unknown;
    try {
      raw = JSON.parse(match[1] ?? '') as unknown;
    } catch {
      return { ok: false, code: 'UNSUPPORTED_CODE' };
    }
    const parsed = RecipeActionGraphSchema.safeParse(raw);
    if (
      !parsed.success ||
      parsed.data.nodes.length > MAX_ACTIONS ||
      parsed.data.edges.length > MAX_EDGES
    ) {
      return { ok: false, code: 'GRAPH_INVALID' };
    }
    const graph: RecipeActionGraph = parsed.data;
    const declaredEffects = [...new Set(graph.nodes.map((node) => node.op))].sort();
    const compiledArtifact = canonicalJson(graph);
    const base = {
      recipeId: hostConfig.recipeId,
      sourceSha256: hash(source),
      actionGraphSha256: hash(compiledArtifact),
      compiledSha256: hash(compiledArtifact),
      declaredEffectsSha256: hash(canonicalJson(declaredEffects)),
      compilerRevision: LITERAL_RECIPE_COMPILER_REVISION,
      contractRevision: hostConfig.contractRevision,
      verifierId: hostConfig.verifierId,
      verifierRevision: hostConfig.verifierRevision,
    };
    const identity: RecipeRevisionIdentity = {
      ...base,
      revisionSha256: computeRecipeRevision(base),
    };
    return {
      ok: true,
      state: 'COMPILED_NOT_EXECUTED',
      compiled: {
        identity,
        sourceText: source,
        compiledArtifact,
        actionGraph: graph,
        declaredEffects,
      },
      modelCalls: 0,
      effectExecuted: false,
      requiresActionControllerRevalidation: true,
    };
  } catch {
    // Exceptions may carry raw model content, local paths or private errors.
    return { ok: false, code: 'SOURCE_INVALID' };
  }
}
