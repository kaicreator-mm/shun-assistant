// T04 narrow closed-world JS/TS Recipe mediation. Only a single literal
// defineRecipe(<strict JSON>) expression is accepted. There is NO interpreter,
// import loader, transpiler, Function/eval, shell or effect dispatch.
import { createHash } from 'node:crypto';
import {
  canonicalJson,
  computeRecipeRevision,
  type RecipeActionGraph,
  RecipeActionGraphSchema,
  type RecipeRevisionIdentity,
} from '@shun/contracts';
import type { RecipeReplaySnapshot } from './recipe-resolver.ts';

const MAX_SOURCE_BYTES = 64 * 1024;
const MAX_ACTIONS = 128;
const MAX_EDGES = 256;
/**
 * Linear-time, exact-envelope parser for a deliberately tiny valid TS subset.
 * Never use a whole-source regex with overlapping whitespace/JSON captures:
 * malformed model text must not block the Node event loop.
 */
function extractLiteralArgument(source: string): string | null {
  const trimmed = source.trim();
  const prefix = 'export default defineRecipe(';
  if (!trimmed.startsWith(prefix) || !trimmed.endsWith(');')) return null;
  const body = trimmed.slice(prefix.length, -2).trim();
  return body.length > 0 ? body : null;
}

/** Strict schema below guarantees shallow string-only parameters and edges. */
function freezeGraph(graph: RecipeActionGraph): RecipeActionGraph {
  for (const node of graph.nodes) {
    Object.freeze(node.parameters);
    Object.freeze(node);
  }
  for (const edge of graph.edges) Object.freeze(edge);
  Object.freeze(graph.nodes);
  Object.freeze(graph.edges);
  return Object.freeze(graph);
}

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
    if (
      typeof source !== 'string' ||
      !source ||
      Buffer.byteLength(source, 'utf8') > MAX_SOURCE_BYTES
    ) {
      return { ok: false, code: 'SOURCE_INVALID' };
    }
    const literal = extractLiteralArgument(source);
    if (literal === null) return { ok: false, code: 'UNSUPPORTED_CODE' };
    let raw: unknown;
    try {
      raw = JSON.parse(literal) as unknown;
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
    const graph: RecipeActionGraph = freezeGraph(parsed.data);
    const declaredEffects = Object.freeze([...new Set(graph.nodes.map((node) => node.op))].sort());
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
    const identity: RecipeRevisionIdentity = Object.freeze({
      ...base,
      revisionSha256: computeRecipeRevision(base),
    });
    return {
      ok: true,
      state: 'COMPILED_NOT_EXECUTED',
      compiled: Object.freeze({
        identity,
        sourceText: source,
        compiledArtifact,
        actionGraph: graph,
        declaredEffects,
      }),
      modelCalls: 0,
      effectExecuted: false,
      requiresActionControllerRevalidation: true,
    };
  } catch {
    // Exceptions may carry raw model content, local paths or private errors.
    return { ok: false, code: 'SOURCE_INVALID' };
  }
}
