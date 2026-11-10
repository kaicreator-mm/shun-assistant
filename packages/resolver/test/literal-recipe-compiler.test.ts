import { RecipeActionGraphSchema, verifyRecipeRevision } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import {
  compileLiteralRecipe,
  LITERAL_RECIPE_COMPILER_REVISION,
} from '../src/literal-recipe-compiler.ts';

const host = {
  recipeId: 'r1',
  contractRevision: 'v02-recipe',
  verifierId: 'trusted-fixed-verifier',
  verifierRevision: '1',
};
const graph = {
  nodes: [
    {
      actionId: 'search-1',
      op: 'file.search',
      parameters: { root: 'C:/selected', query: '*.txt' },
    },
  ],
  edges: [],
};

function literal(value: unknown): string {
  return `export default defineRecipe(${JSON.stringify(value)});`;
}

describe('T04 literal-only JS/TS Recipe-to-typed-action mediation', () => {
  it('compiles a strict literal graph without executing code, model or effects', () => {
    const result = compileLiteralRecipe(literal(graph), host);
    expect(result).toMatchObject({
      ok: true,
      state: 'COMPILED_NOT_EXECUTED',
      modelCalls: 0,
      effectExecuted: false,
      requiresActionControllerRevalidation: true,
      compiled: {
        actionGraph: graph,
        declaredEffects: ['file.search'],
        identity: { compilerRevision: LITERAL_RECIPE_COMPILER_REVISION },
      },
    });
    if (!result.ok) throw new Error('fixture failed');
    expect(verifyRecipeRevision(result.compiled.identity)).toBe(true);
    expect(RecipeActionGraphSchema.safeParse(result.compiled.actionGraph).success).toBe(true);
    expect(result.compiled.compiledArtifact).toContain('"file.search"');
    expect(result.compiled.compiledArtifact).not.toContain('export default');
    expect(compileLiteralRecipe(literal(graph), host)).toEqual(result);
  });

  it('rejects long unterminated whitespace without overlapping-regex backtracking', () => {
    for (const length of [500, 2000, 8192, 32768]) {
      const malformed = `export default defineRecipe(${' '.repeat(length)}`;
      expect(compileLiteralRecipe(malformed, host)).toEqual({
        ok: false,
        code: 'UNSUPPORTED_CODE',
      });
    }
    // A valid JSON string with a literal closing delimiter is still data.
    expect(
      compileLiteralRecipe(
        literal({
          nodes: [
            {
              actionId: 'search-1',
              op: 'file.search',
              parameters: { root: 'C:/selected', query: ');' },
            },
          ],
          edges: [],
        }),
        host,
      ).ok,
    ).toBe(true);
  });

  it('returns a frozen nested graph, identity and effects, never a mutable grant', () => {
    const result = compileLiteralRecipe(literal(graph), host);
    if (!result.ok) throw new Error('fixture');
    expect(Object.isFrozen(result.compiled)).toBe(true);
    expect(Object.isFrozen(result.compiled.identity)).toBe(true);
    expect(Object.isFrozen(result.compiled.declaredEffects)).toBe(true);
    expect(Object.isFrozen(result.compiled.actionGraph)).toBe(true);
    expect(Object.isFrozen(result.compiled.actionGraph.nodes)).toBe(true);
    expect(Object.isFrozen(result.compiled.actionGraph.nodes[0])).toBe(true);
    expect(Object.isFrozen(result.compiled.actionGraph.nodes[0]?.parameters)).toBe(true);
    expect(Object.isFrozen(result.compiled.actionGraph.edges)).toBe(true);
    expect(() => {
      (result.compiled.identity as { verifierRevision: string }).verifierRevision = 'attacker';
    }).toThrow(TypeError);
    expect(result.compiled.identity.verifierRevision).toBe('1');
  });

  it('keeps effectful operations as typed proposals only, never authorization', () => {
    const effectful = {
      nodes: [
        {
          actionId: 'move-1',
          op: 'file.move',
          parameters: { sourcePath: 'C:/a', destinationPath: 'C:/b' },
        },
      ],
      edges: [],
    };
    expect(compileLiteralRecipe(literal(effectful), host)).toMatchObject({
      ok: true,
      effectExecuted: false,
      compiled: { declaredEffects: ['file.move'] },
    });
  });

  it('rejects imports, side-effect statements, dynamic JS and TS runtime execution', () => {
    const invalid = [
      "import fs from 'node:fs';\n" + literal(graph),
      literal(graph) + '\nprocess.exit(0)',
      "export default defineRecipe(require('node:fs'))",
      "export default defineRecipe(eval('1'))",
      'export default defineRecipe((() => ({ nodes: [], edges: [] }))())',
      'export default defineRecipe({ nodes: [], edges: [] })',
      'export default defineRecipe(`unsafe-${process.env.KEY}`)',
      "export default defineRecipe(JSON.parse('[]'))",
      'export default defineRecipe(await getRecipe())',
      'export default defineRecipe(/* comment */ {})',
    ];
    for (const program of invalid) {
      expect(compileLiteralRecipe(program, host).ok).toBe(false);
    }
  });

  it('rejects malicious operations, graph cycles and extra unknown fields', () => {
    const variants = [
      { nodes: [{ actionId: 'x', op: 'cmd.exe', parameters: {} }], edges: [] },
      {
        nodes: [
          {
            actionId: 'x',
            op: 'file.search',
            parameters: {
              root: 'C:/ok',
              query: '*',
              command: 'powershell',
            },
          },
        ],
        edges: [],
      },
      { ...graph, edges: [{ from: 'search-1', to: 'search-1' }] },
      { ...graph, untrusted: 'executionGrant' },
      { nodes: [], edges: [] },
    ];
    for (const variant of variants) {
      expect(compileLiteralRecipe(literal(variant), host)).toEqual({
        ok: false,
        code: 'GRAPH_INVALID',
      });
    }
  });

  it('refuses oversized source, invalid trusted config and throwing getter', () => {
    expect(compileLiteralRecipe(' '.repeat(70_000), host)).toEqual({
      ok: false,
      code: 'SOURCE_INVALID',
    });
    expect(compileLiteralRecipe(literal(graph), { ...host, verifierId: '' })).toEqual({
      ok: false,
      code: 'COMPILER_CONFIG_INVALID',
    });
    expect(
      compileLiteralRecipe(literal(graph), {
        ...host,
        get verifierId(): never {
          throw new Error('Bearer private-token');
        },
      }),
    ).toEqual({ ok: false, code: 'SOURCE_INVALID' });
  });

  it('pins every changed graph, source and verifier revision into a distinct SHA', () => {
    const first = compileLiteralRecipe(literal(graph), host);
    const changed = compileLiteralRecipe(
      literal({
        ...graph,
        nodes: [
          {
            ...graph.nodes[0],
            parameters: {
              root: 'C:/another',
              query: '*.txt',
            },
          },
        ],
      }),
      host,
    );
    const differentVerifier = compileLiteralRecipe(literal(graph), {
      ...host,
      verifierRevision: 'revoked-2',
    });
    if (!first.ok || !changed.ok || !differentVerifier.ok) throw new Error('fixture');
    expect(first.compiled.identity.revisionSha256).not.toBe(
      changed.compiled.identity.revisionSha256,
    );
    expect(first.compiled.identity.revisionSha256).not.toBe(
      differentVerifier.compiled.identity.revisionSha256,
    );
  });
});
