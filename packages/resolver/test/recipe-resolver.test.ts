import { createHash } from 'node:crypto';
import { canonicalJson, computeRecipeRevision } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import {
  ClosedWorldRecipePreview,
  type RecipeReplayCurrentness,
  type RecipeReplaySnapshot,
} from '../src/recipe-resolver.ts';

const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');
const sourceText = 'proposal-only JS source; NEVER executed';
const compiledArtifact = 'opaque-preverified-typed-artifact';
function fixture(): RecipeReplaySnapshot {
  const actionGraph = {
    nodes: [{ actionId: 'read-1', op: 'file.search' as const,
      parameters: { root: 'C:/selected', query: '*.txt' } }],
    edges: [],
  };
  const declaredEffects = ['file.search'];
  const base = {
    recipeId: 'r1',
    sourceSha256: sha(sourceText),
    actionGraphSha256: sha(canonicalJson(actionGraph)),
    compiledSha256: sha(compiledArtifact),
    declaredEffectsSha256: sha(canonicalJson(declaredEffects)),
    compilerRevision: 'compiler-1',
    contractRevision: 'contract-1',
    verifierId: 'fixed-typed-verifier',
    verifierRevision: 'reviewed-1',
  };
  return {
    identity: { ...base, revisionSha256: computeRecipeRevision(base) },
    sourceText, compiledArtifact, actionGraph, declaredEffects,
  };
}
function trustedFacts(saved: RecipeReplaySnapshot): RecipeReplayCurrentness {
  return {
    kind: 'CURRENT', taskId: 'task1', recipeId: 'r1',
    revisionSha256: saved.identity.revisionSha256,
    actionGraphSha256: saved.identity.actionGraphSha256,
    compilerRevision: saved.identity.compilerRevision,
    contractRevision: saved.identity.contractRevision,
    verifierId: saved.identity.verifierId, verifierRevision: saved.identity.verifierRevision,
    registryRevision: 'registry-1', policyRevision: 'policy-1',
    scopeRevision: 'scope-1', revocationEpoch: 1,
    capability: 'PREVIEW_RECIPE',
  };
}
function harness(
  saved: RecipeReplaySnapshot = fixture(),
  current: RecipeReplayCurrentness = trustedFacts(saved),
) {
  let loads = 0; let checks = 0;
  const port = new ClosedWorldRecipePreview({
    loadExact: () => { loads++; return saved; },
    currentness: () => { checks++; return current; },
  });
  return { port, loads: () => loads, checks: () => checks,
    input: { taskId: 'task1', recipeId: 'r1', revisionSha256: saved.identity.revisionSha256 } };
}

describe('T04 immutable closed-world Recipe preview; never execute', () => {
  it('replays exact typed representation with zero LLM calls and zero authority', () => {
    const h = harness();
    const result = h.port.preview(h.input);
    expect(result).toMatchObject({
      ok: true, state: 'PREVIEW_ONLY',
      declaredEffects: ['file.search'],
      modelCalls: 0, requiresActionControllerRevalidation: true, executionAuthorized: false,
    });
    expect(h.loads()).toBe(1);
    expect(h.checks()).toBe(1);
    expect(JSON.stringify(result)).not.toContain(sourceText);
    expect(JSON.stringify(result)).not.toContain(compiledArtifact);
  });

  it('denies changed graph with preserved source and compiled hash (RCP-01)', () => {
    const old = fixture();
    const forged = {
      ...old,
      actionGraph: { nodes: [{ actionId: 'read-1', op: 'file.move' as const,
        parameters: { sourcePath: 'C:/selected/a', destinationPath: 'C:/wrong/b' } }], edges: [] },
    };
    const h = harness(forged);
    expect(h.port.preview(h.input)).toEqual({ ok: false, code: 'RECIPE_CORRUPT' });
    expect(h.checks()).toBe(0);
  });

  it('denies an unregistered raw-shell action and script graph edges with cycles', () => {
    const good = fixture();
    const rogue = { ...good, actionGraph: { nodes: [
      { actionId: 'shell', op: 'cmd /c del C:/Users', parameters: {} },
    ], edges: [] } } as unknown as RecipeReplaySnapshot;
    expect(harness(rogue).port.preview(harness(rogue).input)).toEqual({
      ok: false, code: 'RECIPE_CORRUPT',
    });
    const cycled = { ...good, actionGraph: {
      nodes: good.actionGraph.nodes,
      edges: [{ from: 'read-1', to: 'read-1' }],
    } };
    const h = harness(cycled);
    expect(h.port.preview(h.input)).toEqual({ ok: false, code: 'RECIPE_CORRUPT' });
  });

  it('denies stale scope, changed verifier, invalid revocation and unavailable facts', () => {
    const saved = fixture();
    const current = trustedFacts(saved);
    if (current.kind !== 'CURRENT') throw new Error('bad fixture');
    for (const facts of [
      { ...current, verifierRevision: 'attacker' },
      { ...current, actionGraphSha256: '0'.repeat(64) },
      { ...current, taskId: 'wrong-task' },
      { ...current, revocationEpoch: -1 },
    ]) {
      const h = harness(saved, facts);
      expect(h.port.preview(h.input)).toEqual({ ok: false, code: 'RECIPE_CURRENTNESS_STALE' });
    }
    const h = harness(saved, { kind: 'UNRESOLVABLE' });
    expect(h.port.preview(h.input)).toEqual({ ok: false, code: 'RECIPE_CURRENTNESS_UNKNOWN' });
  });

  it('rejects invalid caller identity before any store or authority lookup', () => {
    const h = harness();
    expect(h.port.preview({ ...h.input, revisionSha256: 'not-a-sha' })).toEqual({
      ok: false, code: 'RECIPE_INVALID',
    });
    expect(h.loads()).toBe(0);
    expect(h.checks()).toBe(0);
  });

  it('redacts throwing revision/corrupt proof getters without passing raw error', () => {
    const h = new ClosedWorldRecipePreview({
      loadExact: () => { throw new Error('Bearer local-private-token'); },
      currentness: () => { throw new Error('should never call'); },
    });
    expect(h.preview({ taskId: 'task1', recipeId: 'r1', revisionSha256: 'a'.repeat(64) }))
      .toEqual({ ok: false, code: 'RECIPE_UNAVAILABLE' });
  });
});
