// Deterministic policy-free ranking: versioned weights, interface/lifecycle
// penalties, uniform fallback mode, explainable reasons (L2 §7.2).
import { describe, expect, it } from 'vitest';
import {
  type BindingScoreFacts,
  RANKING_POLICY_REVISION,
  rankFeasibleBindings,
} from '../src/ranking.ts';
import { bindingDef } from './scenarios.ts';

function binding(bindingId: string, interfaceClass: 'I0' | 'I1' | 'I2' | 'I3' | 'I4') {
  return bindingDef({
    bindingId,
    providerId: `imageProvider.${bindingId}`,
    capabilityId: 'image.batch_process',
    interfaceClass,
  });
}

const B_CLI = binding('b-cli', 'I1');
const B_GUI = binding('b-gui', 'I3');

const FACTS_CLI: BindingScoreFacts = {
  bindingId: 'b-cli',
  components: {
    capabilityFit: 90,
    reliability: 85,
    agentUsability: 92,
    trust: 90,
    environmentCompatibility: 85,
    performance: 80,
    humanUsability: 60,
  },
};

describe('deterministic ranking of feasible bindings', () => {
  it('no score facts selects the interface-class fallback rule, ties by bindingId', () => {
    const ranked = rankFeasibleBindings({ bindings: [B_GUI, B_CLI] });
    expect(ranked.map((entry) => entry.bindingId)).toEqual(['b-cli', 'b-gui']);
    expect(ranked[0]?.reasons[0]).toContain('interface-class fallback');
  });

  it('mixed score-fact coverage falls back for ALL bindings so evidence can never bias a subset', () => {
    const ranked = rankFeasibleBindings({ bindings: [B_GUI, B_CLI], scoreFacts: [FACTS_CLI] });
    expect(ranked.map((entry) => entry.bindingId)).toEqual(['b-cli', 'b-gui']);
    expect(ranked.every((entry) => entry.score === undefined)).toBe(true);
  });

  it('weighted mode: higher final score wins and reasons cite the ranking policy revision', () => {
    const factsGui: BindingScoreFacts = {
      bindingId: 'b-gui',
      components: {
        capabilityFit: 85,
        reliability: 80,
        agentUsability: 25,
        trust: 92,
        environmentCompatibility: 70,
        performance: 55,
        humanUsability: 95,
      },
      lifecyclePenalty: 2,
    };
    const ranked = rankFeasibleBindings({
      bindings: [B_GUI, B_CLI],
      scoreFacts: [FACTS_CLI, factsGui],
    });
    expect(ranked[0]?.bindingId).toBe('b-cli');
    expect(ranked[0]?.score).toBeDefined();
    expect(ranked[0]?.reasons.join(' ')).toContain(RANKING_POLICY_REVISION);
    // I3 interface penalty (6) applies on top of the low agent-usability component.
    expect(ranked[1]?.bindingId).toBe('b-gui');
  });

  it('interface penalty can reorder bindings whose weighted base scores are close', () => {
    const strongGuiFacts: BindingScoreFacts = {
      bindingId: 'b-gui',
      components: {
        capabilityFit: 90,
        reliability: 90,
        agentUsability: 80,
        trust: 90,
        environmentCompatibility: 90,
        performance: 90,
        humanUsability: 90,
      },
    };
    const modestCliFacts: BindingScoreFacts = {
      bindingId: 'b-cli',
      components: {
        capabilityFit: 88,
        reliability: 88,
        agentUsability: 85,
        trust: 88,
        environmentCompatibility: 88,
        performance: 88,
        humanUsability: 88,
      },
    };
    const ranked = rankFeasibleBindings({
      bindings: [B_CLI, B_GUI],
      scoreFacts: [modestCliFacts, strongGuiFacts],
    });
    // GUI base score is higher (88.0 vs 87.4), but the I3 penalty 6 vs I1
    // penalty 1 keeps the structured CLI on top: final 82.0 vs 86.4.
    expect(ranked[0]?.bindingId).toBe('b-cli');
  });

  it('ties break by interface class then bindingId, deterministically', () => {
    const factsA: BindingScoreFacts = { ...FACTS_CLI, bindingId: 'b-cli' };
    const factsB: BindingScoreFacts = { ...FACTS_CLI, bindingId: 'b-gui' };
    const once = rankFeasibleBindings({
      bindings: [B_GUI, B_CLI],
      scoreFacts: [factsA, factsB],
    });
    const twice = rankFeasibleBindings({
      bindings: [B_GUI, B_CLI],
      scoreFacts: [factsA, factsB],
    });
    expect(once.map((entry) => entry.bindingId)).toEqual(['b-cli', 'b-gui']);
    expect(once).toEqual(twice);
  });

  it('ranking is deterministic across repeated runs (same input, same order)', () => {
    const factsGui: BindingScoreFacts = {
      bindingId: 'b-gui',
      components: {
        capabilityFit: 85,
        reliability: 80,
        agentUsability: 25,
        trust: 92,
        environmentCompatibility: 70,
        performance: 55,
        humanUsability: 95,
      },
    };
    const input = { bindings: [B_GUI, B_CLI], scoreFacts: [FACTS_CLI, factsGui] as const };
    expect(rankFeasibleBindings(input)).toEqual(rankFeasibleBindings(input));
  });
});
