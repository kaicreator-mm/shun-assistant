// Deterministic, policy-free ranking of feasible bindings (L2 §7.2, Product
// resolver v0.1 score/penalty tables).
//
// Ranking happens strictly AFTER the hard gates: policy-ineligible bindings no
// longer exist at this point, so the score carries no policy or risk term.
// Weights are versioned experimental data (EXPERIMENTAL in the frozen product
// document), never silently changed. When curated score facts are absent, a
// simple deterministic rule set (interface class, then binding id) is used —
// the frozen requirement is hard gates + explainable selection, not a complex
// scorer (L2 §7.2).

import {
  INTERFACE_CLASSES,
  type InterfaceClass,
  type ProviderCapabilityBinding,
} from '@shun/contracts';
import { z } from 'zod';
import type { SafetyProfile } from './gates.ts';

export const RANKING_POLICY_REVISION = 'shun.resolver.ranking-policy/0.1';

/** Base-score weights (v0.1 experimental, sum = 1). */
export const RANKING_WEIGHTS = {
  capabilityFit: 0.25,
  reliability: 0.2,
  agentUsability: 0.2,
  trust: 0.15,
  environmentCompatibility: 0.1,
  performance: 0.05,
  humanUsability: 0.05,
} as const;

/** Interaction-complexity penalty per interface class (product table, 0–20). */
export const INTERFACE_PENALTY: Record<InterfaceClass, number> = {
  I0: 0,
  I1: 1,
  I2: 2,
  I3: 6,
  I4: 15,
};

const ScoreComponentSchema = z.number().min(0).max(100);

/** Curated per-binding score facts (fact class 1 data; observable attributes only). */
export const BindingScoreFactsSchema = z.strictObject({
  bindingId: z.string().min(1),
  components: z.strictObject({
    capabilityFit: ScoreComponentSchema,
    reliability: ScoreComponentSchema,
    agentUsability: ScoreComponentSchema,
    trust: ScoreComponentSchema,
    environmentCompatibility: ScoreComponentSchema,
    performance: ScoreComponentSchema,
    humanUsability: ScoreComponentSchema,
  }),
  /** Lifecycle cost penalty 0–10 (install size, residency, residue, dependency complexity). */
  lifecyclePenalty: z.number().min(0).max(10).optional(),
});
export type BindingScoreFacts = z.infer<typeof BindingScoreFactsSchema>;

export interface RankedBinding {
  bindingId: string;
  binding: ProviderCapabilityBinding;
  escalation?: SafetyProfile & { acknowledged: boolean };
  /** Human-comprehensible reasons for the ranking position (explainable selection). */
  reasons: string[];
  score?: number;
}

/**
 * Rank feasible bindings. Uniform mode selection: if score facts are supplied
 * for every feasible binding, the weighted v0.1 score decides; otherwise ALL
 * bindings fall back to the deterministic interface-class rule so mixed
 * evidence can never silently bias a subset.
 */
export function rankFeasibleBindings(input: {
  bindings: Array<
    ProviderCapabilityBinding & { gateEscalation?: SafetyProfile & { acknowledged: boolean } }
  >;
  scoreFacts?: readonly BindingScoreFacts[];
}): RankedBinding[] {
  const { bindings, scoreFacts } = input;
  if (bindings.length === 0) return [];

  const factsById = new Map<string, BindingScoreFacts>();
  for (const fact of scoreFacts ?? []) {
    factsById.set(fact.bindingId, fact);
  }
  const complete = bindings.every((binding) => factsById.has(binding.bindingId));

  if (!complete) {
    const fallbackOrder = new Map(INTERFACE_CLASSES.map((cls, index) => [cls, index]));
    const ranked = [...bindings]
      .sort((a, b) => {
        const classDelta =
          (fallbackOrder.get(a.interfaceClass) ?? 0) - (fallbackOrder.get(b.interfaceClass) ?? 0);
        if (classDelta !== 0) return classDelta;
        return a.bindingId < b.bindingId ? -1 : a.bindingId > b.bindingId ? 1 : 0;
      })
      .map((binding) => ({
        bindingId: binding.bindingId,
        binding,
        escalation: binding.gateEscalation,
        reasons: [
          `interface-class fallback ranking (no curated score facts): ${binding.interfaceClass} preferred over worse classes, ties by bindingId`,
        ],
      }));
    return ranked;
  }

  const scored = bindings.map((binding) => {
    const facts = factsById.get(binding.bindingId);
    if (!facts) {
      throw new Error(`ranking invariant violated: missing facts for ${binding.bindingId}`);
    }
    const weighted =
      RANKING_WEIGHTS.capabilityFit * facts.components.capabilityFit +
      RANKING_WEIGHTS.reliability * facts.components.reliability +
      RANKING_WEIGHTS.agentUsability * facts.components.agentUsability +
      RANKING_WEIGHTS.trust * facts.components.trust +
      RANKING_WEIGHTS.environmentCompatibility * facts.components.environmentCompatibility +
      RANKING_WEIGHTS.performance * facts.components.performance +
      RANKING_WEIGHTS.humanUsability * facts.components.humanUsability;
    const interfacePenalty = INTERFACE_PENALTY[binding.interfaceClass];
    const lifecyclePenalty = facts.lifecyclePenalty ?? 0;
    const final = weighted - interfacePenalty - lifecyclePenalty;
    const reasons = [
      `weighted base score ${weighted.toFixed(1)} (fit ${facts.components.capabilityFit}, agentUsability ${facts.components.agentUsability}, trust ${facts.components.trust}, reliability ${facts.components.reliability})`,
      `− interface penalty ${interfacePenalty} (${binding.interfaceClass}) − lifecycle penalty ${lifecyclePenalty} → final ${final.toFixed(1)} under ${RANKING_POLICY_REVISION}`,
    ];
    return {
      bindingId: binding.bindingId,
      binding,
      escalation: binding.gateEscalation,
      reasons,
      score: final,
    };
  });

  return scored.sort((a, b) => {
    const scoreDelta = (b.score ?? 0) - (a.score ?? 0);
    if (scoreDelta !== 0) return scoreDelta;
    const classDelta =
      INTERFACE_PENALTY[a.binding.interfaceClass] - INTERFACE_PENALTY[b.binding.interfaceClass];
    if (classDelta !== 0) return classDelta;
    return a.bindingId < b.bindingId ? -1 : a.bindingId > b.bindingId ? 1 : 0;
  });
}
