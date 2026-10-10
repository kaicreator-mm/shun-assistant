// Gold evidence records for B-033/B-034/B-035 (P1-07, Issue #33).
//
// These tests assert two things, kept strictly apart:
// 1. RECORD INTEGRITY — every gold record carries versioned provenance,
//    hard-requirement derivation and explicit limitations, and declares
//    independentValidation: false (synthetic agreement is never labelled
//    independent validation);
// 2. SYNTHETIC AGREEMENT — the resolver outcome agrees with the gold ranking
//    on the frozen scenario fixtures. This is unit-level agreement only, NOT
//    the independent validation of docs/validation/benchmark-v0.1.md (which
//    requires observed real execution evidence — see the record limitations).
import { describe, expect, it } from 'vitest';
import {
  GOLD_RANKING_EVIDENCE,
  GOLD_RANKING_EVIDENCE_REVISION,
  goldEvidenceFor,
} from '../evidence/gold-ranking-evidence.ts';
import { resolveGoal } from '../src/resolve.ts';
import {
  B033_FACTS,
  B035_FACTS,
  b033Registry,
  b034Registry,
  b035Registry,
} from './benchmark-scenarios.ts';
import { goalRequest } from './scenarios.ts';

function resolvingRequest(goal: string) {
  return goalRequest({ goal });
}

describe('gold evidence record integrity (P1-07)', () => {
  it('a versioned evidence record exists for every ranking benchmark', () => {
    expect(GOLD_RANKING_EVIDENCE_REVISION).toBe('shun.resolver.gold-ranking-evidence/0.1');
    expect(GOLD_RANKING_EVIDENCE.map((record) => record.benchmarkId)).toEqual([
      'B-033',
      'B-034',
      'B-035',
    ]);
  });

  it('every record carries provenance, hard-requirement derivation and explicit limitations', () => {
    for (const record of GOLD_RANKING_EVIDENCE) {
      expect(record.evidenceRevision, record.benchmarkId).toMatch(/^\d+$/);
      expect(record.goldProcedure, record.benchmarkId).toContain('benchmark-v0.1.md');
      expect(record.derivedFrom.length, record.benchmarkId).toBeGreaterThan(0);
      expect(record.derivedBy, record.benchmarkId).toContain('hard-requirements');
      expect(record.frozenScenarioInputs, record.benchmarkId).toContain('benchmark-scenarios.ts');
      expect(record.goldRanking.length, record.benchmarkId).toBeGreaterThan(0);
      expect(record.limitations.join(' '), record.benchmarkId).toContain(
        'no observed real execution evidence',
      );
      expect(record.limitations.join(' '), record.benchmarkId).toContain(
        'must not be cited as independent verification',
      );
    }
  });

  it('no record claims independent validation — synthetic agreement is explicitly disclaimed', () => {
    for (const record of GOLD_RANKING_EVIDENCE) {
      expect(record.independentValidation).toBe(false);
    }
    expect(goldEvidenceFor('B-033').independentValidation).toBe(false);
  });
});

describe('resolver outcome agrees with the gold records on the frozen fixtures (synthetic agreement)', () => {
  it('B-033: top-1 and feasible order match the gold ranking on the offline/batch scenario', () => {
    const request = resolvingRequest('image.batch_process: batch resize my photos offline');
    request.constraints.other = { offline: true };
    const gold = goldEvidenceFor('B-033');
    const result = resolveGoal({
      request,
      registry: b033Registry(),
      objectExists: () => true,
      scoreFacts: B033_FACTS,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBe(gold.goldRanking[0]);
    expect(result.record.feasibleBindings).toEqual([...gold.goldRanking]);
  });

  it('B-034: default policy selects the gold safer uninstaller and surfaces the escalation reason', () => {
    const gold = goldEvidenceFor('B-034');
    const result = resolveGoal({
      request: resolvingRequest('software.uninstall_safe: uninstall a normal desktop app'),
      registry: b034Registry(),
      objectExists: () => true,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBe(gold.goldRanking[0]);
    const aggressiveRow = result.record.hardGateDispositions
      .filter((entry) => entry.bindingId === 'b-aggressive')
      .pop();
    expect(aggressiveRow).toMatchObject({
      gate: 'SAFETY_CONSTRAINTS',
      outcome: 'REJECT',
      reason: expect.stringContaining('aggressive registry/residue cleanup'),
    });
  });

  it('B-035: the structured CLI beats the pretty GUI, matching the gold order', () => {
    const gold = goldEvidenceFor('B-035');
    const result = resolveGoal({
      request: resolvingRequest('image.batch_process: batch resize my photos offline'),
      registry: b035Registry(),
      objectExists: () => true,
      scoreFacts: B035_FACTS,
    });
    expect(result.stage).toBe('RESOLUTION');
    if (result.stage !== 'RESOLUTION') return;
    expect(result.record.selectedBindingId).toBe(gold.goldRanking[0]);
    expect(result.record.feasibleBindings).toEqual([...gold.goldRanking]);
  });
});
