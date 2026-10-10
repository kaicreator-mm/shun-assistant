// Versioned gold provenance + evidence records for the resolver ranking unit
// scenarios B-033/B-034/B-035 (Issue #33 / P1-07).
//
// Authority for the gold procedure: docs/validation/benchmark-v0.1.md
// ("Provider-ranking gold procedure" — gold derived from hard requirements,
// hidden from the resolver run, disagreements kept as evidence).
//
// SCOPE LIMIT (must not be blurred): these are SYNTHETIC AGREEMENT records.
// The gold dispositions are derived from the hard requirements of the frozen
// scenario inputs and never from the resolver score under test, but no
// observed real execution evidence exists. Real independent validation
// (independent evaluator + observed real task outcomes + recorded top-k
// agreement) belongs to a later Integration gate benchmark run. These records
// must not be cited as independent validation of the resolver.

export const GOLD_RANKING_EVIDENCE_REVISION = 'shun.resolver.gold-ranking-evidence/0.1';

/** Benchmark ids of the provider-ranking gold records. */
export type GoldBenchmarkId = 'B-033' | 'B-034' | 'B-035';

export interface GoldRankingEvidence {
  readonly benchmarkId: GoldBenchmarkId;
  /** Version of THIS evidence record; changes to the gold require a revision bump. */
  readonly evidenceRevision: string;
  /** The governing gold procedure (step reference). */
  readonly goldProcedure: string;
  /** Hard requirements the gold disposition was derived from (never the resolver score). */
  readonly derivedFrom: readonly string[];
  /** Who/what produced the gold disposition. */
  readonly derivedBy: string;
  /** Where the frozen scenario inputs (registry fixtures + score facts) live. */
  readonly frozenScenarioInputs: string;
  /** Gold preference order (top-1 first). Empty tail orderings are not claimed. */
  readonly goldRanking: readonly string[];
  /** Always false in v0.1: synthetic agreement is not independent validation. */
  readonly independentValidation: false;
  /** Explicit evaluation limitations attached to this record. */
  readonly limitations: readonly string[];
}

const SHARED_LIMITATIONS: readonly string[] = [
  'Synthetic scenario agreement only: no observed real execution evidence exists for these fixtures.',
  'NOT independent validation in the docs/validation/benchmark-v0.1.md sense — that procedure requires an independent evaluator, observed real task outcomes and recorded top-k agreement from actual benchmark runs.',
  'Real independent validation is deferred to a later Integration gate benchmark run; until then these records are unit-test fixtures and must not be cited as independent verification of the resolver.',
  'Gold dispositions were derived from the hard requirements of the frozen scenario inputs, never from the resolver score under test.',
];

const SHARED_DERIVED_BY =
  'hard-requirements derivation over the frozen scenario inputs (independent of the resolver ranking implementation and score facts)';

const SHARED_INPUTS = 'packages/resolver/test/benchmark-scenarios.ts (frozen v0.1 fixtures)';

export const GOLD_RANKING_EVIDENCE: readonly GoldRankingEvidence[] = [
  {
    benchmarkId: 'B-033',
    evidenceRevision: '1',
    goldProcedure:
      'docs/validation/benchmark-v0.1.md, Provider-ranking gold procedure steps 1–6 (unit-scenario application)',
    derivedFrom: [
      'batch automation must run unattended (no interactive UI per batch)',
      'structured headless input/output preferred for downstream verification',
      'low-resource constraint favors the smallest processing footprint',
      'offline constraint: the scenario declares networkAccess FORBIDDEN for every candidate',
    ],
    derivedBy: SHARED_DERIVED_BY,
    frozenScenarioInputs: SHARED_INPUTS,
    goldRanking: ['b-ff', 'b-hb', 'b-gui'],
    independentValidation: false,
    limitations: SHARED_LIMITATIONS,
  },
  {
    benchmarkId: 'B-034',
    evidenceRevision: '1',
    goldProcedure:
      'docs/validation/benchmark-v0.1.md, Provider-ranking gold procedure steps 1–6 (unit-scenario application)',
    derivedFrom: [
      'default policy (risk escalation not acknowledged): a provider whose curated safetyProfile demands escalation must not be selected',
      'the safer uninstaller satisfies the capability envelope without escalation',
      'with an explicitly acknowledged escalation the stronger tool may win, but only with its upgrade reason surfaced in the record',
    ],
    derivedBy: SHARED_DERIVED_BY,
    frozenScenarioInputs: SHARED_INPUTS,
    goldRanking: ['b-safer'],
    independentValidation: false,
    limitations: SHARED_LIMITATIONS,
  },
  {
    benchmarkId: 'B-035',
    evidenceRevision: '1',
    goldProcedure:
      'docs/validation/benchmark-v0.1.md, Provider-ranking gold procedure steps 1–6 (unit-scenario application)',
    derivedFrom: [
      'hard requirement: unattended structured execution (agent usability governs, not human UI preference)',
      'a pretty GUI with per-batch interaction fails the unattended-automation requirement',
      'human-friendliness must not be conflated with agent-friendliness',
    ],
    derivedBy: SHARED_DERIVED_BY,
    frozenScenarioInputs: SHARED_INPUTS,
    goldRanking: ['b-cli', 'b-pretty'],
    independentValidation: false,
    limitations: SHARED_LIMITATIONS,
  },
];

export function goldEvidenceFor(benchmarkId: GoldBenchmarkId): GoldRankingEvidence {
  const record = GOLD_RANKING_EVIDENCE.find((entry) => entry.benchmarkId === benchmarkId);
  if (!record) {
    throw new Error(`gold evidence record missing for ${benchmarkId}`);
  }
  return record;
}
