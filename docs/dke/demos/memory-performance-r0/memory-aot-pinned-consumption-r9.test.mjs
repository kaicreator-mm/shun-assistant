import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { consumePinnedResearchAot } from './memory-aot-research-consumer-r9.mjs';
import { REVIEWED_AOT_GIT_BLOB } from './memory-aot-integrity.mjs';

const raw = readFileSync(new URL('./AOT_MEMORY_KNOWLEDGE_CANDIDATE_R0.json', import.meta.url), 'utf8');
function report(status = 'LOW_FREE_MEMORY_LEGACY_HEURISTIC') {
  return {
    schema: 'shun.demo.memory-performance-report.v0', outcome: 'OBSERVED_ONLY',
    privacy: { localOnly: true, externalDisclosures: [] },
    source: { processMetric: 'RESIDENT_MEMORY_BYTES_AT_SNAPSHOT', aotRuleIds: [],
      aotRuleConsumption: 'NOT_APPLIED_BY_THIS_DEMO' },
    diagnosis: { status, rootCause: 'UNKNOWN', missingMetrics: ['SYSTEM_COMMIT_BYTES'] },
    evidence: { topResidentProcesses: [{ rank: 1, residentWorkingSetBytes: 512, localAlias: 'PROCESS_01' }] },
    optimizationPlan: { status: 'ADVISORY_ONLY', effectsAuthorized: false, executed: false },
    verification: { speedupClaim: 'NONE',
      improvementComparison: 'UNKNOWN_UNTIL_TRUSTED_COMPARABLE_WORKLOAD_AND_USER_OUTCOME_METRIC' },
  };
}

test('original immutable R0 AOT candidate decision rules are really evaluated by research consumer', () => {
  const result = consumePinnedResearchAot(raw, report());
  assert.equal(result.outcome, 'ADVISORY_ONLY');
  assert.equal(result.sourceGitBlob, REVIEWED_AOT_GIT_BLOB);
  assert.equal(result.researchDecisionRuleConsumption, 'EXECUTED_IN_RESEARCH_RUNTIME_ONLY');
  assert.equal(result.decisionRulesEvaluated.length, 6);
  assert.deepEqual(result.matchedDecisionRuleIds,
    ['MEM-DEC-001','MEM-DEC-003','MEM-DEC-004','MEM-DEC-006']);
  assert.deepEqual(result.sourceRulesApplied, []);
  assert.equal(result.productionAotExecuted, false);
  assert.equal(result.disFunctionInvoked, false);
  assert.equal(result.hostProvenance, 'NOT_ESTABLISHED_BY_RESEARCH_CONSUMER');
});
test('candidate decision predicates consume no-low-memory status without suggesting effects', () => {
  const result = consumePinnedResearchAot(raw, report('NO_LEGACY_LOW_FREE_MEMORY_SIGNAL'));
  assert.equal(result.outcome, 'ADVISORY_ONLY');
  assert.ok(result.matchedDecisionRuleIds.includes('MEM-DEC-002'));
  assert.ok(!result.matchedDecisionRuleIds.includes('MEM-DEC-001'));
  assert.equal(result.effectsAuthorized, false);
});
test('tampered candidate source bytes fail closed before rule execution', () => {
  const changed = raw.replace('MEM-DEC-001', 'MEM-DEC-0XX');
  assert.notEqual(changed, raw);
  const result = consumePinnedResearchAot(changed, report());
  assert.equal(result.outcome, 'UNKNOWN');
  assert.equal(result.code, 'AOT_SOURCE_BLOB_MISMATCH');
  assert.deepEqual(result.decisionRulesEvaluated, []);
});
test('untrusted report cannot manufacture a pinned AOT execution proof', () => {
  const invalid = { ...report(), optimizationPlan: { status: 'APPLIED', executed: true, effectsAuthorized: true } };
  const result = consumePinnedResearchAot(raw, invalid);
  assert.equal(result.outcome, 'UNKNOWN');
  assert.equal(result.productionAotExecuted, false);
  assert.deepEqual(result.matchedDecisionRuleIds, []);
});
