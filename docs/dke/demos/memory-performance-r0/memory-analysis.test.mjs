import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeMemoryObservation, compareMemoryPerformance } from './memory-analysis.mjs';
import {readFileSync} from 'node:fs';
import {validateMemoryAotCandidate,REVIEWED_AOT_GIT_BLOB} from './memory-aot-integrity.mjs';

function diagnostic({ free = 500, total = 1000, signals = ['LOW_FREE_MEMORY'] } = {}) {
  return {
    ok: true,
    report: {
      schema: 'shun.windows-diagnostic-report.v02',
      status: 'OBSERVED_ONLY',
      localOnly: true,
      externalDisclosures: [],
      signals,
      evidence: {
        memoryTotalBytes: total,
        memoryFreeBytes: free,
        processCount: 42,
        startupEntryCount: 5,
      },
    },
  };
}
function processes(top = [{ name: 'Editor', residentBytes: 900 }, { name: 'Browser', residentBytes: 700 }]) {
  return {
    ok: true,
    facts: {
      schema: 'shun.windows-top-memory.v02',
      status: 'OBSERVED_ONLY',
      localOnly: true,
      externalDisclosures: [],
      metric: 'RESIDENT_MEMORY_BYTES_AT_SNAPSHOT',
      interpretation: 'MEMORY_ONLY_NO_CPU_OR_ROOT_CAUSE_INFERENCE',
      provenance: 'fixed-readonly-powershell',
      top,
    },
  };
}
function snapshot(free) {
  return analyzeMemoryObservation(diagnostic({ free, total: 1000, signals: [] }), processes(), { observedAt: '2026-11-12T00:00:00.000Z' });
}

test('reports legacy low-free-memory signal as potential only and never root cause', () => {
  const r = analyzeMemoryObservation(diagnostic({ free: 50 }), processes(), { observedAt: '2026-11-12T00:00:00.000Z' });
  assert.equal(r.outcome, 'OBSERVED_ONLY');
  assert.equal(r.diagnosis.status, 'LOW_FREE_MEMORY_LEGACY_HEURISTIC');
  assert.equal(r.diagnosis.rootCause, 'UNKNOWN');
  assert.equal(r.optimizationPlan.status, 'ADVISORY_ONLY');
  assert.equal(r.optimizationPlan.effectsAuthorized, false);
  assert.equal(r.optimizationPlan.executed, false);
  assert.equal(r.verification.speedupClaim, 'NONE');
});

test('no legacy low-memory signal is not reported as a healthy or pressure-free system', () => {
  const r = analyzeMemoryObservation(diagnostic({ free: 700, signals: [] }), processes());
  assert.equal(r.diagnosis.status, 'NO_LEGACY_LOW_FREE_MEMORY_SIGNAL');
  assert.equal(r.diagnosis.rootCause, 'UNKNOWN');
});

test('redacts process names by default while preserving bounded Working Set facts', () => {
  const r = analyzeMemoryObservation(diagnostic(), processes());
  assert.deepEqual(r.evidence.topResidentProcesses[0], {
    rank: 1, localAlias: 'PROCESS_01', residentWorkingSetBytes: 900,
  });
  assert.equal(JSON.stringify(r).includes('Editor'), false);
  const local = analyzeMemoryObservation(diagnostic(), processes(), { includeLocalProcessNames: true });
  assert.equal(local.evidence.topResidentProcesses[0].localName, 'Editor');
  assert.equal(local.privacy.processNamesRedacted, false);
});

test('does not infer Private Bytes, leak or a process kill target from Working Set', () => {
  const r = analyzeMemoryObservation(diagnostic(), processes());
  assert.equal(r.diagnosis.leakStatus, 'NOT_ASSESSED_NO_TIME_SERIES_OR_STABLE_PROCESS_IDENTITY');
  assert.ok(r.diagnosis.missingMetrics.includes('PROCESS_PRIVATE_USAGE_BYTES'));
  assert.ok(r.optimizationPlan.prohibitedActions.includes('PROCESS_TERMINATION'));
});

test('unavailable or malformed observations fail closed as UNKNOWN', () => {
  assert.equal(analyzeMemoryObservation({ ok: false, code: 'WINDOWS_REQUIRED' }, processes()).outcome, 'UNKNOWN');
  assert.equal(analyzeMemoryObservation(diagnostic({ free: 2000, total: 1000 }), processes()).outcome, 'UNKNOWN');
  assert.equal(analyzeMemoryObservation(diagnostic(), processes([{ name: 'x', residentBytes: -1 }])).outcome, 'UNKNOWN');
});

test('memory-only delta cannot prove performance improvement without trusted workload receipt', () => {
  const r = compareMemoryPerformance(snapshot(100), snapshot(400), null);
  assert.equal(r.outcome, 'UNKNOWN');
  assert.equal(r.speedupClaim, 'NONE');
});

test('mismatched workload or missing user outcome remains UNKNOWN', () => {
  const before = snapshot(100), after = snapshot(400);
  const r = compareMemoryPerformance(before, after, {
    schema: 'shun.demo.workload-comparator-receipt.v1',
    status: 'VERIFIED', sameHost: true, sameWorkload: false,
    sourceRef: 'evidence://fixture/compare',
    userOutcome: { metric: 'P95_RESPONSE_TIME_MS', before: 500, after: 300 },
  });
  assert.equal(r.outcome, 'UNKNOWN');
});

test('a syntactically valid but caller-forged comparator receipt is not trusted', () => {
  const before = snapshot(100), after = snapshot(400);
  const r = compareMemoryPerformance(before, after, {
    schema: 'shun.demo.workload-comparator-receipt.v1',
    status: 'VERIFIED', sameHost: true, sameWorkload: true,
    sourceRef: 'evidence://caller-forged/compare-001',
    userOutcome: { metric: 'P95_RESPONSE_TIME_MS', before: 500, after: 300 },
  });
  assert.equal(r.outcome, 'UNKNOWN');
  assert.equal(r.speedupClaim, 'NONE');
  assert.equal(r.reason, 'INDEPENDENT_TRUSTED_WORKLOAD_COMPARATOR_NOT_IMPLEMENTED');
});

test('invalid process names and unknown provenance fail closed', () => {
  const unsafe = processes([{ name: 'C:/private', residentBytes: 100 }]);
  assert.equal(analyzeMemoryObservation(diagnostic(), unsafe).outcome, 'UNKNOWN');
  const wrong = processes();
  wrong.facts.provenance = 'UNTRUSTED';
  assert.equal(analyzeMemoryObservation(diagnostic(), wrong).outcome, 'UNKNOWN');
});

test('Host sampling time is UNKNOWN even when caller forges future observedAt', () => {
  const r = analyzeMemoryObservation(diagnostic(), processes(), {
    observedAt: '2099-01-01T00:00:00.000Z',
    sampledAt: '2099-01-01T00:00:00.000Z',
  });
  assert.equal(r.outcome, 'OBSERVED_ONLY');
  assert.equal(r.sampledAt, 'UNKNOWN');
  assert.equal(r.observedAt, 'UNKNOWN');
  assert.notEqual(r.analyzedAt, '2099-01-01T00:00:00.000Z');
  assert.ok(!Number.isNaN(Date.parse(r.analyzedAt)));
  const unknown = analyzeMemoryObservation({ok:false,code:'NOT_AVAILABLE'},processes(),{observedAt:'2099-01-01'});
  assert.equal(unknown.sampledAt,'UNKNOWN');
  assert.equal(unknown.observedAt,'UNKNOWN');
});

test('unconsumed AOT IDs are not reported as applied source-backed rules', () => {
  const r = analyzeMemoryObservation(diagnostic(),processes());
  assert.deepEqual(r.source.aotRuleIds,[]);
  assert.equal(r.source.aotRuleConsumption,'NOT_APPLIED_BY_THIS_DEMO');
});

test('AOT candidate exact Git Blob rejects forged semantic rule and matching edited sourceRefs', () => {
  const raw = readFileSync(new URL('./AOT_MEMORY_KNOWLEDGE_CANDIDATE_R0.json',import.meta.url),'utf8');
  const ok = validateMemoryAotCandidate(raw);
  assert.equal(ok.ok,true,JSON.stringify(ok));
  assert.equal(ok.gitBlob,REVIEWED_AOT_GIT_BLOB);
  assert.equal(ok.semanticsConsumed,false);
  assert.deepEqual(ok.appliedRuleIds,[]);
  const tampered = JSON.parse(raw);
  tampered.sourceRules[0].rule = 'WorkingSet64 always equals Private Bytes';
  tampered.sourceRules[0].sourceRefs = ['EXT-MEM-WORKING-SET'];
  assert.deepEqual(validateMemoryAotCandidate(JSON.stringify(tampered)).ok,false);
  assert.deepEqual(validateMemoryAotCandidate('{"status":"DEMO_ONLY_CANDIDATE_NOT_QUALIFIED"}').ok,false);
});
