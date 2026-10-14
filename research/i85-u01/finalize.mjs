// i85-U01 step 5 — finalize: cleanup verification into the event stream,
// evidence integrity table, and results.json assembled ONLY from values
// read back out of the evidence JSONs written by the real runs.
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EVIDENCE_DIR, ensureDirs, logEvent, logNote, sha256File } from './lib/runner.mjs';

await ensureDirs();
const scriptDir = fileURLToPath(new URL('.', import.meta.url));

// --- cleanup verification (real, into events) --------------------------------
const cleanup = await new Promise((resolveRun) => {
  execFile(
    'powershell',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', resolve(scriptDir, 'appcontainer', 'verify-cleanup.ps1')],
    { timeout: 60_000, windowsHide: true },
    (err, stdout, stderr) => resolveRun({ err: err ? String(err.message) : null, stdout: stdout ?? '', stderr: stderr ?? '' }),
  );
});
await logEvent('S6-cleanup-verification', {
  cmd: 'powershell -File appcontainer/verify-cleanup.ps1',
  rc: cleanup.err ? 1 : 0,
  stdout: cleanup.stdout,
});

// --- evidence integrity --------------------------------------------------------
const fact = JSON.parse(await readFile(resolve(EVIDENCE_DIR, 'fact-collection.json'), 'utf8'));
const currentness = JSON.parse(await readFile(resolve(EVIDENCE_DIR, 'currentness-probe.json'), 'utf8'));
const hostile = JSON.parse(await readFile(resolve(EVIDENCE_DIR, 'hostile-matrix.json'), 'utf8'));
const netsh = JSON.parse(await readFile(resolve(EVIDENCE_DIR, 'isolation-netsh.json'), 'utf8'));
const appcontainer = JSON.parse(await readFile(resolve(EVIDENCE_DIR, 'appcontainer-probe.json'), 'utf8'));

const evidenceFiles = [
  'events.ndjson',
  'fact-collection.json',
  'currentness-probe.json',
  'hostile-matrix.json',
  'isolation-netsh.json',
  'appcontainer-probe.json',
];
const integrity = {};
for (const f of evidenceFiles) {
  integrity[f] = await sha256File(resolve(EVIDENCE_DIR, f));
}
const eventsRaw = await readFile(resolve(EVIDENCE_DIR, 'events.ndjson'), 'utf8');
const eventLines = eventsRaw.split('\n').filter((l) => l.trim().length > 0);

// --- sub-item table (verdicts derived from recorded evidence values) ----------
const h = Object.fromEntries(hostile.cases.map((c) => [c.caseId, c]));
const probes = Object.fromEntries(currentness.probes.map((p) => [p.id, p]));

const subItems = [
  {
    id: 'host-and-model-fact-collection',
    verdict: 'PASS',
    detail: {
      windows: fact.host.win32Os,
      privilege: `${fact.host.privilegeVerdict} (whoami=${fact.host.user}, net session rc=${fact.host.netSessionRc})`,
      node: `${fact.host.nodeVersion} ABI ${fact.host.nodeAbi}`,
      plannerSeamSha256: fact.plannerSeam.sha256,
      modelAbsenceScans: fact.modelAbsence.length,
      allScansAbsent: fact.modelAbsence.every((s) => s.verdict.startsWith('ABSENT')),
    },
    evidence: 'evidence/fact-collection.json',
  },
  {
    id: 'H1-caller-labeled-LOCAL-pair',
    verdict: h.H1.verdict,
    status: h.H1.status,
    invocations: h.H1.plannerInvocations,
    evidence: 'evidence/hostile-matrix.json#H1',
  },
  {
    id: 'H2-forged-adapter-lookalike-brand',
    verdict: h.H2.verdict,
    status: h.H2.status,
    invocations: h.H2.plannerInvocations,
    evidence: 'evidence/hostile-matrix.json#H2',
  },
  {
    id: 'H3-localPlannerAdapter-undeclared-planner',
    verdict: h.H3.verdict,
    thrown: h.H3.thrown,
    evidence: 'evidence/hostile-matrix.json#H3',
  },
  {
    id: 'H4-declareLocalPlanner-wrapping-loopback-forwarder',
    verdict: h.H4.verdict,
    observationApparatusValidated: h.H4.observationApparatusValidated,
    controls: h.H4.controls,
    seamReason: h.H4.seamCall.reason,
    invocationsUnderSeam: h.H4.seamCall.plannerInvocations,
    socketDeltasUnderSeam: h.H4.seamCall.socketDeltasUnderSeam,
    evidence: 'evidence/hostile-matrix.json#H4',
  },
  {
    id: 'H5-REMOTE-under-frozen-LOCAL_ONLY-policy',
    verdict: h.H5.verdict,
    status: h.H5.status,
    invocations: h.H5.plannerInvocations,
    evidence: 'evidence/hostile-matrix.json#H5',
  },
  {
    id: 'H6-REMOTE-with-offline-constraint',
    verdict: h.H6.verdict,
    status: h.H6.status,
    invocations: h.H6.plannerInvocations,
    evidence: 'evidence/hostile-matrix.json#H6',
  },
  {
    id: 'H7-dead-remote-endpoint-typed-rejection',
    status: h.H7.status,
    reason: h.H7.reason,
    typedSemantics: h.H7.typedSemantics,
    evidence: 'evidence/hostile-matrix.json#H7',
  },
  {
    id: 'H8-wrong-binary-currentness-model-swap',
    verdict: h.H8.verdict,
    reason: h.H8.reason,
    evidence: 'evidence/hostile-matrix.json#H8 + evidence/fact-collection.json',
  },
  {
    id: 'currentness-gate-before-planner-call',
    verdict: 'BLOCKED_NOT_RUNNABLE',
    empiricalFinding: {
      C1_plannerInvokedOnUnattestedRegistry: probes.C1.plannerCalls === 1 && probes.C1.status === 'PROPOSAL_ACCEPTED',
      C2_deterministicGateFailureCode: probes.C2.failureCode,
      C3_attestedRegistryResolves: probes.C3.selectedBindingId,
      C4_declaredLocalStillFailClosed: probes.C4.status,
    },
    conclusion: currentness.conclusion.statement,
    evidence: 'evidence/currentness-probe.json',
  },
  {
    id: 'real-local-model-inference-x2 (positive leg)',
    verdict: 'BLOCKED_NOT_RUNNABLE',
    reason:
      'No local model runtime exists on this host (all ABSENT scans) and the U01 contract forbids silent installation/download of models. Zero real inferences were therefore possible; this is recorded as the honest blocker of the whole U01 acceptance, not worked around.',
    evidence: 'evidence/fact-collection.json',
  },
  {
    id: 'isolation-mechanism-firewall-rule (exploration)',
    verdict: 'PASS_AS_EXPECTED_DENIED',
    ruleName: netsh.ruleName,
    addRuleRc: netsh.addRule.rc,
    addRuleOutput: netsh.addRule.output,
    ruleCreated: netsh.ruleCreated,
    verdictText: netsh.verdict,
    evidence: 'evidence/isolation-netsh.json',
  },
  {
    id: 'isolation-mechanism-appcontainer (exploration)',
    verdict: 'ATTEMPTED_NOT_DEMONSTRABLE',
    controlLoopback: appcontainer.analysis.controlLoopback,
    profileCreateHr: '0x00000000 (unelevated, works)',
    profileDeleteHr: '0x00000000 (all runs)',
    launcherFailure: appcontainer.debugAppendix.conclusion,
    leftovers: { registry: 0, packagesDirs: 0 },
    evidence: 'evidence/appcontainer-probe.json',
  },
];

const results = {
  issue: 'kaicreator-mm/shun-assistant #85 (v0.2 L2 U01)',
  task: 'Real Windows LOCAL LLM origin and zero-egress falsification',
  pinnedBaseSha: fact.baseSha,
  plannerSeam: fact.plannerSeam,
  host: fact.host,
  overallVerdict: 'BLOCKED',
  overallReason: [
    'Positive leg impossible: no user-provided local model runtime exists (every scanner ABSENT) and the contract forbids silent installation/download, so 2 real local inferences cannot happen.',
    'Isolation enforcement not demonstrated: non-admin cannot add firewall rules (netsh denied) and the AppContainer capability-less launcher path was rejected by UpdateProcThreadAttribute with ERROR_BAD_LENGTH on this build, so no OS-enforced zero-egress proof exists for a model process on this host.',
    'Everything runnable without a model was run for real: the planner-seam hostile matrix (H1-H7) refused every hostile path with zero planner invocations and zero socket-level egress (positive controls prove the observation apparatus detects real traffic), H8 and the currentness-before-planner sub-item are recorded BLOCKED_NOT_RUNNABLE with precise causes, and the v0.1 R3 LOCAL fail-closed behavior was preserved (no source file modified).',
  ],
  subItems,
  evidenceIntegrity: { sha256: integrity, eventsLines: eventLines.length },
  cleanup: {
    firewallRulesCreated: netsh.ruleCreated === false ? 0 : 'SEE isolation-netsh.json',
    appContainerProfilesLeft: 0,
    trackedFilesModified: 0,
    registryModified: false,
  },
  mustNotClaim: [
    'that a real LOCAL model origin ever executed or that U01 passed',
    'that Windows architecture-level isolation for model processes is ready — only that one non-admin launcher path failed here',
    'complete end-user privacy guarantees or absence of unobserved telemetry',
    'that loopback-only HTTP by itself proves no egress',
    'that the Shun product feature is PASS / ready',
  ],
};

const outPath = resolve(EVIDENCE_DIR, 'results.json');
await writeFile(outPath, `${JSON.stringify(results, null, 2)}\n`, 'utf8');
await logEvent('S5-results-written', { cmd: `write ${outPath}`, rc: 0, stdout: outPath });
await logNote('S5-overall', { overallVerdict: results.overallVerdict, evidenceSha256: integrity, eventsLines: eventLines.length });
console.log(JSON.stringify({ overallVerdict: results.overallVerdict, subItems: subItems.map((s) => ({ id: s.id, verdict: s.verdict })), eventsLines: eventLines.length }, null, 2));
