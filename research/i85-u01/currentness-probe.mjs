// i85-U01 step 2 (real run) — does v0.1 have a currentness gate that sits
// BEFORE the planner invocation? Reads say no (planner-seam has no currentness
// input; registry currentness gates the deterministic resolveGoal path;
// authorization currentness gates plan/effect authorization). This probe
// exercises all three paths for real and records the observed semantics:
//   C1: unattested registry + REMOTE adapter + disclosure-allowed policy
//       -> the planner IS invoked (PROPOSAL_ACCEPTED): no currentness gate
//       ahead of the planner call in the seam.
//   C2: the same unattested registry under deterministic resolveGoal
//       -> REGISTRY_CURRENTNESS_INSUFFICIENT (the real v0.1 currentness gate,
//          but there is no model call on that path at all).
//   C3: fromAttestedSnapshot with a currentness authority serving a mismatched
//       revision -> unattested -> resolveGoal fails closed; matching revision
//       -> attested -> resolution proceeds.
// Conclusion recorded: "invalid currentness -> zero model calls" is not an
// exercisable gate in v0.1 because no currentness-conditioned path can reach
// a planner invocation; sub-item recorded BLOCKED_NOT_RUNNABLE upstream.
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  declareLocalPlanner,
  interpretGoalViaPlanner,
  localPlannerAdapter,
  remotePlannerAdapter,
  resolveGoal,
  ShunRegistry,
  snapshotFactsRevision,
} from '../../packages/resolver/src/index.ts';
import {
  bindingDef,
  capabilityDef,
  goalRequest,
  providerDef,
} from '../../packages/resolver/test/scenarios.ts';
import { EVIDENCE_DIR, ensureDirs, logEvent, logNote } from './lib/runner.mjs';

await ensureDirs();
const evidence = { probes: [], conclusion: null };

function registrySnapshot() {
  return {
    capabilities: [capabilityDef({ capabilityId: 'image.batch_process' })],
    providers: [providerDef({ providerId: 'imageProvider.imagemagick' })],
    bindings: [
      bindingDef({
        bindingId: 'b-im',
        providerId: 'imageProvider.imagemagick',
        capabilityId: 'image.batch_process',
      }),
    ],
    environment: {
      environmentId: 'env',
      backendKind: 'LOCAL_WINDOWS',
      os: 'WINDOWS',
      arch: 'X64',
      observationRevision: 'obs-1',
      runtimeCapabilities: [],
      privilegeMode: 'FILTERED_ADMIN',
      guiSession: true,
      filesystemCapabilities: [],
      networkPolicy: 'POLICY_CONTROLLED',
      resources: { cpuCores: 4, memoryMb: 8192, freeDiskMb: 102400 },
    },
  };
}

function spyPlanner(calls) {
  return {
    interpretGoal: async () => {
      calls.count += 1;
      const req = calls.lastRequest;
      return {
        proposalId: 'prop-c1',
        plannerEvidence: { operationId: 'op-c1', modelEvidence: 'remote-model-x' },
        goalContract: {
          taskId: req.taskId,
          objective: 'image.batch_process: organize desktop screenshots by date',
          objects: req.objects,
          constraints: req.constraints,
          privacyPolicy: req.policyContext.privacyPolicy,
          environmentPolicy: req.policyContext.environmentPolicy,
          ambiguityDisposition: 'READY',
        },
      };
    },
  };
}

// C1 — planner seam vs unattested registry
const unattested = await ShunRegistry.fromAttestedSnapshot(registrySnapshot(), {
  currentnessAuthority: { currentRevision: async () => 'does-not-match-any-revision' },
});
const calls = { count: 0 };
const req = goalRequest({ goal: 'organize desktop screenshots by date' });
req.policyContext.privacyPolicy = { localOnly: false, externalDisclosure: 'ALLOWED' };
const c1 = await interpretGoalViaPlanner({
  request: req,
  registry: unattested,
  adapter: remotePlannerAdapter({
    interpretGoal: async (r) => {
      calls.lastRequest = r;
      return spyPlanner(calls).interpretGoal(r);
    },
  }),
  objectExists: () => true,
});
evidence.probes.push({
  id: 'C1',
  claim: 'no currentness gate before the planner invocation in interpretGoalViaPlanner',
  registryCurrentnessAttested: unattested.currentnessAttested,
  plannerCalls: calls.count,
  status: c1.status,
  reason: c1.reason ?? null,
});
await logEvent('C1-planner-seam-no-currentness-gate', {
  cmd: 'interpretGoalViaPlanner (REMOTE adapter, unattested registry)',
  rc: 0,
  stdout: JSON.stringify({ status: c1.status, plannerCalls: calls.count, attested: unattested.currentnessAttested }),
});

// C2 — deterministic resolveGoal vs the same unattested registry.
// The goal carries the capabilityId prefix so normalization reaches the
// RESOLUTION stage where the currentness gate sits (as the real-storage
// backend composes it: '<capabilityId>: <goal>').
const resolveReq = goalRequest({ goal: 'image.batch_process: organize desktop screenshots by date' });
resolveReq.policyContext.privacyPolicy = { localOnly: false, externalDisclosure: 'ALLOWED' };
const c2 = resolveGoal({ request: resolveReq, registry: unattested, objectExists: () => true });
const c2Failure =
  c2?.record?.failureDisposition ??
  c2?.failureDisposition ??
  c2?.failure ??
  null;
evidence.probes.push({
  id: 'C2',
  claim: 'registry currentness gate lives in the deterministic resolveGoal path',
  registryCurrentnessAttested: unattested.currentnessAttested,
  stage: c2.stage,
  failureCode: c2Failure?.failureCode ?? null,
  failureDetail: c2Failure?.detail ?? null,
  fullResult: c2,
});
await logEvent('C2-resolveGoal-currentness-gate', {
  cmd: 'resolveGoal (unattested registry)',
  rc: 0,
  stdout: JSON.stringify({ stage: c2.stage, failureCode: c2Failure?.failureCode ?? null }),
});

// C3 — attested snapshot with a matching authority revision resolves past currentness
const attested = await ShunRegistry.fromAttestedSnapshot(registrySnapshot(), {
  currentnessAuthority: { currentRevision: async () => snapshotFactsRevision(registrySnapshot()) },
});
const c3 = resolveGoal({ request: resolveReq, registry: attested, objectExists: () => true });
const c3Failure =
  c3?.record?.failureDisposition ?? c3?.failureDisposition ?? c3?.failure ?? null;
evidence.probes.push({
  id: 'C3',
  claim: 'matching currentness authority revision attests the registry and resolution proceeds',
  registryCurrentnessAttested: attested.currentnessAttested,
  stage: c3.stage,
  failureCode: c3Failure?.failureCode ?? null,
  selectedBindingId: c3?.record?.selectedBindingId ?? null,
});
await logEvent('C3-attested-registry-resolves', {
  cmd: 'resolveGoal (attested registry, matching revision)',
  rc: 0,
  stdout: JSON.stringify({ attested: attested.currentnessAttested, stage: c3.stage, failureCode: c3Failure?.failureCode ?? null }),
});

// C4 — defense-in-depth sanity at this pinned tree: a properly declared LOCAL
// planner is still refused by the R3 seam disposition (0 invocations).
const callsLocal = { count: 0 };
const localPlanner = {
  interpretGoal: async () => {
    callsLocal.count += 1;
    throw new Error('MUST-NOT-BE-INVOKED');
  },
};
const c4 = await interpretGoalViaPlanner({
  request: req,
  registry: attested,
  adapter: localPlannerAdapter(declareLocalPlanner(localPlanner)),
  objectExists: () => true,
});
evidence.probes.push({
  id: 'C4',
  claim: 'R3: even a declareLocalPlanner-wrapped LOCAL adapter fails closed at the seam with zero invocations',
  status: c4.status,
  reason: c4.reason ?? null,
  plannerCalls: callsLocal.count,
});
await logEvent('C4-local-declared-still-fail-closed', {
  cmd: 'interpretGoalViaPlanner (LOCAL adapter via declareLocalPlanner)',
  rc: 0,
  stdout: JSON.stringify({ status: c4.status, plannerCalls: callsLocal.count }),
});

evidence.conclusion = {
  currentnessGateBeforePlannerCallExistsInV0_1: false,
  statement:
    'v0.1 has NO currentness gate ahead of the planner invocation: interpretGoalViaPlanner consumes no currentness record (C1 shows a planner call succeeding against an unattested registry). The real currentness gates sit (a) in deterministic resolveGoal (C2/C3, REGISTRY_CURRENTNESS_INSUFFICIENT) — a path with no model call at all — and (b) in authorization currentAuthority/authorizePlan/authorizeEffect, downstream of planning. Therefore "invalid currentness -> zero model calls" cannot be exercised against the planner path in v0.1; the planner-gate sub-item is BLOCKED_NOT_RUNNABLE, recorded without modifying any code.',
};
await logNote('C-conclusion', evidence.conclusion);

const outPath = resolve(EVIDENCE_DIR, 'currentness-probe.json');
await writeFile(outPath, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
await logEvent('C-evidence-written', { cmd: `write ${outPath}`, rc: 0, stdout: outPath });
console.log(JSON.stringify(evidence, null, 2));
