import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';

const NOW = 3_000;
const observation = {
  schema: 'shun.guided.host-observation.v1', taskId: 'task-r02', journeyId: 'journey-r02',
  sourceRef: 'host:obs:r02', revision: 'r02',
  caseRef: { snapshotId: 'snap-r02', digest: 'a'.repeat(64) },
  observedAtUnixMs: 1_000, validUntilUnixMs: 60_000,
  evidenceRefs: ['host:scope:r02'],
};
const semantic = {
  status: 'SELECTED',
  semantic: {
    schema: 'shun.goal-semantic.v1', taskId: 'task-r02',
    goalContract: { taskId: 'task-r02', objective: 'inspect selected folder' },
    capabilityId: 'system.storage.diagnose_bounded_action',
    capabilityRevision: 'r1', provenance: { resolverRevision: 'resolver-v03' },
  },
};
const scope = { status: 'KNOWN', selectedRootRef: undefined };

function freshObservation(revision: string, observedAtUnixMs: number, validUntilUnixMs: number) {
  return { ...observation, revision, observedAtUnixMs, validUntilUnixMs };
}

function submitOutcome(step: {
  journeyId: string; taskId: string; stepId: string;
  caseRef: unknown; issuedAtUnixMs?: number; validUntilUnixMs: number;
}, sourceRef: string, occurredAtUnixMs: number, answers: readonly unknown[] = []) {
  return {
    schema: 'shun.guided.step-outcome.v1',
    journeyId: step.journeyId, taskId: step.taskId, stepId: step.stepId,
    caseRef: step.caseRef, event: 'USER_SUBMIT', source: 'USER',
    sourceRef, answers, evidenceRefs: [], occurredAtUnixMs,
  };
}

function relayFor(step: {
  stepId: string; caseRef: unknown; templateRef: { digest: string };
}, decision: 'ANSWER' | 'APPROVE' | 'REFUSE', outcome: unknown) {
  return {
    kind: 'USER_DECISION_RELAY',
    humanApproval: decision !== 'ANSWER',
    authorityClaimed: false,
    decision, relayedVia: '/api', stepId: step.stepId,
    stepDigest: step.templateRef.digest, caseRef: step.caseRef, outcome,
  };
}

// Windows may keep the SQLite WAL handle alive briefly after close(); retry
// per entry so cleanup never masks a real assertion failure as an EPERM.
function cleanup(dir: string): void {
  let lastError: unknown;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      rmSync(dir, { recursive: true, force: true });
      return;
    } catch (error) {
      lastError = error;
      try {
        for (const entry of readdirSync(dir)) {
          rmSync(join(dir, entry), { recursive: true, force: true });
        }
      } catch { /* entry removal is best-effort; the next round retries */ }
      // Allocation pressure nudges the GC to finalize deferred SQLite
      // handles on Windows so the next retry can remove the WAL files.
      for (let i = 0; i < 20; i += 1) {
        new Array(64 * 1024).fill(i);
      }
      const lock = new Int32Array(new SharedArrayBuffer(4));
      Atomics.wait(lock, 0, 0, 200);
    }
  }
  let entries: string[] = [];
  try {
    entries = readdirSync(dir);
  } catch { /* directory already gone */ }
  // Never mask a real assertion failure with a Windows file-lock cleanup error.
  console.error(`cleanup failed after retries: ${(lastError as Error).message}; entries=${entries.join(',')}`);
}

describe('R02-B Host Guided SQLite durability and replay fence', () => {
  it('accepts exactly one bounded UI answer after trusted Host stage, survives restart', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r02-b-'));
    const file = join(dir, 'guided.sqlite');
    try {
      let service = new HostGuidedService(file, () => NOW);
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const step = staged.step;
      expect(service.state().currentStep?.stepId).toBe(step.stepId);
      const outcome = {
        schema: 'shun.guided.step-outcome.v1',
        journeyId: step.journeyId, taskId: step.taskId, stepId: step.stepId,
        caseRef: step.caseRef, event: 'USER_SUBMIT', source: 'USER',
        sourceRef: 'ui:local', answers: [{ fieldId: 'selectedRoot', value: 'C:\\\\Work' }],
        evidenceRefs: [], occurredAtUnixMs: NOW,
      };
      // G2 P2 repair: refusing an ASK step must not silently discard the
      // submitted answer — the refusal is recorded and the answer stays
      // durably readable, with no grant and no effect sent.
      const refuseRelay = relayFor(step, 'REFUSE', outcome);
      const refused = service.decide(refuseRelay);
      expect(refused).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().history).toMatchObject([{ stepId: step.stepId, status: 'REFUSED' }]);
      const preserved = service.readRecordedAnswer(step.stepId) as
        | { event: string; source: string }
        | undefined;
      expect(preserved).toMatchObject({ event: 'USER_SUBMIT', source: 'USER' });
      // Single consumption: the refused step cannot be decided again.
      expect(service.decide(refuseRelay)).toMatchObject({ status: 'STALE' });
      service.close();

      service = new HostGuidedService(file, () => NOW);
      expect(service.state().currentStep).toBeUndefined();
      expect(service.state().history).toHaveLength(1);
      expect(service.readRecordedAnswer(step.stepId)).toEqual(preserved);
      expect(service.decide(refuseRelay)).toMatchObject({ status: 'STALE' });
      service.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('records a non-authorizing ASK answer exactly once and rejects a forged approval', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r04-answer-'));
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => NOW);
    let serviceClosed = false;
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      expect(staged.step.kind).toBe('ASK');
      const step = staged.step;
      const relay = {
        kind: 'USER_DECISION_RELAY', humanApproval: false, authorityClaimed: false,
        decision: 'ANSWER', relayedVia: '/api', stepId: step.stepId,
        stepDigest: step.templateRef.digest, caseRef: step.caseRef,
        outcome: {
          schema: 'shun.guided.step-outcome.v1', journeyId: step.journeyId,
          taskId: step.taskId, stepId: step.stepId, caseRef: step.caseRef,
          event: 'USER_SUBMIT', source: 'USER', sourceRef: 'ui:shun-r04-desktop',
          answers: [{ fieldId: 'selectedRoot', value: 'C:\\Work' }],
          evidenceRefs: [], occurredAtUnixMs: NOW,
        },
      };
      expect(service.decide({ ...relay, humanApproval: true }))
        .toMatchObject({ status: 'REFUSED', code: 'RELAY_SCHEMA_REFUSED' });
      expect(service.decide({ ...relay, outcome: { ...relay.outcome, event: 'OBSERVATION_RECEIPT', source: 'HOST' } }))
        .toMatchObject({ status: 'REFUSED', code: 'GUIDED_DECISION_MATRIX_REFUSED' });
      expect(service.decide({ ...relay, grant: 'forged' }))
        .toMatchObject({ status: 'REFUSED', code: 'RELAY_SCHEMA_REFUSED' });
      expect(service.decide(relay))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      const savedAnswer = service.readRecordedAnswer(step.stepId) as {
        event: string;
        source: string;
        answers: readonly { fieldId: string; value: unknown }[];
      } | undefined;
      expect(savedAnswer).toMatchObject({
        event: 'USER_SUBMIT',
        source: 'USER',
        answers: [{ fieldId: 'selectedRoot', value: 'C:\\Work' }],
      });
      expect(service.decide(relay)).toMatchObject({ status: 'STALE' });
      expect(service.state().currentStep).toBeUndefined();
      service.close();
      serviceClosed = true;
      const restarted = new HostGuidedService(join(dir, 'guided.sqlite'), () => NOW);
      try {
        expect(restarted.readRecordedAnswer(step.stepId)).toEqual(savedAnswer);
      } finally {
        restarted.close();
      }
    } finally {
      if (!serviceClosed) service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses untrusted attempts to supply grant or change active identity', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r02-b-negative-'));
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => NOW);
    try {
      expect(service.decide({ kind: 'USER_DECISION_RELAY', grant: true }))
        .toMatchObject({ status: 'REFUSED', code: 'RELAY_SCHEMA_REFUSED' });
      expect(service.state().currentStep).toBeUndefined();
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
  it('rejects missing, malformed and out-of-schema ASK answers without consuming the current step', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-u03-answer-validation-'));
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => NOW);
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const step = staged.step;
      const relay = {
        kind: 'USER_DECISION_RELAY', humanApproval: false, authorityClaimed: false,
        decision: 'ANSWER', relayedVia: '/api', stepId: step.stepId,
        stepDigest: step.templateRef.digest, caseRef: step.caseRef,
        outcome: {
          schema: 'shun.guided.step-outcome.v1', journeyId: step.journeyId,
          taskId: step.taskId, stepId: step.stepId, caseRef: step.caseRef,
          event: 'USER_SUBMIT', source: 'USER', sourceRef: 'ui:u03-validation',
          answers: [{ fieldId: 'selectedRoot', value: 'C:\\Work' }],
          evidenceRefs: [], occurredAtUnixMs: NOW,
        },
      };
      expect(service.decide({ ...relay, outcome: { ...relay.outcome, answers: [] } }))
        .toMatchObject({ status: 'REFUSED', code: 'ANSWER_REQUIRED_FIELD_MISSING' });
      expect(service.decide({ ...relay, outcome: { ...relay.outcome, answers: [{ fieldId: 'unknown', value: 'x' }] } }))
        .toMatchObject({ status: 'REFUSED', code: 'ANSWER_VALUE_REFUSED' });
      expect(service.decide({ ...relay, outcome: { ...relay.outcome, answers: [{ fieldId: 'selectedRoot', value: 'x'.repeat(1025) }] } }))
        .toMatchObject({ status: 'REFUSED', code: 'ANSWER_VALUE_REFUSED' });
      expect(service.decide({ ...relay, outcome: { ...relay.outcome, extra: 'not-allowed' } }))
        .toMatchObject({ status: 'REFUSED', code: 'STEP_OUTCOME_SCHEMA_REFUSED' });
      expect(service.decide({ ...relay, outcome: { ...relay.outcome, taskId: 'foreign-task' } }))
        .toMatchObject({ status: 'REFUSED', code: 'STEP_OUTCOME_PROVENANCE_REFUSED' });
      const recorded = service.decide(relay);
      expect(recorded).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(Object.keys(recorded).sort()).toEqual(['effectSent', 'history', 'humanGrantIssued', 'status'].sort());
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('validates CHOICE answers against the exact Host-approved ASK template', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-u03-answer-choice-'));
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => NOW);
    try {
      const privacyObservation = {
        ...observation,
        selectedRootRef: 'host:root:r02',
        externalDisclosureRequired: true,
        privacyNoticeAcknowledged: false,
      };
      const staged = service.stageTrustedSelection({
        observation: privacyObservation, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:r02' },
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const step = staged.step;
      expect(step.kind).toBe('ASK');
      expect(step.templateRef.artifactId).toBe('shun.guided.privacy-notice');
      const relay = {
        kind: 'USER_DECISION_RELAY', humanApproval: false, authorityClaimed: false,
        decision: 'ANSWER', relayedVia: '/api', stepId: step.stepId,
        stepDigest: step.templateRef.digest, caseRef: step.caseRef,
        outcome: {
          schema: 'shun.guided.step-outcome.v1', journeyId: step.journeyId,
          taskId: step.taskId, stepId: step.stepId, caseRef: step.caseRef,
          event: 'USER_SUBMIT', source: 'USER', sourceRef: 'ui:u03-choice',
          answers: [{ fieldId: 'privacyRoute', value: 'not-in-approved-catalog' }],
          evidenceRefs: [], occurredAtUnixMs: NOW,
        },
      };
      expect(service.decide(relay)).toMatchObject({ status: 'REFUSED', code: 'ANSWER_VALUE_REFUSED' });
      expect(service.decide({
        ...relay,
        outcome: { ...relay.outcome, answers: [{ fieldId: 'privacyRoute', value: 'keep-local' }] },
      })).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('keeps ANSWER separate from REVIEW_EFFECT approval and preserves the existing APPROVE path', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-u03-answer-approval-separation-'));
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => NOW);
    try {
      const reviewObservation = {
        ...observation,
        selectedRootRef: 'host:root:r02',
        actionPreviewRef: 'host:preview:r02',
      };
      const staged = service.stageTrustedSelection({
        observation: reviewObservation, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:r02' },
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const step = staged.step;
      expect(step.kind).toBe('REVIEW_EFFECT');
      const outcome = {
        schema: 'shun.guided.step-outcome.v1', journeyId: step.journeyId,
        taskId: step.taskId, stepId: step.stepId, caseRef: step.caseRef,
        event: 'USER_SUBMIT', source: 'USER', sourceRef: 'ui:u03-review',
        answers: [{ fieldId: 'continue', value: 'continue-to-independent-approval' }],
        evidenceRefs: [], occurredAtUnixMs: NOW,
      };
      const common = relayFor(step, 'ANSWER', outcome);
      expect(service.decide(common))
        .toMatchObject({ status: 'REFUSED', code: 'GUIDED_DECISION_MATRIX_REFUSED' });
      expect(service.decide(relayFor(step, 'APPROVE', outcome)))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses an expired Host observation instead of recording a late ASK answer', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-u03-answer-expired-'));
    let now = NOW;
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => now);
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const step = staged.step;
      const relay = relayFor(step, 'ANSWER', submitOutcome(step, 'ui:u03-expired', NOW,
        [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]));
      now = step.validUntilUnixMs + 1;
      expect(service.decide(relay)).toMatchObject({ status: 'REFUSED' });
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('restages an expired step only for a fresh advanced Host observation of the same Case', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r02-b-expired-restage-'));
    let now = NOW;
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => now);
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const expiredStep = staged.step;
      now = 70_000; // past the step/observation validity window, at/after fresh observedAt
      // Expired steps disappear from the state view and late decisions are refused.
      expect(service.state().currentStep).toBeUndefined();
      expect(service.decide(relayFor(expiredStep, 'ANSWER',
        submitOutcome(expiredStep, 'ui:r02-b-late', expiredStep.validUntilUnixMs - 1,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'REFUSED' });
      // A fresh observation with advanced revision and observedAt restages the Case.
      const fresh = freshObservation('r03', 65_000, 130_000);
      const restaged = service.stageTrustedSelection({
        observation: fresh, semanticSelection: semantic, scope,
      });
      expect(restaged.status).toBe('CURRENT');
      if (restaged.status !== 'CURRENT') return;
      expect(restaged.step.stepId).not.toBe(expiredStep.stepId);
      expect(service.state().currentStep?.stepId).toBe(restaged.step.stepId);
      expect(service.state().history).toHaveLength(0);
      // While the restaged step is still valid, any staging is refused.
      expect(service.stageTrustedSelection({
        observation: freshObservation('r04', 65_000, 300_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'CURRENT_STEP_ALREADY_EXISTS' });
      // When the second window also closes, freshness replay stays fenced:
      // same observedAt with a new revision, or an older revision/observedAt.
      now = 200_000;
      expect(service.state().currentStep).toBeUndefined();
      expect(service.stageTrustedSelection({
        observation: freshObservation('r04', 65_000, 300_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_OBSERVATION_NOT_ADVANCED' });
      expect(service.stageTrustedSelection({
        observation: freshObservation('r02', 1_000, 300_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_OBSERVATION_NOT_ADVANCED' });
      // A different Case identity can never replace the expired step.
      expect(service.stageTrustedSelection({
        observation: {
          ...freshObservation('r05', 75_000, 300_000),
          caseRef: { snapshotId: 'snap-other', digest: 'b'.repeat(64) },
        },
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_CASE_IDENTITY_REFUSED' });
      // Expiry is recoverable repeatedly: a newer advanced observation
      // restages the same Case again.
      const restagedAgain = service.stageTrustedSelection({
        observation: freshObservation('r06', 140_000, 400_000),
        semanticSelection: semantic, scope,
      });
      expect(restagedAgain.status).toBe('CURRENT');
      if (restagedAgain.status !== 'CURRENT') return;
      expect(restagedAgain.step.stepId).not.toBe(restaged.step.stepId);
    } finally {
      service.close();
      cleanup(dir);
    }
  });

  it('restores a valid CURRENT step across restart and refuses duplicate staging', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r02-b-valid-restore-'));
    const file = join(dir, 'guided.sqlite');
    try {
      let service = new HostGuidedService(file, () => NOW);
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      service.close();

      service = new HostGuidedService(file, () => NOW);
      expect(service.state().currentStep?.stepId).toBe(staged.step.stepId);
      expect(service.state().journey).toMatchObject({ position: 1, total: 1, paused: false });
      expect(service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' });
      expect(service.stageTrustedSelection({
        observation: freshObservation('r03', 2_000, 60_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'CURRENT_STEP_ALREADY_EXISTS' });
      service.close();
    } finally {
      cleanup(dir);
    }
  });

  it('persists PAUSE/RESUME across restart and fences submissions while paused', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r02-b-pause-resume-'));
    const file = join(dir, 'guided.sqlite');
    let now = NOW;
    let service = new HostGuidedService(file, () => now);
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const step = staged.step;
      // Lifecycle transitions are strict: RESUME requires PAUSED, PAUSE requires CURRENT.
      expect(service.decide(relayFor(step, 'ANSWER',
        { ...submitOutcome(step, 'ui:r02-b-resume-too-early', now), event: 'RESUME', answers: [] })))
        .toMatchObject({ status: 'REFUSED', code: 'GUIDED_STEP_LIFECYCLE_REFUSED' });
      now = 4_000;
      const pause = service.decide(relayFor(step, 'ANSWER',
        { ...submitOutcome(step, 'ui:r02-b-pause', now), event: 'PAUSE', answers: [] }));
      expect(pause).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().currentStep?.stepId).toBe(step.stepId);
      expect(service.state().journey.paused).toBe(true);
      expect(service.decide(relayFor(step, 'ANSWER',
        { ...submitOutcome(step, 'ui:r02-b-repause', now), event: 'PAUSE', answers: [] })))
        .toMatchObject({ status: 'REFUSED', code: 'GUIDED_STEP_LIFECYCLE_REFUSED' });
      // A paused step accepts navigation only; the answer must wait for RESUME.
      expect(service.decide(relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:r02-b-while-paused', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'REFUSED', code: 'GUIDED_STEP_PAUSED' });
      service.close();

      // The durable PAUSED state survives a full restart.
      service = new HostGuidedService(file, () => now);
      expect(service.state().currentStep?.stepId).toBe(step.stepId);
      expect(service.state().journey.paused).toBe(true);
      now = 5_000;
      expect(service.decide(relayFor(step, 'ANSWER',
        { ...submitOutcome(step, 'ui:r02-b-resume', now), event: 'RESUME', answers: [] })))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().journey.paused).toBe(false);
      now = 6_000;
      expect(service.decide(relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:r02-b-after-resume', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().currentStep).toBeUndefined();
      expect(service.state().history.map((entry) => entry.status))
        .toEqual(['PAUSE', 'RESUME', 'ACCEPTED']);
    } finally {
      try { service.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('treats BACK as non-consuming navigation that preserves submitted answers', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r02-b-back-non-consuming-'));
    let now = NOW;
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => now);
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const step = staged.step;
      now = 3_500;
      const back = service.decide(relayFor(step, 'ANSWER',
        { ...submitOutcome(step, 'ui:r02-b-back', now), event: 'BACK', answers: [] }));
      expect(back).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(back).toMatchObject({ status: 'RECORDED' });
      if (back.status === 'RECORDED') {
        expect(back.history).toHaveLength(0);
      }
      // Nothing was consumed, no answer row appeared, and the step is still CURRENT.
      expect(service.state().currentStep?.stepId).toBe(step.stepId);
      expect(service.readRecordedAnswer(step.stepId)).toBeUndefined();
      // The same step still accepts its real answer after navigation.
      now = 4_000;
      expect(service.decide(relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:r02-b-after-back', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('preserves a REVIEW_EFFECT REFUSE as durable refusal without answer loss or grant', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r02-b-review-refuse-'));
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => NOW);
    try {
      const reviewObservation = {
        ...observation,
        selectedRootRef: 'host:root:r02',
        actionPreviewRef: 'host:preview:r02',
      };
      const staged = service.stageTrustedSelection({
        observation: reviewObservation, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:r02' },
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const step = staged.step;
      expect(step.kind).toBe('REVIEW_EFFECT');
      const recorded = service.decide(relayFor(step, 'REFUSE',
        submitOutcome(step, 'ui:r02-b-review-refuse', NOW,
          [{ fieldId: 'continue', value: 'continue-to-independent-approval' }])));
      expect(recorded).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().currentStep).toBeUndefined();
      expect(service.state().history).toMatchObject([{ stepId: step.stepId, status: 'REFUSED' }]);
      // A refusal never persists the submitted payload as an authoritative answer.
      expect(service.readRecordedAnswer(step.stepId)).toBeUndefined();
      expect(service.decide(relayFor(step, 'REFUSE',
        submitOutcome(step, 'ui:r02-b-review-refuse-2', NOW,
          [{ fieldId: 'continue', value: 'continue-to-independent-approval' }]))))
        .toMatchObject({ status: 'STALE' });
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

});
