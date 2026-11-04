import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
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

// ---------- G4: durable Host-private consumed-step ledger helpers ----------

type LedgerRowView = {
  step_id: string; task_id: string; case_ref_json: string; template_digest: string;
  terminal_event: string; terminal_decision: string; recorded_at_unix_ms: number;
  row_sha256: string;
};

// The exact StepSpec shape produced by a trusted staging, derived from the
// service itself so the fixtures need no deep package imports.
type GuidedStep = Extract<ReturnType<HostGuidedService['stageTrustedSelection']>,
  { readonly status: 'CURRENT' }>['step'];

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

// Mirrors the service's canonical ledger row-integrity binding so test
// fixtures that pre-seed ledger rows produce digest-verifiable rows.
function ledgerRowSha(row: Omit<LedgerRowView, 'row_sha256'>): string {
  return sha256Hex(
    `${row.step_id}|${row.task_id}|${row.case_ref_json}|${row.template_digest}|` +
    `${row.terminal_event}|${row.terminal_decision}|${row.recorded_at_unix_ms}`,
  );
}

function readLedger(file: string): LedgerRowView[] {
  const db = new DatabaseSync(file);
  try {
    return db.prepare(`SELECT step_id,task_id,case_ref_json,template_digest,
      terminal_event,terminal_decision,recorded_at_unix_ms,row_sha256
      FROM guided_consumed_steps ORDER BY step_id`).all() as unknown as LedgerRowView[];
  } finally {
    db.close();
  }
}

function dropLedgerTable(file: string): void {
  const db = new DatabaseSync(file);
  try {
    db.exec('DROP TABLE IF EXISTS guided_consumed_steps');
  } finally {
    db.close();
  }
}

function tableCount(file: string, table: string): number {
  const db = new DatabaseSync(file);
  try {
    const row = db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number } | undefined;
    return row?.n ?? -1;
  } finally {
    db.close();
  }
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
      // G3 repair: refusing an ASK step persists a separately typed refusal
      // receipt — the submitted payload is preserved as explicit refusal
      // evidence but is never returned by readRecordedAnswer as an accepted
      // answer, with no grant and no effect sent.
      const refuseRelay = relayFor(step, 'REFUSE', outcome);
      const refused = service.decide(refuseRelay);
      expect(refused).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().history).toMatchObject([{ stepId: step.stepId, status: 'REFUSED' }]);
      expect(service.readRecordedAnswer(step.stepId)).toBeUndefined();
      const refusal = service.readRecordedRefusal(step.stepId) as
        | { schema: string; decision: string; outcome: { event: string; source: string } }
        | undefined;
      expect(refusal).toMatchObject({
        schema: 'shun.guided.refusal-receipt.v1',
        decision: 'REFUSE',
        outcome: { event: 'USER_SUBMIT', source: 'USER' },
      });
      // Single consumption: the refused step cannot be decided again.
      expect(service.decide(refuseRelay)).toMatchObject({ status: 'STALE' });
      service.close();

      service = new HostGuidedService(file, () => NOW);
      expect(service.state().currentStep).toBeUndefined();
      expect(service.state().history).toHaveLength(1);
      expect(service.readRecordedAnswer(step.stepId)).toBeUndefined();
      expect(service.readRecordedRefusal(step.stepId)).toEqual(refusal);
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

  it('fences historical step replay after a newer same-Case step is consumed', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r02-b-history-replay-'));
    let now = NOW;
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => now);
    try {
      const first = service.stageTrustedSelection({
        observation: freshObservation('g3-r01', 1_000, 60_000),
        semanticSelection: semantic, scope,
      });
      expect(first.status).toBe('CURRENT');
      if (first.status !== 'CURRENT') return;
      expect(service.decide(relayFor(first.step, 'ANSWER',
        submitOutcome(first.step, 'ui:g3-r01', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      now = 10_000;
      const second = service.stageTrustedSelection({
        observation: freshObservation('g3-r02', 10_000, 60_000),
        semanticSelection: semantic, scope,
      });
      expect(second.status).toBe('CURRENT');
      if (second.status !== 'CURRENT') return;
      expect(second.step.stepId).not.toBe(first.step.stepId);
      expect(service.decide(relayFor(second.step, 'ANSWER',
        submitOutcome(second.step, 'ui:g3-r02', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().history).toHaveLength(2);
      // Replaying the historically consumed r01 is fenced even when the
      // replayed observation carries a later observedAt.
      now = 20_000;
      expect(service.stageTrustedSelection({
        observation: freshObservation('g3-r01', 20_000, 90_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' });
      // Replaying the just-consumed r02 under its own revision is fenced too.
      expect(service.stageTrustedSelection({
        observation: freshObservation('g3-r02', 20_000, 90_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' });
      // A new token with an older observedAt is stale after CONSUMED.
      expect(service.stageTrustedSelection({
        observation: freshObservation('g3-r03', 5_000, 90_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_OBSERVATION_NOT_ADVANCED' });
      // A genuinely advanced observation still progresses the same Case and
      // keeps the carried history.
      const third = service.stageTrustedSelection({
        observation: freshObservation('g3-r03', 20_000, 90_000),
        semanticSelection: semantic, scope,
      });
      expect(third.status).toBe('CURRENT');
      if (third.status !== 'CURRENT') return;
      expect(service.state().history).toHaveLength(2);
      expect(service.decide(relayFor(third.step, 'ANSWER',
        submitOutcome(third.step, 'ui:g3-r03', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().history).toHaveLength(3);
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('starts a clean history for a genuinely different Case after consumption', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r02-b-case-isolation-'));
    let now = NOW;
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => now);
    try {
      const first = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(first.status).toBe('CURRENT');
      if (first.status !== 'CURRENT') return;
      const caseA = first.step.caseRef;
      expect(service.decide(relayFor(first.step, 'ANSWER',
        submitOutcome(first.step, 'ui:g3-case-a', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().history).toHaveLength(1);
      now = 10_000;
      const stagedB = service.stageTrustedSelection({
        observation: {
          ...freshObservation('g3-b1', 10_000, 90_000),
          caseRef: { snapshotId: 'snap-g3-b', digest: 'c'.repeat(64) },
        },
        semanticSelection: semantic, scope,
      });
      expect(stagedB.status).toBe('CURRENT');
      if (stagedB.status !== 'CURRENT') return;
      expect(stagedB.step.caseRef).not.toEqual(caseA);
      // Prior-Case step metadata never leaks into the new Case's projection.
      expect(service.state().history).toEqual([]);
      expect(service.state().currentStep?.stepId).toBe(stagedB.step.stepId);
      expect(service.decide(relayFor(stagedB.step, 'ANSWER',
        submitOutcome(stagedB.step, 'ui:g3-case-b', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().history.map((entry) => entry.stepId))
        .toEqual([stagedB.step.stepId]);
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('records an INSPECT Host receipt as OBSERVATION_RECEIPT, never as REFUSED', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r02-b-inspect-receipt-'));
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => NOW);
    try {
      const staged = service.stageTrustedSelection({
        observation: { ...observation, revision: 'g3-insp', selectedRootRef: 'host:root:g3' },
        semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:g3' },
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const step = staged.step;
      expect(step.kind).toBe('INSPECT');
      const hostReceipt = {
        schema: 'shun.guided.step-outcome.v1',
        journeyId: step.journeyId, taskId: step.taskId, stepId: step.stepId,
        caseRef: step.caseRef, event: 'OBSERVATION_RECEIPT', source: 'HOST',
        sourceRef: 'host:obs:r02', answers: [], evidenceRefs: ['host:scope:r02'],
        occurredAtUnixMs: NOW,
      };
      const receipt = service.decide(relayFor(step, 'REFUSE', hostReceipt));
      expect(receipt).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().history)
        .toMatchObject([{ stepId: step.stepId, status: 'OBSERVATION_RECEIPT' }]);
      // A Host receipt is neither an accepted answer nor a user refusal
      // payload, and it never implies human approval, grant or effect.
      expect(service.readRecordedAnswer(step.stepId)).toBeUndefined();
      expect(service.readRecordedRefusal(step.stepId)).toBeUndefined();
      expect(service.state().currentStep).toBeUndefined();
      expect(service.decide(relayFor(step, 'REFUSE', hostReceipt)))
        .toMatchObject({ status: 'STALE' });
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('G4: fences A->B->A replay of a consumed REVIEW_EFFECT APPROVE across restart', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g4-aba-approve-'));
    const file = join(dir, 'guided.sqlite');
    let now = NOW;
    let service = new HostGuidedService(file, () => now);
    try {
      const reviewA = {
        ...observation, revision: 'g4-a1',
        selectedRootRef: 'host:root:g4-a', actionPreviewRef: 'host:preview:g4-a',
      };
      const stagedA = service.stageTrustedSelection({
        observation: reviewA, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:g4-a' },
      });
      expect(stagedA.status).toBe('CURRENT');
      if (stagedA.status !== 'CURRENT') return;
      const stepA = stagedA.step;
      expect(stepA.kind).toBe('REVIEW_EFFECT');
      const approve = service.decide(relayFor(stepA, 'APPROVE',
        submitOutcome(stepA, 'ui:g4-a-approve', now,
          [{ fieldId: 'continue', value: 'continue-to-independent-approval' }])));
      expect(approve).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(readLedger(file)).toHaveLength(1);

      // Switch to a genuinely different Case B and consume it too.
      now = 10_000;
      const stagedB = service.stageTrustedSelection({
        observation: {
          ...freshObservation('g4-b1', 10_000, 90_000),
          selectedRootRef: 'host:root:g4-b', actionPreviewRef: 'host:preview:g4-b',
          caseRef: { snapshotId: 'snap-g4-b', digest: 'd'.repeat(64) },
        },
        semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:g4-b' },
      });
      expect(stagedB.status).toBe('CURRENT');
      if (stagedB.status !== 'CURRENT') return;
      const stepB = stagedB.step;
      expect(stepB.caseRef).not.toEqual(stepA.caseRef);
      // B's projection starts clean: no A history, no ledger exposure.
      expect(service.state().history).toEqual([]);
      expect(Object.keys(service.state()).sort())
        .toEqual(['currentStep', 'history', 'journey', 'scope']);
      expect(service.decide(relayFor(stepB, 'APPROVE',
        submitOutcome(stepB, 'ui:g4-b-approve', now,
          [{ fieldId: 'continue', value: 'continue-to-independent-approval' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(readLedger(file)).toHaveLength(2);
      service.close();

      // Restart, then attempt A -> B -> A with A's original still-valid
      // observation: the durable ledger refuses the regenerated stepId.
      service = new HostGuidedService(file, () => now);
      expect(service.state().history.map((entry) => entry.stepId)).toEqual([stepB.stepId]);
      expect(service.stageTrustedSelection({
        observation: reviewA, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:g4-a' },
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' });
      // The old A step cannot be consumed again either.
      expect(service.decide(relayFor(stepA, 'APPROVE',
        submitOutcome(stepA, 'ui:g4-a-replay', now,
          [{ fieldId: 'continue', value: 'continue-to-independent-approval' }]))))
        .toMatchObject({ status: 'STALE' });
      expect(readLedger(file)).toHaveLength(2);
      // The fence is per consumed step, not a Case deadlock: a fresh advanced
      // Host observation for A still progresses.
      now = 20_000;
      const stagedA2 = service.stageTrustedSelection({
        observation: { ...reviewA, revision: 'g4-a2', observedAtUnixMs: 15_000 },
        semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:g4-a' },
      });
      expect(stagedA2.status).toBe('CURRENT');
      if (stagedA2.status !== 'CURRENT') return;
      expect(stagedA2.step.stepId).not.toBe(stepA.stepId);
      expect(service.decide(relayFor(stagedA2.step, 'REFUSE',
        submitOutcome(stagedA2.step, 'ui:g4-a2-refuse', now,
          [{ fieldId: 'continue', value: 'continue-to-independent-approval' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(readLedger(file)).toHaveLength(3);
      service.close();
    } finally {
      try { service.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('G4: fences A->B->A replay of REVIEW_EFFECT REFUSE and INSPECT receipts across restarts', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g4-aba-refuse-inspect-'));
    const file = join(dir, 'guided.sqlite');
    let now = NOW;
    let service = new HostGuidedService(file, () => now);
    try {
      // Case A: REVIEW_EFFECT, terminally refused.
      const reviewA = {
        ...observation, revision: 'g4-r1',
        selectedRootRef: 'host:root:g4-r', actionPreviewRef: 'host:preview:g4-r',
      };
      const stagedA = service.stageTrustedSelection({
        observation: reviewA, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:g4-r' },
      });
      expect(stagedA.status).toBe('CURRENT');
      if (stagedA.status !== 'CURRENT') return;
      const stepA = stagedA.step;
      expect(stepA.kind).toBe('REVIEW_EFFECT');
      expect(service.decide(relayFor(stepA, 'REFUSE',
        submitOutcome(stepA, 'ui:g4-r-refuse', now,
          [{ fieldId: 'continue', value: 'continue-to-independent-approval' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      service.close();

      // Restart; switch to Case B (INSPECT) and record a Host receipt.
      now = 6_000;
      service = new HostGuidedService(file, () => now);
      const inspectB = {
        ...freshObservation('g4-i1', 5_000, 90_000),
        selectedRootRef: 'host:root:g4-i',
        caseRef: { snapshotId: 'snap-g4-i', digest: 'e'.repeat(64) },
      };
      const stagedB = service.stageTrustedSelection({
        observation: inspectB, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:g4-i' },
      });
      expect(stagedB.status).toBe('CURRENT');
      if (stagedB.status !== 'CURRENT') return;
      const stepB = stagedB.step;
      expect(stepB.kind).toBe('INSPECT');
      const hostReceipt = {
        schema: 'shun.guided.step-outcome.v1',
        journeyId: stepB.journeyId, taskId: stepB.taskId, stepId: stepB.stepId,
        caseRef: stepB.caseRef, event: 'OBSERVATION_RECEIPT', source: 'HOST',
        sourceRef: 'host:obs:r02', answers: [], evidenceRefs: ['host:scope:r02'],
        occurredAtUnixMs: now,
      };
      const receipt = service.decide(relayFor(stepB, 'REFUSE', hostReceipt));
      expect(receipt).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().history)
        .toMatchObject([{ stepId: stepB.stepId, status: 'OBSERVATION_RECEIPT' }]);
      service.close();

      // Restart; A -> B -> A replay attempts are fenced by the durable ledger.
      service = new HostGuidedService(file, () => now);
      expect(service.state().history.map((entry) => entry.stepId)).toEqual([stepB.stepId]);
      expect(service.stageTrustedSelection({
        observation: reviewA, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:g4-r' },
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' });
      expect(service.stageTrustedSelection({
        observation: inspectB, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:g4-i' },
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' });
      expect(service.decide(relayFor(stepA, 'REFUSE',
        submitOutcome(stepA, 'ui:g4-r-replay', now,
          [{ fieldId: 'continue', value: 'continue-to-independent-approval' }]))))
        .toMatchObject({ status: 'STALE' });
      expect(service.decide(relayFor(stepB, 'REFUSE', hostReceipt)))
        .toMatchObject({ status: 'STALE' });
      // Both terminal outcomes are durably bound with verifiable integrity.
      const rows = readLedger(file);
      expect(rows).toHaveLength(2);
      for (const row of rows) {
        expect(row.row_sha256).toBe(ledgerRowSha(row));
      }
      expect(rows.find((row) => row.step_id === stepA.stepId)).toMatchObject({
        terminal_event: 'USER_SUBMIT', terminal_decision: 'REFUSE',
      });
      expect(rows.find((row) => row.step_id === stepB.stepId)).toMatchObject({
        terminal_event: 'OBSERVATION_RECEIPT', terminal_decision: 'REFUSE',
      });
      service.close();
    } finally {
      try { service.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('G4: BACK/PAUSE/RESUME never consume; ASK ANSWER and ASK REFUSE each bind exactly one ledger row', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g4-lifecycle-ledger-'));
    const file = join(dir, 'guided.sqlite');
    let now = NOW;
    const service = new HostGuidedService(file, () => now);
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const step = staged.step;
      expect(step.kind).toBe('ASK');
      // BACK is non-consuming navigation: no ledger row, step stays CURRENT.
      const back = service.decide(relayFor(step, 'ANSWER',
        { ...submitOutcome(step, 'ui:g4-back', now), event: 'BACK', answers: [] }));
      expect(back).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(readLedger(file)).toHaveLength(0);
      expect(service.state().currentStep?.stepId).toBe(step.stepId);
      // PAUSE/RESUME are lifecycle transitions, not terminal consumption.
      now = 3_500;
      expect(service.decide(relayFor(step, 'ANSWER',
        { ...submitOutcome(step, 'ui:g4-pause', now), event: 'PAUSE', answers: [] })))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(readLedger(file)).toHaveLength(0);
      expect(service.decide(relayFor(step, 'ANSWER',
        { ...submitOutcome(step, 'ui:g4-resume', now), event: 'RESUME', answers: [] })))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(readLedger(file)).toHaveLength(0);
      // The terminal ANSWER binds exactly one ledger row.
      now = 4_000;
      expect(service.decide(relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:g4-answer', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      const afterAnswer = readLedger(file);
      expect(afterAnswer).toHaveLength(1);
      const [answerRow] = afterAnswer;
      expect(answerRow).toMatchObject({
        step_id: step.stepId, terminal_event: 'USER_SUBMIT', terminal_decision: 'ANSWER',
      });
      if (!answerRow) return;
      expect(answerRow.row_sha256).toBe(ledgerRowSha(answerRow));
      // Same-Case progression on a fresh advanced observation, then an ASK
      // REFUSE binds a second ledger row.
      now = 10_000;
      const staged2 = service.stageTrustedSelection({
        observation: freshObservation('g4-c2', 10_000, 90_000),
        semanticSelection: semantic, scope,
      });
      expect(staged2.status).toBe('CURRENT');
      if (staged2.status !== 'CURRENT') return;
      const step2 = staged2.step;
      now = 11_000;
      expect(service.decide(relayFor(step2, 'REFUSE',
        submitOutcome(step2, 'ui:g4-refuse', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      const afterRefuse = readLedger(file);
      expect(afterRefuse).toHaveLength(2);
      expect(afterRefuse.find((row) => row.step_id === step2.stepId)).toMatchObject({
        terminal_event: 'USER_SUBMIT', terminal_decision: 'REFUSE',
      });
      // The historically consumed first step stays fenced via the ledger.
      expect(service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' });
      service.close();

      // Restart: the ledger is durable and the refusal receipt survives.
      const restarted = new HostGuidedService(file, () => now);
      try {
        expect(readLedger(file)).toHaveLength(2);
        expect(restarted.decide(relayFor(step2, 'REFUSE',
          submitOutcome(step2, 'ui:g4-refuse-replay', now,
            [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
          .toMatchObject({ status: 'STALE' });
        expect(restarted.readRecordedRefusal(step2.stepId)).toMatchObject({
          schema: 'shun.guided.refusal-receipt.v1', decision: 'REFUSE',
        });
      } finally {
        restarted.close();
      }
    } finally {
      try { service.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('G4: two service instances cannot consume the same step concurrently', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g4-concurrent-'));
    const file = join(dir, 'guided.sqlite');
    const first = new HostGuidedService(file, () => NOW);
    let second: HostGuidedService | null = null;
    try {
      const staged = first.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const relay = relayFor(staged.step, 'ANSWER',
        submitOutcome(staged.step, 'ui:g4-concurrent', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]));
      second = new HostGuidedService(file, () => NOW);
      const results = [first.decide(relay), second.decide(relay)];
      expect(results.filter((result) => result.status === 'RECORDED')).toHaveLength(1);
      expect(results.filter((result) => result.status === 'STALE')).toHaveLength(1);
      for (const result of results) {
        if (result.status === 'RECORDED') {
          expect(result.humanGrantIssued).toBe(false);
          expect(result.effectSent).toBe(false);
        }
      }
      expect(readLedger(file)).toHaveLength(1);
    } finally {
      try { first.close(); } catch { /* already closed */ }
      try { second?.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('G4: a pre-seeded ledger row for a still-current step fails closed without persisting an answer', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g4-ledger-conflict-'));
    const file = join(dir, 'guided.sqlite');
    let service = new HostGuidedService(file, () => NOW);
    let step: GuidedStep;
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      step = staged.step;
    } finally {
      service.close();
    }
    // A durable ledger row exists for a step the selected Case still presents
    // as CURRENT (e.g. a partially-rolled-back legacy write): the unique
    // conflict must fail closed and roll back the whole decision.
    const seeded: LedgerRowView = {
      step_id: step.stepId, task_id: step.taskId,
      case_ref_json: JSON.stringify(step.caseRef), template_digest: step.templateRef.digest,
      terminal_event: 'USER_SUBMIT', terminal_decision: 'ANSWER', recorded_at_unix_ms: NOW,
      row_sha256: '',
    };
    seeded.row_sha256 = ledgerRowSha(seeded);
    const db = new DatabaseSync(file);
    try {
      db.prepare(`INSERT INTO guided_consumed_steps(
        step_id,task_id,case_ref_json,template_digest,terminal_event,terminal_decision,recorded_at_unix_ms,row_sha256
      ) VALUES(?,?,?,?,?,?,?,?)`).run(
        seeded.step_id, seeded.task_id, seeded.case_ref_json, seeded.template_digest,
        seeded.terminal_event, seeded.terminal_decision, seeded.recorded_at_unix_ms, seeded.row_sha256,
      );
    } finally {
      db.close();
    }
    service = new HostGuidedService(file, () => NOW);
    try {
      expect(service.decide(relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:g4-conflict', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'STALE', code: 'GUIDED_STEP_ALREADY_CONSUMED' });
      // The rolled-back answer is not persisted and the step stays CURRENT.
      expect(service.readRecordedAnswer(step.stepId)).toBeUndefined();
      expect(service.state().currentStep?.stepId).toBe(step.stepId);
    } finally {
      service.close();
      cleanup(dir);
    }
  });

  it('G4: idempotently backfills the ledger from provable legacy evidence and fences replay', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g4-migration-backfill-'));
    const file = join(dir, 'guided.sqlite');
    let now = NOW;
    let service = new HostGuidedService(file, () => now);
    let stepA: GuidedStep;
    let stepB: GuidedStep;
    try {
      // Case A (ASK) answered, then a genuinely different Case B answered —
      // the exact G3-era state whose cross-Case replay fence was missing.
      const stagedA = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(stagedA.status).toBe('CURRENT');
      if (stagedA.status !== 'CURRENT') return;
      stepA = stagedA.step;
      expect(service.decide(relayFor(stepA, 'ANSWER',
        submitOutcome(stepA, 'ui:g4-m-a', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      now = 10_000;
      const stagedB = service.stageTrustedSelection({
        observation: {
          ...freshObservation('g4-m1', 10_000, 90_000),
          caseRef: { snapshotId: 'snap-g4-m', digest: 'f'.repeat(64) },
        },
        semanticSelection: semantic, scope,
      });
      expect(stagedB.status).toBe('CURRENT');
      if (stagedB.status !== 'CURRENT') return;
      stepB = stagedB.step;
      expect(service.decide(relayFor(stepB, 'ANSWER',
        submitOutcome(stepB, 'ui:g4-m-b', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      service.close();

      // Simulate the pre-G4 schema: the consumed-step ledger did not exist.
      dropLedgerTable(file);
      // Reopen: the migration backfills the digest-verified answer rows and
      // the persisted CONSUMED terminal, all inside one transaction.
      service = new HostGuidedService(file, () => now);
      expect(readLedger(file)).toHaveLength(2);
      // Idempotent: reopening changes nothing and stays consistent.
      service.close();
      service = new HostGuidedService(file, () => now);
      const rows = readLedger(file);
      expect(rows).toHaveLength(2);
      for (const row of rows) {
        expect(row.row_sha256).toBe(ledgerRowSha(row));
      }
      expect(rows.find((row) => row.step_id === stepA.stepId)).toMatchObject({
        terminal_event: 'USER_SUBMIT', terminal_decision: 'ANSWER',
      });
      expect(rows.find((row) => row.step_id === stepB.stepId)).toMatchObject({
        terminal_event: 'USER_SUBMIT', terminal_decision: 'ANSWER',
      });
      // A -> B -> A replay is now fenced from the backfilled evidence alone,
      // and B's projection still exposes no A history.
      expect(service.state().history.map((entry) => entry.stepId)).toEqual([stepB.stepId]);
      expect(service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' });
      expect(service.decide(relayFor(stepA, 'ANSWER',
        submitOutcome(stepA, 'ui:g4-m-replay', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'STALE' });
      // Migration never deletes provable payload evidence.
      expect(service.readRecordedAnswer(stepA.stepId)).toBeDefined();
      service.close();
    } finally {
      try { service.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('G4: conflicting legacy consumption evidence fails closed without deleting data', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g4-migration-conflict-'));
    const file = join(dir, 'guided.sqlite');
    let service = new HostGuidedService(file, () => NOW);
    let step: GuidedStep;
    let relay: ReturnType<typeof relayFor>;
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      step = staged.step;
      relay = relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:g4-conflict-a', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]));
      expect(service.decide(relay)).toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Tampered legacy state: an answer row AND a refusal row now claim the
    // same consumed step — the terminal decision is unprovable.
    const refusal = {
      schema: 'shun.guided.refusal-receipt.v1',
      stepId: step.stepId, taskId: step.taskId, caseRef: step.caseRef,
      templateDigest: step.templateRef.digest, decision: 'REFUSE',
      outcome: (relay as { outcome: unknown }).outcome,
    };
    const refusalJson = JSON.stringify(refusal);
    const db = new DatabaseSync(file);
    try {
      db.prepare(`INSERT INTO guided_step_refusals(
        step_id,task_id,case_ref_json,template_digest,refusal_json,refusal_sha256,recorded_at_unix_ms
      ) VALUES(?,?,?,?,?,?,?)`).run(
        step.stepId, step.taskId, JSON.stringify(step.caseRef), step.templateRef.digest,
        refusalJson, sha256Hex(refusalJson), NOW,
      );
    } finally {
      db.close();
    }
    service = new HostGuidedService(file, () => NOW);
    try {
      // Fail closed with the stable migration code on every mutation path.
      expect(service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.decide(relay))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
    } finally {
      service.close();
    }
    // No silent reset: every original row is still present.
    expect(tableCount(file, 'guided_step_answers')).toBe(1);
    expect(tableCount(file, 'guided_step_refusals')).toBe(1);
    expect(tableCount(file, 'guided_selected_case')).toBe(1);
    cleanup(dir);
  });

  it('G4: corrupt legacy digest fails closed and preserves data', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g4-migration-corrupt-'));
    const file = join(dir, 'guided.sqlite');
    let service = new HostGuidedService(file, () => NOW);
    let step: GuidedStep;
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      step = staged.step;
      expect(service.decide(relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:g4-corrupt', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Corrupt the persisted answer digest: the evidence can no longer be
    // trusted, so the ledger cannot be established.
    const db = new DatabaseSync(file);
    try {
      db.prepare('UPDATE guided_step_answers SET outcome_sha256=? WHERE step_id=?')
        .run('0'.repeat(64), step.stepId);
    } finally {
      db.close();
    }
    service = new HostGuidedService(file, () => NOW);
    try {
      expect(service.stageTrustedSelection({
        observation: freshObservation('g4-x1', 2_000, 60_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.decide(relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:g4-corrupt-replay', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
    } finally {
      service.close();
    }
    // The corrupt row is preserved, not deleted or reset.
    expect(tableCount(file, 'guided_step_answers')).toBe(1);
    expect(tableCount(file, 'guided_selected_case')).toBe(1);
    cleanup(dir);
  });

});
