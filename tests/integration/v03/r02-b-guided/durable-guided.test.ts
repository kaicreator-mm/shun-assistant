import { mkdtempSync, rmSync } from 'node:fs';
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

describe('R02-B Host Guided SQLite durability and replay fence', () => {
  it('accepts exactly one bounded UI answer after trusted Host stage, survives restart', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r02-b-'));
    const file = join(dir, 'guided.sqlite');
    try {
      let service = new HostGuidedService(file, () => NOW);
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: undefined },
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
      const relay = {
        kind: 'USER_DECISION_RELAY', humanApproval: true, authorityClaimed: false,
        decision: 'REFUSE', relayedVia: '/api', stepId: step.stepId,
        stepDigest: step.templateRef.digest, caseRef: step.caseRef, outcome,
      };
      const recorded = service.decide(relay);
      expect(recorded).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.decide(relay)).toMatchObject({ status: 'STALE' });
      service.close();

      service = new HostGuidedService(file, () => NOW);
      expect(service.state().currentStep).toBeUndefined();
      expect(service.state().history).toHaveLength(1);
      expect(service.decide(relay)).toMatchObject({ status: 'STALE' });
      service.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('records a non-authorizing ASK answer exactly once and rejects a forged approval', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r04-answer-'));
    const service = new HostGuidedService(join(dir, 'guided.sqlite'), () => NOW);
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: undefined },
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
        .toMatchObject({ status: 'REFUSED', code: 'GUIDED_ANSWER_PROVENANCE_REFUSED' });
      expect(service.decide({ ...relay, grant: 'forged' }))
        .toMatchObject({ status: 'REFUSED', code: 'RELAY_SCHEMA_REFUSED' });
      expect(service.decide(relay))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.decide(relay)).toMatchObject({ status: 'STALE' });
      expect(service.state().currentStep).toBeUndefined();
    } finally {
      service.close();
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
        observation, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: undefined },
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
      const common = {
        kind: 'USER_DECISION_RELAY', authorityClaimed: false,
        relayedVia: '/api', stepId: step.stepId,
        stepDigest: step.templateRef.digest, caseRef: step.caseRef, outcome,
      };
      expect(service.decide({ ...common, decision: 'ANSWER', humanApproval: false }))
        .toMatchObject({ status: 'STALE', code: 'GUIDED_STEP_IDENTITY_MISMATCH' });
      expect(service.decide({ ...common, decision: 'APPROVE', humanApproval: true }))
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
        observation, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: undefined },
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
          event: 'USER_SUBMIT', source: 'USER', sourceRef: 'ui:u03-expired',
          answers: [{ fieldId: 'selectedRoot', value: 'C:\\Work' }],
          evidenceRefs: [], occurredAtUnixMs: NOW,
        },
      };
      now = step.validUntilUnixMs + 1;
      expect(service.decide(relay)).toMatchObject({ status: 'REFUSED' });
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

});
