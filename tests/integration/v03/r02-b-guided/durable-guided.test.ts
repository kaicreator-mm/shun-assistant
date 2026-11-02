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
});
