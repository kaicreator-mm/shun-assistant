import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import {
  FolderSelectionHost,
  type FolderSelectionStoragePort,
} from '../../../../apps/control-api/src/v03/folder-selection-host.ts';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import type { GuidedProvenanceAuthority } from '../../../../packages/domain-host/src/guided/guided-provenance-authority.ts';

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

// ---------- G4-G6: durable Host-private consumed-step ledger helpers ----------

type LedgerRowView = {
  step_id: string; task_id: string; case_ref_json: string; template_digest: string;
  step_kind: string; receipt_kind: string;
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
    `${row.step_kind}|${row.receipt_kind}|${row.terminal_event}|${row.terminal_decision}|` +
    `${row.recorded_at_unix_ms}`,
  );
}

function readLedger(file: string): LedgerRowView[] {
  const db = new DatabaseSync(file);
  try {
    return db.prepare(`SELECT step_id,task_id,case_ref_json,template_digest,
      step_kind,receipt_kind,terminal_event,terminal_decision,recorded_at_unix_ms,row_sha256
      FROM guided_consumed_steps ORDER BY step_id`).all() as unknown as LedgerRowView[];
  } finally {
    db.close();
  }
}

function dropTable(file: string, table: string): void {
  const db = new DatabaseSync(file);
  try {
    db.exec(`DROP TABLE IF EXISTS ${table}`);
  } finally {
    db.close();
  }
}

function guidedTableNames(file: string): string[] {
  const db = new DatabaseSync(file);
  try {
    const rows = db.prepare(
      `SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'guided\\_%' ESCAPE '\\'`,
    ).all() as unknown as { readonly name: string }[];
    return rows.map((row) => row.name).sort();
  } finally {
    db.close();
  }
}

type ReceiptRowView = {
  schema_version: number;
  schema_digest: string;
  database_id: string;
  issued_at_unix_ms: number;
  receipt_digest: string;
};

function readReceipt(file: string): ReceiptRowView | undefined {
  const db = new DatabaseSync(file);
  try {
    return db.prepare(`SELECT schema_version, schema_digest, database_id,
      issued_at_unix_ms, receipt_digest
      FROM guided_schema_receipt WHERE slot='schema'`).get() as ReceiptRowView | undefined;
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

// ---------- U05-A: Host startup recovery for the select-root crash window ----------

// Mock native picker identity; the native addon itself is exercised by the
// Rust unit tests and the interactive desktop smoke, not by this file.
const folderIdentity = {
  userSid: 'S-1-5-21-9-8-7-1001',
  logonSid: 'S-1-5-5-0-4321',
  sessionId: 1,
  volumeSerial: '9a8b7c6d',
  fileId: '0fedcba987654321',
};

function folderPickerNative(root: string) {
  return {
    pickFolder: async () => ({
      status: 'SELECTED' as const,
      path: root,
      displayName: 'Documents',
      identity: folderIdentity,
    }),
    currentIdentity: () => ({
      userSid: folderIdentity.userSid,
      logonSid: folderIdentity.logonSid,
      sessionId: folderIdentity.sessionId,
    }),
    inspectFolder: () => ({
      ...folderIdentity,
      isDirectory: true,
      isReparsePoint: false,
      isNetworkPath: false,
      isVolumeRoot: false,
    }),
    acquireDirectoryLease: () => ({
      leaseId: 'f'.repeat(32),
      directory: {
        ...folderIdentity,
        isDirectory: true,
        isReparsePoint: false,
        isNetworkPath: false,
        isVolumeRoot: false,
      },
    }),
    verifyDirectoryLease: () => ({
      ...folderIdentity,
      isDirectory: true,
      isReparsePoint: false,
      isNetworkPath: false,
      isVolumeRoot: false,
    }),
    releaseDirectoryLease: () => {},
    directoryLeasePath: () => root,
  };
}

function folderFakeStorage(): FolderSelectionStoragePort {
  return {
    resolveScope: async (_volume, declared) => ({ roots: [...declared.roots] }),
    observeStorage: async (scope) => ({
      observedAt: '2026-11-06T12:00:00.000Z',
      roots: [...scope.roots],
      directories: [],
      rootFiles: [],
      totalBytes: 0,
    }),
  };
}

function openFolderSelectionHost(
  guided: HostGuidedService,
  selectionFile: string,
  root: string,
  now: () => number,
): FolderSelectionHost {
  return new FolderSelectionHost({
    guided,
    databaseFile: selectionFile,
    native: folderPickerNative(root),
    clock: now,
    storage: folderFakeStorage(),
  });
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

  it('advances only the durable accepted opaque select-root answer to INSPECT', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-r04-folder-stage-'));
    const file = join(dir, 'guided.sqlite');
    let service = new HostGuidedService(file, () => NOW);
    try {
      const staged = service.stageTrustedSelection({ observation, semanticSelection: semantic, scope });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      expect(staged.step.templateRef.artifactId).toBe('shun.guided.select-root');
      const selectionRef = 'host:folder:' + 'b'.repeat(64);
      const outcome = submitOutcome(
        staged.step, 'ui:shun-r04-desktop', NOW,
        [{ fieldId: 'selectedRoot', value: selectionRef }],
      );
      expect(service.decide(relayFor(staged.step, 'ANSWER', outcome)))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.stageTrustedSelectedRoot({
        selectionRef: 'host:folder:' + 'c'.repeat(64), expiresAtUnixMs: NOW + 60_000,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_FOLDER_ANSWER_NOT_RECORDED' });
      expect(service.stageTrustedSelectedRoot({
        selectionRef, expiresAtUnixMs: NOW,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_FOLDER_SELECTION_INVALID' });
      expect(service.stageTrustedSelectedRoot({
        selectionRef, expiresAtUnixMs: NOW + 60_000,
      })).toMatchObject({
        status: 'CURRENT',
        step: { kind: 'INSPECT', templateRef: { artifactId: 'shun.guided.inspect-scope' } },
      });
      const context = service.readTrustedContext();
      expect(context).toMatchObject({
        state: 'CURRENT',
        observation: { selectedRootRef: selectionRef },
      });
      expect(service.stageTrustedSelectedRoot({
        selectionRef, expiresAtUnixMs: NOW + 60_000,
      })).toMatchObject({ status: 'CURRENT', step: { kind: 'INSPECT' } });
      const receipt = service.recordHostObservationReceipt();
      expect(receipt).toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      expect(service.state().history).toMatchObject([
        { stepId: staged.step.stepId, status: 'ACCEPTED' },
        { status: 'OBSERVATION_RECEIPT' },
      ]);
      expect(service.state().currentStep).toBeUndefined();
      service.close();
      service = new HostGuidedService(file, () => NOW);
      expect(service.state().history).toHaveLength(2);
      expect(service.readTrustedContext()?.state).toBe('CONSUMED');
    } finally {
      service.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('U05-A: startup recovery restages the consumed select-root answer across a restart', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-u05-recovery-'));
    const guidedFile = join(dir, 'guided.sqlite');
    const selectionFile = join(dir, 'folder-selection.sqlite');
    const root = join(dir, 'selected-root');
    mkdirSync(join(root, 'Documents'), { recursive: true });
    writeFileSync(join(root, 'root.txt'), 'x');
    let now = NOW;
    let guided = new HostGuidedService(guidedFile, () => now);
    let host = openFolderSelectionHost(guided, selectionFile, root, () => now);
    try {
      const staged = guided.stageTrustedSelection({ observation, semanticSelection: semantic, scope });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const selected = await host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      if (selected.status !== 'SELECTED') return;
      // The crash window: the USER_SUBMIT answer is durably recorded while
      // the next INSPECT step was never staged.
      const outcome = submitOutcome(
        staged.step,
        'ui:shun-u05-desktop',
        now,
        [{ fieldId: 'selectedRoot', value: selected.selectionRef }],
      );
      expect(guided.decide(relayFor(staged.step, 'ANSWER', outcome)))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      guided.close();
      host.close();

      // Restart on the same durable files, inside the selection TTL.
      now = NOW + 1_000;
      guided = new HostGuidedService(guidedFile, () => now);
      host = openFolderSelectionHost(guided, selectionFile, root, () => now);
      expect(guided.readTrustedContext()).toMatchObject({ state: 'CONSUMED' });
      const recovery = host.recoverInterruptedSelection();
      expect(recovery.status).toBe('RECOVERED');
      if (recovery.status !== 'RECOVERED') return;
      expect(recovery.selectionRef).toBe(selected.selectionRef);
      expect(guided.state().currentStep?.stepId).toBe(recovery.stagedStepId);
      expect(guided.state().currentStep).toMatchObject({
        kind: 'INSPECT',
        templateRef: { artifactId: 'shun.guided.inspect-scope' },
      });
      expect(guided.readTrustedContext()).toMatchObject({
        state: 'CURRENT',
        observation: { selectedRootRef: selected.selectionRef },
      });
      // The recovered INSPECT step immediately supports the trusted
      // observation receipt flow.
      const observed = await host.observeCurrentSelectedFolder();
      expect(observed).toMatchObject({ ok: true });
      expect(guided.state().history).toMatchObject([
        { stepId: staged.step.stepId, status: 'ACCEPTED' },
        { status: 'OBSERVATION_RECEIPT' },
      ]);
    } finally {
      try { host.close(); } catch { /* already closed */ }
      try { guided.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('U05-A: startup recovery keeps an expired crash-window selection refused across restart', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-u05-recovery-expired-'));
    const guidedFile = join(dir, 'guided.sqlite');
    const selectionFile = join(dir, 'folder-selection.sqlite');
    const root = join(dir, 'selected-root');
    mkdirSync(root, { recursive: true });
    let now = NOW;
    let guided = new HostGuidedService(guidedFile, () => now);
    let host = openFolderSelectionHost(guided, selectionFile, root, () => now);
    try {
      const staged = guided.stageTrustedSelection({ observation, semanticSelection: semantic, scope });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const selected = await host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      if (selected.status !== 'SELECTED') return;
      const outcome = submitOutcome(
        staged.step,
        'ui:shun-u05-desktop',
        now,
        [{ fieldId: 'selectedRoot', value: selected.selectionRef }],
      );
      expect(guided.decide(relayFor(staged.step, 'ANSWER', outcome)))
        .toMatchObject({ status: 'RECORDED' });
      guided.close();
      host.close();

      // Restart far beyond the 5-minute selection TTL.
      now = NOW + 400_000;
      guided = new HostGuidedService(guidedFile, () => now);
      host = openFolderSelectionHost(guided, selectionFile, root, () => now);
      expect(host.recoverInterruptedSelection()).toEqual({
        status: 'STALE',
        code: 'FOLDER_SELECTION_EXPIRED',
      });
      // Nothing was staged, nothing deleted, and no automatic re-selection
      // is offered: a new selection is required.
      expect(guided.readTrustedContext()).toMatchObject({ state: 'CONSUMED' });
      expect(guided.state().currentStep).toBeUndefined();
      expect(guided.readRecordedAnswer(staged.step.stepId)).toBeDefined();
      expect(await host.selectRoot()).toEqual({
        status: 'STALE',
        code: 'GUIDED_SELECT_ROOT_NOT_CURRENT',
      });
    } finally {
      try { host.close(); } catch { /* already closed */ }
      try { guided.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('U05-A: startup recovery refuses a selection row whose binding was tampered', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-u05-recovery-tamper-'));
    const guidedFile = join(dir, 'guided.sqlite');
    const selectionFile = join(dir, 'folder-selection.sqlite');
    const root = join(dir, 'selected-root');
    mkdirSync(root, { recursive: true });
    let now = NOW;
    let guided = new HostGuidedService(guidedFile, () => now);
    let host = openFolderSelectionHost(guided, selectionFile, root, () => now);
    try {
      const staged = guided.stageTrustedSelection({ observation, semanticSelection: semantic, scope });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const selected = await host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      if (selected.status !== 'SELECTED') return;
      const outcome = submitOutcome(
        staged.step,
        'ui:shun-u05-desktop',
        now,
        [{ fieldId: 'selectedRoot', value: selected.selectionRef }],
      );
      expect(guided.decide(relayFor(staged.step, 'ANSWER', outcome)))
        .toMatchObject({ status: 'RECORDED' });
      guided.close();
      host.close();
      // Tamper the private ledger row before the restart: the durable
      // answer no longer matches the row's task binding.
      const ledger = new DatabaseSync(selectionFile);
      try {
        ledger.exec("UPDATE folder_selection_records SET task_id='task-tampered'");
      } finally {
        ledger.close();
      }
      now = NOW + 1_000;
      guided = new HostGuidedService(guidedFile, () => now);
      host = openFolderSelectionHost(guided, selectionFile, root, () => now);
      expect(host.recoverInterruptedSelection()).toEqual({
        status: 'STALE',
        code: 'FOLDER_SELECTION_STEP_BINDING_MISMATCH',
      });
      expect(guided.state().currentStep).toBeUndefined();
      expect(guided.readTrustedContext()).toMatchObject({ state: 'CONSUMED' });
    } finally {
      try { host.close(); } catch { /* already closed */ }
      try { guided.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('U05-A: startup recovery refuses a root directory identity that was replaced', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-u05-recovery-replaced-'));
    const guidedFile = join(dir, 'guided.sqlite');
    const selectionFile = join(dir, 'folder-selection.sqlite');
    const root = join(dir, 'selected-root');
    mkdirSync(root, { recursive: true });
    let now = NOW;
    let guided = new HostGuidedService(guidedFile, () => now);
    let host = openFolderSelectionHost(guided, selectionFile, root, () => now);
    try {
      const staged = guided.stageTrustedSelection({ observation, semanticSelection: semantic, scope });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      const selected = await host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      if (selected.status !== 'SELECTED') return;
      const outcome = submitOutcome(
        staged.step,
        'ui:shun-u05-desktop',
        now,
        [{ fieldId: 'selectedRoot', value: selected.selectionRef }],
      );
      expect(guided.decide(relayFor(staged.step, 'ANSWER', outcome)))
        .toMatchObject({ status: 'RECORDED' });
      guided.close();
      host.close();

      // The native root identity no longer matches the recorded row on the
      // restarted host (root replaced/moved between crash and restart).
      now = NOW + 1_000;
      guided = new HostGuidedService(guidedFile, () => now);
      const replacedNative = {
        ...folderPickerNative(root),
        inspectFolder: () => ({
          ...folderIdentity,
          fileId: 'deadbeefdeadbeef',
          isDirectory: true,
          isReparsePoint: false,
          isNetworkPath: false,
          isVolumeRoot: false,
        }),
      };
      host = new FolderSelectionHost({
        guided,
        databaseFile: selectionFile,
        native: replacedNative,
        clock: () => now,
        storage: folderFakeStorage(),
      });
      expect(host.recoverInterruptedSelection()).toEqual({
        status: 'STALE',
        code: 'FOLDER_SELECTION_IDENTITY_DRIFT',
      });
      expect(guided.state().currentStep).toBeUndefined();
    } finally {
      try { host.close(); } catch { /* already closed */ }
      try { guided.close(); } catch { /* already closed */ }
      cleanup(dir);
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
      expect(service.decide(relayFor(step, 'REFUSE', hostReceipt)))
        .toMatchObject({ status: 'REFUSED', code: 'GUIDED_DECISION_MATRIX_REFUSED' });
      const receipt = service.recordHostObservationReceipt();
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
      // A forged HTTP REFUSE relay can no longer record an INSPECT receipt
      // (U05-A trusted-relay hardening); it must be refused, and only the
      // trusted in-process Host capability records the receipt.
      expect(service.decide(relayFor(stepB, 'REFUSE', hostReceipt)))
        .toMatchObject({ status: 'REFUSED', code: 'GUIDED_DECISION_MATRIX_REFUSED' });
      const receipt = service.recordHostObservationReceipt();
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

  it('G5: a pre-seeded ledger row for a still-current step fails closed without persisting an answer', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g5-ledger-conflict-'));
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
    // as CURRENT (e.g. a partially-rolled-back legacy write). Seeded as a
    // REVIEW_EFFECT REFUSE/NONE row: it needs no payload binding, so
    // open-time validation of the receipt-bearing database passes and the
    // decision-time fence is what fires.
    const seeded: LedgerRowView = {
      step_id: step.stepId, task_id: step.taskId,
      case_ref_json: JSON.stringify(step.caseRef), template_digest: step.templateRef.digest,
      step_kind: 'REVIEW_EFFECT', receipt_kind: 'NONE',
      terminal_event: 'USER_SUBMIT', terminal_decision: 'REFUSE', recorded_at_unix_ms: NOW,
      row_sha256: '',
    };
    seeded.row_sha256 = ledgerRowSha(seeded);
    const db = new DatabaseSync(file);
    try {
      db.prepare(`INSERT INTO guided_consumed_steps(
        step_id,task_id,case_ref_json,template_digest,step_kind,receipt_kind,
        terminal_event,terminal_decision,recorded_at_unix_ms,row_sha256
      ) VALUES(?,?,?,?,?,?,?,?,?,?)`).run(
        seeded.step_id, seeded.task_id, seeded.case_ref_json, seeded.template_digest,
        seeded.step_kind, seeded.receipt_kind,
        seeded.terminal_event, seeded.terminal_decision, seeded.recorded_at_unix_ms, seeded.row_sha256,
      );
    } finally {
      db.close();
    }
    service = new HostGuidedService(file, () => NOW);
    try {
      expect(service.decide(relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:g5-conflict', NOW,
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

  it('G5: a non-empty pre-G5 database without a provenance marker fails closed and preserves data', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g5-legacy-g3-'));
    const file = join(dir, 'guided.sqlite');
    let now = NOW;
    let service = new HostGuidedService(file, () => now);
    let stepA: GuidedStep;
    let stepB: GuidedStep;
    try {
      // A real G3-era shape: Case A (ASK) answered, then a genuinely
      // different Case B answered — the single selected-case row no longer
      // holds Case A's terminal history.
      const stagedA = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(stagedA.status).toBe('CURRENT');
      if (stagedA.status !== 'CURRENT') return;
      stepA = stagedA.step;
      expect(service.decide(relayFor(stepA, 'ANSWER',
        submitOutcome(stepA, 'ui:g5-m-a', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      now = 10_000;
      const stagedB = service.stageTrustedSelection({
        observation: {
          ...freshObservation('g5-m1', 10_000, 90_000),
          caseRef: { snapshotId: 'snap-g5-m', digest: 'f'.repeat(64) },
        },
        semanticSelection: semantic, scope,
      });
      expect(stagedB.status).toBe('CURRENT');
      if (stagedB.status !== 'CURRENT') return;
      stepB = stagedB.step;
      expect(service.decide(relayFor(stepB, 'ANSWER',
        submitOutcome(stepB, 'ui:g5-m-b', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      service.close();

      // Simulate the pre-G5 legacy schema: neither the consumed-step ledger
      // nor a provenance marker existed under G3. Case A's terminal history
      // was discarded when Case B was selected and cannot be reconstructed.
      dropTable(file, 'guided_consumed_steps');
      dropTable(file, 'guided_schema_receipt');
      // Reopen under G5: the complete replay fence is unknowable, so every
      // mutation path fails closed with the stable migration code.
      service = new HostGuidedService(file, () => now);
      expect(service.stageTrustedSelection({
        observation: freshObservation('g5-m2', 20_000, 120_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.decide(relayFor(stepA, 'ANSWER',
        submitOutcome(stepA, 'ui:g5-m-replay', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      // No silent reset: every original row is preserved untouched.
      expect(tableCount(file, 'guided_step_answers')).toBe(2);
      expect(tableCount(file, 'guided_selected_case')).toBe(1);
      service.close();
    } finally {
      try { service.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('G5: conflicting answer+refusal evidence for the consumed step fails closed without deleting data', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g5-migration-conflict-'));
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
        submitOutcome(step, 'ui:g5-conflict-a', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]));
      expect(service.decide(relay)).toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Tampered state: an answer row AND a refusal row now claim the same
    // consumed step — the terminal decision is unprovable. The provenance
    // marker stays in place, so it is the G5 complete-dataset validation
    // (cross-table conflict, then payload/ledger bindings) that fails closed.
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

  it('G5: corrupt payload digest on a marked database fails closed and preserves data', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g5-migration-corrupt-'));
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
        submitOutcome(step, 'ui:g5-corrupt', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Corrupt the persisted answer digest: the evidence can no longer be
    // trusted, so G5 open-time validation of the marked database fails
    // closed instead of enabling mutations on corrupt data.
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
        observation: freshObservation('g5-x1', 2_000, 60_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.decide(relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:g5-corrupt-replay', NOW,
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

  it('G5: a non-empty G4-era database with a ledger but no provenance marker fails closed', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g5-ledger-no-marker-'));
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
        submitOutcome(step, 'ui:g5-g4era', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Simulate a G4-initialized database: G4 created the ledger but wrote no
    // provenance marker, so prior-Case terminal history discarded before G4
    // ran cannot be proven recoverable. G5 must fail closed, not extend a
    // possibly-partial fence.
    dropTable(file, 'guided_schema_receipt');
    service = new HostGuidedService(file, () => NOW);
    try {
      expect(service.stageTrustedSelection({
        observation: freshObservation('g5-g4e1', 2_000, 60_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.decide(relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:g5-g4e-replay', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
    } finally {
      service.close();
    }
    // Every existing row is preserved untouched.
    expect(tableCount(file, 'guided_consumed_steps')).toBe(1);
    expect(tableCount(file, 'guided_step_answers')).toBe(1);
    expect(tableCount(file, 'guided_selected_case')).toBe(1);
    cleanup(dir);
  });

  it('G5: a provably fresh database initializes transactionally and reopens idempotently', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g6-fresh-init-'));
    const file = join(dir, 'guided.sqlite');
    let service = new HostGuidedService(file, () => NOW);
    let consumed: GuidedStep;
    try {
      // The authority receipt is committed with the exact schema in one
      // transaction and binds the schema version, canonical schema digest
      // and an authority-issued database identifier.
      const receipt = readReceipt(file);
      expect(receipt).toBeDefined();
      if (!receipt) return;
      expect(receipt.schema_version).toBe(6);
      expect(receipt.schema_digest).toMatch(/^[a-f0-9]{64}$/);
      expect(receipt.database_id).toMatch(/^guidedb-/);
      expect(receipt.receipt_digest).toMatch(/^[a-f0-9]{64}$/);
      expect(guidedTableNames(file)).toEqual([
        'guided_consumed_steps',
        'guided_schema_receipt',
        'guided_selected_case',
        'guided_step_answers',
        'guided_step_refusals',
      ]);
      // The fresh database operates normally.
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      consumed = staged.step;
      expect(service.decide(relayFor(staged.step, 'ANSWER',
        submitOutcome(staged.step, 'ui:g6-fresh', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      service.close();

      // Reopen: the receipt-bearing database validates the exact schema,
      // the receipt against the authority, every ledger and payload
      // envelope, digest and binding, then keeps operating — and the
      // validation writes nothing (idempotent: receipt byte-identical).
      service = new HostGuidedService(file, () => NOW);
      expect(readReceipt(file)).toEqual(receipt);
      expect(service.state().currentStep).toBeUndefined();
      expect(service.readRecordedAnswer(consumed.stepId)).toBeDefined();
      const progressed = service.stageTrustedSelection({
        observation: freshObservation('g6-f2', 2_000, 60_000),
        semanticSelection: semantic, scope,
      });
      expect(progressed.status).toBe('CURRENT');
      if (progressed.status === 'CURRENT') {
        expect(service.decide(relayFor(progressed.step, 'REFUSE',
          submitOutcome(progressed.step, 'ui:g6-fresh-2', NOW,
            [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
          .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      }
      service.close();
      expect(readReceipt(file)).toEqual(receipt);
      expect(tableCount(file, 'guided_consumed_steps')).toBe(2);
    } finally {
      try { service.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('G5: a partial initialization without a committed marker stays fail-closed after restart', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g5-partial-init-'));
    const file = join(dir, 'guided.sqlite');
    // Simulate a crashed initialization: one guided table exists, with no
    // marker and no sibling tables. It cannot be proven fresh, so G5 must
    // not initialize over it and must not enable mutations.
    const db = new DatabaseSync(file);
    try {
      db.exec(`CREATE TABLE guided_selected_case (
        slot TEXT PRIMARY KEY,
        state_json TEXT NOT NULL,
        revision INTEGER NOT NULL
      )`);
    } finally {
      db.close();
    }
    expect(guidedTableNames(file)).toEqual(['guided_selected_case']);
    const service = new HostGuidedService(file, () => NOW);
    try {
      expect(service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.decide({ kind: 'USER_DECISION_RELAY' }))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
    } finally {
      service.close();
    }
    // No table was created, no row was written, no marker appeared.
    expect(guidedTableNames(file)).toEqual(['guided_selected_case']);
    expect(tableCount(file, 'guided_selected_case')).toBe(0);
    cleanup(dir);
  });

  it('G5: a non-current step present in both payload tables fails closed even when another step is selected', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g5-noncurrent-conflict-'));
    const file = join(dir, 'guided.sqlite');
    let now = NOW;
    let service = new HostGuidedService(file, () => now);
    let historical: GuidedStep;
    try {
      // step1 answered, then the same Case progresses to step2 which is
      // refused: the selected row now belongs to step2, so step1 is a
      // non-current historical step.
      const first = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(first.status).toBe('CURRENT');
      if (first.status !== 'CURRENT') return;
      historical = first.step;
      expect(service.decide(relayFor(first.step, 'ANSWER',
        submitOutcome(first.step, 'ui:g5-nc-a', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      now = 10_000;
      const second = service.stageTrustedSelection({
        observation: freshObservation('g5-nc1', 10_000, 90_000),
        semanticSelection: semantic, scope,
      });
      expect(second.status).toBe('CURRENT');
      if (second.status !== 'CURRENT') return;
      now = 11_000;
      expect(service.decide(relayFor(second.step, 'REFUSE',
        submitOutcome(second.step, 'ui:g5-nc-r', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      service.close();

      // Tamper: a refusal row now also claims the historical step1. The
      // currently selected step is step2 — the conflict must still fail
      // closed; it is never resolved silently by first-write-wins.
      const refusal = {
        schema: 'shun.guided.refusal-receipt.v1',
        stepId: historical.stepId, taskId: historical.taskId,
        caseRef: historical.caseRef, templateDigest: historical.templateRef.digest,
        decision: 'REFUSE',
        outcome: submitOutcome(historical, 'ui:g5-nc-tamper', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]),
      };
      const refusalJson = JSON.stringify(refusal);
      const db = new DatabaseSync(file);
      try {
        db.prepare(`INSERT INTO guided_step_refusals(
          step_id,task_id,case_ref_json,template_digest,refusal_json,refusal_sha256,recorded_at_unix_ms
        ) VALUES(?,?,?,?,?,?,?)`).run(
          historical.stepId, historical.taskId, JSON.stringify(historical.caseRef),
          historical.templateRef.digest, refusalJson, sha256Hex(refusalJson), now,
        );
      } finally {
        db.close();
      }
      service = new HostGuidedService(file, () => now);
      expect(service.stageTrustedSelection({
        observation: freshObservation('g5-nc2', 20_000, 120_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.decide(relayFor(second.step, 'REFUSE',
        submitOutcome(second.step, 'ui:g5-nc-replay', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      service.close();
    } finally {
      try { service.close(); } catch { /* already closed */ }
    }
    // All rows, including the conflicting ones, are preserved.
    expect(tableCount(file, 'guided_step_answers')).toBe(1);
    expect(tableCount(file, 'guided_step_refusals')).toBe(2);
    expect(tableCount(file, 'guided_consumed_steps')).toBe(2);
    expect(tableCount(file, 'guided_selected_case')).toBe(1);
    cleanup(dir);
  });

  // Rewrites one ledger field and re-binds the row digest, so open-time
  // validation sees a well-formed row whose binding disagrees with the
  // payload evidence.
  function tamperLedgerField(
    file: string,
    step: GuidedStep,
    field: keyof Omit<LedgerRowView, 'row_sha256'>,
    value: string | number,
  ): void {
    const db = new DatabaseSync(file);
    try {
      const row = db.prepare(`SELECT step_id,task_id,case_ref_json,template_digest,
        terminal_event,terminal_decision,recorded_at_unix_ms,row_sha256
        FROM guided_consumed_steps WHERE step_id=?`).get(step.stepId) as LedgerRowView;
      const changed: LedgerRowView = { ...row, [field]: value };
      db.prepare(`UPDATE guided_consumed_steps SET ${field}=?, row_sha256=? WHERE step_id=?`)
        .run(value, ledgerRowSha(changed), step.stepId);
    } finally {
      db.close();
    }
  }

  it('G5: existing ledger rows that disagree with payload bindings fail closed without modifying data', () => {
    const tamperCases: readonly {
      readonly field: keyof Omit<LedgerRowView, 'row_sha256'>;
      readonly value: string | number;
    }[] = [
      { field: 'task_id', value: 'tampered-task' },
      { field: 'case_ref_json', value: JSON.stringify({ snapshotId: 'snap-tampered', digest: '9'.repeat(64) }) },
      { field: 'template_digest', value: 'e'.repeat(64) },
      { field: 'step_kind', value: 'REVIEW_EFFECT' },
      { field: 'receipt_kind', value: 'NONE' },
      { field: 'terminal_event', value: 'OBSERVATION_RECEIPT' },
      { field: 'terminal_decision', value: 'REFUSE' },
      { field: 'recorded_at_unix_ms', value: NOW + 1 },
    ];
    for (const tamper of tamperCases) {
      const dir = mkdtempSync(join(tmpdir(), 'shun-g5-binding-'));
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
          submitOutcome(step, 'ui:g5-bind', NOW,
            [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
          .toMatchObject({ status: 'RECORDED' });
      } finally {
        service.close();
      }
      // The row digest is valid over the tampered content, so only the
      // binding cross-check can catch it — it must, and must fail closed.
      tamperLedgerField(file, step, tamper.field, tamper.value);
      service = new HostGuidedService(file, () => NOW);
      try {
        expect(service.stageTrustedSelection({
          observation: freshObservation('g5-b1', 2_000, 60_000),
          semanticSelection: semantic, scope,
        })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
        expect(service.decide(relayFor(step, 'ANSWER',
          submitOutcome(step, 'ui:g5-bind-replay', NOW,
            [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
          .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      } finally {
        service.close();
      }
      // The tampered ledger row and the original payload row are preserved.
      expect(tableCount(file, 'guided_consumed_steps')).toBe(1);
      expect(tableCount(file, 'guided_step_answers')).toBe(1);
      cleanup(dir);
    }
  });

  // ---------- G6: trusted provenance authority ----------

  // Explicitly test-only authority: the secret lives in this test file,
  // never in the database, and its registry is an external in-memory trust
  // record keyed by canonical database path.
  function createTestGuidedProvenanceAuthority(secret: string): GuidedProvenanceAuthority {
    const registry = new Map<string, { readonly databaseId: string; readonly schemaDigest: string }>();
    const digest = (receipt: { readonly databaseId: string; readonly schemaVersion: number;
      readonly schemaDigest: string; readonly issuedAtUnixMs: number }): string =>
      sha256Hex(`${secret}|${receipt.databaseId}|${receipt.schemaVersion}|${receipt.schemaDigest}|${receipt.issuedAtUnixMs}`);
    return {
      issueFreshReceipt({ canonicalDatabasePath, schemaDigest, issuedAtUnixMs }) {
        const databaseId = `guidedb-${sha256Hex(`${secret}|${canonicalDatabasePath}`).slice(0, 24)}`;
        registry.set(canonicalDatabasePath, { databaseId, schemaDigest });
        const receipt = { schemaVersion: 6, schemaDigest, databaseId, issuedAtUnixMs };
        return { ...receipt, receiptDigest: digest(receipt) };
      },
      verifyReceipt(receipt: unknown, canonicalDatabasePath: string) {
        if (typeof receipt !== 'object' || receipt === null) return false;
        const record = receipt as Record<string, unknown>;
        const expected = registry.get(canonicalDatabasePath);
        if (!expected || record.databaseId !== expected.databaseId ||
            record.schemaDigest !== expected.schemaDigest || record.schemaVersion !== 6 ||
            typeof record.issuedAtUnixMs !== 'number' || typeof record.receiptDigest !== 'string') {
          return false;
        }
        return digest({
          databaseId: String(record.databaseId),
          schemaVersion: 6,
          schemaDigest: String(record.schemaDigest),
          issuedAtUnixMs: record.issuedAtUnixMs,
        }) === record.receiptDigest;
      },
    };
  }

  it('G6: a forged G5-style self-asserted marker on a legacy database fails closed', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g6-forged-marker-'));
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
        submitOutcome(step, 'ui:g6-forge', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Reduce the database to a G4-era shape, then attach a G5-style marker
    // minted with the exact PUBLIC G5 formula — the attack G6 must refuse.
    dropTable(file, 'guided_schema_receipt');
    dropTable(file, 'guided_consumed_steps');
    const db = new DatabaseSync(file);
    try {
      db.exec(`CREATE TABLE guided_schema_marker (
        slot TEXT PRIMARY KEY CHECK (slot='schema'),
        schema_version INTEGER NOT NULL,
        initialized_at_unix_ms INTEGER NOT NULL,
        marker_sha256 TEXT NOT NULL
      )`);
      db.prepare(`INSERT INTO guided_schema_marker(
        slot,schema_version,initialized_at_unix_ms,marker_sha256
      ) VALUES(?,?,?,?)`).run(
        'schema', 5, NOW, sha256Hex(`guided-schema-marker|v5|${NOW}`),
      );
    } finally {
      db.close();
    }
    service = new HostGuidedService(file, () => NOW);
    try {
      expect(service.stageTrustedSelection({
        observation: freshObservation('g6-fg1', 2_000, 60_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.decide(relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:g6-forge-replay', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
    } finally {
      service.close();
    }
    // Every original row — and the forged marker itself — is preserved.
    expect(tableCount(file, 'guided_step_answers')).toBe(1);
    expect(tableCount(file, 'guided_selected_case')).toBe(1);
    expect(tableCount(file, 'guided_schema_marker')).toBe(1);
    cleanup(dir);
  });

  it('G6: a receipt copied to a different database identity fails verification', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g6-copied-receipt-'));
    const file1 = join(dir, 'guided-one.sqlite');
    const file2 = join(dir, 'guided-two.sqlite');
    const auth = createTestGuidedProvenanceAuthority('test-secret-copied-receipt');
    const file1Unix = file1.replace(/\\/g, '/');
    const file2Unix = file2.replace(/\\/g, '/');
    let service = new HostGuidedService(file1, () => NOW, auth);
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      expect(service.decide(relayFor(staged.step, 'ANSWER',
        submitOutcome(staged.step, 'ui:g6-copy', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Clone the whole database — receipt included — to a different path.
    const clone = new DatabaseSync(file1);
    try {
      clone.exec(`VACUUM INTO '${file2Unix}'`);
    } finally {
      clone.close();
    }
    // The original opens fine at its own identity.
    service = new HostGuidedService(file1, () => NOW, auth);
    expect(service.state().currentStep).toBeUndefined();
    service.close();
    // The copy cannot be verified: the authority's external record binds
    // the receipt's databaseId to the original path only.
    const copied = new HostGuidedService(file2, () => NOW, auth);
    try {
      expect(copied.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(copied.decide({ kind: 'USER_DECISION_RELAY' }))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
    } finally {
      copied.close();
    }
    // The copied database file is untouched.
    expect(tableCount(file2, 'guided_step_answers')).toBe(1);
    cleanup(dir);
  });

  it('G6: reopen depends on the authority external record, not on receipt bytes in the database', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g6-external-record-'));
    const file = join(dir, 'guided.sqlite');
    const auth = createTestGuidedProvenanceAuthority('test-secret-external-record');
    let service = new HostGuidedService(file, () => NOW, auth);
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      expect(service.decide(relayFor(staged.step, 'ANSWER',
        submitOutcome(staged.step, 'ui:g6-ext', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Same authority instance: its protected record knows this path.
    service = new HostGuidedService(file, () => NOW, auth);
    expect(service.state().currentStep).toBeUndefined();
    service.close();
    // A brand-new authority with an empty external record must refuse the
    // identical bytes — trust never comes from the database contents.
    const stranger = createTestGuidedProvenanceAuthority('test-secret-external-record');
    const reopened = new HostGuidedService(file, () => NOW, stranger);
    try {
      expect(reopened.stageTrustedSelection({
        observation: freshObservation('g6-ext1', 2_000, 60_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(reopened.decide({ kind: 'USER_DECISION_RELAY' }))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
    } finally {
      reopened.close();
    }
    expect(tableCount(file, 'guided_step_answers')).toBe(1);
    cleanup(dir);
  });

  it('G6: schema drift with a retained receipt fails closed without modifying data', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g6-schema-drift-'));
    const file = join(dir, 'guided.sqlite');
    let service = new HostGuidedService(file, () => NOW);
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      expect(service.decide(relayFor(staged.step, 'ANSWER',
        submitOutcome(staged.step, 'ui:g6-drift', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Plant an extra guided object while the receipt stays in place.
    const db = new DatabaseSync(file);
    try {
      db.exec('CREATE INDEX guided_tamper_idx ON guided_step_answers(step_id)');
    } finally {
      db.close();
    }
    service = new HostGuidedService(file, () => NOW);
    try {
      expect(service.stageTrustedSelection({
        observation: freshObservation('g6-drift1', 2_000, 60_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.decide({ kind: 'USER_DECISION_RELAY' }))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
    } finally {
      service.close();
    }
    expect(tableCount(file, 'guided_step_answers')).toBe(1);
    expect(tableCount(file, 'guided_consumed_steps')).toBe(1);
    cleanup(dir);
  });

  it('G6: a recomputed digest over tampered embedded answer content fails open and readback', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g6-answer-tamper-'));
    const file = join(dir, 'guided.sqlite');
    let service = new HostGuidedService(file, () => NOW);
    let step: GuidedStep;
    let answer: Record<string, unknown> | undefined;
    try {
      const staged = service.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      step = staged.step;
      const relay = relayFor(step, 'ANSWER',
        submitOutcome(step, 'ui:g6-tamper-a', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]));
      answer = (relay as { outcome: Record<string, unknown> }).outcome;
      expect(service.decide(relay)).toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Tamper the EMBEDDED step identity and recompute the unkeyed payload
    // digest: digest equality alone must not be enough.
    const tampered = JSON.stringify({ ...answer, stepId: 'guided:tampered:step' });
    const db = new DatabaseSync(file);
    try {
      db.prepare('UPDATE guided_step_answers SET outcome_json=?, outcome_sha256=? WHERE step_id=?')
        .run(tampered, sha256Hex(tampered), step.stepId);
    } finally {
      db.close();
    }
    service = new HostGuidedService(file, () => NOW);
    try {
      expect(service.stageTrustedSelection({
        observation: freshObservation('g6-ta1', 2_000, 60_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      // Host readback rejects the tampered envelope without modifying data.
      expect(service.readRecordedAnswer(step.stepId)).toBeUndefined();
    } finally {
      service.close();
    }
    expect(tableCount(file, 'guided_step_answers')).toBe(1);
    cleanup(dir);
  });

  it('G6: a recomputed digest over tampered embedded refusal content fails open and readback', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g6-refusal-tamper-'));
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
      expect(service.decide(relayFor(step, 'REFUSE',
        submitOutcome(step, 'ui:g6-tamper-r', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Tamper the nested outcome identity inside the typed refusal envelope
    // and recompute the digest.
    const db = new DatabaseSync(file);
    let tampered: string;
    try {
      const row = db.prepare('SELECT refusal_json FROM guided_step_refusals WHERE step_id=?')
        .get(step.stepId) as { refusal_json: string } | undefined;
      if (!row) return;
      const parsed = JSON.parse(row.refusal_json) as { outcome: Record<string, unknown> };
      tampered = JSON.stringify({
        ...parsed,
        outcome: { ...parsed.outcome, stepId: 'guided:tampered:step' },
      });
      db.prepare('UPDATE guided_step_refusals SET refusal_json=?, refusal_sha256=? WHERE step_id=?')
        .run(tampered, sha256Hex(tampered), step.stepId);
    } finally {
      db.close();
    }
    service = new HostGuidedService(file, () => NOW);
    try {
      expect(service.stageTrustedSelection({
        observation: freshObservation('g6-tr1', 2_000, 60_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.readRecordedRefusal(step.stepId)).toBeUndefined();
    } finally {
      service.close();
    }
    expect(tableCount(file, 'guided_step_refusals')).toBe(1);
    cleanup(dir);
  });

  it('G6: a consumed ASK refusal with its payload deleted fails closed while ledger and history remain', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g6-lost-ask-refusal-'));
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
      expect(step.kind).toBe('ASK');
      expect(service.decide(relayFor(step, 'REFUSE',
        submitOutcome(step, 'ui:g6-lost-r', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED' });
    } finally {
      service.close();
    }
    // Destroy the refusal payload; the ledger still says this ASK step was
    // terminally refused, which is now unprovable — fail closed. (A
    // REVIEW_EFFECT REFUSE or INSPECT receipt with no payload stays valid
    // because its ledger kind proves the absence.)
    const db = new DatabaseSync(file);
    try {
      db.prepare('DELETE FROM guided_step_refusals WHERE step_id=?').run(step.stepId);
    } finally {
      db.close();
    }
    service = new HostGuidedService(file, () => NOW);
    try {
      expect(service.stageTrustedSelection({
        observation: freshObservation('g6-lr1', 2_000, 60_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.decide(relayFor(step, 'REFUSE',
        submitOutcome(step, 'ui:g6-lost-replay', NOW,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
    } finally {
      service.close();
    }
    expect(tableCount(file, 'guided_consumed_steps')).toBe(1);
    expect(tableCount(file, 'guided_step_refusals')).toBe(0);
    expect(tableCount(file, 'guided_selected_case')).toBe(1);
    cleanup(dir);
  });

  it('G6: a G3 database that lost Case-A REVIEW_EFFECT terminal history fails closed with all data preserved', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g6-g3-lost-history-'));
    const file = join(dir, 'guided.sqlite');
    let now = NOW;
    let service = new HostGuidedService(file, () => now);
    let reviewStep: GuidedStep;
    let caseBStep: GuidedStep;
    try {
      // Case A consumes a REVIEW_EFFECT approval — the exact history that
      // G3's single selected-Case row destroys on a Case switch.
      const reviewA = {
        ...observation, revision: 'g6-h1',
        selectedRootRef: 'host:root:g6-h', actionPreviewRef: 'host:preview:g6-h',
      };
      const stagedA = service.stageTrustedSelection({
        observation: reviewA, semanticSelection: semantic,
        scope: { status: 'KNOWN', selectedRootRef: 'host:root:g6-h' },
      });
      expect(stagedA.status).toBe('CURRENT');
      if (stagedA.status !== 'CURRENT') return;
      reviewStep = stagedA.step;
      expect(reviewStep.kind).toBe('REVIEW_EFFECT');
      expect(service.decide(relayFor(reviewStep, 'APPROVE',
        submitOutcome(reviewStep, 'ui:g6-h-approve', now,
          [{ fieldId: 'continue', value: 'continue-to-independent-approval' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      // Case B replaces the single selected-Case row; Case A's terminal
      // history is gone. G3 had no ledger and no receipt.
      now = 10_000;
      const stagedB = service.stageTrustedSelection({
        observation: {
          ...freshObservation('g6-hb1', 10_000, 90_000),
          caseRef: { snapshotId: 'snap-g6-hb', digest: '7'.repeat(64) },
        },
        semanticSelection: semantic, scope,
      });
      expect(stagedB.status).toBe('CURRENT');
      if (stagedB.status !== 'CURRENT') return;
      caseBStep = stagedB.step;
      expect(service.decide(relayFor(caseBStep, 'ANSWER',
        submitOutcome(caseBStep, 'ui:g6-hb', now,
          [{ fieldId: 'selectedRoot', value: 'C:\\Work' }]))))
        .toMatchObject({ status: 'RECORDED', humanGrantIssued: false, effectSent: false });
      service.close();

      dropTable(file, 'guided_schema_receipt');
      dropTable(file, 'guided_consumed_steps');
      // G6 open without a verifiable external receipt fails closed.
      service = new HostGuidedService(file, () => now);
      expect(service.stageTrustedSelection({
        observation: freshObservation('g6-h2', 20_000, 120_000),
        semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      expect(service.decide(relayFor(reviewStep, 'APPROVE',
        submitOutcome(reviewStep, 'ui:g6-h-replay', now,
          [{ fieldId: 'continue', value: 'continue-to-independent-approval' }]))))
        .toMatchObject({ status: 'UNKNOWN', code: 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS' });
      // The complete original database is preserved — including Case B's
      // still-readable answer.
      expect(service.readRecordedAnswer(caseBStep.stepId)).toBeDefined();
      expect(tableCount(file, 'guided_step_answers')).toBe(1);
      expect(tableCount(file, 'guided_selected_case')).toBe(1);
      service.close();
    } finally {
      try { service.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

  it('G6: two racing first openers converge on one valid schema', () => {
    const dir = mkdtempSync(join(tmpdir(), 'shun-g6-race-init-'));
    const file = join(dir, 'guided.sqlite');
    const first = new HostGuidedService(file, () => NOW);
    let second: HostGuidedService | null = null;
    try {
      // The second opener serializes on BEGIN IMMEDIATE, re-reads the first
      // opener's committed schema and validates it — it does not attempt a
      // duplicate CREATE and is not left unavailable.
      second = new HostGuidedService(file, () => NOW);
      const staged = first.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      });
      expect(staged.status).toBe('CURRENT');
      if (staged.status !== 'CURRENT') return;
      expect(second.stageTrustedSelection({
        observation, semanticSelection: semantic, scope,
      })).toMatchObject({ status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' });
      expect(second.state().currentStep?.stepId).toBe(staged.step.stepId);
    } finally {
      try { first.close(); } catch { /* already closed */ }
      try { second?.close(); } catch { /* already closed */ }
      cleanup(dir);
    }
  });

});
