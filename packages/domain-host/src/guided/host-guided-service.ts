/**
 * R02-B: persistent Host boundary for the v0.3 bounded Guided Journey.
 * This is business/UI acknowledgement evidence, NOT a second Kernel Journal,
 * consent issuer, ActionController grant or effect dispatcher.
 * Only the trusted Host composition calls stageTrustedSelection.
 */
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  createNextGuidedStep,
  validateGuidedStepOutcome,
} from '../../../domain-computer/src/guided/guided-journey.ts';
import type { StepSpec } from '../../../domain-computer/src/guided/guided-contract.ts';

type StoredCase = {
  readonly step: StepSpec;
  readonly observation: unknown;
  readonly semanticSelection: unknown;
  readonly scope: unknown;
  readonly state: 'CURRENT' | 'CONSUMED';
  readonly history: readonly { readonly at: string; readonly stepId: string; readonly status: string }[];
};

export type GuidedDecisionReceipt =
  | { readonly status: 'RECORDED'; readonly humanGrantIssued: false; readonly effectSent: false; readonly history: StoredCase['history'] }
  | { readonly status: 'REFUSED' | 'STALE' | 'UNKNOWN'; readonly code: string };

type Row = { readonly state_json: string; readonly revision: number };
const CASE_KEY = 'selected-case';
const TASK_ID = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/;
const STEP_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

export class HostGuidedService {
  readonly #db: DatabaseSync;
  readonly #clock: () => number;

  constructor(file: string, clock: () => number = Date.now) {
    if (typeof file !== 'string' || !file || file === ':memory:' ||
        typeof clock !== 'function') {
      throw new TypeError('GUIDED_DURABLE_HOST_CONFIG_REQUIRED');
    }
    this.#db = new DatabaseSync(file);
    this.#db.exec('PRAGMA journal_mode=WAL');
    this.#db.exec('PRAGMA synchronous=FULL');
    this.#db.exec('PRAGMA busy_timeout=5000');
    this.#db.exec(`CREATE TABLE IF NOT EXISTS guided_selected_case (
      slot TEXT PRIMARY KEY CHECK (slot='selected-case'),
      state_json TEXT NOT NULL,
      revision INTEGER NOT NULL
    )`);
    this.#db.exec(`CREATE TABLE IF NOT EXISTS guided_step_answers (
      step_id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      case_ref_json TEXT NOT NULL,
      template_digest TEXT NOT NULL,
      outcome_json TEXT NOT NULL,
      outcome_sha256 TEXT NOT NULL,
      recorded_at_unix_ms INTEGER NOT NULL
    )`);
    this.#clock = clock;
  }

  /** Only callable by a trusted process-side selection, never an HTTP route. */
  stageTrustedSelection(input: {
    readonly observation: unknown;
    readonly semanticSelection: unknown;
    readonly scope: unknown;
  }): { readonly status: 'CURRENT'; readonly step: StepSpec } | { readonly status: 'REFUSED'; readonly code: string } {
    const now = this.#clock();
    const next = createNextGuidedStep({
      observation: input.observation,
      semanticSelection: input.semanticSelection,
      nowUnixMs: now,
    });
    if (next.status !== 'STEP') return { status: 'REFUSED', code: next.code };
    if (!TASK_ID.test(next.step.taskId)) return { status: 'REFUSED', code: 'TASK_ID_INVALID' };
    const state: StoredCase = {
      step: next.step, observation: input.observation,
      semanticSelection: input.semanticSelection, scope: input.scope,
      state: 'CURRENT', history: [],
    };
    const serialized = JSON.stringify(state);
    if (serialized.length > 262_144) return { status: 'REFUSED', code: 'GUIDED_STATE_TOO_LARGE' };
    try {
      this.#db.exec('BEGIN IMMEDIATE');
      const current = this.#read();
      // A consumed step may never be reissued under the same identity after
      // a restart: the next Host observation must advance the real revision.
      if (current && current.step.stepId === next.step.stepId) {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' };
      }
      if (current?.state === 'CURRENT') {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: 'CURRENT_STEP_ALREADY_EXISTS' };
      }
      const revision = this.#row()?.revision ?? 0;
      this.#db.prepare(`INSERT INTO guided_selected_case(slot,state_json,revision)
        VALUES(?,?,?) ON CONFLICT(slot) DO UPDATE SET
          state_json=excluded.state_json, revision=excluded.revision`)
        .run(CASE_KEY, serialized, revision + 1);
      this.#db.exec('COMMIT');
      return { status: 'CURRENT', step: next.step };
    } catch {
      this.#rollback();
      return { status: 'REFUSED', code: 'GUIDED_DURABILITY_UNKNOWN' };
    }
  }

  state(): {
    readonly currentStep?: StepSpec;
    readonly scope: unknown;
    readonly journey: { readonly position?: number; readonly total?: number; readonly paused: boolean };
    readonly history: StoredCase['history'];
    readonly advisory?: unknown;
  } {
    const stored = this.#read();
    if (!stored) {
      return { scope: undefined, journey: { paused: false }, history: [] };
    }
    return {
      currentStep: stored.state === 'CURRENT' ? stored.step : undefined,
      scope: stored.scope,
      journey: { position: 1, total: 1, paused: stored.state !== 'CURRENT' },
      history: stored.history,
    };
  }

  /** Same-call atomic compare-and-consume. No auto-grant or Kernel send. */
  decide(raw: unknown): GuidedDecisionReceipt {
    if (!isRecord(raw) || Object.keys(raw).sort().join('|') !==
      ['authorityClaimed','caseRef','decision','humanApproval','kind','outcome','relayedVia','stepDigest','stepId'].sort().join('|') ||
      raw.kind !== 'USER_DECISION_RELAY' ||
      raw.authorityClaimed !== false || raw.relayedVia !== '/api' ||
      !((raw.decision === 'ANSWER' && raw.humanApproval === false) ||
        ((raw.decision === 'APPROVE' || raw.decision === 'REFUSE') && raw.humanApproval === true))) {
      return { status: 'REFUSED', code: 'RELAY_SCHEMA_REFUSED' };
    }
    const now = this.#clock();
    try {
      this.#db.exec('BEGIN IMMEDIATE');
      const row = this.#row();
      const stored = row && this.#read(row);
      if (!stored || stored.state !== 'CURRENT' || !row) {
        this.#db.exec('ROLLBACK');
        return { status: 'STALE', code: 'GUIDED_STEP_NOT_CURRENT' };
      }
      // Untrusted ASK answers must not impersonate trusted Host receipts.
      if (raw.decision === 'ANSWER' &&
          (!isRecord(raw.outcome) || raw.outcome.event !== 'USER_SUBMIT' ||
           raw.outcome.source !== 'USER')) {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: 'GUIDED_ANSWER_PROVENANCE_REFUSED' };
      }
      if (raw.stepId !== stored.step.stepId ||
          raw.stepDigest !== stored.step.templateRef.digest ||
          JSON.stringify(raw.caseRef) !== JSON.stringify(stored.step.caseRef) ||
          ((raw.decision === 'ANSWER' && stored.step.kind !== 'ASK') ||
           (raw.decision === 'APPROVE' && stored.step.kind !== 'REVIEW_EFFECT')))  {
        this.#db.exec('ROLLBACK');
        return { status: 'STALE', code: 'GUIDED_STEP_IDENTITY_MISMATCH' };
      }
      const checked = validateGuidedStepOutcome({
        stepSpec: stored.step,
        currentObservation: stored.observation,
        currentSemanticSelection: stored.semanticSelection,
        currentStepId: stored.step.stepId,
        currentStepState: stored.state,
        outcome: raw.outcome,
        nowUnixMs: now,
      });
      if (checked.status !== 'ACCEPTED') {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: checked.code };
      }
      const history = [...stored.history, {
        at: new Date(now).toISOString(),
        stepId: stored.step.stepId,
        status: raw.decision === 'REFUSE' ? 'REFUSED' : 'ACCEPTED',
      }];
      if (raw.decision === 'ANSWER') {
        const outcomeJson = JSON.stringify(checked.outcome);
        if (typeof outcomeJson !== 'string' || outcomeJson.length > 65_536) {
          this.#db.exec('ROLLBACK');
          return { status: 'REFUSED', code: 'GUIDED_ANSWER_TOO_LARGE' };
        }
        const outcomeSha256 = createHash('sha256').update(outcomeJson, 'utf8').digest('hex');
        const saved = this.#db.prepare(`INSERT INTO guided_step_answers(
          step_id,task_id,case_ref_json,template_digest,outcome_json,outcome_sha256,recorded_at_unix_ms
        ) VALUES(?,?,?,?,?,?,?)`).run(
          stored.step.stepId,
          stored.step.taskId,
          JSON.stringify(stored.step.caseRef),
          stored.step.templateRef.digest,
          outcomeJson,
          outcomeSha256,
          now,
        );
        if (saved.changes !== 1) {
          this.#db.exec('ROLLBACK');
          return { status: 'STALE', code: 'GUIDED_ANSWER_ALREADY_RECORDED' };
        }
      }
      const updated: StoredCase = { ...stored, state: 'CONSUMED', history };
      const change = this.#db.prepare(`UPDATE guided_selected_case
        SET state_json=?, revision=revision+1 WHERE slot=? AND revision=?`)
        .run(JSON.stringify(updated), CASE_KEY, row.revision);
      if (change.changes !== 1) {
        this.#db.exec('ROLLBACK');
        return { status: 'STALE', code: 'GUIDED_CONCURRENT_CONSUMPTION' };
      }
      this.#db.exec('COMMIT');
      return { status: 'RECORDED', humanGrantIssued: false, effectSent: false, history };
    } catch {
      this.#rollback();
      return { status: 'UNKNOWN', code: 'GUIDED_DURABILITY_UNKNOWN' };
    }
  }

  /**
   * Trusted Host-only readback for the exact consumed ASK step. This is not
   * included in the HTTP state projection; the digest detects local record
   * corruption before an answer is reused by a later Host step.
   */
  readRecordedAnswer(stepId: string): unknown | undefined {
    if (typeof stepId !== 'string' || !STEP_ID.test(stepId)) return undefined;
    const row = this.#db.prepare(`SELECT outcome_json,outcome_sha256
      FROM guided_step_answers WHERE step_id=?`).get(stepId) as
      | { outcome_json: string; outcome_sha256: string }
      | undefined;
    if (!row || !/^[a-f0-9]{64}$/.test(row.outcome_sha256)) return undefined;
    const digest = createHash('sha256').update(row.outcome_json, 'utf8').digest('hex');
    if (digest !== row.outcome_sha256) return undefined;
    try {
      return JSON.parse(row.outcome_json) as unknown;
    } catch {
      return undefined;
    }
  }

  close(): void { this.#db.close(); }

  #row(): Row | null {
    return (this.#db.prepare('SELECT state_json,revision FROM guided_selected_case WHERE slot=?')
      .get(CASE_KEY) as Row | undefined) ?? null;
  }

  #read(row: Row | null = this.#row()): StoredCase | null {
    if (!row) return null;
    return JSON.parse(row.state_json) as StoredCase;
  }

  #rollback(): void {
    try { this.#db.exec('ROLLBACK'); } catch { /* retain unknown, no false receipt */ }
  }
}
