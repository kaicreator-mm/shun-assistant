/**
 * R02-B: persistent Host boundary for the v0.3 bounded Guided Journey.
 * This is business/UI acknowledgement evidence, NOT a second Kernel Journal,
 * consent issuer, ActionController grant or effect dispatcher.
 * Only the trusted Host composition calls stageTrustedSelection.
 *
 * G6: durable schema provenance is vouched for by an INJECTED
 * GuidedProvenanceAuthority (see guided-provenance-authority.ts), never by a
 * self-asserted marker. A fresh database is initialized only inside one
 * BEGIN IMMEDIATE transaction that commits the exact schema plus an
 * authority-issued receipt; every reopen validates the exact stored DDL,
 * the receipt against the authority's protected external record, and every
 * payload/ledger envelope and binding before enabling mutations. Any
 * database that cannot be proven — legacy G3/G4/G5 data, a copied or forged
 * receipt, a tampered schema or payload — fails closed with the stable code
 * GUIDED_LEDGER_MIGRATION_AMBIGUOUS and is never modified.
 */
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  createNextGuidedStep,
  validateGuidedStepOutcome,
} from '../../../domain-computer/src/guided/guided-journey.ts';
import type { StepSpec } from '../../../domain-computer/src/guided/guided-contract.ts';
import {
  developmentGuidedProvenanceAuthority,
  GUIDED_SCHEMA_VERSION,
  isGuidedProvenanceAuthority,
} from './guided-provenance-authority.ts';
import type { GuidedProvenanceAuthority } from './guided-provenance-authority.ts';

type StoredCase = {
  readonly step: StepSpec;
  readonly observation: unknown;
  readonly semanticSelection: unknown;
  readonly scope: unknown;
  readonly state: 'CURRENT' | 'PAUSED' | 'CONSUMED';
  readonly history: readonly { readonly at: string; readonly stepId: string; readonly status: string }[];
};

export type GuidedDecisionReceipt =
  | { readonly status: 'RECORDED'; readonly humanGrantIssued: false; readonly effectSent: false; readonly history: StoredCase['history'] }
  | { readonly status: 'REFUSED' | 'STALE' | 'UNKNOWN'; readonly code: string };

type Row = { readonly state_json: string; readonly revision: number };
type LedgerRow = {
  readonly step_id: string;
  readonly task_id: string;
  readonly case_ref_json: string;
  readonly template_digest: string;
  readonly step_kind: string;
  readonly receipt_kind: string;
  readonly terminal_event: string;
  readonly terminal_decision: string;
  readonly recorded_at_unix_ms: number;
  readonly row_sha256: string;
};
type AnswerRow = {
  readonly step_id: string; readonly task_id: string; readonly case_ref_json: string;
  readonly template_digest: string; readonly outcome_json: string; readonly outcome_sha256: string;
  readonly recorded_at_unix_ms: number;
};
type RefusalRow = {
  readonly step_id: string; readonly task_id: string; readonly case_ref_json: string;
  readonly template_digest: string; readonly refusal_json: string; readonly refusal_sha256: string;
  readonly recorded_at_unix_ms: number;
};
const CASE_KEY = 'selected-case';
const RECEIPT_KEY = 'schema';

/**
 * Canonical schema definition. The exact DDL text is executed verbatim at
 * initialization and compared verbatim against sqlite_master on every open
 * (tables, columns, types, nullability, primary keys and CHECK
 * constraints), so any drift — altered column, constraint, index or extra
 * guided object — fails closed. The canonical digest of this exact text is
 * bound into the authority receipt.
 */
const GUIDED_SCHEMA_DDL = [
  `CREATE TABLE guided_selected_case (
      slot TEXT PRIMARY KEY CHECK (slot='selected-case'),
      state_json TEXT NOT NULL,
      revision INTEGER NOT NULL
    )`,
  `CREATE TABLE guided_step_answers (
      step_id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      case_ref_json TEXT NOT NULL,
      template_digest TEXT NOT NULL,
      outcome_json TEXT NOT NULL,
      outcome_sha256 TEXT NOT NULL,
      recorded_at_unix_ms INTEGER NOT NULL
    )`,
  `CREATE TABLE guided_step_refusals (
      step_id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      case_ref_json TEXT NOT NULL,
      template_digest TEXT NOT NULL,
      refusal_json TEXT NOT NULL,
      refusal_sha256 TEXT NOT NULL,
      recorded_at_unix_ms INTEGER NOT NULL
    )`,
  `CREATE TABLE guided_consumed_steps (
      step_id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      case_ref_json TEXT NOT NULL,
      template_digest TEXT NOT NULL,
      step_kind TEXT NOT NULL CHECK (step_kind IN ('ASK','REVIEW_EFFECT','INSPECT')),
      receipt_kind TEXT NOT NULL CHECK (receipt_kind IN ('ANSWER','REFUSAL','NONE')),
      terminal_event TEXT NOT NULL CHECK (terminal_event IN ('USER_SUBMIT','OBSERVATION_RECEIPT')),
      terminal_decision TEXT NOT NULL CHECK (terminal_decision IN ('ANSWER','APPROVE','REFUSE')),
      recorded_at_unix_ms INTEGER NOT NULL,
      row_sha256 TEXT NOT NULL
    )`,
  `CREATE TABLE guided_schema_receipt (
      slot TEXT PRIMARY KEY CHECK (slot='schema'),
      schema_version INTEGER NOT NULL,
      schema_digest TEXT NOT NULL,
      database_id TEXT NOT NULL,
      issued_at_unix_ms INTEGER NOT NULL,
      receipt_digest TEXT NOT NULL
    )`,
] as const;

const GUIDED_TABLES = [
  'guided_selected_case',
  'guided_step_answers',
  'guided_step_refusals',
  'guided_consumed_steps',
  'guided_schema_receipt',
] as const;

const GUIDED_SCHEMA_DIGEST = createHash('sha256')
  .update(GUIDED_SCHEMA_DDL.join('\n'), 'utf8')
  .digest('hex');

const TASK_ID = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/;
const STEP_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$/;
const TERMINAL_HISTORY = new Set(['ACCEPTED', 'REFUSED', 'OBSERVATION_RECEIPT']);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

export class HostGuidedService {
  readonly #db: DatabaseSync;
  readonly #clock: () => number;
  readonly #authority: GuidedProvenanceAuthority;
  readonly #canonicalPath: string;
  /**
   * Set when the database cannot prove a complete, trusted replay fence:
   * a non-empty pre-G6 database without a verifiable authority receipt
   * (its prior-Case terminal history may have been discarded and is
   * unrecoverable), or a receipt-bearing database whose exact schema,
   * receipt, row digests, payload envelopes or bindings fail validation.
   * The service then fails closed: staging and decisions are refused with
   * the stable code until the state is repaired out of band. Never reset
   * silently, never deletes data.
   */
  #ledgerUnavailable: string | null = null;
  /** Capability token for in-process Host-generated INSPECT receipts. */
  readonly #trustedHostObservationRelays = new WeakSet<object>();

  constructor(
    file: string,
    clock: () => number = Date.now,
    authority: GuidedProvenanceAuthority = developmentGuidedProvenanceAuthority,
  ) {
    if (typeof file !== 'string' || !file || file === ':memory:' ||
        typeof clock !== 'function' || !isGuidedProvenanceAuthority(authority)) {
      throw new TypeError('GUIDED_DURABLE_HOST_CONFIG_REQUIRED');
    }
    this.#db = new DatabaseSync(file);
    this.#db.exec('PRAGMA journal_mode=WAL');
    this.#db.exec('PRAGMA synchronous=FULL');
    this.#db.exec('PRAGMA busy_timeout=5000');
    this.#clock = clock;
    this.#authority = authority;
    this.#canonicalPath = resolve(file);
    this.#initializeOrValidate();
  }

  /** Only callable by a trusted process-side selection, never an HTTP route. */
  stageTrustedSelection(input: {
    readonly observation: unknown;
    readonly semanticSelection: unknown;
    readonly scope: unknown;
  }): { readonly status: 'CURRENT'; readonly step: StepSpec } | { readonly status: 'REFUSED'; readonly code: string } {
    if (this.#ledgerUnavailable) {
      return { status: 'REFUSED', code: this.#ledgerUnavailable };
    }
    const now = this.#clock();
    const next = createNextGuidedStep({
      observation: input.observation,
      semanticSelection: input.semanticSelection,
      nowUnixMs: now,
    });
    if (next.status !== 'STEP') return { status: 'REFUSED', code: next.code };
    if (!TASK_ID.test(next.step.taskId)) return { status: 'REFUSED', code: 'TASK_ID_INVALID' };
    try {
      this.#db.exec('BEGIN IMMEDIATE');
      // G4 global replay fence: any stepId ever terminally consumed — under
      // this Case or any other — is refused here, before the selected-Case
      // projection is even read. A -> B -> A and restarts cannot regenerate
      // a consumable step from a still-valid old observation.
      if (this.#ledgerRow(next.step.stepId)) {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' };
      }
      const current = this.#read();
      const sameCase = !!current &&
        next.step.taskId === current.step.taskId &&
        JSON.stringify(next.step.caseRef) === JSON.stringify(current.step.caseRef);
      // Replay fence. The immediate-step check covers a live CURRENT/PAUSED
      // step (not yet in history); the history scan covers every step this
      // Case already consumed or navigated, so consuming r02 never reopens a
      // historically consumed r01 — even behind a later observedAt.
      if (current && current.step.stepId === next.step.stepId) {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' };
      }
      if (current && sameCase &&
          current.history.some((entry) => entry.stepId === next.step.stepId)) {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' };
      }
      // History is carried only within one task/Case identity. A genuinely
      // different Case starts a clean history so prior-Case step metadata is
      // never returned through state().
      const fresh: StoredCase = {
        step: next.step, observation: input.observation,
        semanticSelection: input.semanticSelection, scope: input.scope,
        state: 'CURRENT', history: [],
      };
      const state: StoredCase = current && sameCase ? { ...fresh, history: current.history } : fresh;
      const serialized = JSON.stringify(state);
      if (serialized.length > 262_144) {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: 'GUIDED_STATE_TOO_LARGE' };
      }
      if (current && (current.state === 'CURRENT' || current.state === 'PAUSED')) {
        if (now <= current.step.validUntilUnixMs) {
          this.#db.exec('ROLLBACK');
          return { status: 'REFUSED', code: 'CURRENT_STEP_ALREADY_EXISTS' };
        }
        // Expired step: only a fresh, advanced Host observation for the same
        // task/Case identity may replace it; anything else stays fenced.
        if (!sameCase) {
          this.#db.exec('ROLLBACK');
          return { status: 'REFUSED', code: 'GUIDED_CASE_IDENTITY_REFUSED' };
        }
        if (!this.#observationAdvanced(current.observation, input.observation)) {
          this.#db.exec('ROLLBACK');
          return { status: 'REFUSED', code: 'GUIDED_OBSERVATION_NOT_ADVANCED' };
        }
      } else if (current && current.state === 'CONSUMED' && sameCase) {
        // Same-Case progression after consumption also requires a fresh Host
        // observation; a stale or replayed observation stays fenced.
        if (!this.#observationAdvanced(current.observation, input.observation)) {
          this.#db.exec('ROLLBACK');
          return { status: 'REFUSED', code: 'GUIDED_OBSERVATION_NOT_ADVANCED' };
        }
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
    // An expired step is neither current nor recoverable through this view:
    // the next trusted Host observation must restage it. Paused steps stay
    // visible so the UI can offer RESUME while they remain valid.
    const live = (stored.state === 'CURRENT' || stored.state === 'PAUSED') &&
      this.#clock() <= stored.step.validUntilUnixMs;
    return {
      currentStep: live ? stored.step : undefined,
      scope: stored.scope,
      journey: { position: 1, total: 1, paused: stored.state === 'PAUSED' && live },
      history: stored.history,
    };
  }

  /** Same-call atomic compare-and-consume. No auto-grant or Kernel send. */
  decide(raw: unknown): GuidedDecisionReceipt {
    if (this.#ledgerUnavailable) {
      return { status: 'UNKNOWN', code: this.#ledgerUnavailable };
    }
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
      if (!stored || !row || stored.state === 'CONSUMED') {
        this.#db.exec('ROLLBACK');
        return { status: 'STALE', code: 'GUIDED_STEP_NOT_CURRENT' };
      }
      const outcomeEvent = isRecord(raw.outcome) && typeof raw.outcome.event === 'string'
        ? raw.outcome.event
        : undefined;
      const navigation = outcomeEvent === 'BACK' || outcomeEvent === 'PAUSE' ||
        outcomeEvent === 'RESUME';
      // Explicit decision matrix, enforced before anything is consumed:
      // - ANSWER submits data only on ASK steps and is the only tuple that
      //   persists an accepted answer row;
      // - APPROVE decides only REVIEW_EFFECT submissions;
      // - REFUSE covers REVIEW_EFFECT submissions, ASK submissions and
      //   INSPECT Host receipts. An ASK refusal persists the submitted
      //   answers as a separately typed refusal receipt (never an answer
      //   row, never returned by readRecordedAnswer); an INSPECT Host
      //   receipt is recorded in history as OBSERVATION_RECEIPT, not
      //   REFUSED. Navigation (BACK/PAUSE/RESUME) never mints authority and
      //   rides only under the non-approving ANSWER relay.
      const submission = outcomeEvent === 'USER_SUBMIT';
      let matrixValid: boolean;
      if (navigation) {
        matrixValid = raw.decision === 'ANSWER';
      } else if (raw.decision === 'ANSWER') {
        matrixValid = stored.step.kind === 'ASK' && submission;
      } else if (raw.decision === 'APPROVE') {
        matrixValid = stored.step.kind === 'REVIEW_EFFECT' && submission;
      } else {
        matrixValid = (submission &&
            (stored.step.kind === 'REVIEW_EFFECT' || stored.step.kind === 'ASK')) ||
          (outcomeEvent === 'OBSERVATION_RECEIPT' && stored.step.kind === 'INSPECT');
      }
      if (!matrixValid) {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: 'GUIDED_DECISION_MATRIX_REFUSED' };
      }
      // A paused step accepts navigation only; submissions wait for RESUME.
      if (stored.state === 'PAUSED' && !navigation) {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: 'GUIDED_STEP_PAUSED' };
      }
      if (raw.stepId !== stored.step.stepId ||
          raw.stepDigest !== stored.step.templateRef.digest ||
          JSON.stringify(raw.caseRef) !== JSON.stringify(stored.step.caseRef)) {
        this.#db.exec('ROLLBACK');
        return { status: 'STALE', code: 'GUIDED_STEP_IDENTITY_MISMATCH' };
      }
      // Untrusted ASK answers must not impersonate trusted Host receipts.
      if (raw.decision === 'ANSWER' &&
          (!isRecord(raw.outcome) || raw.outcome.source !== 'USER')) {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: 'GUIDED_ANSWER_PROVENANCE_REFUSED' };
      }
      const checked = validateGuidedStepOutcome({
        stepSpec: stored.step,
        currentObservation: stored.observation,
        currentSemanticSelection: stored.semanticSelection,
        currentStepId: stored.step.stepId,
        // The pure validator's state enum has no PAUSED; a paused step is
        // still live Host state, so it validates as CURRENT.
        currentStepState: 'CURRENT',
        outcome: raw.outcome,
        nowUnixMs: now,
      });
      if (checked.status !== 'ACCEPTED') {
        this.#db.exec('ROLLBACK');
        return { status: 'REFUSED', code: checked.code };
      }
      if (outcomeEvent === 'BACK') {
        // Non-consuming navigation: no authority minted, no durable change,
        // and any previously submitted answers stay recorded.
        this.#db.exec('ROLLBACK');
        return { status: 'RECORDED', humanGrantIssued: false, effectSent: false, history: stored.history };
      }
      if (outcomeEvent === 'PAUSE' || outcomeEvent === 'RESUME') {
        if ((outcomeEvent === 'PAUSE' && stored.state !== 'CURRENT') ||
            (outcomeEvent === 'RESUME' && stored.state !== 'PAUSED')) {
          this.#db.exec('ROLLBACK');
          return { status: 'REFUSED', code: 'GUIDED_STEP_LIFECYCLE_REFUSED' };
        }
        const history = [...stored.history, {
          at: new Date(now).toISOString(),
          stepId: stored.step.stepId,
          status: outcomeEvent,
        }];
        const updated: StoredCase = {
          ...stored,
          state: outcomeEvent === 'PAUSE' ? 'PAUSED' : 'CURRENT',
          history,
        };
        const change = this.#db.prepare(`UPDATE guided_selected_case
          SET state_json=?, revision=revision+1 WHERE slot=? AND revision=?`)
          .run(JSON.stringify(updated), CASE_KEY, row.revision);
        if (change.changes !== 1) {
          this.#db.exec('ROLLBACK');
          return { status: 'STALE', code: 'GUIDED_CONCURRENT_CONSUMPTION' };
        }
        this.#db.exec('COMMIT');
        return { status: 'RECORDED', humanGrantIssued: false, effectSent: false, history };
      }
      // The durable terminal record binds to the outcome's OWN occurredAt —
      // already validated against the step window above — rather than to the
      // wall clock at persistence: across a relay the two can differ by a
      // millisecond, and open-time envelope validation compares them
      // exactly. Navigation/lifecycle timestamps above intentionally keep
      // the local clock.
      const recordedAt = isRecord(checked.outcome) &&
        typeof checked.outcome.occurredAtUnixMs === 'number'
        ? checked.outcome.occurredAtUnixMs
        : now;
      const history = [...stored.history, {
        at: new Date(recordedAt).toISOString(),
        stepId: stored.step.stepId,
        // A REFUSE is a refusal, but a trusted Host observation receipt is
        // recorded as what it is — an observation receipt — never mislabeled
        // REFUSED and never implying human refusal, grant or effect.
        status: raw.decision === 'REFUSE'
          ? (outcomeEvent === 'OBSERVATION_RECEIPT' ? 'OBSERVATION_RECEIPT' : 'REFUSED')
          : 'ACCEPTED',
      }];
      // The durable ledger binds every terminal outcome; check it BEFORE any
      // payload write so a pre-existing row (the step was already consumed)
      // fails closed as STALE with nothing written. The check-then-insert is
      // race-free because BEGIN IMMEDIATE excludes every other writer for
      // the whole transaction.
      if (this.#ledgerRow(stored.step.stepId)) {
        this.#db.exec('ROLLBACK');
        return { status: 'STALE', code: 'GUIDED_STEP_ALREADY_CONSUMED' };
      }
      // Only an accepted ANSWER persists an answer row. An ASK refusal is
      // persisted as a separately typed durable refusal receipt (digest
      // verified) so the submitted payload is preserved as evidence but can
      // never be read back as an accepted answer; a REVIEW_EFFECT refusal
      // records no payload at all.
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
          recordedAt,
        );
        if (saved.changes !== 1) {
          this.#db.exec('ROLLBACK');
          return { status: 'STALE', code: 'GUIDED_ANSWER_ALREADY_RECORDED' };
        }
      } else if (raw.decision === 'REFUSE' && stored.step.kind === 'ASK') {
        const refusal = {
          schema: 'shun.guided.refusal-receipt.v1',
          stepId: stored.step.stepId,
          taskId: stored.step.taskId,
          caseRef: stored.step.caseRef,
          templateDigest: stored.step.templateRef.digest,
          decision: 'REFUSE',
          outcome: checked.outcome,
        };
        const refusalJson = JSON.stringify(refusal);
        if (typeof refusalJson !== 'string' || refusalJson.length > 65_536) {
          this.#db.exec('ROLLBACK');
          return { status: 'REFUSED', code: 'GUIDED_REFUSAL_TOO_LARGE' };
        }
        const refusalSha256 = createHash('sha256').update(refusalJson, 'utf8').digest('hex');
        const saved = this.#db.prepare(`INSERT INTO guided_step_refusals(
          step_id,task_id,case_ref_json,template_digest,refusal_json,refusal_sha256,recorded_at_unix_ms
        ) VALUES(?,?,?,?,?,?,?)`).run(
          stored.step.stepId,
          stored.step.taskId,
          JSON.stringify(stored.step.caseRef),
          stored.step.templateRef.digest,
          refusalJson,
          refusalSha256,
          recordedAt,
        );
        if (saved.changes !== 1) {
          this.#db.exec('ROLLBACK');
          return { status: 'STALE', code: 'GUIDED_REFUSAL_ALREADY_RECORDED' };
        }
      }
      // The consumed-step ledger records every terminal outcome (ANSWER,
      // APPROVE, REFUSE on ASK/REVIEW_EFFECT, and the INSPECT Host receipt)
      // — including the StepKind and receipt kind that make historical
      // payload cardinality unambiguous — in the same transaction as the
      // payload receipt above and the selected-case CAS below. RECORDED is
      // never reported unless all durable writes commit.
      const terminalEvent = outcomeEvent === 'OBSERVATION_RECEIPT' ? 'OBSERVATION_RECEIPT' : 'USER_SUBMIT';
      const terminalDecision = raw.decision === 'ANSWER' ? 'ANSWER' : raw.decision === 'APPROVE' ? 'APPROVE' : 'REFUSE';
      const receiptKind = terminalDecision === 'ANSWER' ? 'ANSWER'
        : (terminalDecision === 'REFUSE' && stored.step.kind === 'ASK') ? 'REFUSAL' : 'NONE';
      const caseRefJson = JSON.stringify(stored.step.caseRef);
      const ledgerSaved = this.#db.prepare(`INSERT INTO guided_consumed_steps(
        step_id,task_id,case_ref_json,template_digest,step_kind,receipt_kind,
        terminal_event,terminal_decision,recorded_at_unix_ms,row_sha256
      ) VALUES(?,?,?,?,?,?,?,?,?,?)`).run(
        stored.step.stepId,
        stored.step.taskId,
        caseRefJson,
        stored.step.templateRef.digest,
        stored.step.kind,
        receiptKind,
        terminalEvent,
        terminalDecision,
        recordedAt,
        this.#ledgerDigest({
          step_id: stored.step.stepId,
          task_id: stored.step.taskId,
          case_ref_json: caseRefJson,
          template_digest: stored.step.templateRef.digest,
          step_kind: stored.step.kind,
          receipt_kind: receiptKind,
          terminal_event: terminalEvent,
          terminal_decision: terminalDecision,
          recorded_at_unix_ms: recordedAt,
        }),
      );
      if (ledgerSaved.changes !== 1) {
        this.#db.exec('ROLLBACK');
        return { status: 'STALE', code: 'GUIDED_STEP_ALREADY_CONSUMED' };
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
   * included in the HTTP state projection. The envelope validator re-binds
   * the embedded identity, event, source and timestamp to the indexed row,
   * so a recomputed digest over tampered content is rejected here without
   * modifying any data.
   */
  readRecordedAnswer(stepId: string): unknown | undefined {
    if (typeof stepId !== 'string' || !STEP_ID.test(stepId)) return undefined;
    const row = this.#db.prepare(`SELECT step_id,task_id,case_ref_json,recorded_at_unix_ms,
      outcome_json,outcome_sha256 FROM guided_step_answers WHERE step_id=?`).get(stepId) as
      | AnswerRow
      | undefined;
    if (!row || !/^[a-f0-9]{64}$/.test(row.outcome_sha256)) return undefined;
    return this.#answerEnvelope(row.outcome_json, row.outcome_sha256, row) ?? undefined;
  }

  /**
   * Trusted Host-only readback for the explicit refusal outcome of the exact
   * consumed ASK step. A refused payload is preserved as refusal evidence —
   * never as an accepted answer — and the full envelope is re-validated on
   * readback, including the nested outcome binding.
   */
  readRecordedRefusal(stepId: string): unknown | undefined {
    if (typeof stepId !== 'string' || !STEP_ID.test(stepId)) return undefined;
    const row = this.#db.prepare(`SELECT step_id,task_id,case_ref_json,template_digest,
      recorded_at_unix_ms,refusal_json,refusal_sha256 FROM guided_step_refusals WHERE step_id=?`).get(stepId) as
      | RefusalRow
      | undefined;
    if (!row || !/^[a-f0-9]{64}$/.test(row.refusal_sha256)) return undefined;
    const parsed = this.#refusalEnvelope(row.refusal_json, row.refusal_sha256, row);
    if (!parsed) return undefined;
    try {
      return JSON.parse(row.refusal_json) as unknown;
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

  /**
   * A replacing Host observation is fresh only when its revision token
   * differs and its observedAt is strictly later than the stored one.
   */
  #observationAdvanced(storedObservation: unknown, incomingObservation: unknown): boolean {
    const previous = isRecord(storedObservation) ? storedObservation : null;
    const incoming = isRecord(incomingObservation) ? incomingObservation : null;
    const previousRevision = previous?.revision;
    const incomingRevision = incoming?.revision;
    const previousObservedAt = previous?.observedAtUnixMs;
    const incomingObservedAt = incoming?.observedAtUnixMs;
    return typeof previousRevision === 'string' && typeof incomingRevision === 'string' &&
      typeof previousObservedAt === 'number' && typeof incomingObservedAt === 'number' &&
      incomingRevision !== previousRevision && incomingObservedAt > previousObservedAt;
  }

  #ledgerRow(stepId: string): LedgerRow | null {
    return (this.#db.prepare(`SELECT step_id,task_id,case_ref_json,template_digest,
      terminal_event,terminal_decision,recorded_at_unix_ms,row_sha256
      FROM guided_consumed_steps WHERE step_id=?`).get(stepId) as LedgerRow | undefined) ?? null;
  }

  /**
   * Row-integrity digest over the canonical field binding. The ledger is
   * internal replay evidence; a mismatched digest means the durable layer
   * can no longer be trusted, so validation fails closed instead of fencing
   * (or not fencing) on corrupt data.
   */
  #ledgerDigest(row: Omit<LedgerRow, 'row_sha256'>): string {
    return createHash('sha256').update(
      `${row.step_id}|${row.task_id}|${row.case_ref_json}|${row.template_digest}|` +
      `${row.step_kind}|${row.receipt_kind}|${row.terminal_event}|${row.terminal_decision}|` +
      `${row.recorded_at_unix_ms}`,
      'utf8',
    ).digest('hex');
  }

  /** Names of every guided-domain object (table or index) in the database. */
  #guidedObjects(): { readonly name: string; readonly type: string; readonly sql: string | null }[] {
    return this.#db.prepare(
      `SELECT name, type, sql FROM sqlite_master WHERE name LIKE 'guided\\_%' ESCAPE '\\'`,
    ).all() as unknown as { readonly name: string; readonly type: string; readonly sql: string | null }[];
  }

  /**
   * G6 admission, serialized from the first byte: the schema state is
   * inspected only AFTER acquiring BEGIN IMMEDIATE, so two concurrent first
   * openers cannot both observe an empty database. The second opener waits,
   * then re-reads and validates the first opener's committed schema. A fresh
   * database (no guided object at all) initializes with an authority receipt
   * in the same transaction; anything else — legacy G3/G4/G5 data, a forged
   * or copied marker, a partial residue — cannot prove trusted provenance
   * and fails closed.
   */
  #initializeOrValidate(): void {
    try {
      this.#db.exec('BEGIN IMMEDIATE');
      try {
        const objects = this.#guidedObjects();
        const tableNames = new Set(objects.filter((o) => o.type === 'table').map((o) => o.name));
        if (tableNames.has('guided_schema_receipt')) {
          this.#validateMarkedLocked(tableNames, objects);
        } else if (objects.length === 0) {
          this.#initializeFreshLocked();
        } else {
          throw new Error('pre-G6 database without trusted provenance');
        }
        this.#db.exec('COMMIT');
      } catch {
        this.#rollback();
        throw new Error('guided provenance admission failed');
      }
    } catch {
      this.#ledgerUnavailable = 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS';
    }
  }

  #createTables(): void {
    for (const ddl of GUIDED_SCHEMA_DDL) {
      this.#db.exec(ddl);
    }
  }

  /**
   * Initialize a provably fresh database: the authority issues the receipt
   * FIRST (registering the canonical path in its protected external
   * record), then the exact schema and the receipt row commit in ONE
   * transaction. A crash before the commit leaves no receipt table, so the
   * database either initializes cleanly on retry or — if any residue
   * exists — stays fail-closed. If the authority refuses (e.g. a
   * non-scratch production path without a real injected authority), the
   * whole initialization rolls back and the service fails closed.
   */
  #initializeFreshLocked(): void {
    const issuedAt = this.#clock();
    const receipt = this.#authority.issueFreshReceipt({
      canonicalDatabasePath: this.#canonicalPath,
      schemaDigest: GUIDED_SCHEMA_DIGEST,
      issuedAtUnixMs: issuedAt,
    });
    if (receipt.schemaVersion !== GUIDED_SCHEMA_VERSION ||
        receipt.schemaDigest !== GUIDED_SCHEMA_DIGEST) {
      throw new Error('authority receipt does not bind this schema');
    }
    this.#createTables();
    this.#db.prepare(`INSERT INTO guided_schema_receipt(
      slot,schema_version,schema_digest,database_id,issued_at_unix_ms,receipt_digest
    ) VALUES(?,?,?,?,?,?)`).run(
      RECEIPT_KEY, receipt.schemaVersion, receipt.schemaDigest, receipt.databaseId,
      receipt.issuedAtUnixMs, receipt.receiptDigest,
    );
  }

  /** True when the ledger row binds exactly the given terminal evidence. */
  #ledgerAgrees(
    row: LedgerRow,
    taskId: string,
    caseRefJson: string,
    templateDigest: string,
    stepKind: string,
    receiptKind: string,
    terminalEvent: string,
    terminalDecision: string,
    recordedAtUnixMs: number,
  ): boolean {
    return row.task_id === taskId && row.case_ref_json === caseRefJson &&
      row.template_digest === templateDigest && row.step_kind === stepKind &&
      row.receipt_kind === receiptKind && row.terminal_event === terminalEvent &&
      row.terminal_decision === terminalDecision && row.recorded_at_unix_ms === recordedAtUnixMs;
  }

  /**
   * Strictly parse and bind one persisted Answer envelope to its indexed
   * row: digest equality alone is not sufficient, because a recomputed
   * unkeyed digest can conceal tampered embedded content. Returns the parsed
   * envelope, or null when any binding fails.
   */
  #answerEnvelope(
    outcomeJson: string,
    outcomeSha256: string,
    row: Pick<AnswerRow, 'step_id' | 'task_id' | 'case_ref_json' | 'recorded_at_unix_ms'>,
  ): Record<string, unknown> | null {
    if (createHash('sha256').update(outcomeJson, 'utf8').digest('hex') !== outcomeSha256) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(outcomeJson);
    } catch {
      return null;
    }
    if (!isRecord(parsed) ||
        parsed.schema !== 'shun.guided.step-outcome.v1' ||
        parsed.stepId !== row.step_id ||
        parsed.taskId !== row.task_id ||
        JSON.stringify(parsed.caseRef) !== row.case_ref_json ||
        parsed.event !== 'USER_SUBMIT' ||
        parsed.source !== 'USER' ||
        parsed.occurredAtUnixMs !== row.recorded_at_unix_ms ||
        !Array.isArray(parsed.answers)) {
      return null;
    }
    return parsed;
  }

  /**
   * Strictly parse and bind one persisted typed Refusal envelope to its
   * indexed row, including the nested full outcome envelope.
   */
  #refusalEnvelope(
    refusalJson: string,
    refusalSha256: string,
    row: Pick<RefusalRow, 'step_id' | 'task_id' | 'case_ref_json' | 'template_digest' | 'recorded_at_unix_ms'>,
  ): Record<string, unknown> | null {
    if (createHash('sha256').update(refusalJson, 'utf8').digest('hex') !== refusalSha256) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(refusalJson);
    } catch {
      return null;
    }
    if (!isRecord(parsed) ||
        parsed.schema !== 'shun.guided.refusal-receipt.v1' ||
        parsed.decision !== 'REFUSE' ||
        parsed.stepId !== row.step_id ||
        parsed.taskId !== row.task_id ||
        JSON.stringify(parsed.caseRef) !== row.case_ref_json ||
        parsed.templateDigest !== row.template_digest ||
        !isRecord(parsed.outcome) ||
        parsed.outcome.schema !== 'shun.guided.step-outcome.v1' ||
        parsed.outcome.event !== 'USER_SUBMIT' ||
        parsed.outcome.source !== 'USER' ||
        parsed.outcome.stepId !== row.step_id ||
        parsed.outcome.taskId !== row.task_id ||
        JSON.stringify(parsed.outcome.caseRef) !== row.case_ref_json ||
        parsed.outcome.occurredAtUnixMs !== row.recorded_at_unix_ms ||
        !Array.isArray(parsed.outcome.answers)) {
      return null;
    }
    return parsed;
  }

  /**
   * Validate a receipt-bearing G6 database before enabling mutations, while
   * holding BEGIN IMMEDIATE. Validates, in order: the exact stored schema
   * definition (verbatim DDL text of every expected table, and no extra
   * guided objects such as planted indexes); the authority receipt against
   * the authority's protected external record for this canonical database
   * path; every ledger row digest; every Answer/Refusal envelope parsed and
   * bound to its indexed row; cross-table conflicts across the complete
   * payload datasets; payload↔ledger bindings with exact StepKind and
   * receipt-kind cardinality (a missing ASK refusal receipt is ambiguous
   * and fails closed, while REVIEW_EFFECT APPROVE/REFUSE and INSPECT
   * receipts are provably payload-free through their ledger kinds); and the
   * terminal classification of a persisted CONSUMED selected Case. Any
   * inconsistency fails closed without modifying a single row.
   */
  #validateMarkedLocked(
    tables: ReadonlySet<string>,
    objects: ReadonlyArray<{ readonly name: string; readonly type: string; readonly sql: string | null }>,
  ): void {
    for (const name of GUIDED_TABLES) {
      if (!tables.has(name)) throw new Error(`missing table ${name}`);
    }
    for (const object of objects) {
      if (object.type !== 'table') throw new Error(`unexpected guided object ${object.name}`);
      const index = (GUIDED_TABLES as readonly string[]).indexOf(object.name);
      if (index < 0 || object.sql !== GUIDED_SCHEMA_DDL[index]) {
        throw new Error(`schema drift on ${object.name}`);
      }
    }
    const receiptRow = this.#db.prepare(`SELECT schema_version, schema_digest, database_id,
      issued_at_unix_ms, receipt_digest FROM guided_schema_receipt WHERE slot=?`).get(RECEIPT_KEY) as
      | { readonly schema_version: number; readonly schema_digest: string; readonly database_id: string;
          readonly issued_at_unix_ms: number; readonly receipt_digest: string }
      | undefined;
    if (!receiptRow || receiptRow.schema_version !== GUIDED_SCHEMA_VERSION ||
        receiptRow.schema_digest !== GUIDED_SCHEMA_DIGEST) {
      throw new Error('untrusted provenance receipt');
    }
    const receipt: unknown = {
      schemaVersion: receiptRow.schema_version,
      schemaDigest: receiptRow.schema_digest,
      databaseId: receiptRow.database_id,
      issuedAtUnixMs: receiptRow.issued_at_unix_ms,
      receiptDigest: receiptRow.receipt_digest,
    };
    if (!this.#authority.verifyReceipt(receipt, this.#canonicalPath)) {
      throw new Error('provenance receipt verification refused');
    }
    const ledgerRows = this.#db.prepare(`SELECT step_id,task_id,case_ref_json,template_digest,
      step_kind,receipt_kind,terminal_event,terminal_decision,recorded_at_unix_ms,row_sha256
      FROM guided_consumed_steps`).all() as unknown as LedgerRow[];
    const ledgerById = new Map<string, LedgerRow>();
    for (const row of ledgerRows) {
      if (this.#ledgerDigest(row) !== row.row_sha256) throw new Error('ledger row digest mismatch');
      ledgerById.set(row.step_id, row);
    }
    const answerRows = this.#db.prepare(`SELECT step_id,task_id,case_ref_json,template_digest,
      outcome_json,outcome_sha256,recorded_at_unix_ms FROM guided_step_answers`).all() as unknown as AnswerRow[];
    const refusalRows = this.#db.prepare(`SELECT step_id,task_id,case_ref_json,template_digest,
      refusal_json,refusal_sha256,recorded_at_unix_ms FROM guided_step_refusals`).all() as unknown as RefusalRow[];
    for (const row of answerRows) {
      if (!this.#answerEnvelope(row.outcome_json, row.outcome_sha256, row)) {
        throw new Error('answer envelope binding mismatch');
      }
    }
    for (const row of refusalRows) {
      if (!this.#refusalEnvelope(row.refusal_json, row.refusal_sha256, row)) {
        throw new Error('refusal envelope binding mismatch');
      }
    }
    const answerById = new Map(answerRows.map((row) => [row.step_id, row]));
    const refusalById = new Map(refusalRows.map((row) => [row.step_id, row]));
    // Historical conflicts across the complete datasets: a stepId present
    // in BOTH payload tables is ambiguous no matter which Case or step is
    // currently selected. Never resolved silently.
    for (const stepId of answerById.keys()) {
      if (refusalById.has(stepId)) throw new Error('conflicting answer+refusal evidence');
    }
    // Exact payload cardinality, driven by the persisted StepKind and
    // receipt kind in the ledger.
    for (const row of answerRows) {
      const ledger = ledgerById.get(row.step_id);
      if (!ledger || !this.#ledgerAgrees(ledger, row.task_id, row.case_ref_json,
          row.template_digest, 'ASK', 'ANSWER', 'USER_SUBMIT', 'ANSWER', row.recorded_at_unix_ms)) {
        throw new Error('answer/ledger binding mismatch');
      }
    }
    for (const row of refusalRows) {
      const ledger = ledgerById.get(row.step_id);
      if (!ledger || !this.#ledgerAgrees(ledger, row.task_id, row.case_ref_json,
          row.template_digest, 'ASK', 'REFUSAL', 'USER_SUBMIT', 'REFUSE', row.recorded_at_unix_ms)) {
        throw new Error('refusal/ledger binding mismatch');
      }
    }
    for (const row of ledgerRows) {
      if (row.receipt_kind === 'ANSWER' && !answerById.has(row.step_id)) {
        throw new Error('unbound ledger answer row');
      }
      if (row.receipt_kind === 'REFUSAL' && !refusalById.has(row.step_id)) {
        // A consumed ASK refusal whose payload was lost cannot be
        // distinguished from a REVIEW_EFFECT refusal — ambiguous.
        throw new Error('missing ASK refusal receipt');
      }
    }
    const current = this.#read();
    if (current && current.state === 'CONSUMED') {
      // The persisted consumed Case must agree exactly with the ledger row,
      // which carries the StepKind and receipt kind that make the terminal
      // status unambiguous.
      const last = current.history[current.history.length - 1];
      if (!last || !TERMINAL_HISTORY.has(last.status) || last.stepId !== current.step.stepId) {
        throw new Error('consumed case terminal state unprovable');
      }
      const consumedAt = Date.parse(last.at);
      if (!Number.isFinite(consumedAt)) throw new Error('consumed case timestamp unprovable');
      const ledgerRow = ledgerById.get(current.step.stepId);
      let expectedStatus: string;
      if (!ledgerRow || ledgerRow.step_kind !== current.step.kind) {
        throw new Error('history/ledger kind mismatch');
      } else if (ledgerRow.receipt_kind === 'ANSWER') {
        expectedStatus = 'ACCEPTED';
      } else if (ledgerRow.receipt_kind === 'REFUSAL') {
        expectedStatus = 'REFUSED';
      } else if (ledgerRow.terminal_decision === 'APPROVE') {
        expectedStatus = 'ACCEPTED';
      } else if (current.step.kind === 'INSPECT') {
        expectedStatus = 'OBSERVATION_RECEIPT';
      } else {
        expectedStatus = 'REFUSED';
      }
      if (last.status !== expectedStatus ||
          !this.#ledgerAgrees(ledgerRow, current.step.taskId,
            JSON.stringify(current.step.caseRef), current.step.templateRef.digest,
            current.step.kind, ledgerRow.receipt_kind, ledgerRow.terminal_event,
            ledgerRow.terminal_decision, consumedAt)) {
        throw new Error('history/ledger terminal mismatch');
      }
    }
  }

  #rollback(): void {
    try { this.#db.exec('ROLLBACK'); } catch { /* retain unknown, no false receipt */ }
  }
}
