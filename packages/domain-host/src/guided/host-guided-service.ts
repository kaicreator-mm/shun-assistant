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
  readonly terminal_event: string;
  readonly terminal_decision: string;
  readonly recorded_at_unix_ms: number;
  readonly row_sha256: string;
};
const CASE_KEY = 'selected-case';
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
  /**
   * Set when the open-time ledger migration cannot prove a complete replay
   * fence from the persisted evidence. The service then fails closed: staging
   * and decisions are refused with the stable code until the state is
   * repaired out of band. Never reset silently, never deletes data.
   */
  #ledgerUnavailable: string | null = null;

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
    // A refused ASK submission is durable evidence of the refusal, but it is
    // a separately typed receipt: it never lands in guided_step_answers and
    // can never be read back as an accepted answer.
    this.#db.exec(`CREATE TABLE IF NOT EXISTS guided_step_refusals (
      step_id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      case_ref_json TEXT NOT NULL,
      template_digest TEXT NOT NULL,
      refusal_json TEXT NOT NULL,
      refusal_sha256 TEXT NOT NULL,
      recorded_at_unix_ms INTEGER NOT NULL
    )`);
    // G4: Host-private durable consumed-step ledger. The uniqueness fence is
    // global — keyed by stepId, independent of the single selected-Case row —
    // so a step consumed under Case A stays fenced after A -> B -> A and
    // across service/process restarts. Rows are never exposed through
    // state(); they are internal replay evidence with row-integrity digests.
    this.#db.exec(`CREATE TABLE IF NOT EXISTS guided_consumed_steps (
      step_id TEXT PRIMARY KEY,
      task_id TEXT NOT NULL,
      case_ref_json TEXT NOT NULL,
      template_digest TEXT NOT NULL,
      terminal_event TEXT NOT NULL CHECK (terminal_event IN ('USER_SUBMIT','OBSERVATION_RECEIPT')),
      terminal_decision TEXT NOT NULL CHECK (terminal_decision IN ('ANSWER','APPROVE','REFUSE')),
      recorded_at_unix_ms INTEGER NOT NULL,
      row_sha256 TEXT NOT NULL
    )`);
    this.#clock = clock;
    this.#migrateLedger();
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
      const history = [...stored.history, {
        at: new Date(now).toISOString(),
        stepId: stored.step.stepId,
        // A REFUSE is a refusal, but a trusted Host observation receipt is
        // recorded as what it is — an observation receipt — never mislabeled
        // REFUSED and never implying human refusal, grant or effect.
        status: raw.decision === 'REFUSE'
          ? (outcomeEvent === 'OBSERVATION_RECEIPT' ? 'OBSERVATION_RECEIPT' : 'REFUSED')
          : 'ACCEPTED',
      }];
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
          now,
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
          now,
        );
        if (saved.changes !== 1) {
          this.#db.exec('ROLLBACK');
          return { status: 'STALE', code: 'GUIDED_REFUSAL_ALREADY_RECORDED' };
        }
      }
      // The consumed-step ledger binds every terminal outcome (ANSWER,
      // APPROVE, REFUSE on ASK/REVIEW_EFFECT, and the INSPECT Host receipt)
      // in the same transaction as the payload receipt above and the
      // selected-case CAS below. A pre-existing row means the step was
      // already consumed: fail closed as STALE and roll everything back —
      // RECORDED is never reported unless all durable writes commit. The
      // check-then-insert is race-free because BEGIN IMMEDIATE already
      // excludes every other writer for the whole transaction.
      if (this.#ledgerRow(stored.step.stepId)) {
        this.#db.exec('ROLLBACK');
        return { status: 'STALE', code: 'GUIDED_STEP_ALREADY_CONSUMED' };
      }
      const terminalEvent = outcomeEvent === 'OBSERVATION_RECEIPT' ? 'OBSERVATION_RECEIPT' : 'USER_SUBMIT';
      const terminalDecision = raw.decision === 'ANSWER' ? 'ANSWER' : raw.decision === 'APPROVE' ? 'APPROVE' : 'REFUSE';
      const caseRefJson = JSON.stringify(stored.step.caseRef);
      const ledgerSaved = this.#db.prepare(`INSERT INTO guided_consumed_steps(
        step_id,task_id,case_ref_json,template_digest,terminal_event,terminal_decision,recorded_at_unix_ms,row_sha256
      ) VALUES(?,?,?,?,?,?,?,?)`).run(
        stored.step.stepId,
        stored.step.taskId,
        caseRefJson,
        stored.step.templateRef.digest,
        terminalEvent,
        terminalDecision,
        now,
        this.#ledgerDigest({
          step_id: stored.step.stepId,
          task_id: stored.step.taskId,
          case_ref_json: caseRefJson,
          template_digest: stored.step.templateRef.digest,
          terminal_event: terminalEvent,
          terminal_decision: terminalDecision,
          recorded_at_unix_ms: now,
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

  /**
   * Trusted Host-only readback for the explicit refusal outcome of the exact
   * consumed ASK step. A refused payload is preserved as refusal evidence —
   * never as an accepted answer — and the digest detects local corruption.
   */
  readRecordedRefusal(stepId: string): unknown | undefined {
    if (typeof stepId !== 'string' || !STEP_ID.test(stepId)) return undefined;
    const row = this.#db.prepare(`SELECT refusal_json,refusal_sha256
      FROM guided_step_refusals WHERE step_id=?`).get(stepId) as
      | { refusal_json: string; refusal_sha256: string }
      | undefined;
    if (!row || !/^[a-f0-9]{64}$/.test(row.refusal_sha256)) return undefined;
    const digest = createHash('sha256').update(row.refusal_json, 'utf8').digest('hex');
    if (digest !== row.refusal_sha256) return undefined;
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
   * can no longer be trusted, so migration fails closed instead of fencing
   * (or not fencing) on corrupt data.
   */
  #ledgerDigest(row: Omit<LedgerRow, 'row_sha256'>): string {
    return createHash('sha256').update(
      `${row.step_id}|${row.task_id}|${row.case_ref_json}|${row.template_digest}|` +
      `${row.terminal_event}|${row.terminal_decision}|${row.recorded_at_unix_ms}`,
      'utf8',
    ).digest('hex');
  }

  /**
   * Open-time, transactional, idempotent backfill of the consumed-step
   * ledger from everything the persisted state can prove: digest-verified
   * answer/refusal payload rows and the terminal history of the currently
   * persisted selected Case. Previously discarded other-Case history is not
   * reconstructable and is not claimed; ambiguous or corrupt evidence fails
   * closed with a stable code and never deletes or resets data.
   */
  #migrateLedger(): void {
    try {
      this.#db.exec('BEGIN IMMEDIATE');
      const existing = this.#db.prepare(`SELECT step_id,task_id,case_ref_json,template_digest,
        terminal_event,terminal_decision,recorded_at_unix_ms,row_sha256
        FROM guided_consumed_steps`).all() as unknown as LedgerRow[];
      for (const row of existing) {
        if (this.#ledgerDigest(row) !== row.row_sha256) throw new Error('ledger row digest mismatch');
      }
      const answerRows = this.#db.prepare(`SELECT step_id,task_id,case_ref_json,template_digest,
        outcome_json,outcome_sha256,recorded_at_unix_ms FROM guided_step_answers`).all() as unknown as {
        step_id: string; task_id: string; case_ref_json: string; template_digest: string;
        outcome_json: string; outcome_sha256: string; recorded_at_unix_ms: number;
      }[];
      const refusalRows = this.#db.prepare(`SELECT step_id,task_id,case_ref_json,template_digest,
        refusal_json,refusal_sha256,recorded_at_unix_ms FROM guided_step_refusals`).all() as unknown as {
        step_id: string; task_id: string; case_ref_json: string; template_digest: string;
        refusal_json: string; refusal_sha256: string; recorded_at_unix_ms: number;
      }[];
      for (const row of answerRows) {
        if (createHash('sha256').update(row.outcome_json, 'utf8').digest('hex') !== row.outcome_sha256) {
          throw new Error('answer row digest mismatch');
        }
      }
      for (const row of refusalRows) {
        if (createHash('sha256').update(row.refusal_json, 'utf8').digest('hex') !== row.refusal_sha256) {
          throw new Error('refusal row digest mismatch');
        }
      }
      const answerById = new Map(answerRows.map((row) => [row.step_id, row]));
      const refusalById = new Map(refusalRows.map((row) => [row.step_id, row]));
      const backfill = this.#db.prepare(`INSERT OR IGNORE INTO guided_consumed_steps(
        step_id,task_id,case_ref_json,template_digest,terminal_event,terminal_decision,recorded_at_unix_ms,row_sha256
      ) VALUES(?,?,?,?,?,?,?,?)`);
      const writeRow = (row: Omit<LedgerRow, 'row_sha256'>): void => {
        backfill.run(row.step_id, row.task_id, row.case_ref_json, row.template_digest,
          row.terminal_event, row.terminal_decision, row.recorded_at_unix_ms, this.#ledgerDigest(row));
      };
      for (const row of answerRows) {
        writeRow({
          step_id: row.step_id, task_id: row.task_id, case_ref_json: row.case_ref_json,
          template_digest: row.template_digest, terminal_event: 'USER_SUBMIT',
          terminal_decision: 'ANSWER', recorded_at_unix_ms: row.recorded_at_unix_ms,
        });
      }
      for (const row of refusalRows) {
        writeRow({
          step_id: row.step_id, task_id: row.task_id, case_ref_json: row.case_ref_json,
          template_digest: row.template_digest, terminal_event: 'USER_SUBMIT',
          terminal_decision: 'REFUSE', recorded_at_unix_ms: row.recorded_at_unix_ms,
        });
      }
      const current = this.#read();
      if (current && current.state === 'CONSUMED') {
        // Classify the terminal decision of the persisted consumed Case from
        // provable evidence only; any inconsistency is ambiguous and fails
        // closed. Note prior-Case terminal rows that were discarded when
        // their Case was deselected are not reconstructable and are not
        // claimed as fenced.
        const last = current.history[current.history.length - 1];
        if (!last || !TERMINAL_HISTORY.has(last.status) || last.stepId !== current.step.stepId) {
          throw new Error('consumed case terminal state unprovable');
        }
        const consumedAt = Date.parse(last.at);
        if (!Number.isFinite(consumedAt)) throw new Error('consumed case timestamp unprovable');
        const answerRow = answerById.get(current.step.stepId);
        const refusalRow = refusalById.get(current.step.stepId);
        if (answerRow && refusalRow) throw new Error('conflicting consumption evidence');
        const caseRefJson = JSON.stringify(current.step.caseRef);
        let terminal: Omit<LedgerRow, 'row_sha256'>;
        if (answerRow) {
          if (last.status !== 'ACCEPTED') throw new Error('answer evidence conflicts with history');
          terminal = {
            step_id: current.step.stepId, task_id: current.step.taskId, case_ref_json: caseRefJson,
            template_digest: current.step.templateRef.digest, terminal_event: 'USER_SUBMIT',
            terminal_decision: 'ANSWER', recorded_at_unix_ms: consumedAt,
          };
        } else if (refusalRow) {
          if (last.status !== 'REFUSED') throw new Error('refusal evidence conflicts with history');
          terminal = {
            step_id: current.step.stepId, task_id: current.step.taskId, case_ref_json: caseRefJson,
            template_digest: current.step.templateRef.digest, terminal_event: 'USER_SUBMIT',
            terminal_decision: 'REFUSE', recorded_at_unix_ms: consumedAt,
          };
        } else if (last.status === 'ACCEPTED') {
          // An ASK answer always persists a payload row, so ACCEPTED without
          // one is provably a REVIEW_EFFECT approval.
          terminal = {
            step_id: current.step.stepId, task_id: current.step.taskId, case_ref_json: caseRefJson,
            template_digest: current.step.templateRef.digest, terminal_event: 'USER_SUBMIT',
            terminal_decision: 'APPROVE', recorded_at_unix_ms: consumedAt,
          };
        } else if (last.status === 'REFUSED') {
          // A G3 ASK refusal always persists a typed refusal receipt, so
          // REFUSED without one is provably a REVIEW_EFFECT refusal.
          terminal = {
            step_id: current.step.stepId, task_id: current.step.taskId, case_ref_json: caseRefJson,
            template_digest: current.step.templateRef.digest, terminal_event: 'USER_SUBMIT',
            terminal_decision: 'REFUSE', recorded_at_unix_ms: consumedAt,
          };
        } else {
          terminal = {
            step_id: current.step.stepId, task_id: current.step.taskId, case_ref_json: caseRefJson,
            template_digest: current.step.templateRef.digest, terminal_event: 'OBSERVATION_RECEIPT',
            terminal_decision: 'REFUSE', recorded_at_unix_ms: consumedAt,
          };
        }
        writeRow(terminal);
      }
      this.#db.exec('COMMIT');
    } catch {
      this.#rollback();
      this.#ledgerUnavailable = 'GUIDED_LEDGER_MIGRATION_AMBIGUOUS';
    }
  }

  #rollback(): void {
    try { this.#db.exec('ROLLBACK'); } catch { /* retain unknown, no false receipt */ }
  }
}
