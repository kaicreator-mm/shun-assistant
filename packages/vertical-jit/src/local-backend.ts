// Privileged backend base for the Loop B vertical (L2 §9.1/§9.3/§9.4).
//
// The backend receives ONLY an AuthorizedAction plus its grant presentation
// and re-validates the presentation itself against the trusted plan ledger
// and the CURRENT authority/policy state — never on the caller's say-so. The
// concrete side effect is delegated to a `perform` closure (winget adapter,
// memory effects in tests), while this base owns the phase journal, the
// fail-closed validation order and the recovery semantics:
//
//   RECEIVED → (grant validation) → VALIDATED → EXEC_START → EXEC_DONE →
//   RECEIPT_WRITTEN
//
// A refused presentation journals RECEIVED only (recovery NOT_STARTED); a
// declined elevation journals a NO_EFFECT marker (NOT_STARTED, L2 §9.4);
// an interruption between EXEC_START and EXEC_DONE leaves the journal torn
// and classifies MAY_HAVE_EXECUTED_UNCERTAIN upstream.
import {
  type AuthorizedAction,
  type ExecutionBackend,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
  type ExecutionTerminal,
  type PlanAction,
  ShunContractError,
} from '@shun/contracts';
import type { JournalPort } from './journal.ts';
import type { LocalAuthority } from './local-authority.ts';

/** Transport-level crash of the privileged worker (simulates a killed helper). */
export class BackendInterruptError extends Error {
  constructor(actionId: string) {
    super(`privileged worker for ${actionId} was interrupted mid-effect`);
    this.name = 'BackendInterruptError';
  }
}

export type PrivilegedFault = {
  kind: 'UAC_DECLINED' | 'INTERRUPT' | 'FAIL_EXEC' | 'CRASH_AFTER_EFFECT';
  /** Match the affected actions; absent ⇒ applies to every action. */
  when?: (action: AuthorizedAction) => boolean;
};

export interface PerformOutcome {
  readonly ok: boolean;
  readonly exitCode?: number;
  readonly note?: string;
  readonly outputRefs?: readonly string[];
  /**
   * True when the worker refused before any effect phase (e.g. elevation
   * declined): receipt classifies NOT_STARTED and the journal carries an
   * explicit NO_EFFECT marker (L2 §9.4 UAC_DECLINED semantics).
   */
  readonly noEffect?: true;
}

export interface LocalBackendDeps {
  readonly authority: LocalAuthority;
  readonly clock: () => string;
  readonly journals: (actionId: string) => JournalPort;
  readonly environmentId: string;
  readonly providerId: (action: AuthorizedAction) => string;
  readonly providerVersion: (action: AuthorizedAction) => string;
  perform(action: PlanAction): Promise<PerformOutcome>;
  /** Fault injection for negative scenarios; production adapters pass none. */
  faults?: readonly PrivilegedFault[];
}

export class LocalPrivilegedBackend implements ExecutionBackend {
  readonly #deps: LocalBackendDeps;

  constructor(deps: LocalBackendDeps) {
    this.#deps = deps;
  }

  async #journalFor(actionId: string): Promise<JournalPort> {
    return this.#deps.journals(actionId);
  }

  async #receipt(
    action: AuthorizedAction,
    startedAt: string,
    terminal: ExecutionTerminal,
    classification: ExecutionReceipt['sideEffectEvidence']['recoveryClassification'],
    postStateVerified: boolean,
    exitCode: number | undefined,
    outputRefs: string[],
    note?: string,
  ): Promise<ExecutionReceipt> {
    return ExecutionReceiptSchema.parse({
      actionId: action.actionId,
      environmentId: this.#deps.environmentId,
      providerId: this.#deps.providerId(action),
      providerVersion: this.#deps.providerVersion(action),
      startedAt,
      finishedAt: this.#deps.clock(),
      terminal,
      ...(exitCode !== undefined ? { exitCode } : {}),
      outputRefs,
      sideEffectEvidence: {
        sideEffectClass: action.action.sideEffectClass,
        recoveryClassification: classification,
        postStateVerified,
        ...(note ? { journalRef: note } : {}),
      },
    });
  }

  async execute(action: AuthorizedAction, presentation: unknown): Promise<ExecutionReceipt> {
    const journal = await this.#journalFor(action.actionId);
    const startedAt = this.#deps.clock();
    await journal.append({
      seq: 0,
      ts: startedAt,
      phase: 'RECEIVED',
      actionId: action.actionId,
    });

    const plan = await this.#deps.authority.ledger.byHash(action.planHash);
    if (!plan) {
      throw new ShunContractError(
        'GRANT_PLAN_MISMATCH',
        `plan ${action.planHash} is not in the trusted ledger — the boundary never accepts unseen plans`,
      );
    }
    // Fail-closed boundary validation (contracts §4.6.1): typed refusal
    // BEFORE any effect; the journal intentionally stays at RECEIVED.
    const verdict = this.#deps.authority.validatePresentation({
      grant: presentation,
      plan,
      action,
      now: this.#deps.clock(),
    });
    if (!verdict.ok) {
      throw new ShunContractError(verdict.code, verdict.detail);
    }
    await journal.append({
      seq: 1,
      ts: this.#deps.clock(),
      phase: 'VALIDATED',
      actionId: action.actionId,
      detail: `grant ${verdict.grant.grantId}`,
    });

    const fault = this.#deps.faults?.find((candidate) =>
      candidate.when ? candidate.when(action) : true,
    );

    if (fault?.kind === 'UAC_DECLINED') {
      // The elevation seam refused BEFORE any effect phase (L2 §9.4:
      // UAC_DECLINED ⇒ NOT_STARTED).
      await journal.append({
        seq: 2,
        ts: this.#deps.clock(),
        phase: 'RECEIPT_WRITTEN',
        actionId: action.actionId,
        detail: 'NO_EFFECT:UAC_DECLINED — elevation refused before the effect phase',
      });
      return this.#receipt(
        action,
        startedAt,
        'UAC_DECLINED',
        'NOT_STARTED',
        false,
        undefined,
        [],
        `journal:${action.actionId}`,
      );
    }

    await journal.append({
      seq: 3,
      ts: this.#deps.clock(),
      phase: 'EXEC_START',
      actionId: action.actionId,
    });

    if (fault?.kind === 'INTERRUPT') {
      // Simulates the worker dying mid-effect: no EXEC_DONE is ever written.
      throw new BackendInterruptError(action.actionId);
    }

    if (fault?.kind === 'CRASH_AFTER_EFFECT') {
      // Real effect first, then the worker dies before journaling the outcome:
      // exactly the crash-after-effect window the reconcile-first rule exists
      // for (L2 §9.4 MAY_HAVE_EXECUTED_UNCERTAIN).
      await this.#deps.perform(action.action);
      throw new BackendInterruptError(action.actionId);
    }

    if (fault?.kind === 'FAIL_EXEC') {
      // Simulates the worker completing with a failed outcome: the journal is
      // whole, the receipt records FAILED, the expected state is not met.
      await journal.append({
        seq: 7,
        ts: this.#deps.clock(),
        phase: 'EXEC_DONE',
        actionId: action.actionId,
        detail: 'simulated execution failure',
      });
      await journal.append({
        seq: 8,
        ts: this.#deps.clock(),
        phase: 'RECEIPT_WRITTEN',
        actionId: action.actionId,
      });
      return this.#receipt(action, startedAt, 'FAILED', 'COMPLETED_VERIFIED', true, 1, []);
    }

    const outcome = await this.#deps.perform(action.action);
    if (outcome.noEffect) {
      await journal.append({
        seq: 6,
        ts: this.#deps.clock(),
        phase: 'RECEIPT_WRITTEN',
        actionId: action.actionId,
        detail: `NO_EFFECT:${outcome.note ?? 'worker refused before effect'}`,
      });
      return this.#receipt(
        action,
        startedAt,
        'UAC_DECLINED',
        'NOT_STARTED',
        false,
        outcome.exitCode,
        [],
        `journal:${action.actionId}`,
      );
    }
    await journal.append({
      seq: 4,
      ts: this.#deps.clock(),
      phase: 'EXEC_DONE',
      actionId: action.actionId,
      ...(outcome.note ? { detail: outcome.note } : {}),
    });
    await journal.append({
      seq: 5,
      ts: this.#deps.clock(),
      phase: 'RECEIPT_WRITTEN',
      actionId: action.actionId,
    });
    return this.#receipt(
      action,
      startedAt,
      outcome.ok ? 'SUCCEEDED' : 'FAILED',
      'COMPLETED_VERIFIED',
      true,
      outcome.exitCode,
      [...(outcome.outputRefs ?? [])],
      `journal:${action.actionId}`,
    );
  }
}
