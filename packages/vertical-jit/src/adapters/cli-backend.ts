// Real CLI task backend for the Loop B vertical: executes the acquired
// provider's command-line interface with typed argv (I1 interface class,
// L2 §8.1 EnvironmentBackend seam). Task output lands on disk as evidence;
// the receipt references the files, never inlines them.

import { join } from 'node:path';
import {
  type AuthorizedAction,
  canonicalJson,
  type EnvironmentBackend,
  type EnvironmentFacts,
  type EnvironmentRequirements,
  ExecutionReceiptSchema,
  type Feasibility,
  type PreparedEnvironment,
  type ProviderCapabilityBinding,
  type ProviderEnvironmentBinding,
} from '@shun/contracts';
import type { FilesystemPort, PlanLedgerPort, ProcessPort } from '../ports.ts';

export interface CliTaskBackendDeps {
  readonly process: ProcessPort;
  readonly fs: FilesystemPort;
  readonly facts: EnvironmentFacts;
  readonly clock: () => string;
  readonly taskOutputDir: string;
  readonly timeoutMs?: number;
  /**
   * Trusted plan ledger (L2 §9.3). Every presented action is re-validated
   * against the ledger BEFORE any process spawn: a plan that never entered
   * the ledger, an action body that diverges from the ledger's copy, or an
   * expired authorization window is refused with zero side effects
   * (VJ-P1-03). An unwired ledger is a wiring fault and fails closed — this
   * backend refuses to spawn argv on the caller's presentation alone.
   */
  readonly ledger?: PlanLedgerPort;
}

export class CliTaskBackend implements EnvironmentBackend {
  readonly #deps: CliTaskBackendDeps;

  constructor(deps: CliTaskBackendDeps) {
    this.#deps = deps;
  }

  async observe(): Promise<EnvironmentFacts> {
    return this.#deps.facts;
  }

  async canPrepare(requirements: EnvironmentRequirements): Promise<Feasibility> {
    const facts = this.#deps.facts;
    const rejectionReasons: Feasibility['rejectionReasons'] = [];
    if (requirements.backendKind !== facts.backendKind) {
      rejectionReasons.push('BACKEND_KIND_INELIGIBLE');
    }
    if (requirements.os && !facts.os.toLowerCase().startsWith(requirements.os.toLowerCase())) {
      rejectionReasons.push('PLATFORM_UNSUPPORTED');
    }
    if (requirements.guiSessionRequired && !facts.guiSession) {
      rejectionReasons.push('GUI_SESSION_UNAVAILABLE');
    }
    if (requirements.networkAccess === 'FORBIDDEN' && facts.networkPolicy === 'OPEN') {
      rejectionReasons.push('NETWORK_POLICY_FORBIDDEN');
    }
    return { feasible: rejectionReasons.length === 0, rejectionReasons };
  }

  async prepare(
    _binding: ProviderEnvironmentBinding | ProviderCapabilityBinding,
  ): Promise<PreparedEnvironment> {
    return {
      preparedEnvironmentId: `prepared-${this.#deps.facts.environmentId}`,
      environmentId: this.#deps.facts.environmentId,
    };
  }

  async execute(action: AuthorizedAction) {
    const startedAt = this.#deps.clock();
    // Trusted-boundary re-validation (VJ-P1-03): argv is never spawned for a
    // presentation the trusted ledger does not back.
    const refusal = await this.#ledgerRefusal(action);
    if (refusal) {
      return this.#refusedReceipt(action, startedAt);
    }
    const parameters = action.action.parameters as { executable?: unknown; argv?: unknown };
    const executable = typeof parameters.executable === 'string' ? parameters.executable : '';
    const argv = Array.isArray(parameters.argv)
      ? parameters.argv.filter((entry): entry is string => typeof entry === 'string')
      : [];
    if (!executable) {
      return this.#failedReceipt(action, startedAt);
    }
    const result = await this.#deps.process.run({
      argv: [executable, ...argv],
      timeoutMs: this.#deps.timeoutMs ?? 5 * 60_000,
    });
    const stdoutPath = join(this.#deps.taskOutputDir, 'stdout.txt');
    const stderrPath = join(this.#deps.taskOutputDir, 'stderr.txt');
    await this.#deps.fs.writeText(stdoutPath, result.stdout);
    await this.#deps.fs.writeText(stderrPath, result.stderr);
    const ok = result.exitCode === 0 && !result.timedOut;
    return ExecutionReceiptSchema.parse({
      actionId: action.actionId,
      environmentId: this.#deps.facts.environmentId,
      providerId: 'cli-task',
      providerVersion: 'task-execution',
      startedAt,
      finishedAt: this.#deps.clock(),
      terminal: ok ? 'SUCCEEDED' : 'FAILED',
      exitCode: result.exitCode,
      outputRefs: [stdoutPath, stderrPath],
      stdoutRef: stdoutPath,
      sideEffectEvidence: {
        sideEffectClass: action.action.sideEffectClass,
        // VJ-P2-06: exit-0 is effect completion, not verification. The
        // expected post-state is verified independently downstream (the
        // precommitted oracle / orchestrator post-state checks); until then
        // the receipt must not claim COMPLETED_VERIFIED. The frozen taxonomy
        // has no "completed-unverified" value, so the conservative non-claim
        // is MAY_HAVE_EXECUTED_UNCERTAIN with postStateVerified=false.
        recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        postStateVerified: false,
      },
    });
  }

  /**
   * Trusted-ledger check for one presented action. Returns a refusal reason,
   * or undefined when the presentation is backed by the ledger. Refusals
   * happen BEFORE any process spawn (VJ-P1-03).
   */
  async #ledgerRefusal(action: AuthorizedAction): Promise<string | undefined> {
    const ledger = this.#deps.ledger;
    if (!ledger) {
      // Fail-closed (VJ-P1-03): no trusted ledger wired means argv cannot be
      // re-validated against anything — spawn nothing and refuse. An
      // unwired ledger is a wiring fault, never consent.
      return 'trusted plan ledger is not wired — refusing to spawn argv on the caller presentation alone';
    }
    const plan = await ledger.byHash(action.planHash);
    if (!plan) {
      return `plan ${action.planHash} is not in the trusted ledger`;
    }
    const planned = plan.actions.find((candidate) => candidate.actionId === action.actionId);
    if (!planned) {
      return `action ${action.actionId} is not part of plan ${action.planHash}`;
    }
    if (canonicalJson(planned) !== canonicalJson(action.action)) {
      return 'presented action body does not match the trusted plan ledger';
    }
    if (action.expiresAt !== undefined && action.expiresAt <= this.#deps.clock()) {
      return `authorization window expired at ${action.expiresAt}`;
    }
    return undefined;
  }

  #refusedReceipt(action: AuthorizedAction, startedAt: string) {
    // Refused before any effect: terminal REFUSED, fail-closed recovery.
    // (The refusal reason is computed by #ledgerRefusal; the receipt schema
    // carries no free-text field for it and the classification is what
    // recovery consumes.)
    return ExecutionReceiptSchema.parse({
      actionId: action.actionId,
      environmentId: this.#deps.facts.environmentId,
      providerId: 'cli-task',
      providerVersion: 'task-execution',
      startedAt,
      finishedAt: this.#deps.clock(),
      terminal: 'REFUSED',
      outputRefs: [],
      sideEffectEvidence: {
        sideEffectClass: action.action.sideEffectClass,
        recoveryClassification: 'FAILED_BEFORE_EFFECT',
        postStateVerified: false,
      },
    });
  }

  #failedReceipt(action: AuthorizedAction, startedAt: string) {
    return ExecutionReceiptSchema.parse({
      actionId: action.actionId,
      environmentId: this.#deps.facts.environmentId,
      providerId: 'cli-task',
      providerVersion: 'task-execution',
      startedAt,
      finishedAt: this.#deps.clock(),
      terminal: 'FAILED',
      outputRefs: [],
      sideEffectEvidence: {
        sideEffectClass: action.action.sideEffectClass,
        recoveryClassification: 'FAILED_BEFORE_EFFECT',
        // VJ-P2-06: nothing was verified — the executable was never spawned.
        postStateVerified: false,
      },
    });
  }

  async cancel(_actionId: string): Promise<void> {
    /* the process port has no live handle exposure; timeouts bound the task */
  }

  async cleanup(_prepared: PreparedEnvironment): Promise<void> {
    /* task outputs are evidence — cleanup is deliberately not automatic */
  }
}
