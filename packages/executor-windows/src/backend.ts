// LocalWindowsBackend — the P0 unprivileged execution surface (L2 §8.1, §8.2).
//
// In-process typed execution for NONE/USER-privilege actions: same allowlist,
// same interpreter, same journal/receipt/recovery semantics as the privileged
// helper — the privilege boundary is the only difference. Elevated actions
// are structured REFUSED here (the privileged ExecutionBackend owns them);
// grant/plan validation runs fail-closed against the SAME trusted authority
// store the helper uses, so authorization is never "caller's say-so" on
// either surface.

import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';
import {
  type AuthorizedAction,
  type EnvironmentBackend,
  type EnvironmentFacts,
  type EnvironmentRequirements,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
  type Feasibility,
  type PreparedEnvironment,
  type ProviderEnvironmentBinding,
  validateGrantPresentation,
} from '@shun/contracts';
import { assertSafeActionId } from './action-id.ts';
import { checkStepSurface, resolveActionStep } from './action-surface.ts';
import { observeEnvironment } from './facts.ts';
import {
  CancelledError,
  checkGuards,
  DeadlineError,
  type InterpreterContext,
  type InterpreterScope,
  runStep,
  type StepOutcome,
} from './interpreter.ts';
import { JournalWriter, journalDigest, readJournal } from './journal.ts';
import { reconcileExpectedState, rerunVerifyStep } from './poststate.ts';
import { type ClassificationResult, classifyRecovery } from './recovery.ts';
import { preflightScope } from './scope-preflight.ts';
import {
  FileCurrentnessSource,
  FileGrantSource,
  FilePlanSource,
  hmacGrantIntegrityVerifier,
} from './trusted-store.ts';

export const PROVIDER_ID = 'shun.executor-windows';
export const PROVIDER_VERSION = '0.1.0';

export interface LocalWindowsBackendOptions {
  /** Trusted authority store (currentness, grants, plans, HMAC key). */
  authorityDir: string;
  /** Root for per-action journals/evidence; also the disk-free probe root. */
  workspaceRoot: string;
  defaultTimeoutMs?: number;
  networkPolicy?: EnvironmentFacts['networkPolicy'];
}

interface InFlightRun {
  runDir: string;
  cancelFile: string;
}

export class LocalWindowsBackend implements EnvironmentBackend {
  private readonly options: LocalWindowsBackendOptions;
  private factsCache?: EnvironmentFacts;
  private readonly inFlight = new Map<string, InFlightRun>();

  constructor(options: LocalWindowsBackendOptions) {
    this.options = options;
  }

  async observe(): Promise<EnvironmentFacts> {
    this.factsCache ??= await observeEnvironment({
      workspaceRoot: this.options.workspaceRoot,
      networkPolicy: this.options.networkPolicy,
    });
    return this.factsCache;
  }

  async canPrepare(requirements: EnvironmentRequirements): Promise<Feasibility> {
    const facts = await this.observe();
    const rejections: Feasibility['rejectionReasons'] = [];
    if (requirements.backendKind !== 'LOCAL_WINDOWS') rejections.push('BACKEND_KIND_INELIGIBLE');
    if (requirements.os && requirements.os !== 'WINDOWS') rejections.push('PLATFORM_UNSUPPORTED');
    if (requirements.arch && facts.arch !== archOf(requirements.arch))
      rejections.push('ARCH_UNSUPPORTED');
    if (
      requirements.privilegeMode === 'ELEVATED_ADMIN' &&
      facts.privilegeMode !== 'ELEVATED_ADMIN'
    ) {
      rejections.push('PRIVILEGE_INSUFFICIENT');
    }
    if (requirements.guiSessionRequired && !facts.guiSession)
      rejections.push('GUI_SESSION_UNAVAILABLE');
    if (requirements.networkAccess === 'REQUIRED' && facts.networkPolicy === 'OFFLINE') {
      rejections.push('NETWORK_POLICY_FORBIDDEN');
    }
    if (requirements.networkAccess === 'FORBIDDEN' && facts.networkPolicy === 'OPEN') {
      rejections.push('NETWORK_POLICY_FORBIDDEN');
    }
    if (
      requirements.minFreeDiskMb !== undefined &&
      facts.resources.freeDiskMb < requirements.minFreeDiskMb
    ) {
      rejections.push('RESOURCE_INSUFFICIENT');
    }
    const missing = (requirements.runtimeCapabilities ?? []).filter(
      (c) => !facts.runtimeCapabilities.includes(c),
    );
    if (missing.length > 0) rejections.push('RUNTIME_CAPABILITY_MISSING');
    return { feasible: rejections.length === 0, rejectionReasons: rejections };
  }

  async prepare(binding: ProviderEnvironmentBinding): Promise<PreparedEnvironment> {
    const facts = await this.observe();
    if (binding.environmentId !== facts.environmentId) {
      throw new Error(
        `binding targets environment ${binding.environmentId}, this backend observes ${facts.environmentId}`,
      );
    }
    if (!binding.feasibility.feasible) {
      throw new Error(
        `binding marked infeasible: ${binding.feasibility.rejectionReasons.join(', ')}`,
      );
    }
    return {
      preparedEnvironmentId: `prep-${randomUUID()}`,
      environmentId: binding.environmentId,
    };
  }

  async cleanup(prepared: PreparedEnvironment): Promise<void> {
    // The P0 local backend prepares no durable environment resources; the
    // prepared handle is disposable. Journals/evidence are retained as
    // recovery evidence, deliberately not cleaned here.
    void prepared;
  }

  /** Unprivileged in-process execution of ONE allowlisted action (L2 §8.1). */
  async execute(action: AuthorizedAction): Promise<ExecutionReceipt> {
    // actionId is caller-controlled (contracts floor: min length only) and is
    // spliced into the run directory name below — reject path semantics before
    // any artifact path is derived from it.
    assertSafeActionId(action.actionId);
    const runDir = join(
      this.options.workspaceRoot,
      'executions',
      `${action.actionId}-${Date.now()}-${randomUUID().slice(0, 8)}`,
    );
    mkdirSync(runDir, { recursive: true });
    const journalFile = join(runDir, 'journal.jsonl');
    const receiptFile = join(runDir, 'receipt.json');
    const cancelFile = join(runDir, 'cancel.sentinel');
    const journal = new JournalWriter(journalFile, process.pid);
    const startedAt = new Date().toISOString();
    this.inFlight.set(action.actionId, { runDir, cancelFile });
    try {
      journal.append('RECEIVED', {
        detail: { actionId: action.actionId, surface: 'in-process-unprivileged' },
      });

      const refused = (reason: string, code?: string): ExecutionReceipt =>
        refusedReceipt({
          actionId: action.actionId,
          journal,
          journalFile,
          receiptFile,
          startedAt,
          reason,
          code,
          sideEffectClass: action.action.sideEffectClass,
        });

      // Trusted inputs: grant fetched from the authority store by
      // authorizationRef; plan by planHash; currentness current.
      const grant = new FileGrantSource(join(this.options.authorityDir, 'grants')).byGrantId(
        action.authorizationRef,
      );
      if (!grant)
        return refused(`grant ${action.authorizationRef} not found in the authority store`);
      const plan = new FilePlanSource(join(this.options.authorityDir, 'plans')).byPlanHash(
        action.planHash,
      );
      if (!plan) return refused(`plan ${action.planHash} not found in the authority store`);
      const currentness = new FileCurrentnessSource(
        join(this.options.authorityDir, 'current-authority.json'),
      ).read();
      const verdict = validateGrantPresentation({
        grant,
        plan,
        action,
        currentAuthority: currentness,
        now: new Date().toISOString(),
        verifyIntegrity: hmacGrantIntegrityVerifier(this.options.authorityDir),
      });
      if (!verdict.ok)
        return refused(`grant rejected: ${verdict.code} — ${verdict.detail}`, verdict.code);
      journal.append('PLAN_IDENTITY_OK', { detail: { planHash: action.planHash } });
      journal.append('GRANT_OK', { detail: { grantId: grant.grantId } });

      const step = resolveActionStep(action);
      if (!step) return refused(`unknown op '${action.action.op}' — no arbitrary shell endpoint`);
      const surface = checkStepSurface(step);
      if (!surface.ok) return refused(`action surface refused: ${surface.reason}`);

      const scope: InterpreterScope = {
        filesystem: verdict.grant.actionScope.filesystem,
        registry: verdict.grant.actionScope.registry,
      };
      const scopeReason = preflightScope(step, scope);
      if (scopeReason) return refused(`scope escape refused before any effect: ${scopeReason}`);
      if (action.action.requiredPrivilege === 'ELEVATED') {
        return refused('ELEVATED actions must go through the privileged one-shot helper backend');
      }
      journal.append('SCOPE_OK', { detail: { actionId: action.actionId } });
      journal.append('PRIVILEGE_OK', {
        detail: { privilegeLevel: verdict.grant.actionScope.privilegeLevel },
      });

      const timeoutMs = action.action.timeoutMs ?? this.options.defaultTimeoutMs ?? 60000;
      const ctx: InterpreterContext = {
        journal,
        scope,
        isElevated: (await this.observe()).privilegeMode === 'ELEVATED_ADMIN',
        deadlineAt: new Date(Date.now() + timeoutMs),
        cancelFile,
        evidenceDir: join(runDir, 'evidence'),
      };

      journal.append('EXEC_BEGIN', { detail: { totalSteps: 1 } });
      journal.append('EXEC_START', { step: 0, op: step.op });
      let outcome: StepOutcome;
      try {
        checkGuards(ctx, 'before-step');
        outcome = await runStep(step, ctx);
        checkGuards(ctx, 'after-step');
      } catch (err) {
        if (err instanceof CancelledError) {
          return this.finalize({
            action: action.actionId,
            terminal: 'CANCELLED',
            startedAt,
            reason: 'cancel sentinel observed around the effect window',
            sideEffectClass: action.action.sideEffectClass,
            journal,
            journalFile,
            receiptFile,
            classification: {
              recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
              resolvedByPostState: false,
              basis: 'cancelled around the effect window',
            },
            postStateVerified: false,
          });
        }
        if (err instanceof DeadlineError) {
          return this.finalize({
            action: action.actionId,
            terminal: 'TIMED_OUT',
            startedAt,
            reason: err.message,
            sideEffectClass: action.action.sideEffectClass,
            journal,
            journalFile,
            receiptFile,
            classification: {
              recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
              resolvedByPostState: false,
              basis: 'deadline fired around the effect window',
            },
            postStateVerified: false,
          });
        }
        throw err;
      }

      if (outcome.ok) {
        journal.append('EXEC_DONE', { step: 0, op: step.op, detail: outcome.result });
      } else {
        journal.append('EXEC_STEP_FAILED', {
          step: 0,
          op: step.op,
          detail: { reason: outcome.reason, ...outcome.result },
        });
      }

      // Independent post-state verification (§9.4): the launcher re-runs
      // declared verify steps on success, and reconciles declared
      // expectedState before classifying a failure.
      let postState = outcome.ok
        ? await rerunVerifyStep(action, scope, journal)
        : await reconcileExpectedState(action, scope, journal);
      if (outcome.ok && !postState.verified) {
        // A mutating action may still declare verifiable expected state —
        // the reconcile convention doubles as its success verification.
        postState = await reconcileExpectedState(action, scope, journal);
      }
      const classification = classifyRecovery({
        journal: readJournal(journalFile),
        receipt: { terminal: outcome.ok ? 'SUCCEEDED' : 'FAILED' },
        allStepsSettled: true,
        postState,
      });

      return this.finalize({
        action: action.actionId,
        terminal: outcome.ok ? 'SUCCEEDED' : 'FAILED',
        exitCode: typeof outcome.result.exitCode === 'number' ? outcome.result.exitCode : undefined,
        startedAt,
        reason: outcome.ok ? 'step completed' : outcome.reason,
        sideEffectClass: action.action.sideEffectClass,
        journal,
        journalFile,
        receiptFile,
        classification,
        postStateVerified: postState.verified && postState.holds,
        outputRefs: stringRefsOf(outcome.result),
        stdoutRef: stringOf(outcome.result.stdoutRef),
        stderrRef: stringOf(outcome.result.stderrRef),
      });
    } finally {
      this.inFlight.delete(action.actionId);
    }
  }

  /** Cooperative cancellation: sentinel polled by the interpreter between guards. */
  async cancel(actionId: string): Promise<void> {
    const run = this.inFlight.get(actionId);
    if (run && !existsSync(run.cancelFile)) {
      writeFileSync(run.cancelFile, `${new Date().toISOString()}\n`, 'utf8');
    }
  }

  private finalize(input: {
    action: string;
    terminal: ExecutionReceipt['terminal'];
    exitCode?: number;
    startedAt: string;
    reason: string;
    sideEffectClass: ExecutionReceipt['sideEffectEvidence']['sideEffectClass'];
    journal: JournalWriter;
    journalFile: string;
    receiptFile: string;
    classification: ClassificationResult;
    postStateVerified: boolean;
    outputRefs?: string[];
    stdoutRef?: string;
    stderrRef?: string;
  }): ExecutionReceipt {
    const receipt = ExecutionReceiptSchema.parse({
      actionId: input.action,
      environmentId: environmentId(),
      providerId: PROVIDER_ID,
      providerVersion: PROVIDER_VERSION,
      startedAt: input.startedAt,
      finishedAt: new Date().toISOString(),
      terminal: input.terminal,
      ...(input.exitCode !== undefined ? { exitCode: input.exitCode } : {}),
      outputRefs: [...(input.outputRefs ?? []), input.journalFile, input.receiptFile],
      ...(input.stdoutRef ? { stdoutRef: input.stdoutRef } : {}),
      ...(input.stderrRef ? { stderrRef: input.stderrRef } : {}),
      sideEffectEvidence: {
        sideEffectClass: input.sideEffectClass,
        recoveryClassification: input.classification.recoveryClassification,
        postStateVerified: input.postStateVerified,
        journalRef: input.journalFile,
      },
    });
    persistReceiptFile(input.receiptFile, input.journalFile, {
      reason: input.reason,
      classificationBasis: input.classification.basis,
      resolvedByPostState: input.classification.resolvedByPostState,
      receipt,
    });
    return receipt;
  }
}

// ---- launcher-side receipt files (evidence artifacts next to the journal). ----

function refusedReceipt(input: {
  actionId: string;
  journal: JournalWriter;
  journalFile: string;
  receiptFile: string;
  startedAt: string;
  reason: string;
  code?: string;
  sideEffectClass: ExecutionReceipt['sideEffectEvidence']['sideEffectClass'];
}): ExecutionReceipt {
  input.journal.append('REFUSED', {
    detail: { why: input.reason, ...(input.code ? { code: input.code } : {}) },
  });
  const receipt = ExecutionReceiptSchema.parse({
    actionId: input.actionId,
    environmentId: environmentId(),
    providerId: PROVIDER_ID,
    providerVersion: PROVIDER_VERSION,
    startedAt: input.startedAt,
    finishedAt: new Date().toISOString(),
    terminal: 'REFUSED',
    outputRefs: [input.journalFile, input.receiptFile],
    sideEffectEvidence: {
      sideEffectClass: input.sideEffectClass,
      recoveryClassification: 'FAILED_BEFORE_EFFECT',
      postStateVerified: false,
      journalRef: input.journalFile,
    },
  });
  persistReceiptFile(input.receiptFile, input.journalFile, {
    reason: input.reason,
    code: input.code,
    receipt,
  });
  return receipt;
}

function persistReceiptFile(
  receiptFile: string,
  journalFile: string,
  detail: {
    reason: string;
    code?: string;
    classificationBasis?: string;
    resolvedByPostState?: boolean;
    receipt: ExecutionReceipt;
  },
): void {
  writeFileSync(
    receiptFile,
    `${JSON.stringify(
      {
        ...detail.receipt,
        launcherDetail: {
          ...detail,
          receipt: undefined,
          journalDigest: journalDigest(readJournal(journalFile)),
        },
      },
      null,
      2,
    )}\n`,
    'utf8',
  );
}

function environmentId(): string {
  return `local-windows/${hostname()}`;
}

function stringRefsOf(result: Record<string, unknown>): string[] {
  const refs: string[] = [];
  for (const key of ['stdoutRef', 'stderrRef'] as const) {
    const v = result[key];
    if (typeof v === 'string') refs.push(v);
  }
  return refs;
}

function stringOf(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function archOf(arch: 'X64' | 'ARM64'): string {
  return arch === 'X64' ? 'x64' : 'arm64';
}
