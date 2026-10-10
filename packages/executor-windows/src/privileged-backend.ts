// PrivilegedWindowsExecutionBackend — the privileged one-shot helper launcher
// (L2 §8.2.1, §9.1/§9.3; contracts ExecutionBackend seam).
//
// The launcher is UNTRUSTED transport: it never executes action content
// itself. It assembles the envelope (action + grant presentation + plan,
// re-validated inside the helper), verifies the pinned helper identity,
// performs the single UAC elevation via the pinned relay, and classifies the
// outcome ONLY from the phase journal + structured receipt + independent
// post-state verification (§9.4) — never from transport/exit optimism.
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  type AuthorizationGrantPresentationInput,
  type AuthorizedAction,
  type ExecutionBackend,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
} from '@shun/contracts';
import { PROVIDER_ID, PROVIDER_VERSION } from './backend.ts';
import { type HelperReceiptFile, HelperReceiptFileSchema, writeEnvelopeFile } from './envelope.ts';
import { verifyPinnedHelper } from './helper-pinning.ts';
import type { InterpreterScope } from './interpreter.ts';
import { JournalWriter, journalDigest, readJournal } from './journal.ts';
import { reconcileExpectedState, rerunVerifyStep } from './poststate.ts';
import {
  type ClassificationResult,
  classifyRecovery,
  terminalForClassification,
} from './recovery.ts';
import { FileGrantSource, FilePlanSource, readHelperPin } from './trusted-store.ts';

export interface PrivilegedBackendOptions {
  /** Trusted authority store (helper pin, plans, currentness, HMAC key). */
  authorityDir: string;
  /** Root for per-action run artifacts; MUST equal the pin's workspaceRoot. */
  workspaceRoot: string;
  /** Package root containing dist/executor-helper.mjs and the relay script. */
  packageRoot?: string;
  /** Explicit helper bundle path (tests build a pinned bundle per authority store). */
  helperBundlePath?: string;
  /** Explicit relay script path (defaults to the package relay). */
  relayScriptPath?: string;
  /** Grace for the secure-desktop prompt + helper run, over the action deadline. */
  uacGraceMs?: number;
  defaultTimeoutMs?: number;
}

interface InFlightElevation {
  runDir: string;
  cancelFile: string;
  relayPid?: number;
  elevated: boolean;
}

const POWERSELL_EXE = () =>
  join(
    process.env.SystemRoot ?? 'C:\\Windows',
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  );
const TASKKILL_EXE = () =>
  join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'taskkill.exe');

export class PrivilegedWindowsExecutionBackend implements ExecutionBackend {
  private readonly options: PrivilegedBackendOptions;
  private readonly inFlight = new Map<string, InFlightElevation>();

  constructor(options: PrivilegedBackendOptions) {
    this.options = options;
  }

  private get packageRoot(): string {
    return this.options.packageRoot ?? join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  }

  private helperBundlePath(): string {
    return this.options.helperBundlePath ?? join(this.packageRoot, 'dist', 'executor-helper.mjs');
  }

  private relayScriptPath(): string {
    return (
      this.options.relayScriptPath ?? join(this.packageRoot, 'src', 'relay', 'elevate-relay.ps1')
    );
  }

  /**
   * Execute ONE allowlisted action in a fresh elevated one-shot helper.
   * Returns the classified contracts receipt; every launch-side failure
   * before helper start is a structured REFUSED with NOT_STARTED.
   */
  async execute(
    action: AuthorizedAction,
    grant: AuthorizationGrantPresentationInput,
  ): Promise<ExecutionReceipt> {
    const runDir = join(
      this.options.workspaceRoot,
      'executions',
      `${action.actionId}-${Date.now()}-${randomUUID().slice(0, 8)}`,
    );
    const startedAt = new Date().toISOString();
    const cancelFile = join(runDir, 'cancel.sentinel');
    const launcherJournal = new JournalWriter(join(runDir, 'launch.jsonl'), process.pid);
    this.inFlight.set(action.actionId, { runDir, cancelFile, elevated: true });

    const launchRefused = async (reason: string, code?: string): Promise<ExecutionReceipt> => {
      const receipt = ExecutionReceiptSchema.parse({
        actionId: action.actionId,
        environmentId: `local-windows/${hostname()}`,
        providerId: PROVIDER_ID,
        providerVersion: PROVIDER_VERSION,
        startedAt,
        finishedAt: new Date().toISOString(),
        terminal: 'REFUSED',
        outputRefs: [join(runDir, 'launch.jsonl')],
        sideEffectEvidence: {
          sideEffectClass: action.action.sideEffectClass,
          recoveryClassification: 'NOT_STARTED',
          postStateVerified: false,
        },
      });
      persistLaunchReceipt(runDir, receipt, { reason, ...(code ? { code } : {}) });
      return receipt;
    };

    try {
      // ---- launch-side pin verification (the helper re-checks its own). ----
      const pin = readHelperPin(this.options.authorityDir);
      const identity = verifyPinnedHelper(this.helperBundlePath(), this.relayScriptPath(), pin);
      if (!identity.ok) return await launchRefused(identity.reason);
      if (!pin)
        return await launchRefused(
          'helper pin vanished between verification and launch (fail closed)',
        );

      // ---- trusted plan source; a missing plan fails closed. ----
      const plan = new FilePlanSource(join(this.options.authorityDir, 'plans')).byPlanHash(
        action.planHash,
      );
      if (!plan)
        return await launchRefused(`plan ${action.planHash} not found in the authority store`);

      // ---- run artifacts + envelope (typed JSON on disk, never shell text). ----
      mkdirSync(runDir, { recursive: true });
      const evidenceDir = join(runDir, 'evidence');
      mkdirSync(evidenceDir, { recursive: true });
      const envelopeFile = join(runDir, 'envelope.json');
      const journalFile = join(runDir, 'journal.jsonl');
      const receiptFile = join(runDir, 'receipt.json');
      writeEnvelopeFile(envelopeFile, {
        action,
        grant,
        plan,
        io: {
          journalFile,
          receiptFile,
          cancelFile,
          evidenceDir,
        },
      });
      launcherJournal.append('LAUNCH_BEGIN', {
        detail: {
          actionId: action.actionId,
          helperRevision: identity.helperRevision,
          helperSha256: identity.measuredSha256,
        },
      });

      // ---- single UAC elevation via the pinned relay. ----
      const relayResult = await spawnRelay({
        nodeExe: process.execPath,
        relayScript: this.relayScriptPath(),
        helperBundle: this.helperBundlePath(),
        helperArgs: [envelopeFile, journalFile, receiptFile],
        relayFile: join(runDir, 'relay.json'),
        timeoutMs:
          (action.action.timeoutMs ?? this.options.defaultTimeoutMs ?? 120000) +
          (this.options.uacGraceMs ?? 150000),
        onRelayPid: (pid) => {
          const run = this.inFlight.get(action.actionId);
          if (run) run.relayPid = pid;
        },
      });
      launcherJournal.append('LAUNCH_RELAY', { detail: { ...relayResult } });

      // ---- classification: journal + receipt + independent post-state ONLY. ----
      return await this.classify({
        action,
        runDir,
        relayResult,
        startedAt,
        launcherJournal,
        pinWorkspaceRoot: pin.workspaceRoot,
      });
    } finally {
      this.inFlight.delete(action.actionId);
    }
  }

  /**
   * Cooperative cancellation: sentinel polled by the helper between phases
   * and inside long steps. A non-elevated parent cannot force-kill the
   * elevated child (Access Denied) — the helper-side deadline remains the
   * bound; the launcher-side tree-kill is last resort for the NON-elevated
   * relay tree only.
   */
  async cancel(actionId: string): Promise<void> {
    const run = this.inFlight.get(actionId);
    if (!run) return;
    if (!existsSync(run.cancelFile)) {
      writeFileSync(run.cancelFile, `${new Date().toISOString()}\n`, 'utf8');
    }
  }

  private async classify(input: {
    action: AuthorizedAction;
    runDir: string;
    relayResult: RelayResult;
    startedAt: string;
    launcherJournal: JournalWriter;
    pinWorkspaceRoot: string;
  }): Promise<ExecutionReceipt> {
    const { action, runDir, relayResult, startedAt } = input;
    const journalFile = join(runDir, 'journal.jsonl');
    const receiptFile = join(runDir, 'receipt.json');
    const journal = readJournal(journalFile);

    const mint = (fields: {
      terminal: ExecutionReceipt['terminal'];
      exitCode?: number;
      classification: ClassificationResult;
      postStateVerified: boolean;
      outputRefs?: string[];
      stdoutRef?: string;
      stderrRef?: string;
      reason: string;
    }): ExecutionReceipt => {
      const receipt = ExecutionReceiptSchema.parse({
        actionId: action.actionId,
        environmentId: `local-windows/${hostname()}`,
        providerId: PROVIDER_ID,
        providerVersion: PROVIDER_VERSION,
        startedAt,
        finishedAt: new Date().toISOString(),
        terminal: fields.terminal,
        ...(fields.exitCode !== undefined ? { exitCode: fields.exitCode } : {}),
        outputRefs: [...(fields.outputRefs ?? []), journalFile, receiptFile],
        ...(fields.stdoutRef ? { stdoutRef: fields.stdoutRef } : {}),
        ...(fields.stderrRef ? { stderrRef: fields.stderrRef } : {}),
        sideEffectEvidence: {
          sideEffectClass: action.action.sideEffectClass,
          recoveryClassification: fields.classification.recoveryClassification,
          postStateVerified: fields.postStateVerified,
          journalRef: journalFile,
        },
      });
      persistLaunchReceipt(runDir, receipt, {
        reason: fields.reason,
        classificationBasis: fields.classification.basis,
        resolvedByPostState: fields.classification.resolvedByPostState,
        relay: relayResult,
        journalDigest: journalDigest(journal),
      });
      return receipt;
    };

    // UAC refusal: relay exception, helper provably never started — verify
    // the empty journal is REALLY empty before classifying NOT_STARTED.
    if (relayResult.kind === 'UAC_DECLINED') {
      const clean = journal.length === 0;
      return mint({
        terminal: 'UAC_DECLINED',
        classification: {
          recoveryClassification: clean ? 'NOT_STARTED' : 'MAY_HAVE_EXECUTED_UNCERTAIN',
          resolvedByPostState: false,
          basis: clean
            ? 'UAC consent refused/timed out; empty journal — helper provably never started'
            : 'UAC relay reported decline but the journal is non-empty — fail-closed to uncertain',
        },
        postStateVerified: false,
        reason: `UAC declined (${relayResult.hresult ?? 'n/a'})`,
      });
    }

    // Helper wrote a structured receipt: classify around it, then finalize
    // the recovery classification with INDEPENDENT post-state verification.
    if (existsSync(receiptFile)) {
      let helperReceipt: HelperReceiptFile | undefined;
      try {
        helperReceipt = HelperReceiptFileSchema.parse(
          JSON.parse(readFileSync(receiptFile, 'utf8')),
        );
      } catch {
        // Corrupt receipt = receipt channel failure; fall through to journal classification.
        helperReceipt = undefined;
      }
      if (helperReceipt) {
        const scope = await scopeOf(action, this.options.authorityDir);
        let postState =
          helperReceipt.terminal === 'SUCCEEDED'
            ? await rerunVerifyStep(action, scope, input.launcherJournal)
            : await reconcileExpectedState(action, scope, input.launcherJournal);
        if (helperReceipt.terminal === 'SUCCEEDED' && !postState.verified) {
          // A mutating action may declare verifiable expected state — the
          // reconcile convention doubles as its success verification.
          postState = await reconcileExpectedState(action, scope, input.launcherJournal);
        }
        const classification = classifyRecovery({
          journal,
          receipt: { terminal: helperReceipt.terminal },
          allStepsSettled: true,
          postState,
        });
        const terminal: ExecutionReceipt['terminal'] =
          helperReceipt.terminal === 'SUCCEEDED'
            ? classification.recoveryClassification === 'COMPLETED_VERIFIED'
              ? 'SUCCEEDED'
              : 'UNCERTAIN'
            : helperReceipt.terminal;
        return mint({
          terminal,
          exitCode: helperReceipt.exitCode,
          classification,
          postStateVerified: postState.verified && postState.holds,
          outputRefs: helperReceipt.outputRefs,
          stdoutRef: helperReceipt.stdoutRef,
          stderrRef: helperReceipt.stderrRef,
          reason: helperReceipt.detail?.reason ?? 'helper receipt',
        });
      }
    }

    // No receipt: crash / kill / lost channel. Journal + reconcile-first decide.
    const scope = await scopeOf(action, this.options.authorityDir);
    const postState = await reconcileExpectedState(action, scope, input.launcherJournal);
    const classification = classifyRecovery({
      journal,
      receipt: undefined,
      postState,
      relay: {
        kind: relayResult.kind === 'RAN' ? 'RAN' : 'NO_RELAY',
        exitCode: relayResult.exitCode,
      },
    });
    return mint({
      terminal: terminalForClassification(classification),
      exitCode: relayResult.exitCode,
      classification,
      postStateVerified: postState.verified && postState.holds,
      reason: `no helper receipt; classified from journal + post-state (${relayResult.kind})`,
    });
  }
}

// ---- relay spawn (typed argv, shell:false; tree-kill last resort). ----

type RelayResult = {
  kind: 'RAN' | 'UAC_DECLINED' | 'NO_RELAY' | 'SPAWN_ERROR' | 'TIMED_OUT';
  exitCode?: number;
  childPid?: number;
  hresult?: string;
  error?: string;
  timedOut?: boolean;
};

async function spawnRelay(params: {
  nodeExe: string;
  relayScript: string;
  helperBundle: string;
  helperArgs: string[];
  relayFile: string;
  timeoutMs: number;
  onRelayPid?: (pid: number) => void;
}): Promise<RelayResult> {
  const helperArgsJson = JSON.stringify(params.helperArgs);
  const child = spawn(
    POWERSELL_EXE(),
    [
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-File',
      params.relayScript,
      '-NodeExe',
      params.nodeExe,
      '-HelperBundle',
      params.helperBundle,
      '-HelperArgsJson',
      helperArgsJson,
      '-RelayFile',
      params.relayFile,
    ],
    { shell: false, windowsHide: true },
  );
  params.onRelayPid?.(child.pid ?? -1);
  return new Promise((resolve) => {
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      // The relay tree is NON-elevated: tree-kill reaches it. The elevated
      // helper child survives (Access Denied) — exactly why the helper owns
      // its deadline and the journal decides the outcome (§8.2.1).
      if (child.pid) {
        spawn(TASKKILL_EXE(), ['/PID', String(child.pid), '/T', '/F'], {
          shell: false,
          windowsHide: true,
        });
      }
    }, params.timeoutMs);
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ kind: 'SPAWN_ERROR', error: String(err) });
    });
    child.on('exit', () => {
      clearTimeout(timer);
      let relay: Record<string, unknown> | undefined;
      try {
        if (existsSync(params.relayFile)) {
          relay = JSON.parse(readFileSync(params.relayFile, 'utf8')) as Record<string, unknown>;
        }
      } catch {
        relay = undefined;
      }
      if (timedOut && !relay) {
        resolve({ kind: 'TIMED_OUT', timedOut });
        return;
      }
      if (!relay) {
        resolve({ kind: 'NO_RELAY', timedOut });
        return;
      }
      if (relay.kind === 'UAC_DECLINED') {
        resolve({
          kind: 'UAC_DECLINED',
          hresult: typeof relay.hresult === 'string' ? relay.hresult : undefined,
          error: typeof relay.error === 'string' ? relay.error : undefined,
        });
        return;
      }
      resolve({
        kind: 'RAN',
        exitCode: typeof relay.exitCode === 'number' ? relay.exitCode : undefined,
        childPid: typeof relay.childPid === 'number' ? relay.childPid : undefined,
      });
    });
  });
}

// ---- shared helpers. ----

function scopeOf(action: AuthorizedAction, authorityDir: string): InterpreterScope {
  // The grant (hence scope) is re-read from the trusted store for the
  // launcher-side post-state run; the helper already validated the
  // presentation, and the scope only READS what the grant declared.
  const grant = new FileGrantSource(join(authorityDir, 'grants')).byGrantId(
    action.authorizationRef,
  );
  return {
    filesystem: grant?.actionScope.filesystem,
    registry: grant?.actionScope.registry,
  };
}

function persistLaunchReceipt(
  runDir: string,
  receipt: ExecutionReceipt,
  detail: Record<string, unknown>,
): void {
  mkdirSync(runDir, { recursive: true });
  writeFileSync(
    join(runDir, 'receipt.json'),
    `${JSON.stringify({ ...receipt, launcherDetail: detail }, null, 2)}\n`,
    'utf8',
  );
}

// Exposed for evidence tooling: read back the helper's structured receipt file.
export function readHelperReceiptFile(runDir: string): unknown | undefined {
  const file = join(runDir, 'receipt.json');
  if (!existsSync(file)) return undefined;
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return undefined;
  }
}
