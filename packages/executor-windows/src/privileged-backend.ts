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
  canonicalJson,
  type ExecutionBackend,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
} from '@shun/contracts';
import { assertSafeActionId } from './action-id.ts';
import { resolveActionStep } from './action-surface.ts';
import { assessAuthorityAnchors } from './anchor-protection.ts';
import { PROVIDER_ID, PROVIDER_VERSION } from './backend.ts';
import { type HelperReceiptFile, HelperReceiptFileSchema, writeEnvelopeFile } from './envelope.ts';
import { resolveAgainstRoot } from './fs-safety.ts';
import { grantHmacKeyFileOverride } from './helper/authority-dir.ts';
import { verifyPinnedHelper } from './helper-pinning.ts';
import type { InterpreterScope } from './interpreter.ts';
import { JournalWriter, journalDigest, readJournal } from './journal.ts';
import { reconcileExpectedState, rerunVerifyStep } from './poststate.ts';
import { verifyPinnedProgram } from './program-pinning.ts';
import {
  type ClassificationResult,
  classifyRecovery,
  terminalForClassification,
} from './recovery.ts';
import { privilegedSpawnEnv } from './safe-env.ts';
import { systemPowershellExe, systemTaskkillExe } from './system-exe.ts';
import {
  FileGrantSource,
  FilePlanSource,
  readHelperPin,
  resolveGrantHmacKeyFile,
} from './trusted-store.ts';

export interface PrivilegedBackendOptions {
  /** Trusted authority store (helper pin, plans, currentness, HMAC key). */
  authorityDir: string;
  /**
   * Content-addressed ActionPlan ledger. The launcher may read this from a
   * runtime-writable cache because the protected grant binds planHash and the
   * helper re-derives the hash/action identity before any effect.
   */
  planDir?: string;
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
  /**
   * Externalized HMAC key path this deployment trusts (P2-2 anchor probing).
   * Falls back to the build-time define (grantHmacKeyFileOverride); the
   * co-located default is probed in addition, never instead.
   */
  grantHmacKeyFileOverride?: string;
}

interface InFlightElevation {
  runDir: string;
  cancelFile: string;
  relayPid?: number;
  elevated: boolean;
}

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
    // actionId is caller-controlled (contracts floor: min length only) and is
    // spliced into the run directory name below — reject path semantics before
    // any artifact path (or the elevated helper's I/O envelope) is derived.
    assertSafeActionId(action.actionId);
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
      // C08: this backend is the ELEVATED surface. USER/NONE actions belong
      // to the unprivileged in-process backend; launching them through the
      // UAC-relayed helper would execute user-level actions with admin
      // rights. Refuse before any pin read, envelope write or relay spawn.
      if (action.action.requiredPrivilege !== 'ELEVATED') {
        return await launchRefused(
          `privileged backend only accepts ELEVATED actions; ${action.action.requiredPrivilege} actions must run on the unprivileged surface`,
          'PRIVILEGE_LEVEL_MISMATCH',
        );
      }

      // P2-2 / N-R2-4: interim fail-closed default for the open C06
      // architecture — no privileged side effect under anchors a same-user
      // attacker could have forged. Read-only (R0) observations are untouched;
      // deployments that externalize the HMAC key to a genuinely protected
      // path keep working (the probes reflect what the OS actually enforces
      // for this token). This refusal happens BEFORE any UAC work: no consent
      // is ever requested, so no elevated effect can occur. The readable-key
      // re-sign attack is NOT this gate's trigger — it stays the known-open
      // C06 defect for the L2 v0.2 privileged writer (see anchor-protection.ts).
      if (action.action.sideEffectClass !== 'R0') {
        const anchors = assessAuthorityAnchors(
          this.options.authorityDir,
          resolveGrantHmacKeyFile(
            this.options.authorityDir,
            grantHmacKeyFileOverride() ?? this.options.grantHmacKeyFileOverride,
          ),
        );
        if (anchors.forgeable) {
          return await launchRefused(
            `authorization anchors are same-user-writable (interim fail-closed default while the privileged writer architecture is open): ${anchors.reasons.join('; ')}`,
            'ANCHOR_FORGEABLE_SAME_USER',
          );
        }
      }

      // The presented grant crosses an untrusted caller boundary. Even a
      // caller who somehow learns the symmetric HMAC key cannot mint a new
      // privileged presentation unless the exact grant record was first
      // committed by the elevated-only anchor writer.
      const storedGrant = new FileGrantSource(join(this.options.authorityDir, 'grants')).byGrantId(
        action.authorizationRef,
      );
      if (!storedGrant) {
        return await launchRefused(
          `grant ${action.authorizationRef} is absent from the protected authority store`,
          'GRANT_NOT_AUTHENTIC',
        );
      }
      if (canonicalJson(storedGrant) !== canonicalJson(grant)) {
        return await launchRefused(
          'presented grant does not byte-canonically match the protected pre-issued record',
          'GRANT_NOT_AUTHENTIC',
        );
      }

      // ---- launch-side pin verification (the helper re-checks its own). ----
      const pin = readHelperPin(this.options.authorityDir);
      // C12: the pin covers the interpreter too — the launcher measures
      // node.exe (the very binary the relay will elevate) before any spawn.
      const identity = verifyPinnedHelper(
        this.helperBundlePath(),
        this.relayScriptPath(),
        process.execPath,
        pin,
      );
      if (!identity.ok) return await launchRefused(identity.reason);
      if (!pin)
        return await launchRefused(
          'helper pin vanished between verification and launch (fail closed)',
        );

      // C07: the run artifacts (and therefore the elevated helper's I/O
      // envelope) must resolve INSIDE the pinned workspace root on real
      // paths — a launcher-configured root outside the pin would make every
      // helper run refuse at containment, or worse, resolve through a
      // junction outside the pin. Fail fast before any envelope/UAC work.
      const rootCheck = resolveAgainstRoot(this.options.workspaceRoot, pin.workspaceRoot);
      if (!rootCheck.ok) {
        return await launchRefused(
          `configured workspace root refused against the pinned root: ${rootCheck.reason}`,
          'WORKSPACE_ROOT_ESCAPE',
        );
      }

      // ---- trusted plan source; a missing plan fails closed. ----
      const plan = new FilePlanSource(
        this.options.planDir ?? join(this.options.authorityDir, 'plans'),
      ).byPlanHash(action.planHash);
      if (!plan)
        return await launchRefused(`plan ${action.planHash} not found in the authority store`);

      // ---- N-2 program identity preflight, BEFORE any UAC work. ----
      // A protected authority root is runtime READ-ONLY: an unprivileged
      // launcher must NEVER create/update program pins. Program identity is a
      // provisioning/authority event. Here we only verify the already-pinned
      // canonical path + bytes; the elevated helper repeats this check.
      const preflightStep = resolveActionStep(action);
      if (preflightStep?.op === 'windows.proc.exec') {
        const programPin = verifyPinnedProgram(
          this.options.authorityDir,
          preflightStep.args.program,
        );
        if (!programPin.ok) {
          return await launchRefused(
            `program identity preflight failed: ${programPin.reason}`,
            'PROGRAM_PIN_REFUSED',
          );
        }
      }

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
      // C13: the relay host is the MOST sensitive spawn — it is the binary
      // UAC elevates. Refuse to launch from an inherited-SystemRoot guess:
      // a planted root would hand the RunAs prompt's consent to a fake
      // powershell. N-1: the candidate binaries are additionally verified
      // against the authority store's system-tools identity pin — a forged
      // tool, or a missing/corrupt pin, refuses the launch (fail closed).
      const powershellExe = systemPowershellExe(this.options.authorityDir);
      const taskkillExe = systemTaskkillExe(this.options.authorityDir);
      if (!powershellExe || !taskkillExe) {
        return await launchRefused(
          'system directory unresolvable or system-tool identity pin missing/mismatched — refusing to spawn the elevation relay (fail closed)',
          'SYSTEM_DIR_UNRESOLVABLE',
        );
      }
      const relayResult = await spawnRelay({
        powershellExe,
        taskkillExe,
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

    // UAC refusal: only "helper provably never started" when the EMPTY
    // journal agrees (C15). A non-empty journal contradicting the relay
    // verdict fails closed via classifyRecovery (execStart → UNCERTAIN,
    // received-only → FAILED_BEFORE_EFFECT).
    if (relayResult.kind === 'UAC_DECLINED') {
      const classification = classifyRecovery({
        journal,
        relay: { kind: 'UAC_DECLINED', hresult: relayResult.hresult },
      });
      const terminal: ExecutionReceipt['terminal'] =
        classification.recoveryClassification === 'NOT_STARTED'
          ? 'UAC_DECLINED'
          : terminalForClassification(classification);
      return mint({
        terminal,
        classification,
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
            ? await rerunVerifyStep(action, scope, input.launcherJournal, this.options.authorityDir)
            : await reconcileExpectedState(
                action,
                scope,
                input.launcherJournal,
                this.options.authorityDir,
              );
        if (helperReceipt.terminal === 'SUCCEEDED' && !postState.verified) {
          // A mutating action may declare verifiable expected state — the
          // reconcile convention doubles as its success verification.
          postState = await reconcileExpectedState(
            action,
            scope,
            input.launcherJournal,
            this.options.authorityDir,
          );
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
    const postState = await reconcileExpectedState(
      action,
      scope,
      input.launcherJournal,
      this.options.authorityDir,
    );
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
  /** Observed lifecycle diagnostics (Issue #345): wall time from spawn call to resolution. */
  elapsedMs?: number;
  /** Whether the OS actually created the relay process (spawn event fired). */
  spawned?: boolean;
  /** Bytes the relay wrote to stdout/stderr before resolution (0 = silent init-phase stall). */
  outputBytes?: number;
  /** taskkill tree-kill exit code, when a timeout kill was issued. */
  killExitCode?: number;
  /**
   * True when the relay process tree was observed to exit after the timeout
   * kill (no orphan); false means the kill grace elapsed without an exit.
   * Exit evidence only — never cleanup optimism (Issue #345 P1-01).
   */
  killConfirmed?: boolean;
  /**
   * P1-01 (#345): explicit, bounded disposition of the taskkill helper
   * itself — present on every TIMED_OUT result. EXITED_ZERO/EXITED_NONZERO:
   * the helper exited with that class of code; SPAWN_ERROR: the helper never
   * came into existence; TIMED_OUT: the helper hit its own grace bound and
   * termination was requested (killHelperConfirmed separately records whether
   * its exit was observed); NOT_ISSUED: no kill was issued (no relay pid to kill).
   */
  killDisposition?: 'NOT_ISSUED' | 'EXITED_ZERO' | 'EXITED_NONZERO' | 'SPAWN_ERROR' | 'TIMED_OUT';
  /** P1-01: retained taskkill helper pid (-1 when the helper never spawned). */
  taskkillPid?: number;
  /**
   * P1-01: the launcher's direct relay-root kill fallback was used because
   * the helper could not be trusted (spawn error, nonzero exit, or its own
   * bound elapsed without a tree kill).
   */
  fallbackKillUsed?: boolean;
  /**
   * P1-01: the helper's lifecycle is provably closed — it exited (any code),
   * or it never came into existence. false only when the reaped helper's
   * exit could not be observed within the outer kill grace (honest
   * unproven-cleanup evidence, never reported as success).
   */
  killHelperConfirmed?: boolean;
};

/**
 * Bounded stdio capture: the relay's console text is intentionally NOT a
 * structured channel (§8.2.1), but its tail is diagnostic gold when the
 * relay process never exits or never writes its relay file — keep the last
 * few KiB, never the whole stream.
 */
function stdioTail(): { push(chunk: Buffer | string): void; tail(): string | undefined } {
  const decoder = new TextDecoder('utf8', { fatal: false });
  let buffered = '';
  return {
    push(chunk: Buffer | string): void {
      buffered = (buffered + (typeof chunk === 'string' ? chunk : decoder.decode(chunk))).slice(
        -8192,
      );
    },
    tail(): string | undefined {
      const t = buffered.trim();
      return t.length > 0 ? t.slice(-2048) : undefined;
    },
  };
}

/**
 * Two bounded phases after a relay timeout kill (Issue #345, P1-01):
 *
 * - TASKKILL_KILL_GRACE_MS bounds the taskkill helper's OWN lifecycle. The
 *   helper is a retained ChildProcess whose exit is explicitly awaited; if
 *   it has not exited within this bound (or it errored / exited nonzero),
 *   the launcher requests direct termination of the helper and falls back to
 *   killing the relay root it owns. The helper's exit is observed within the
 *   outer grace or reported as unconfirmed; it is never silently treated as
 *   reaped.
 * - RELAY_KILL_GRACE_MS is the hard ceiling for observing the relay root
 *   exit after the kill. The timeout result settles only once BOTH
 *   dispositions (helper + relay root) are explicit — and it never reports
 *   cleanup success that cannot be proven: `killConfirmed` stays
 *   exit-evidence only, and an unproven helper exit stays
 *   `killHelperConfirmed: false`.
 */
const TASKKILL_KILL_GRACE_MS = 10000;
const RELAY_KILL_GRACE_MS = 15000;

// Exported for the N-R2-1 negative controls (test/evidence tooling): the
// privileged-path relay spawn must demonstrably carry a sterilized
// environment. Security callers still enter through PrivilegedWindowsExecutionBackend.
export async function spawnRelay(params: {
  powershellExe: string;
  taskkillExe: string;
  nodeExe: string;
  relayScript: string;
  helperBundle: string;
  helperArgs: string[];
  relayFile: string;
  timeoutMs: number;
  onRelayPid?: (pid: number) => void;
  /** P1-01 (#345): test/evidence hook — fires once with the taskkill helper pid (-1 = never spawned). */
  onTaskkillPid?: (pid: number) => void;
}): Promise<RelayResult> {
  const helperArgsJson = JSON.stringify(params.helperArgs);
  // N-R2-1: the relay host is the spawn UAC consents FOR — an inherited
  // NODE_OPTIONS here becomes attacker JS inside the pinned elevated node
  // before any self-check. Both spawns below (relay + tree-kill) pass the
  // explicit minimal environment; the pinned relay re-scrubs on top.
  const sterileEnv = privilegedSpawnEnv();
  const stdout = stdioTail();
  const stderr = stdioTail();
  const startedAtMs = Date.now();
  let spawned = false;
  let outputBytes = 0;
  const child = spawn(
    params.powershellExe,
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
    { shell: false, windowsHide: true, env: sterileEnv },
  );
  child.stdout?.on('data', (c: Buffer) => {
    outputBytes += c.length;
    stdout.push(c);
  });
  child.stderr?.on('data', (c: Buffer) => {
    outputBytes += c.length;
    stderr.push(c);
  });
  child.once('spawn', () => {
    spawned = true;
  });
  params.onRelayPid?.(child.pid ?? -1);
  return new Promise((resolve) => {
    let settled = false;
    let timedOut = false;
    let killExitCode: number | undefined;
    let killConfirmed = false;
    // P1-01 (#345): the taskkill helper is a retained child with its own
    // bounded, explicit disposition, and the relay root gets a bounded
    // direct-kill fallback whenever the helper cannot be trusted.
    let killDisposition: RelayResult['killDisposition'] | undefined;
    let taskkillPid: number | undefined;
    let fallbackKillUsed = false;
    let killHelperConfirmed = false;
    let relayExitSeen = false;
    let killGraceElapsed = false;
    let killGraceTimer: ReturnType<typeof setTimeout> | undefined;
    let taskkillTimer: ReturnType<typeof setTimeout> | undefined;
    const lifecycle = () => ({
      elapsedMs: Date.now() - startedAtMs,
      spawned,
      outputBytes,
      ...(killExitCode !== undefined ? { killExitCode } : {}),
    });
    const tails = (): string =>
      [stderr.tail(), stdout.tail()].filter((t) => t !== undefined).join(' | ');
    const timeoutDiagnostics = (): string =>
      [
        `relay did not exit within ${params.timeoutMs}ms`,
        `spawned=${spawned}`,
        `outputBytes=${outputBytes}`,
        ...(taskkillPid !== undefined ? [`taskkillPid=${taskkillPid}`] : []),
        ...(killDisposition !== undefined ? [`taskkillDisposition=${killDisposition}`] : []),
        ...(killExitCode !== undefined ? [`taskkillExit=${killExitCode}`] : []),
        `fallbackKill=${fallbackKillUsed}`,
        `treeExitedAfterKill=${killConfirmed}`,
        `killHelperConfirmed=${killHelperConfirmed}`,
        tails(),
      ]
        .filter((part) => part !== '')
        .join('; ');
    const settle = (result: RelayResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killGraceTimer) clearTimeout(killGraceTimer);
      if (taskkillTimer) clearTimeout(taskkillTimer);
      resolve(result);
    };
    /**
     * P1-01: the TIMED_OUT result settles only when both dispositions are
     * explicit — the taskkill helper's (bounded by TASKKILL_KILL_GRACE_MS)
     * and the relay root's (bounded by RELAY_KILL_GRACE_MS). A reaped
     * helper's exit is part of its disposition and is awaited within the
     * outer grace, so the result never claims a helper lifecycle that is
     * still open.
     */
    const settleTimedOut = (): void => {
      if (settled || !timedOut) return;
      if (killDisposition === undefined) return;
      if (!relayExitSeen && !killGraceElapsed) return;
      if (
        killDisposition === 'TIMED_OUT' &&
        taskkillPid !== undefined &&
        taskkillPid > 0 &&
        !killHelperConfirmed &&
        !killGraceElapsed
      ) {
        return;
      }
      settle({
        kind: 'TIMED_OUT',
        timedOut,
        error: timeoutDiagnostics(),
        ...lifecycle(),
        killConfirmed: relayExitSeen,
        killDisposition,
        taskkillPid,
        fallbackKillUsed,
        killHelperConfirmed,
      });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      // The relay tree is NON-elevated: tree-kill reaches it. The elevated
      // helper child survives (Access Denied) — exactly why the helper owns
      // its deadline and the journal decides the outcome (§8.2.1).
      if (child.pid) {
        const kill = spawn(params.taskkillExe, ['/PID', String(child.pid), '/T', '/F'], {
          shell: false,
          windowsHide: true,
          env: sterileEnv,
        });
        // P1-01: retain the helper pid and bound its exit/reap lifecycle.
        taskkillPid = kill.pid ?? -1;
        params.onTaskkillPid?.(taskkillPid);
        let killSpawned = false;
        kill.once('spawn', () => {
          killSpawned = true;
        });
        const fallbackKill = (): void => {
          // Bounded fallback for the DIRECT relay child (the process the
          // launcher spawned and owns): the tree below the root is NOT
          // reachable this way, so killConfirmed stays exit-evidence only.
          if (fallbackKillUsed || relayExitSeen) return;
          fallbackKillUsed = true;
          child.kill();
        };
        kill.on('error', () => {
          if (!killSpawned) {
            // The helper never came into existence: nothing to prove gone.
            if (killExitCode === undefined) killExitCode = -1;
            killHelperConfirmed = true;
            if (killDisposition === undefined) {
              killDisposition = 'SPAWN_ERROR';
              fallbackKill();
            }
            settleTimedOut();
          }
        });
        kill.on('exit', (code) => {
          killHelperConfirmed = true;
          if (killDisposition === undefined) {
            const resolved = code ?? -1;
            killDisposition = resolved === 0 ? 'EXITED_ZERO' : 'EXITED_NONZERO';
            if (killExitCode === undefined) killExitCode = resolved;
            if (resolved !== 0) fallbackKill();
          }
          // Re-triggers a deferred settle: the helper's exit completes its
          // disposition even when the relay root exited first.
          settleTimedOut();
        });
        // P1-01: the helper's own grace bound. Fires when the helper is
        // still running (reap it, disposition TIMED_OUT) or when it already
        // exited zero without a proven relay exit (wedged tree) — either
        // way the relay root gets the bounded direct fallback here.
        taskkillTimer = setTimeout(() => {
          if (killDisposition === undefined) {
            killDisposition = 'TIMED_OUT';
            kill.kill();
          }
          fallbackKill();
          settleTimedOut();
        }, TASKKILL_KILL_GRACE_MS);
        killGraceTimer = setTimeout(() => {
          killGraceElapsed = true;
          if (killDisposition === undefined) killDisposition = 'TIMED_OUT';
          settleTimedOut();
        }, RELAY_KILL_GRACE_MS);
      } else {
        killDisposition = 'NOT_ISSUED';
        settle({
          kind: 'TIMED_OUT',
          timedOut,
          error: timeoutDiagnostics(),
          ...lifecycle(),
          killConfirmed: false,
          killDisposition,
        });
      }
    }, params.timeoutMs);
    child.on('error', (err) => {
      settle({ kind: 'SPAWN_ERROR', error: String(err), ...lifecycle() });
    });
    child.on('exit', () => {
      relayExitSeen = true;
      // The tree died on its own (or under the kill): proven-gone evidence.
      if (timedOut) killConfirmed = true;
      let relay: Record<string, unknown> | undefined;
      try {
        if (existsSync(params.relayFile)) {
          relay = JSON.parse(readFileSync(params.relayFile, 'utf8')) as Record<string, unknown>;
        }
      } catch {
        relay = undefined;
      }
      const diagnostics = tails();
      if (timedOut && !relay) {
        settleTimedOut();
        return;
      }
      if (!relay) {
        settle({ kind: 'NO_RELAY', timedOut, error: diagnostics || undefined, ...lifecycle() });
        return;
      }
      if (relay.kind === 'UAC_DECLINED') {
        settle({
          kind: 'UAC_DECLINED',
          hresult: typeof relay.hresult === 'string' ? relay.hresult : undefined,
          error: typeof relay.error === 'string' ? relay.error : undefined,
          ...lifecycle(),
        });
        return;
      }
      settle({
        kind: 'RAN',
        exitCode: typeof relay.exitCode === 'number' ? relay.exitCode : undefined,
        childPid: typeof relay.childPid === 'number' ? relay.childPid : undefined,
        ...lifecycle(),
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
