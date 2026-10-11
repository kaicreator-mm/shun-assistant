// ONE-SHOT privileged Windows action helper (L2 §8.2.1, §9.3).
//
// Bundled to a single .mjs (one canonicalization implementation: the workspace
// contracts sources, verbatim), launched elevated exactly once per action via
// UAC. Contract: one envelope file in, one structured receipt out, phase
// journal along the way, then exit. No listening channel, no reuse, no shell
// endpoint; an unknown op is a structural refusal.
//
// Startup ordering matters for the §9.4 invariant "empty journal ⇒ helper
// provably never started": while the launcher-supplied I/O paths are still
// unvalidated (pre envelope-parse, pre pin self-check, pre containment), the
// helper writes NOTHING and exits REFUSED through the relay exit code only.
// The journal opens only after every trusted anchor has been re-established
// inside the privileged boundary.
//
// Independently re-verified here, never on the launcher's say-so (§4.6.1):
// envelope schema → own-bundle pin self-check → own-interpreter pin self-check
// → I/O containment → currentness
// (trusted store, UNRESOLVABLE fails closed) → grant authenticity (HMAC) →
// grant currentness/expiry → plan-hash re-derivation → action↔plan exact
// identity → op allowlist + typed surface + declared scope → privilege
// consistency → execute → structured receipt.
import { execFile } from 'node:child_process';
import { renameSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  type ExecutionReceipt,
  ExecutionReceiptSchema,
  validateGrantPresentation,
} from '@shun/contracts';
import { checkStepSurface, resolveActionStep } from '../action-surface.ts';
import { isElevatedToken } from '../elevation.ts';
import {
  ENVELOPE_SCHEMA_VERSION,
  type Envelope,
  HELPER_EXIT_CODES,
  HelperReceiptFileSchema,
  readEnvelopeFile,
} from '../envelope.ts';
import { resolveAgainstRoot } from '../fs-safety.ts';
import {
  CancelledError,
  checkGuards,
  DeadlineError,
  type InterpreterContext,
  type InterpreterScope,
  runStep,
} from '../interpreter.ts';
import { durableWriteFileSync, JournalWriter } from '../journal.ts';
import { preflightScope } from '../scope-preflight.ts';
import { systemWhoamiExe } from '../system-exe.ts';
import {
  FileCurrentnessSource,
  hmacGrantIntegrityVerifier,
  readHelperPin,
  resolveGrantHmacKeyFile,
  sha256File,
} from '../trusted-store.ts';
import { authorityDirectory, grantHmacKeyFileOverride } from './authority-dir.ts';

const PROVIDER_ID = 'shun.executor-windows';
const PROVIDER_VERSION = '0.1.0';

interface ReceiptInput {
  actionId: string;
  terminal: 'SUCCEEDED' | 'FAILED' | 'REFUSED' | 'CANCELLED' | 'TIMED_OUT';
  exitCode: number;
  reason: string;
  rejectionCode?: string;
  isElevated: boolean;
  startedAt: string;
  sideEffectClass: 'R0' | 'R1' | 'R2' | 'R3';
  recoveryClassification:
    | 'NOT_STARTED'
    | 'FAILED_BEFORE_EFFECT'
    | 'MAY_HAVE_EXECUTED_UNCERTAIN'
    | 'COMPLETED_VERIFIED';
  postStateVerified: boolean;
  journalFile: string;
  receiptFile: string;
  outputRefs?: string[];
  stdoutRef?: string;
  stderrRef?: string;
}

class Helper {
  private startedAt = new Date().toISOString();
  private journal!: JournalWriter;
  private envelope!: Envelope;
  private isElevated = false;
  private sideEffectClass: 'R0' | 'R1' | 'R2' | 'R3' = 'R0';
  private journalFile = '';
  private receiptFile = '';

  async run(argv: string[]): Promise<number> {
    const [, , envelopeFile, journalFile, receiptFile] = argv;
    if (!envelopeFile || !journalFile || !receiptFile) {
      process.stderr.write('usage: executor-helper.mjs <envelope> <journal> <receipt>\n');
      return HELPER_EXIT_CODES.REFUSED;
    }
    this.journalFile = journalFile;
    this.receiptFile = receiptFile;

    // ---- pre-journal phase: no file writes, failures exit REFUSED only. ----
    try {
      this.envelope = readEnvelopeFile(envelopeFile);
    } catch (e) {
      process.stderr.write(`envelope rejected: ${message(e)}\n`);
      return HELPER_EXIT_CODES.REFUSED;
    }
    this.sideEffectClass = this.envelope.action.action.sideEffectClass;

    const pin = readHelperPin(authorityDirectory());
    if (!pin) {
      process.stderr.write(
        'authority store has no helper pin — refusing to execute (fail closed)\n',
      );
      return HELPER_EXIT_CODES.REFUSED;
    }
    let selfSha256: string;
    try {
      selfSha256 = sha256File(fileURLToPath(import.meta.url));
    } catch {
      process.stderr.write('helper cannot read its own bundle for pin self-check\n');
      return HELPER_EXIT_CODES.REFUSED;
    }
    if (selfSha256 !== pin.helperSha256) {
      process.stderr.write(
        `helper bundle hash ${selfSha256} != pinned ${pin.helperSha256} — substitution refused\n`,
      );
      return HELPER_EXIT_CODES.REFUSED;
    }
    // C12: the interpreter is part of the pinned identity. The launcher
    // chooses WHICH node.exe runs this bundle; without this re-measure a
    // launcher that slipped a substitute interpreter past the launch-side
    // check would still get an elevated arbitrary-code primitive (the
    // substitute can ignore this bundle entirely). Pre-journal: nothing
    // written, REFUSED via the relay exit code only.
    let nodeSha256: string;
    try {
      nodeSha256 = sha256File(process.execPath);
    } catch {
      process.stderr.write('helper cannot measure its own node.exe for the pin self-check\n');
      return HELPER_EXIT_CODES.REFUSED;
    }
    if (nodeSha256 !== pin.nodeExeSha256) {
      process.stderr.write(
        `node.exe identity mismatch: measured sha256 ${nodeSha256} != pinned ${pin.nodeExeSha256} — refusing to run on an unpinned interpreter\n`,
      );
      return HELPER_EXIT_CODES.REFUSED;
    }
    // C07: containment on RESOLVED paths, not lexical ones — a junction
    // planted inside the pinned root would otherwise turn the elevated
    // journal/receipt/evidence writes into an arbitrary-write primitive.
    for (const p of [
      journalFile,
      receiptFile,
      this.envelope.io.cancelFile,
      this.envelope.io.evidenceDir,
    ]) {
      if (p === undefined) continue;
      const contained = resolveAgainstRoot(p, pin.workspaceRoot);
      if (!contained.ok) {
        process.stderr.write(`I/O path refused: ${contained.reason}\n`);
        return HELPER_EXIT_CODES.REFUSED;
      }
    }

    // ---- trusted anchors established: the journal may open. ----
    this.journal = new JournalWriter(journalFile, process.pid);
    this.journal.append('RECEIVED', { detail: { envelopeFile, helperPid: process.pid } });
    this.isElevated = isElevatedToken(await whoamiGroups());
    try {
      return await this.execute();
    } catch (e) {
      // Fail-closed receipts: an unexpected exception still produces a
      // structured receipt so §9.4 classification stays derivable.
      const detail = message(e);
      this.journal.append('REFUSED', { detail: { why: 'exception', detail } });
      try {
        this.writeReceipt({
          actionId: this.envelope.action.actionId,
          terminal: 'REFUSED',
          exitCode: HELPER_EXIT_CODES.REFUSED,
          reason: `unexpected failure: ${detail}`,
          isElevated: this.isElevated,
          sideEffectClass: this.sideEffectClass,
          recoveryClassification: 'FAILED_BEFORE_EFFECT',
          postStateVerified: false,
        });
        return HELPER_EXIT_CODES.REFUSED;
      } catch {
        return HELPER_EXIT_CODES.RECEIPT_LOST;
      }
    }
  }

  private async execute(): Promise<number> {
    const actionId = this.envelope.action.actionId;
    this.journal.append('VALIDATED', { detail: { actionId } });

    // Grant presentation validation against trusted currentness (§4.6.1).
    const currentness = new FileCurrentnessSource(
      join(authorityDirectory(), 'current-authority.json'),
    ).read();
    const verdict = validateGrantPresentation({
      grant: this.envelope.grant,
      plan: this.envelope.plan,
      action: this.envelope.action,
      currentAuthority: currentness,
      now: new Date().toISOString(),
      verifyIntegrity: hmacGrantIntegrityVerifier(
        // C06: the key may be externalized to a protected path (build define);
        // a store-located key tampered by a same-user attacker then simply
        // fails verification — refuse, never "presented, therefore fine".
        resolveGrantHmacKeyFile(authorityDirectory(), grantHmacKeyFileOverride()),
      ),
    });
    if (!verdict.ok) {
      this.journal.append('REFUSED', {
        detail: { why: 'grant', code: verdict.code, detail: verdict.detail },
      });
      return this.refuse(`grant rejected: ${verdict.code} — ${verdict.detail}`, verdict.code);
    }
    this.journal.append('PLAN_IDENTITY_OK', {
      detail: { planHash: this.envelope.action.planHash },
    });
    this.journal.append('GRANT_OK', {
      detail: {
        grantId: verdict.grant.grantId,
        authorityRevision: verdict.grant.issuer.authorityRevision,
      },
    });

    // Typed op surface: exactly one allowlisted op with strict typed
    // parameters and lexically-legal path/key surface.
    const step = resolveActionStep(this.envelope.action);
    if (!step) {
      this.journal.append('REFUSED', { detail: { why: 'op', op: this.envelope.action.action.op } });
      return this.refuse(
        `unknown op '${this.envelope.action.action.op}' — no arbitrary shell endpoint`,
      );
    }
    const surface = checkStepSurface(step);
    if (!surface.ok) {
      this.journal.append('REFUSED', { detail: { why: 'surface', detail: surface.reason } });
      return this.refuse(`action surface refused: ${surface.reason}`);
    }

    // Declared-scope containment before any effect (every declared path/key,
    // fs AND registry); re-checked at execution time.
    const scope: InterpreterScope = {
      filesystem: verdict.grant.actionScope.filesystem,
      registry: verdict.grant.actionScope.registry,
    };
    const scopeReason = preflightScope(step, scope);
    if (scopeReason) {
      this.journal.append('REFUSED', { detail: { why: 'scope', detail: scopeReason } });
      return this.refuse(`declared scope refused before any effect: ${scopeReason}`);
    }
    this.journal.append('SCOPE_OK', { detail: { actionId } });

    // C08: the one-shot helper IS the elevated execution surface. A USER/NONE
    // grant executed here would run a user-level action with admin rights —
    // a privilege gain across the boundary. The unprivileged in-process
    // backend owns NONE/USER actions; this surface accepts ELEVATED only.
    const grantLevel = verdict.grant.actionScope.privilegeLevel;
    if (grantLevel !== 'ELEVATED') {
      this.journal.append('REFUSED', {
        detail: {
          why: 'privilege',
          detail: `grant privilegeLevel ${grantLevel} presented to the privileged helper`,
        },
      });
      return this.refuse(
        `privileged helper refuses ${grantLevel} grants — USER/NONE actions must run on the unprivileged surface`,
      );
    }

    // Privilege consistency: ELEVATED action on a filtered token is a
    // structured refusal (also the direct-launch negative evidence path).
    if (this.envelope.action.action.requiredPrivilege === 'ELEVATED' && !this.isElevated) {
      this.journal.append('REFUSED', {
        detail: { why: 'requiredPrivilege', isElevated: this.isElevated },
      });
      return this.refuse('action requires elevated admin context but the helper token is filtered');
    }
    this.journal.append('PRIVILEGE_OK', { detail: { isElevated: this.isElevated } });

    const timeoutMs = this.envelope.action.action.timeoutMs ?? 120000;
    const ctx: InterpreterContext = {
      journal: this.journal,
      scope,
      isElevated: this.isElevated,
      deadlineAt: new Date(Date.now() + timeoutMs),
      cancelFile: this.envelope.io.cancelFile,
      evidenceDir: this.envelope.io.evidenceDir,
    };

    this.journal.append('EXEC_BEGIN', { detail: { totalSteps: 1 } });
    this.journal.append('EXEC_START', { step: 0, op: step.op });
    let outcome: Awaited<ReturnType<typeof runStep>>;
    try {
      checkGuards(ctx, 'before-step');
      outcome = await runStep(step, ctx);
      checkGuards(ctx, 'after-step');
    } catch (err) {
      if (err instanceof CancelledError) {
        this.writeReceipt({
          actionId,
          terminal: 'CANCELLED',
          exitCode: HELPER_EXIT_CODES.CANCELLED,
          reason: 'cancel sentinel observed around the effect window',
          isElevated: this.isElevated,
          sideEffectClass: this.sideEffectClass,
          recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
          postStateVerified: false,
        });
        return HELPER_EXIT_CODES.CANCELLED;
      }
      if (err instanceof DeadlineError) {
        this.writeReceipt({
          actionId,
          terminal: 'TIMED_OUT',
          exitCode: HELPER_EXIT_CODES.TIMED_OUT,
          reason: err.message,
          isElevated: this.isElevated,
          sideEffectClass: this.sideEffectClass,
          recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
          postStateVerified: false,
        });
        return HELPER_EXIT_CODES.TIMED_OUT;
      }
      throw err;
    }

    if (outcome.ok) {
      this.journal.append('EXEC_DONE', { step: 0, op: step.op, detail: outcome.result });
      // Helper-local preliminary classification: COMPLETED_VERIFIED requires
      // an independent post-state check, which is the LAUNCHER's re-run of
      // the declared verify steps (L2 §9.4). Without one the honest value is
      // MAY_HAVE_EXECUTED_UNCERTAIN; the launcher finalizes either way.
      const verifiedHere = isReadOnlyOp(step.op);
      this.writeReceipt({
        actionId,
        terminal: 'SUCCEEDED',
        exitCode: HELPER_EXIT_CODES.OK,
        reason: 'step completed',
        isElevated: this.isElevated,
        sideEffectClass: this.sideEffectClass,
        recoveryClassification: verifiedHere ? 'COMPLETED_VERIFIED' : 'MAY_HAVE_EXECUTED_UNCERTAIN',
        postStateVerified: verifiedHere,
        outputRefs: outputRefsOf(outcome.result),
        stdoutRef: stdoutRefOf(outcome.result),
        stderrRef: stderrRefOf(outcome.result),
      });
      return HELPER_EXIT_CODES.OK;
    }

    this.journal.append('EXEC_STEP_FAILED', {
      step: 0,
      op: step.op,
      detail: { reason: outcome.reason, ...outcome.result },
    });
    const mutating = !isReadOnlyOp(step.op);
    this.writeReceipt({
      actionId,
      terminal: 'FAILED',
      exitCode: HELPER_EXIT_CODES.FAILED,
      reason: outcome.reason,
      isElevated: this.isElevated,
      sideEffectClass: this.sideEffectClass,
      recoveryClassification: mutating ? 'MAY_HAVE_EXECUTED_UNCERTAIN' : 'FAILED_BEFORE_EFFECT',
      postStateVerified: false,
      outputRefs: outputRefsOf(outcome.result),
      stdoutRef: stdoutRefOf(outcome.result),
      stderrRef: stderrRefOf(outcome.result),
    });
    return HELPER_EXIT_CODES.FAILED;
  }

  private refuse(reason: string, rejectionCode?: string): number {
    this.writeReceipt({
      actionId: this.envelope.action.actionId,
      terminal: 'REFUSED',
      exitCode: HELPER_EXIT_CODES.REFUSED,
      reason,
      rejectionCode,
      isElevated: this.isElevated,
      sideEffectClass: this.sideEffectClass,
      recoveryClassification: 'FAILED_BEFORE_EFFECT',
      postStateVerified: false,
    });
    return HELPER_EXIT_CODES.REFUSED;
  }

  private writeReceipt(
    input: Omit<ReceiptInput, 'journalFile' | 'receiptFile' | 'startedAt'>,
  ): void {
    const payload = {
      schemaVersion: ENVELOPE_SCHEMA_VERSION,
      actionId: input.actionId,
      environmentId: `local-windows/${hostname()}`,
      providerId: PROVIDER_ID,
      providerVersion: PROVIDER_VERSION,
      startedAt: this.startedAt,
      finishedAt: new Date().toISOString(),
      terminal: input.terminal,
      exitCode: input.exitCode,
      outputRefs: [...(input.outputRefs ?? []), this.journalFile, this.receiptFile],
      ...(input.stdoutRef ? { stdoutRef: input.stdoutRef } : {}),
      ...(input.stderrRef ? { stderrRef: input.stderrRef } : {}),
      sideEffectEvidence: {
        sideEffectClass: input.sideEffectClass,
        recoveryClassification: input.recoveryClassification,
        postStateVerified: input.postStateVerified,
        journalRef: this.journalFile,
      },
      detail: {
        reason: input.reason,
        ...(input.rejectionCode ? { rejectionCode: input.rejectionCode } : {}),
        isElevated: input.isElevated,
      },
    };
    const parsed = HelperReceiptFileSchema.parse(payload);
    const tmp = `${this.receiptFile}.tmp`;
    durableWriteFileSync(tmp, `${JSON.stringify(parsed, null, 2)}\n`);
    renameSync(tmp, this.receiptFile);
    this.journal.append('RECEIPT_WRITTEN', {
      detail: { terminal: input.terminal, receiptFile: this.receiptFile },
    });
  }
}

// ---- small utilities. ----

async function whoamiGroups(): Promise<string> {
  return new Promise((resolvePromise) => {
    // C13: machine-evidenced resolution, never PATH and never the inherited
    // SystemRoot alone: the launcher controls both, and a planted fake
    // whoami could get a filtered token judged elevated. Unresolvable ⇒
    // empty capture ⇒ isElevatedToken('') = false ⇒ ELEVATED refused.
    const exe = systemWhoamiExe();
    if (!exe) {
      resolvePromise('');
      return;
    }
    execFile(exe, ['/groups', '/fo', 'csv'], { windowsHide: true }, (err, stdout) => {
      resolvePromise(err ? '' : String(stdout));
    });
  });
}

function _fsArgsOf(action: Envelope['action']['action']): string[] {
  if (
    action.op === 'windows.fs.write' ||
    action.op === 'windows.fs.delete' ||
    action.op === 'windows.fs.verify'
  ) {
    const p = (action.parameters as { path?: unknown }).path;
    return [typeof p === 'string' ? p : ''];
  }
  if (action.op === 'windows.proc.exec') {
    const p = (action.parameters as { program?: unknown }).program;
    return [typeof p === 'string' ? p : ''];
  }
  return [];
}

function isReadOnlyOp(op: string): boolean {
  return (
    op === 'windows.fs.verify' ||
    op === 'windows.registry.verify' ||
    op === 'windows.proc.contextCheck'
  );
}

function outputRefsOf(result: Record<string, unknown>): string[] {
  const refs: string[] = [];
  for (const key of ['stdoutRef', 'stderrRef'] as const) {
    const v = result[key];
    if (typeof v === 'string') refs.push(v);
  }
  return refs;
}

function stdoutRefOf(result: Record<string, unknown>): string | undefined {
  const v = result.stdoutRef;
  return typeof v === 'string' ? v : undefined;
}

function stderrRefOf(result: Record<string, unknown>): string | undefined {
  const v = result.stderrRef;
  return typeof v === 'string' ? v : undefined;
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Contracts-shaped receipt projection (diagnostic `detail` stripped). */
export function toContractsReceipt(helper: unknown): ExecutionReceipt {
  const {
    detail: _detail,
    schemaVersion: _schemaVersion,
    ...rest
  } = helper as Record<string, unknown>;
  return ExecutionReceiptSchema.parse(rest);
}

// Natural exit (exitCode, not process.exit): an explicit process.exit can
// truncate pending stderr pipe writes on Windows, and the pre-journal refusal
// messages ARE the negative evidence channel.
const exitCode = await new Helper().run(process.argv);
process.exitCode = exitCode;
