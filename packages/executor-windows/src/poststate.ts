// Independent post-state verification and reconcile-first expected-state
// checks, run by the LAUNCHER side (never the actor of the original effect).
// This is what makes COMPLETED_VERIFIED mean something (L2 §9.4): the helper
// ran the action; the launcher re-establishes the resulting state with
// read-only ops of its own.
import type { AuthorizedAction } from '@shun/contracts';
import { resolveActionStep } from './action-surface.ts';
import { type InterpreterContext, type InterpreterScope, runStep } from './interpreter.ts';
import type { JournalWriter } from './journal.ts';
import type { PostStateOutcome } from './recovery.ts';

/** Verify-family ops the launcher may re-run independently (contextCheck excluded: it asserts the privileged token state, which the launcher cannot replicate). */
const LAUNCHER_RERUNNABLE = new Set(['windows.fs.verify', 'windows.registry.verify']);

/**
 * Re-run a readonly verify step with identical typed args. The launcher runs
 * with its own (non-elevated) rights; fs/registry reads covered by the grant
 * scope do not need elevation, which is exactly what makes the check
 * independent of the privileged side.
 */
export async function rerunVerifyStep(
  action: AuthorizedAction,
  scope: InterpreterScope,
  journal: JournalWriter,
): Promise<PostStateOutcome> {
  const step = resolveActionStep(action);
  if (!step || !LAUNCHER_RERUNNABLE.has(step.op)) {
    return { verified: false, basis: 'action declares no launcher-verifiable post-state step' };
  }
  const ctx: InterpreterContext = {
    journal,
    scope,
    isElevated: false,
    deadlineAt: new Date(Date.now() + 30000),
    evidenceDir: '',
  };
  const outcome = await runStep(step, ctx);
  return outcome.ok
    ? { verified: true, holds: true, basis: `launcher re-ran ${step.op}: post-state holds` }
    : { verified: true, holds: false, basis: `launcher re-ran ${step.op}: ${outcome.reason}` };
}

/**
 * Reconcile-first (§9.4): resolve an interruption inside [EXEC_START,
 * EXEC_DONE) against the action's declared `expectedState`. Convention —
 * expectedState mirrors the matching verify-op args for the op family:
 *   windows.fs.write/delete  → { path, exists, content?, sha256? }
 *   windows.registry.*       → { key, expectKeyExists?, expectValues? }
 * Ops without a declared, verifiable expected state stay honestly UNCERTAIN.
 */
export async function reconcileExpectedState(
  action: AuthorizedAction,
  scope: InterpreterScope,
  journal: JournalWriter,
): Promise<PostStateOutcome> {
  const expected = action.action.expectedState;
  if (!expected || Object.keys(expected).length === 0) {
    return { verified: false, basis: 'interrupted step declares no verifiable expected state' };
  }
  const op = action.action.op;
  let synthesized:
    | { op: 'windows.fs.verify' | 'windows.registry.verify'; args: Record<string, unknown> }
    | undefined;
  if (
    op === 'windows.fs.write' ||
    op === 'windows.fs.delete' ||
    // proc.exec children typically land artifacts; the declared expected
    // state uses the same fs verify convention.
    op === 'windows.proc.exec'
  ) {
    const es = expected as { path?: unknown; exists?: unknown };
    if (typeof es.path !== 'string' || typeof es.exists !== 'boolean') {
      return { verified: false, basis: 'expectedState does not match the fs verify convention' };
    }
    synthesized = {
      op: 'windows.fs.verify',
      args: {
        path: es.path,
        expectExists: es.exists,
        ...(typeof (expected as { content?: unknown }).content === 'string'
          ? { expectContent: (expected as { content: string }).content }
          : {}),
        ...(typeof (expected as { sha256?: unknown }).sha256 === 'string'
          ? { expectSha256: (expected as { sha256: string }).sha256 }
          : {}),
      },
    };
  } else if (op.startsWith('windows.registry.')) {
    const es = expected as { key?: unknown };
    if (typeof es.key !== 'string') {
      return {
        verified: false,
        basis: 'expectedState does not match the registry verify convention',
      };
    }
    synthesized = {
      op: 'windows.registry.verify',
      args: {
        key: es.key,
        ...(typeof (expected as { expectKeyExists?: unknown }).expectKeyExists === 'boolean'
          ? { expectKeyExists: (expected as { expectKeyExists: boolean }).expectKeyExists }
          : {}),
        ...(expected.expectValues && typeof expected.expectValues === 'object'
          ? { expectValues: expected.expectValues }
          : {}),
      },
    };
  } else {
    return { verified: false, basis: `op ${op} has no expected-state convention` };
  }
  const ctx: InterpreterContext = {
    journal,
    scope,
    isElevated: false,
    deadlineAt: new Date(Date.now() + 30000),
    evidenceDir: '',
  };
  const outcome = await runStep(
    { op: synthesized.op, args: synthesized.args } as Parameters<typeof runStep>[0],
    ctx,
  );
  return outcome.ok
    ? {
        verified: true,
        holds: true,
        basis: `reconcile-first verified expected state via ${synthesized.op}`,
      }
    : {
        verified: true,
        holds: false,
        basis: `reconcile-first proved expected state absent via ${synthesized.op}: ${outcome.reason}`,
      };
}
