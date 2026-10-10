// The bounded cleanup executor — the privileged boundary of this vertical
// (L2 §9.3): it receives an AuthorizedAction plus its grant presentation and
// re-verifies the presentation itself against current authority/policy state
// before any side effect, using the frozen contracts validator. Deletion is
// structurally size-blind: the only paths ever deleted are files enumerated
// under target directories carried by hashed plan actions; expected reclaim
// bytes in a parameter can no more delete something than a size reading can.
import { createHash } from 'node:crypto';
import { type Dirent, promises as fsp, type Stats } from 'node:fs';
import * as path from 'node:path';
import {
  type ActionPlan,
  type AuthorizationGrant,
  type AuthorizedAction,
  AuthorizedActionSchema,
  assertGrantPresentation,
  type CurrentAuthorityState,
  type ExecutionReceipt,
  ExecutionReceiptSchema,
  type GrantIntegrity,
  type GrantIntegrityVerifier,
  pathWithin,
} from '@shun/contracts';
import type { CleanupCategory } from './classify.ts';
import { classifyDirectory, touchesProtectedAsset } from './classify.ts';
import { StorageVerticalError } from './errors.ts';
import { classifyFromJournal, PhaseJournal, replayJournal } from './journal.ts';

export interface CleanupExecutionResult {
  receipt: ExecutionReceipt;
  /** Per-target outcomes keyed by actionId (stable identity, L2 §9.4). */
  targets: Record<
    string,
    {
      targetPath: string;
      deletedFiles: number;
      blockedFiles: number;
      blockedErrors: string[];
      reclaimedBytes: number;
    }
  >;
  journalPath: string;
}

export interface ExecuteCleanupInput {
  authorizedAction: AuthorizedAction;
  plan: ActionPlan;
  grant: unknown;
  currentAuthority: CurrentAuthorityState;
  now: string;
  verifyIntegrity: GrantIntegrityVerifier;
  scopeRoots: readonly string[];
  protectedRealPaths: readonly string[];
  eligibleCategories: readonly CleanupCategory[];
  journalPath: string;
  environmentId: string;
  providerId: string;
  providerVersion: string;
  /**
   * Deterministic race-injection seam for tests only: invoked synchronously
   * around effect-time filesystem operations so Windows-native TOCTOU swaps
   * (junction/reparse-point replacement mid-delete) can be reproduced
   * repeatably. Never set in production wiring.
   */
  testHooks?: DeleteTestHooks;
}

/** Test-only seams around effect-time operations (see ExecuteCleanupInput.testHooks). */
export interface DeleteTestHooks {
  /** Runs immediately before a file's effect-time target re-check and deletion. */
  beforeFileDelete?: (filePath: string) => void | Promise<void>;
  /** Runs immediately before descending into a subdirectory of the target. */
  beforeDirDescend?: (dirPath: string) => void | Promise<void>;
}

/**
 * Execute one bounded cleanup AuthorizedAction. Multiple actions (one per
 * target) are dispatched sequentially by the diagnose flow; this function
 * handles exactly one, under its own stable actionId.
 */
export async function executeBoundedCleanup(
  input: ExecuteCleanupInput,
): Promise<CleanupExecutionResult> {
  const { authorizedAction, plan } = input;
  const startedAt = input.now;

  // ---- Reconcile-first reentry guard (L2 §9.4): a same-action reentry whose
  // prior journal state is uncertain (torn mid-effect) or already completed
  // must never blindly re-execute — reconcile the checkpoint manifest first.
  // Only a prior run that provably never started effects may be retried.
  const priorClassification = classifyFromJournal(
    (await replayJournal(input.journalPath)).entries,
    authorizedAction.actionId,
  );
  if (
    priorClassification === 'MAY_HAVE_EXECUTED_UNCERTAIN' ||
    priorClassification === 'COMPLETED_VERIFIED'
  ) {
    throw new StorageVerticalError(
      'ACTION_NOT_BOUNDED',
      `action ${authorizedAction.actionId} was already executed (journal classification ${priorClassification}); reconcile against the checkpoint manifest first (reconcileAfterInterruption) instead of reentering`,
    );
  }

  const journal = await PhaseJournal.open(input.journalPath);
  await journal.append({
    at: startedAt,
    phase: 'RECEIVED',
    actionId: authorizedAction.actionId,
  });

  // ---- Privileged-boundary re-verification (never on the caller's say-so). ----
  try {
    assertGrantPresentation({
      grant: input.grant,
      plan,
      action: authorizedAction,
      currentAuthority: input.currentAuthority,
      now: input.now,
      verifyIntegrity: input.verifyIntegrity,
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    await journal.append({
      at: new Date().toISOString(),
      phase: 'GRANT_VALIDATED',
      actionId: authorizedAction.actionId,
      errorKind: detail.slice(0, 200),
    });
    const receipt = buildReceipt(input, startedAt, 'REFUSED', {
      recoveryClassification: 'NOT_STARTED',
      postStateVerified: false,
      journalRef: `evidence://journal/${path.basename(input.journalPath)}`,
    });
    return {
      receipt,
      targets: {},
      journalPath: input.journalPath,
    };
  }
  await journal.append({
    at: new Date().toISOString(),
    phase: 'GRANT_VALIDATED',
    actionId: authorizedAction.actionId,
  });

  // ---- Defense in depth beyond the contracts validator: scope, protected,
  // classification and op checks on the ACTUAL action surface. ----
  const action: AuthorizedAction = AuthorizedActionSchema.parse(authorizedAction);
  const params = action.action.parameters as {
    targetPath?: unknown;
    classification?: unknown;
    checkpointRef?: unknown;
  };
  const targetPath = typeof params.targetPath === 'string' ? params.targetPath : undefined;
  const classification =
    typeof params.classification === 'string' ? params.classification : undefined;
  if (action.action.op !== 'storage.clean_directory' || !targetPath || !classification) {
    throw new StorageVerticalError(
      'ACTION_NOT_BOUNDED',
      `action ${action.actionId} is not a well-formed storage.clean_directory action`,
    );
  }
  if (!input.eligibleCategories.includes(classification as CleanupCategory)) {
    throw new StorageVerticalError(
      'DATA_CLASSIFICATION_UNKNOWN',
      `action ${action.actionId} carries classification ${classification}, which the cleanup policy does not make eligible`,
    );
  }
  const realTarget = await fsp.realpath(targetPath);
  const inScope = input.scopeRoots.some((root) => pathWithin(realTarget, root));
  if (!inScope) {
    throw new StorageVerticalError(
      'ACTION_NOT_BOUNDED',
      `target ${targetPath} (realpath ${realTarget}) is outside the resolved scope`,
    );
  }
  // ---- Effect-time independent classification (never the caller's label):
  // the action parameter is attacker-controlled surface; the disposable
  // verdict is re-derived here from the path policy at the moment of effect
  // and must agree with the declared category, else nothing is deleted.
  const independent = classifyDirectory(realTarget, {
    protectedRealPaths: input.protectedRealPaths,
    scopeRoots: input.scopeRoots,
  });
  if (
    independent.cleanupCategory === null ||
    !input.eligibleCategories.includes(independent.cleanupCategory) ||
    independent.cleanupCategory !== classification
  ) {
    await journal.append({
      at: new Date().toISOString(),
      phase: 'TARGET_VALIDATED',
      actionId: action.actionId,
      errorKind: 'INDEPENDENT_CLASSIFICATION_MISMATCH',
    });
    const receipt = buildReceipt(input, startedAt, 'REFUSED', {
      recoveryClassification: 'FAILED_BEFORE_EFFECT',
      postStateVerified: false,
      journalRef: `evidence://journal/${path.basename(input.journalPath)}`,
    });
    return { receipt, targets: {}, journalPath: input.journalPath };
  }
  if (touchesProtectedAsset(realTarget, input.protectedRealPaths)) {
    await journal.append({
      at: new Date().toISOString(),
      phase: 'TARGET_VALIDATED',
      actionId: action.actionId,
      errorKind: 'PROTECTED_ASSET_TOUCHED',
    });
    const receipt = buildReceipt(input, startedAt, 'REFUSED', {
      recoveryClassification: 'FAILED_BEFORE_EFFECT',
      postStateVerified: false,
      journalRef: `evidence://journal/${path.basename(input.journalPath)}`,
    });
    return { receipt, targets: {}, journalPath: input.journalPath };
  }
  await journal.append({
    at: new Date().toISOString(),
    phase: 'TARGET_VALIDATED',
    actionId: action.actionId,
  });

  // ---- Bounded deletion: enumerate NOW under the approved target, delete
  // file-by-file with per-file journal phases. Reparse points are never
  // followed or deleted. ----
  let deletedFiles = 0;
  let blockedFiles = 0;
  let reclaimedBytes = 0;
  const blockedErrors: string[] = [];
  await deleteRecursively(
    realTarget,
    realTarget,
    action.actionId,
    journal,
    {
      onDeleted: (bytes) => {
        deletedFiles += 1;
        reclaimedBytes += bytes;
      },
      onBlocked: (kind) => {
        blockedFiles += 1;
        blockedErrors.push(kind);
      },
    },
    input.testHooks,
  );

  // ---- Durable receipt BEFORE any completed-verified claim (L2 §9.4 state
  // order: effects → durable RECEIPT_WRITTEN → classification). The receipt
  // itself is built only after the journal proves durability, and it never
  // claims post-state verification — that is the independent verifier's job
  // (verify.ts), which runs after this function returns.
  const terminal = blockedFiles === 0 ? 'SUCCEEDED' : 'FAILED';
  await journal.append({
    at: new Date().toISOString(),
    phase: 'RECEIPT_WRITTEN',
    actionId: action.actionId,
  });
  const recovery = classifyFromJournal(
    (await replayJournal(input.journalPath)).entries,
    action.actionId,
  );
  const receipt = buildReceipt(input, startedAt, terminal, {
    recoveryClassification: recovery === 'NOT_STARTED' ? 'FAILED_BEFORE_EFFECT' : recovery,
    postStateVerified: false,
    journalRef: `evidence://journal/${path.basename(input.journalPath)}`,
  });

  return {
    receipt,
    targets: {
      [action.actionId]: {
        targetPath,
        deletedFiles,
        blockedFiles,
        blockedErrors,
        reclaimedBytes,
      },
    },
    journalPath: input.journalPath,
  };
}

async function deleteRecursively(
  root: string,
  dir: string,
  actionId: string,
  journal: PhaseJournal,
  counters: { onDeleted: (bytes: number) => void; onBlocked: (kind: string) => void },
  hooks?: DeleteTestHooks,
  depth = 0,
): Promise<void> {
  if (depth > 16) return;
  let entries: Dirent[];
  try {
    entries = await fsp.readdir(dir, { withFileTypes: true });
  } catch {
    counters.onBlocked(`EREADDIR:${dir}`);
    return;
  }
  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) {
      // Never delete through or across reparse points; record honestly.
      counters.onBlocked(`REPARSE_POINT:${entryPath}`);
      continue;
    }
    if (entry.isDirectory()) {
      // TOCTOU re-check at descend time: between readdir and now the entry may
      // have been swapped for a junction/reparse point (Windows descendant
      // swap). Never descend into anything that is not still a plain directory.
      await hooks?.beforeDirDescend?.(entryPath);
      const dirStat: Stats | null = await fsp.lstat(entryPath).catch(() => null);
      if (!dirStat) continue; // raced away before descent: nothing happened
      if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
        counters.onBlocked(`REPARSE_POINT:${entryPath}`);
        continue;
      }
      await deleteRecursively(root, entryPath, actionId, journal, counters, hooks, depth + 1);
      await removeEmptyDir(entryPath, journal, actionId);
      continue;
    }
    if (!entry.isFile()) continue;
    let size = 0;
    try {
      size = (await fsp.lstat(entryPath)).size;
    } catch {
      continue; // raced away before EXEC_START: nothing happened, nothing to journal
    }
    await journal.append({
      at: new Date().toISOString(),
      phase: 'EXEC_START',
      actionId,
      file: entryPath,
      bytes: size,
    });
    // TOCTOU re-check at effect time: the entry (or an ancestor directory)
    // may have been swapped for a junction since enumeration. lstat does not
    // follow intermediate reparse points, so verify the real target
    // component-wise (attributes + resolved path inside the authorized
    // target) immediately before every deletion — a swapped path is blocked,
    // never deleted through.
    await hooks?.beforeFileDelete?.(entryPath);
    const target = await checkDeletionTarget(entryPath, root);
    if (!target.ok) {
      await journal.append({
        at: new Date().toISOString(),
        phase: 'EXEC_BLOCKED',
        actionId,
        file: entryPath,
        errorKind: target.kind.split(':')[0] ?? 'BLOCKED',
      });
      counters.onBlocked(target.kind);
      continue;
    }
    try {
      await fsp.rm(entryPath, { force: false });
      await journal.append({
        at: new Date().toISOString(),
        phase: 'EXEC_DONE',
        actionId,
        file: entryPath,
        bytes: size,
      });
      counters.onDeleted(size);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? 'UNKNOWN';
      await journal.append({
        at: new Date().toISOString(),
        phase: 'EXEC_BLOCKED',
        actionId,
        file: entryPath,
        errorKind: code,
      });
      counters.onBlocked(`${code}:${entryPath}`);
    }
  }
}

type DeletionTargetCheck = { ok: true } | { ok: false; kind: string };

/**
 * Effect-time verification of one deletion target, defeating the descendant
 * junction/reparse swap (VS-P0-01): the final component must still be a plain
 * file (lstat never follows it), and the fully resolved real path of its
 * PARENT must still lie inside the authorized target tree — resolving the
 * parent traverses every ancestor, so a swap of any ancestor (or of the
 * parent itself) to a junction resolves outside and is blocked instead of
 * deleted through. The parent is resolved rather than the file: realpath on
 * the file would open a handle (failing under deny-Delete ACLs), while the
 * parent resolution needs no access to the file itself.
 */
async function checkDeletionTarget(
  entryPath: string,
  rootReal: string,
): Promise<DeletionTargetCheck> {
  let st: Stats;
  try {
    st = await fsp.lstat(entryPath);
  } catch {
    return { ok: false, kind: `VANISHED:${entryPath}` };
  }
  if (st.isSymbolicLink() || !st.isFile()) {
    return { ok: false, kind: `REPARSE_POINT:${entryPath}` };
  }
  let parentReal: string;
  try {
    parentReal = await fsp.realpath(path.dirname(entryPath));
  } catch {
    return { ok: false, kind: `VANISHED:${entryPath}` };
  }
  if (!pathWithin(parentReal, rootReal)) {
    return { ok: false, kind: `OUTSIDE_SCOPE:${entryPath}` };
  }
  return { ok: true };
}

async function removeEmptyDir(dir: string, journal: PhaseJournal, actionId: string): Promise<void> {
  try {
    // Never rmdir through a swap: a junction that replaced the directory is
    // left untouched (the executor never deletes reparse points).
    const st = await fsp.lstat(dir);
    if (st.isSymbolicLink() || !st.isDirectory()) return;
    const remaining = await fsp.readdir(dir);
    if (remaining.length === 0) {
      await fsp.rmdir(dir);
      await journal.append({
        at: new Date().toISOString(),
        phase: 'EXEC_DONE',
        actionId,
        file: `${dir}/(dir)`,
        bytes: 0,
      });
    }
  } catch {
    // dir raced away or is gone: honest no-op
  }
}

function buildReceipt(
  input: ExecuteCleanupInput,
  startedAt: string,
  terminal: ExecutionReceipt['terminal'],
  sideEffect: {
    recoveryClassification: ExecutionReceipt['sideEffectEvidence']['recoveryClassification'];
    postStateVerified: boolean;
    journalRef: string;
  },
): ExecutionReceipt {
  const finishedAt = new Date().toISOString();
  return ExecutionReceiptSchema.parse({
    actionId: input.authorizedAction.actionId,
    environmentId: input.environmentId,
    providerId: input.providerId,
    providerVersion: input.providerVersion,
    startedAt,
    finishedAt,
    terminal,
    outputRefs: [sideEffect.journalRef],
    sideEffectEvidence: {
      sideEffectClass: 'R2',
      recoveryClassification: sideEffect.recoveryClassification,
      postStateVerified: sideEffect.postStateVerified,
      journalRef: sideEffect.journalRef,
    },
  });
}

/**
 * Reconcile-first recovery (L2 §9.4): given a possibly torn journal and the
 * checkpoint manifest, determine which manifest files still exist; returns the
 * bytes that a retry would still reclaim. Never deletes — reconciliation only.
 */
export async function reconcileAfterInterruption(input: {
  journalPath: string;
  actionId: string;
  manifestFiles: readonly { path: string; sizeBytes: number }[];
}): Promise<{
  classification: RecoveryClassificationOf;
  filesStillPresent: number;
  bytesStillPresent: number;
}> {
  const { entries } = await replayJournal(input.journalPath);
  const classification = classifyFromJournal(entries, input.actionId);
  let filesStillPresent = 0;
  let bytesStillPresent = 0;
  for (const file of input.manifestFiles) {
    try {
      const st = await fsp.lstat(file.path);
      if (st.isFile()) {
        filesStillPresent += 1;
        bytesStillPresent += st.size;
      }
    } catch {
      // gone — either never created or already deleted by the interrupted run
    }
  }
  return { classification, filesStillPresent, bytesStillPresent };
}
type RecoveryClassificationOf = ReturnType<typeof classifyFromJournal>;

/** Convenience for tests/evidence: stable digest of a grant envelope (no secret material). */
export function grantFingerprint(grant: AuthorizationGrant, envelope: GrantIntegrity): string {
  return createHash('sha256')
    .update(`${grant.grantId}|${envelope.scheme}|${envelope.value}`)
    .digest('hex');
}
