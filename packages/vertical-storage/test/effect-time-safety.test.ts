// T07 negative controls for the Audit-B storage findings (Issue #40): every
// test here encodes a safety property that MUST hold at effect time, on the
// real local Windows filesystem where required:
//   VS-P0-01  descendant junction/reparse swap mid-delete must not escape scope
//   VS-P1-02  executor must independently re-classify (never trust caller labels)
//   VS-P1-04  COMPLETED_VERIFIED only after durable RECEIPT_WRITTEN (+ verification)
//   VS-P1-05  uncertain same-action reentry must reconcile first
// The tests use the executor's deterministic race-injection seams to make
// TOCTOU swaps reproducible; on non-Windows hosts the Windows-mechanism
// controls skip honestly while the portable controls still run.
import { promises as fsp, symlinkSync as fspSymlink } from 'node:fs';
import * as path from 'path';
import {
  type ActionPlan,
  type AuthorizedAction,
  computePlanHash,
  PlanActionSchema,
} from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import {
  classifyFromJournal,
  executeBoundedCleanup,
  type ExecuteCleanupInput,
  replayJournal,
  StorageVerticalError,
} from '../src/index.ts';
import {
  type AuthorityDouble,
  makeAuthorityDouble,
  makeClock,
  makeFixtureRoot,
  plantFiles,
} from './helpers.ts';

interface Ctx {
  root: string;
  scopeRoot: string;
  targetDir: string;
  authority: AuthorityDouble;
  journalPath: string;
}

async function setup(label: string, targetName = 'cache'): Promise<Ctx> {
  const root = await makeFixtureRoot(label);
  const scopeRoot = path.join(root, 'scope');
  const targetDir = path.join(scopeRoot, targetName);
  await plantFiles(targetDir, [{ relativePath: 'a.bin', bytes: 512 }]);
  return {
    root,
    scopeRoot,
    targetDir,
    authority: makeAuthorityDouble(makeClock().now),
    journalPath: path.join(root, 'evidence', 'journal.jsonl'),
  };
}

async function runCleanup(
  ctx: Ctx,
  options: {
    targetPath?: string;
    classification?: string;
    testHooks?: ExecuteCleanupInput['testHooks'];
    journalPath?: string;
  } = {},
) {
  const targetPath = options.targetPath ?? ctx.targetDir;
  const planAction = PlanActionSchema.parse({
    actionId: 'action/test/clean-safety-1',
    bindingRef: 'binding/test',
    op: 'storage.clean_directory',
    parameters: {
      targetPath,
      classification: options.classification ?? 'CACHE',
      expectedReclaimBytes: 0,
      checkpointRef: 'evidence://t/cp.json',
    },
    sideEffectClass: 'R2',
    requiredPrivilege: 'USER',
    filesystemScope: { read: [targetPath], write: [targetPath] },
    networkScope: { allowed: false },
    expectedState: { targetPath, postCleanFiles: 0, manifestRef: 'evidence://t/cp.json' },
  });
  const draft = {
    taskId: 'task-t07-safety',
    capabilityId: 'system.storage.diagnose_bounded_action',
    bindingRefs: ['binding/test'],
    rankingPolicyRevision: 'ranking-rev-1',
    policySnapshotRevision: 'policy-rev-1',
    actions: [planAction],
    verificationPlan: {
      verifierId: 'verifier.storage-c003',
      verifierRevision: 'r1',
      checks: [{ checkId: 'reclaimed-bytes-verified' }],
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE' as const,
      reconcileBeforeRetry: true as const,
      retryAllowedWhen: 'DECLARED_IDEMPOTENT' as const,
    },
  };
  const plan: ActionPlan = {
    ...draft,
    planHash: computePlanHash({ ...draft, planHash: '0'.repeat(64) }),
  };
  const grant = await ctx.authority.issueGrant({
    taskId: plan.taskId,
    planHash: plan.planHash,
    policySnapshotRevision: plan.policySnapshotRevision,
    actionScope: {
      actionIds: plan.actions.map((a) => a.actionId),
      privilegeLevel: 'USER',
      filesystem: { read: [ctx.scopeRoot], write: [ctx.scopeRoot] },
      network: { allowed: false },
    },
    authorizationKind: 'EXPLICIT_APPROVAL',
    approvalRef: 'approval-1',
  });
  const action: AuthorizedAction = {
    taskId: plan.taskId,
    actionId: planAction.actionId,
    planHash: plan.planHash,
    policySnapshotRevision: plan.policySnapshotRevision,
    authorizationKind: 'EXPLICIT_APPROVAL',
    authorizationRef: (grant as { grantId: string }).grantId,
    action: planAction,
  };
  const clock = makeClock();
  return executeBoundedCleanup({
    authorizedAction: action,
    plan,
    grant,
    currentAuthority: await ctx.authority.currentAuthority(),
    now: clock.now(),
    verifyIntegrity: ctx.authority.verifyIntegrity,
    scopeRoots: [ctx.scopeRoot],
    protectedRealPaths: [],
    eligibleCategories: ['CACHE', 'TEMP'],
    journalPath: options.journalPath ?? ctx.journalPath,
    environmentId: 'env-t07-safety',
    providerId: 'storage.cleaner.local-windows',
    providerVersion: '0.1.0-t07',
    testHooks: options.testHooks,
  });
}

describe('VS-P0-01 — descendant junction/reparse swap cannot escape the delete scope', () => {
  const itWin = process.platform === 'win32' ? it : it.skip;

  itWin(
    'a subdirectory swapped to a junction mid-delete is never traversed (descend-time re-check)',
    async () => {
      const ctx = await setup('swap-descend');
      const outsideDir = path.join(ctx.root, 'outside');
      // Same-named bait files: without the re-check these would be deleted
      // THROUGH the junction, outside the authorized target.
      await plantFiles(outsideDir, [
        { relativePath: 'f1.bin', bytes: 32 },
        { relativePath: 'f2.bin', bytes: 32 },
      ]);
      const sub = path.join(ctx.targetDir, 'sub');
      await plantFiles(sub, [
        { relativePath: 'f1.bin', bytes: 32 },
        { relativePath: 'f2.bin', bytes: 32 },
      ]);
      let swapped = false;
      const result = await runCleanup(ctx, {
        testHooks: {
          beforeDirDescend: async (dirPath) => {
            if (swapped || dirPath !== sub) return;
            swapped = true;
            await fsp.rename(sub, `${sub}.hidden`);
            fspSymlink(outsideDir, sub, 'junction');
          },
        },
      });
      // The swap is observed at descend time: blocked, never traversed.
      expect(result.receipt.terminal).toBe('FAILED');
      const target = result.targets[result.receipt.actionId];
      expect(target?.blockedErrors.join(';')).toMatch(/REPARSE_POINT/);
      // Nothing outside the target was touched.
      expect(await fsp.readFile(path.join(outsideDir, 'f1.bin'), 'utf8')).toBe('x'.repeat(32));
      expect(await fsp.readFile(path.join(outsideDir, 'f2.bin'), 'utf8')).toBe('x'.repeat(32));
      // The real descendant content (now at the hidden name) also survives.
      expect(await fsp.readFile(path.join(`${sub}.hidden`, 'f1.bin'), 'utf8')).toBe('x'.repeat(32));
    },
  );

  itWin(
    'a subdirectory swapped to a junction between enumeration and file delete cannot redirect deletions outside scope',
    async () => {
      const ctx = await setup('swap-effect');
      const outsideDir = path.join(ctx.root, 'outside');
      await plantFiles(outsideDir, [
        { relativePath: 'f1.bin', bytes: 32 },
        { relativePath: 'f2.bin', bytes: 32 },
      ]);
      const sub = path.join(ctx.targetDir, 'sub');
      await plantFiles(sub, [
        { relativePath: 'f1.bin', bytes: 32 },
        { relativePath: 'f2.bin', bytes: 32 },
      ]);
      let swapped = false;
      const result = await runCleanup(ctx, {
        testHooks: {
          beforeFileDelete: async (filePath) => {
            if (swapped || !filePath.startsWith(sub)) return;
            swapped = true;
            await fsp.rename(sub, `${sub}.hidden`);
            fspSymlink(outsideDir, sub, 'junction');
          },
        },
      });
      const target = result.targets[result.receipt.actionId];
      // Every post-swap deletion path resolves through the junction to a real
      // file OUTSIDE the target: the effect-time realpath re-check must block
      // each one, never delete through the reparse point.
      expect(result.receipt.terminal).toBe('FAILED');
      expect(target?.blockedErrors.join(';')).toMatch(/OUTSIDE_SCOPE/);
      expect(await fsp.readFile(path.join(outsideDir, 'f1.bin'), 'utf8')).toBe('x'.repeat(32));
      expect(await fsp.readFile(path.join(outsideDir, 'f2.bin'), 'utf8')).toBe('x'.repeat(32));
      // The authentic descendant files survive under the hidden real directory.
      expect(await fsp.readFile(path.join(`${sub}.hidden`, 'f1.bin'), 'utf8')).toBe('x'.repeat(32));
      expect(await fsp.readFile(path.join(`${sub}.hidden`, 'f2.bin'), 'utf8')).toBe('x'.repeat(32));
    },
  );
});

describe('VS-P1-02 — executor independently re-classifies at effect time', () => {
  it('refuses (REFUSED, no deletion) when the caller labels a non-disposable directory CACHE', async () => {
    const ctx = await setup('classify-mismatch', 'userdata');
    const result = await runCleanup(ctx, { classification: 'CACHE' });
    expect(result.receipt.terminal).toBe('REFUSED');
    // The caller label was not trusted: no effect happened.
    expect(await fsp.readdir(ctx.targetDir)).toEqual(['a.bin']);
    const entries = (await replayJournal(ctx.journalPath)).entries;
    expect(entries.some((e) => e.phase === 'EXEC_START')).toBe(false);
    expect(entries.some((e) => e.errorKind === 'INDEPENDENT_CLASSIFICATION_MISMATCH')).toBe(true);
  });

  it('still executes when the independent classification matches the declared category', async () => {
    const ctx = await setup('classify-match');
    const result = await runCleanup(ctx);
    expect(result.receipt.terminal).toBe('SUCCEEDED');
    expect(await fsp.readdir(ctx.targetDir)).toEqual([]);
  });
});

describe('VS-P1-04 — COMPLETED_VERIFIED only after durable RECEIPT_WRITTEN and verification', () => {
  it('in-run receipt does not claim post-state verification (the verifier does that later)', async () => {
    const ctx = await setup('receipt-honesty');
    const result = await runCleanup(ctx);
    expect(result.receipt.terminal).toBe('SUCCEEDED');
    expect(result.receipt.sideEffectEvidence.postStateVerified).toBe(false);
  });

  it('journal without a durable RECEIPT_WRITTEN classifies as MAY_HAVE_EXECUTED_UNCERTAIN, never COMPLETED_VERIFIED', async () => {
    const ctx = await setup('receipt-durability');
    const { PhaseJournal } = await import('../src/index.ts');
    const journal = await PhaseJournal.open(ctx.journalPath);
    await journal.append({ at: makeClock().now(), phase: 'RECEIVED', actionId: 'a1' });
    await journal.append({
      at: makeClock().now(),
      phase: 'EXEC_START',
      actionId: 'a1',
      file: path.join(ctx.targetDir, 'a.bin'),
      bytes: 512,
    });
    await journal.append({
      at: makeClock().now(),
      phase: 'EXEC_DONE',
      actionId: 'a1',
      file: path.join(ctx.targetDir, 'a.bin'),
      bytes: 512,
    });
    // All effects journaled, but the receipt never became durable: an observer
    // must see uncertainty (reconcile-first), not a verified completion.
    const classification = classifyFromJournal(
      (await replayJournal(ctx.journalPath)).entries,
      'a1',
    );
    expect(classification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
  });

  it('a finished run journals RECEIPT_WRITTEN, and replay then classifies COMPLETED_VERIFIED', async () => {
    const ctx = await setup('receipt-order');
    const result = await runCleanup(ctx);
    const replay = await replayJournal(ctx.journalPath);
    expect(replay.entries.some((e) => e.phase === 'RECEIPT_WRITTEN')).toBe(true);
    expect(classifyFromJournal(replay.entries, result.receipt.actionId)).toBe('COMPLETED_VERIFIED');
    // Ordering: RECEIPT_WRITTEN is durable only after every EXEC_DONE.
    const lastDone = replay.entries.map((e) => e.phase).lastIndexOf('EXEC_DONE');
    const receiptAt = replay.entries.map((e) => e.phase).indexOf('RECEIPT_WRITTEN');
    expect(receiptAt).toBeGreaterThan(lastDone);
  });
});

describe('VS-P1-05 — uncertain same-action reentry must reconcile first', () => {
  it('refuses to re-execute an action whose journal is MAY_HAVE_EXECUTED_UNCERTAIN', async () => {
    const ctx = await setup('reentry-uncertain');
    const { PhaseJournal } = await import('../src/index.ts');
    const journal = await PhaseJournal.open(ctx.journalPath);
    await journal.append({ at: makeClock().now(), phase: 'RECEIVED', actionId: 'action/test/clean-safety-1' });
    await journal.append({
      at: makeClock().now(),
      phase: 'EXEC_START',
      actionId: 'action/test/clean-safety-1',
      file: path.join(ctx.targetDir, 'a.bin'),
      bytes: 512,
    });
    const before = (await replayJournal(ctx.journalPath)).entries.length;
    await expect(runCleanup(ctx)).rejects.toThrow(/reconcile/i);
    // Reentry attempted nothing: journal and filesystem are untouched.
    expect((await replayJournal(ctx.journalPath)).entries.length).toBe(before);
    expect(await fsp.readdir(ctx.targetDir)).toEqual(['a.bin']);
  });

  it('refuses duplicate execution of an already-completed action (no second RECEIVED)', async () => {
    const ctx = await setup('reentry-completed');
    const first = await runCleanup(ctx);
    expect(first.receipt.terminal).toBe('SUCCEEDED');
    const before = (await replayJournal(ctx.journalPath)).entries.length;
    await expect(runCleanup(ctx)).rejects.toThrow(StorageVerticalError);
    expect((await replayJournal(ctx.journalPath)).entries.length).toBe(before);
  });
});
