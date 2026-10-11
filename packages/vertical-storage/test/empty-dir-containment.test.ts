// T07 negative controls for the empty-dir ancestor-swap finding natively
// validated on PR #48 @1c8afb8 (Issue #40 controller disposition): after the
// per-file checks, removeEmptyDir only lstat/readdir/rmdir'd the FINAL
// directory component and never re-checked the resolved parent chain, so an
// ancestor swapped to a REAL Windows junction let the executor rmdir an
// EXTERNAL empty mirror directory and journal a false EXEC_DONE (dir) entry —
// an unauthorized out-of-scope destructive effect. These tests encode the
// CORRECT behavior and must hold at effect time on the real local Windows
// filesystem:
//   empty-dir-1  ancestor junction swap must not rmdir the external empty
//                mirror; the block is journaled honestly (OUTSIDE_SCOPE);
//                no false EXEC_DONE (dir) may ever enter the journal
//   empty-dir-2  in-scope empty subdirectory deletion still succeeds
//                (positive control — the repair must not break the feature)
//   empty-dir-3  an ancestor swap over a FOREIGN NONEMPTY directory stays a
//                safe honest no-op (ENOTEMPTY path unchanged)
//   empty-dir-4  a final-segment junction at removal time is never removed
//                (regression guard for the existing reparse-point gate)
// The swaps use real `cmd /c mklink /J` junctions injected through the
// executor's deterministic testHooks seam. Windows-mechanism controls skip
// honestly on non-Windows hosts.
import { execSync } from 'node:child_process';
import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import {
  type ActionPlan,
  type AuthorizedAction,
  computePlanHash,
  PlanActionSchema,
} from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { type ExecuteCleanupInput, executeBoundedCleanup, replayJournal } from '../src/index.ts';
import {
  type AuthorityDouble,
  makeAuthorityDouble,
  makeClock,
  makeFixtureRoot,
  plantFiles,
} from './helpers.ts';

const itWin = process.platform === 'win32' ? it : it.skip;

/** Real Windows directory junction via cmd mklink /J (no Node symlink API). */
function mklinkJunction(link: string, target: string): void {
  execSync(`cmd /c mklink /J "${link}" "${target}"`, { stdio: 'pipe' });
}

interface Ctx {
  root: string;
  scopeRoot: string;
  targetDir: string;
  authority: AuthorityDouble;
  journalPath: string;
}

async function setup(label: string): Promise<Ctx> {
  const root = await makeFixtureRoot(label);
  const scopeRoot = path.join(root, 'scope');
  const targetDir = path.join(scopeRoot, 'cache');
  // No top-level file is planted: the only content lives in `sub` so the
  // swap timing (last file of `sub`) is exactly the validated repro.
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
    testHooks?: ExecuteCleanupInput['testHooks'];
  } = {},
) {
  const targetPath = options.targetPath ?? ctx.targetDir;
  const planAction = PlanActionSchema.parse({
    actionId: 'action/test/clean-emptydir-1',
    bindingRef: 'binding/test',
    op: 'storage.clean_directory',
    parameters: {
      targetPath,
      classification: 'CACHE',
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
    taskId: 'task-t07-emptydir',
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
    journalPath: ctx.journalPath,
    environmentId: 'env-t07-emptydir',
    providerId: 'storage.cleaner.local-windows',
    providerVersion: '0.1.0-t07',
    testHooks: options.testHooks,
  });
}

interface SwapDeps {
  ctx: Ctx;
  sub: string;
  outside: string;
}

/**
 * The timed swap under test: when the LAST file inside `sub` is about to be
 * deleted, the ANCESTOR directory (`cache`, the authorized target itself) is
 * renamed aside and replaced by a real junction pointing at the external
 * tree — exactly the natively validated attack. Every later path resolution
 * (effect-time file checks AND removeEmptyDir) therefore traverses the
 * junction. `didSwap` lets a test prove the negative actually fired.
 */
function ancestorSwapHook(deps: SwapDeps): {
  hooks: NonNullable<ExecuteCleanupInput['testHooks']>;
  didSwap: () => boolean;
  junctionPath: string;
} {
  let swapped = false;
  return {
    hooks: {
      beforeFileDelete: async (filePath) => {
        if (swapped || !filePath.startsWith(deps.sub) || !filePath.endsWith('b.bin')) return;
        swapped = true;
        await fsp.rename(deps.ctx.targetDir, `${deps.ctx.targetDir}.hidden`);
        mklinkJunction(deps.ctx.targetDir, deps.outside);
      },
    },
    didSwap: () => swapped,
    junctionPath: deps.ctx.targetDir,
  };
}

describe('empty-dir removal — ancestor junction containment at effect time', () => {
  itWin(
    'an ancestor swapped to a junction cannot make removeEmptyDir rmdir an external EMPTY mirror (no false EXEC_DONE (dir))',
    async () => {
      const ctx = await setup('emptydir-ancestor');
      const sub = path.join(ctx.targetDir, 'sub');
      await plantFiles(sub, [
        { relativePath: 'a.bin', bytes: 32 },
        { relativePath: 'b.bin', bytes: 32 },
      ]);
      const outside = path.join(ctx.root, 'outside');
      const outsideSub = path.join(outside, 'sub'); // the EMPTY external mirror
      await fsp.mkdir(outsideSub, { recursive: true });
      const baitContent = 'OUTSIDE-BAIT-EMPTYDIR-CANARY';
      await plantFiles(outside, [{ relativePath: 'bait.bin', bytes: 64, content: baitContent }]);
      const swap = ancestorSwapHook({ ctx, sub, outside });
      const result = await runCleanup(ctx, { testHooks: swap.hooks });
      try {
        const target = result.targets[result.receipt.actionId];
        // The timed swap must actually have fired, or this control is void.
        expect(swap.didSwap()).toBe(true);
        // The last file resolves through the junction to a nonexistent path
        // and is VANISHED-blocked by the per-file checks: the receipt must be
        // an honest FAILED, never a silent success.
        expect(result.receipt.terminal).toBe('FAILED');
        expect(target?.deletedFiles).toBeLessThanOrEqual(1);
        // The out-of-scope canary file is byte-exact: no file effects escaped.
        expect(await fsp.readFile(path.join(outside, 'bait.bin'), 'utf8')).toBe(
          baitContent.padEnd(64, 'x'),
        );
        // The file the swap protected survives under the hidden original
        // directory (earlier in-scope files may have been legitimately
        // deleted before the swap).
        expect(
          await fsp.readFile(path.join(`${ctx.targetDir}.hidden`, 'sub', 'b.bin'), 'utf8'),
        ).toBe('a'.repeat(32));
        // The empty-dir removal is BLOCKED at effect time with honest
        // containment journaling, never executed out of scope.
        expect(target?.blockedErrors.join(';')).toMatch(/OUTSIDE_SCOPE/);
        const entries = (await replayJournal(ctx.journalPath)).entries;
        const dirBlocked = entries.filter(
          (e) =>
            e.phase === 'EXEC_BLOCKED' &&
            e.errorKind === 'OUTSIDE_SCOPE' &&
            e.file?.endsWith('(dir)'),
        );
        expect(dirBlocked.length).toBe(1);
        // No false deletion claim: removeEmptyDir must never journal EXEC_DONE
        // for the out-of-scope mirror it must not touch.
        const dirDone = entries.filter((e) => e.phase === 'EXEC_DONE' && e.file?.endsWith('(dir)'));
        expect(dirDone).toEqual([]);
        // The external EMPTY mirror survives path-exact (never rmdir'd through
        // the junction), still an empty directory.
        const mirrorStat = await fsp.lstat(outsideSub);
        expect(mirrorStat.isDirectory()).toBe(true);
        expect(await fsp.readdir(outsideSub)).toEqual([]);
        // The junction itself is never deleted by the executor.
        expect((await fsp.lstat(swap.junctionPath)).isSymbolicLink()).toBe(true);
      } finally {
        // Remove the junction link itself so teardown never traverses it.
        await fsp.rmdir(swap.junctionPath).catch(() => {});
      }
    },
  );

  it('still deletes an in-scope empty subdirectory (positive control)', async () => {
    const ctx = await setup('emptydir-positive');
    const sub = path.join(ctx.targetDir, 'sub');
    await fsp.mkdir(sub, { recursive: true });
    const result = await runCleanup(ctx);
    expect(result.receipt.terminal).toBe('SUCCEEDED');
    expect(await fsp.readdir(ctx.targetDir)).toEqual([]);
    const target = result.targets[result.receipt.actionId];
    expect(target?.blockedErrors).toEqual([]);
    const entries = (await replayJournal(ctx.journalPath)).entries;
    const dirDone = entries.filter((e) => e.phase === 'EXEC_DONE' && e.file?.endsWith('(dir)'));
    expect(dirDone.length).toBe(1);
  });

  itWin(
    'an ancestor swap over a FOREIGN NONEMPTY directory stays a safe honest no-op (ENOTEMPTY path unchanged)',
    async () => {
      const ctx = await setup('emptydir-foreign');
      const sub = path.join(ctx.targetDir, 'sub');
      await plantFiles(sub, [
        { relativePath: 'a.bin', bytes: 32 },
        { relativePath: 'b.bin', bytes: 32 },
      ]);
      const outside = path.join(ctx.root, 'outside');
      const outsideSub = path.join(outside, 'sub'); // foreign NONEMPTY mirror
      const foreignContent = 'FOREIGN-NONEMPTY-CANARY';
      await plantFiles(outsideSub, [
        { relativePath: 'data.bin', bytes: 64, content: foreignContent },
      ]);
      const swap = ancestorSwapHook({ ctx, sub, outside });
      const result = await runCleanup(ctx, { testHooks: swap.hooks });
      try {
        expect(swap.didSwap()).toBe(true);
        // The last file is still VANISHED-blocked through the junction.
        expect(result.receipt.terminal).toBe('FAILED');
        // The foreign directory is neither removed nor journaled as an
        // effect: a nonempty directory is a safe silent no-op (ENOTEMPTY).
        const entries = (await replayJournal(ctx.journalPath)).entries;
        expect(entries.filter((e) => e.file?.endsWith('(dir)'))).toEqual([]);
        // The foreign content is byte-exact.
        expect(await fsp.readFile(path.join(outsideSub, 'data.bin'), 'utf8')).toBe(
          foreignContent.padEnd(64, 'x'),
        );
        expect((await fsp.lstat(outsideSub)).isDirectory()).toBe(true);
        // The junction itself survives; the executor never deletes reparse points.
        expect((await fsp.lstat(swap.junctionPath)).isSymbolicLink()).toBe(true);
      } finally {
        await fsp.rmdir(swap.junctionPath).catch(() => {});
      }
    },
  );

  itWin(
    'a final-segment junction at empty-dir removal time is never removed (regression guard)',
    async () => {
      const ctx = await setup('emptydir-finalseg');
      const sub = path.join(ctx.targetDir, 'sub');
      await plantFiles(sub, [
        { relativePath: 'a.bin', bytes: 32 },
        { relativePath: 'b.bin', bytes: 32 },
      ]);
      const outsideEmpty = path.join(ctx.root, 'outside-empty'); // external EMPTY
      await fsp.mkdir(outsideEmpty, { recursive: true });
      let swapped = false;
      const result = await runCleanup(ctx, {
        testHooks: {
          beforeFileDelete: async (filePath) => {
            if (swapped || !filePath.startsWith(sub) || !filePath.endsWith('b.bin')) return;
            swapped = true;
            await fsp.rename(sub, `${sub}.hidden`);
            mklinkJunction(sub, outsideEmpty);
          },
        },
      });
      try {
        expect(swapped).toBe(true);
        // The final-segment gate holds: `sub` is now the junction and the
        // executor never removes a reparse point.
        expect((await fsp.lstat(sub)).isSymbolicLink()).toBe(true);
        expect((await fsp.lstat(outsideEmpty)).isDirectory()).toBe(true);
        expect(await fsp.readdir(outsideEmpty)).toEqual([]);
        const entries = (await replayJournal(ctx.journalPath)).entries;
        expect(entries.filter((e) => e.file?.endsWith('(dir)'))).toEqual([]);
        expect(result.receipt.terminal).toBe('FAILED');
        // The real content survives under the hidden original directory.
        expect(await fsp.readFile(path.join(`${sub}.hidden`, 'b.bin'), 'utf8')).toBe(
          'a'.repeat(32),
        );
      } finally {
        await fsp.rmdir(sub).catch(() => {});
      }
    },
  );
});
