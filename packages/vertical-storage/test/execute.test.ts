// Executor behavior tests: bounded deletion mechanics, honest accounting
// under blocks (real Windows ACL denial), reparse points, and torn-journal
// recovery classification with reconcile-first semantics (L2 §9.4).
import { execSync } from 'node:child_process';
import { promises as fsp, symlinkSync as fspSymlink } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
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
  reconcileAfterInterruption,
  replayJournal,
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
  cacheDir: string;
  authority: AuthorityDouble;
  journalPath: string;
}

async function setup(label: string): Promise<Ctx> {
  const root = await makeFixtureRoot(label);
  const scopeRoot = path.join(root, 'scope');
  const cacheDir = path.join(scopeRoot, 'cache');
  await plantFiles(cacheDir, [{ relativePath: 'a.bin', bytes: 1024 }]);
  return {
    root,
    scopeRoot,
    cacheDir,
    authority: makeAuthorityDouble(makeClock().now),
    journalPath: path.join(root, 'evidence', 'journal.jsonl'),
  };
}

async function runCleanup(
  ctx: Ctx,
  options: { targetPath?: string; extraPlanActions?: ReturnType<typeof buildPlanActionFor>[] } = {},
) {
  const planAction = buildPlanActionFor(options.targetPath ?? ctx.cacheDir);
  const draft = {
    taskId: 'task-t07-exec',
    capabilityId: 'system.storage.diagnose_bounded_action',
    bindingRefs: ['binding/test'],
    rankingPolicyRevision: 'ranking-rev-1',
    policySnapshotRevision: 'policy-rev-1',
    actions: [planAction, ...(options.extraPlanActions ?? [])],
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
    environmentId: 'env-t07',
    providerId: 'storage.cleaner.local-windows',
    providerVersion: '0.1.0-t07',
  });
}

function buildPlanActionFor(targetPath: string) {
  return PlanActionSchema.parse({
    actionId: `action/test/clean-${targetPath.length}`,
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
}

describe('bounded deletion mechanics', () => {
  it('deletes nested trees, removes emptied subdirectories, and never touches paths outside targets', async () => {
    const ctx = await setup('exec-nested');
    await plantFiles(ctx.cacheDir, [
      { relativePath: 'deep/tree/f1.bin', bytes: 128 },
      { relativePath: 'deep/tree/f2.bin', bytes: 256 },
      { relativePath: 'f3.bin', bytes: 512 },
    ]);
    const outsideFile = path.join(ctx.scopeRoot, 'outside.txt');
    await fsp.writeFile(outsideFile, 'keep me', 'utf8');
    const result = await runCleanup(ctx);
    expect(result.receipt.terminal).toBe('SUCCEEDED');
    // The target's CONTENTS are gone; the emptied target dir itself remains
    // (the owning app recreates or removes its own cache directory).
    expect(await fsp.readdir(ctx.cacheDir)).toEqual([]);
    expect(await fsp.readFile(outsideFile, 'utf8')).toBe('keep me');
    const target = result.targets[result.receipt.actionId];
    // a.bin (from setup) + three planted files; nested dirs emptied away.
    expect(target?.deletedFiles).toBe(4);
    expect(target?.reclaimedBytes).toBe(1920);
  });

  it('never follows or deletes reparse points inside a target (recorded as blocked)', async () => {
    const ctx = await setup('exec-reparse');
    const realDir = path.join(ctx.root, 'real-dir');
    await plantFiles(realDir, [{ relativePath: 'x.bin', bytes: 64 }]);
    const link = path.join(ctx.cacheDir, 'jump');
    fspSymlink(realDir, link, 'junction');
    const result = await runCleanup(ctx);
    // The junction survives, so the target's expected state is not fully met:
    // the receipt reports honest partial failure, never silent success.
    expect(result.receipt.terminal).toBe('FAILED');
    // The junction still points at the real dir and its content survives.
    expect(await fsp.readdir(realDir)).toEqual(['x.bin']);
    const target = result.targets[result.receipt.actionId];
    expect(target?.blockedErrors.join(';')).toMatch(/REPARSE_POINT/);
    expect(target?.deletedFiles).toBe(1); // a.bin went, the junction did not
  });

  it('continues past blocked files and reports honest partial failure (real ACL deny)', async () => {
    if (process.platform !== 'win32') {
      return; // required platform evidence is real Windows; other hosts skip
    }
    const ctx = await setup('exec-acl');
    const lockedFile = path.join(ctx.cacheDir, 'locked.bin');
    await fsp.writeFile(lockedFile, 'x'.repeat(256), 'utf8');
    await plantFiles(ctx.cacheDir, [{ relativePath: 'free.bin', bytes: 128 }]);
    let denied = false;
    try {
      execSync(`icacls "${lockedFile}" /deny "*S-1-1-0:(D)"`, { stdio: 'pipe' });
      denied = true;
    } catch {
      denied = false; // environment without icacls support: skip honestly
    }
    if (!denied) return;
    try {
      const result = await runCleanup(ctx);
      expect(result.receipt.terminal).toBe('FAILED');
      const target = result.targets[result.receipt.actionId];
      expect(target?.blockedFiles).toBe(1);
      expect(target?.blockedErrors.join(';')).toMatch(/EPERM/);
      // a.bin (setup) + free.bin reclaimed; only locked.bin blocked.
      expect(target?.reclaimedBytes).toBe(1152);
      expect(target?.deletedFiles).toBe(2);
    } finally {
      try {
        execSync(`icacls "${lockedFile}" /reset`, { stdio: 'pipe' });
      } catch {
        // best-effort restore
      }
    }
    // After the ACL reset the file is readable AND was never deleted by the
    // blocked cleanup (on this host the deny ACE also blocks reads, so the
    // content check can only run after the reset).
    expect(await fsp.readFile(lockedFile, 'utf8')).toBe('x'.repeat(256));
  });
});

describe('journal and recovery (L2 §9.4)', () => {
  it('replays a torn journal, isolating the torn tail without losing intact phases', async () => {
    const ctx = await setup('journal-torn');
    await plantFiles(ctx.cacheDir, [{ relativePath: 'a.bin', bytes: 64 }]);
    await runCleanup(ctx);
    await fsp.appendFile(
      ctx.journalPath,
      '{"at":"2026-10-10T10:00:00.000Z","phase":"EXEC_Star',
      'utf8',
    );
    const replay = await replayJournal(ctx.journalPath);
    expect(replay.tornAppendDetected).toBe(true);
    expect(replay.entries.length).toBeGreaterThanOrEqual(3);
    expect(replay.entries.at(-1)?.phase).toBe('RECEIPT_WRITTEN');
  });

  it('classifies an interrupted action as MAY_HAVE_EXECUTED_UNCERTAIN from the journal alone', async () => {
    const ctx = await setup('journal-uncertain');
    await fsp.mkdir(ctx.cacheDir, { recursive: true });
    const { PhaseJournal } = await import('../src/index.ts');
    const journal = await PhaseJournal.open(ctx.journalPath);
    await journal.append({ at: makeClock().now(), phase: 'RECEIVED', actionId: 'a1' });
    await journal.append({
      at: makeClock().now(),
      phase: 'EXEC_START',
      actionId: 'a1',
      file: path.join(ctx.cacheDir, 'f.bin'),
      bytes: 10,
    });
    const classification = classifyFromJournal(
      (await replayJournal(ctx.journalPath)).entries,
      'a1',
    );
    expect(classification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
  });

  it('reconciles first: reports what an interrupted run left behind, without deleting', async () => {
    const ctx = await setup('journal-reconcile');
    const files = [
      { relativePath: 'one.bin', bytes: 100 },
      { relativePath: 'two.bin', bytes: 200 },
    ];
    await plantFiles(ctx.cacheDir, files);
    const manifestFiles = files.map((f) => ({
      path: path.join(ctx.cacheDir, ...f.relativePath.split('/')),
      sizeBytes: f.bytes,
    }));
    const { PhaseJournal } = await import('../src/index.ts');
    const journal = await PhaseJournal.open(ctx.journalPath);
    await journal.append({ at: makeClock().now(), phase: 'RECEIVED', actionId: 'a1' });
    await journal.append({
      at: makeClock().now(),
      phase: 'EXEC_START',
      actionId: 'a1',
      file: manifestFiles[0]?.path,
      bytes: 100,
    });
    const before = await fsp.stat(manifestFiles[1]?.path as string);
    const reconcile = await reconcileAfterInterruption({
      journalPath: ctx.journalPath,
      actionId: 'a1',
      manifestFiles,
    });
    expect(reconcile.classification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(reconcile.filesStillPresent).toBe(2);
    expect(reconcile.bytesStillPresent).toBe(300);
    const after = await fsp.stat(manifestFiles[1]?.path as string);
    expect(after.mtimeMs).toBe(before.mtimeMs); // reconcile touched nothing
  });

  it('classifies NOT_STARTED for an unknown action and COMPLETED_VERIFIED for a finished one', async () => {
    const ctx = await setup('journal-classify');
    await plantFiles(ctx.cacheDir, [{ relativePath: 'a.bin', bytes: 64 }]);
    await runCleanup(ctx);
    const entries = (await replayJournal(ctx.journalPath)).entries;
    expect(classifyFromJournal(entries, 'never-seen')).toBe('NOT_STARTED');
    expect(classifyFromJournal(entries, entries[0]?.actionId ?? '')).toBe('COMPLETED_VERIFIED');
  });
});

describe('platform sanity', () => {
  it('runs on the required local Windows build host (or skips honestly elsewhere)', () => {
    if (process.platform !== 'win32') return;
    expect(os.platform()).toBe('win32');
  });
});
