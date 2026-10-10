// Privileged-boundary tests for the bounded cleanup executor: the presentation
// is re-verified against current authority/policy state (L2 §4.6.1) and every
// rejection leaves the filesystem untouched (fail-closed receipts).
import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import {
  type ActionPlan,
  type AuthorizedAction,
  computePlanHash,
  PlanActionSchema,
} from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { executeBoundedCleanup, StorageVerticalError } from '../src/index.ts';
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
  await plantFiles(cacheDir, [
    { relativePath: 'a.bin', bytes: 1024 },
    { relativePath: 'b.bin', bytes: 512 },
  ]);
  return {
    root,
    scopeRoot,
    cacheDir,
    authority: makeAuthorityDouble(makeClock().now),
    journalPath: path.join(root, 'evidence', 'journal.jsonl'),
  };
}

function buildPlanAction(targetPath: string, classification = 'CACHE') {
  return PlanActionSchema.parse({
    actionId: 'action/test/clean-0',
    bindingRef: 'binding/test',
    op: 'storage.clean_directory',
    parameters: {
      targetPath,
      classification,
      expectedReclaimBytes: 1536,
      checkpointRef: 'evidence://t/cp.json',
    },
    sideEffectClass: 'R2',
    requiredPrivilege: 'USER',
    filesystemScope: { read: [targetPath], write: [targetPath] },
    networkScope: { allowed: false },
    expectedState: { targetPath, postCleanFiles: 0, manifestRef: 'evidence://t/cp.json' },
  });
}

function buildPlanAndAction(planAction: ReturnType<typeof buildPlanAction>) {
  const draft = {
    taskId: 'task-t07-x',
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
  const action: AuthorizedAction = {
    taskId: plan.taskId,
    actionId: planAction.actionId,
    planHash: plan.planHash,
    policySnapshotRevision: plan.policySnapshotRevision,
    authorizationKind: 'EXPLICIT_APPROVAL',
    authorizationRef: 'grant-under-test',
    action: planAction,
  };
  return { plan, action };
}

interface RunOptions {
  grantScopeWrite?: string[];
  tamperGrant?: (grant: Record<string, unknown>) => Record<string, unknown>;
  eligibleCategories?: ('CACHE' | 'TEMP')[];
  protectedRealPaths?: string[];
  scopeRoots?: string[];
  mutateAuthorityBeforeExecute?: (authority: AuthorityDouble) => void;
}

async function run(ctx: Ctx, options: RunOptions = {}) {
  const planAction = buildPlanAction(ctx.cacheDir);
  const { plan, action } = buildPlanAndAction(planAction);
  const grant = (await ctx.authority.issueGrant({
    taskId: plan.taskId,
    planHash: plan.planHash,
    policySnapshotRevision: plan.policySnapshotRevision,
    actionScope: {
      actionIds: plan.actions.map((a) => a.actionId),
      privilegeLevel: 'USER',
      filesystem: {
        read: options.grantScopeWrite ?? [ctx.cacheDir],
        write: options.grantScopeWrite ?? [ctx.cacheDir],
      },
      network: { allowed: false },
    },
    authorizationKind: 'EXPLICIT_APPROVAL',
    approvalRef: 'approval-1',
  })) as Record<string, unknown>;
  // The action must reference the ACTUAL issued grant identity.
  action.authorizationRef = (grant as { grantId: string }).grantId;
  options.mutateAuthorityBeforeExecute?.(ctx.authority);
  const clock = makeClock();
  return executeBoundedCleanup({
    authorizedAction: action,
    plan,
    grant: options.tamperGrant ? options.tamperGrant(grant) : grant,
    currentAuthority: await ctx.authority.currentAuthority(),
    now: clock.now(),
    verifyIntegrity: ctx.authority.verifyIntegrity,
    scopeRoots: options.scopeRoots ?? [ctx.scopeRoot],
    protectedRealPaths: options.protectedRealPaths ?? [],
    eligibleCategories: options.eligibleCategories ?? ['CACHE', 'TEMP'],
    journalPath: ctx.journalPath,
    environmentId: 'env-t07',
    providerId: 'storage.cleaner.local-windows',
    providerVersion: '0.1.0-t07',
  });
}

describe('executeBoundedCleanup authorization boundary', () => {
  it('executes a fully validated grant and deletes only the planned target', async () => {
    const ctx = await setup('grant-happy');
    const result = await run(ctx);
    expect(result.receipt.terminal).toBe('SUCCEEDED');
    expect(await fsp.readdir(ctx.cacheDir)).toHaveLength(0);
    const target = result.targets['action/test/clean-0'];
    expect(target?.deletedFiles).toBe(2);
    expect(target?.reclaimedBytes).toBe(1536);
    expect(result.receipt.sideEffectEvidence.sideEffectClass).toBe('R2');
  });

  it('refuses a forged grant with no integrity envelope and deletes nothing', async () => {
    const ctx = await setup('grant-forged');
    const result = await run(ctx, {
      tamperGrant: (g) => {
        const { integrity: _removed, ...rest } = g;
        return rest;
      },
    });
    expect(result.receipt.terminal).toBe('REFUSED');
    expect(await fsp.readdir(ctx.cacheDir)).toHaveLength(2);
    expect(result.receipt.sideEffectEvidence.recoveryClassification).toBe('NOT_STARTED');
  });

  it('refuses a tampered integrity value', async () => {
    const ctx = await setup('grant-tampered');
    const result = await run(ctx, {
      tamperGrant: (g) => ({ ...g, integrity: { scheme: 'HMAC_SHA256', value: '0'.repeat(64) } }),
    });
    expect(result.receipt.terminal).toBe('REFUSED');
    expect(await fsp.readdir(ctx.cacheDir)).toHaveLength(2);
  });

  it('refuses a grant bound to a different plan (plan-hash mismatch)', async () => {
    const ctx = await setup('grant-planhash');
    const result = await run(ctx, { tamperGrant: (g) => ({ ...g, planHash: 'f'.repeat(64) }) });
    expect(result.receipt.terminal).toBe('REFUSED');
    expect(await fsp.readdir(ctx.cacheDir)).toHaveLength(2);
  });

  it('refuses a revoked grant', async () => {
    const ctx = await setup('grant-revoked');
    const result = await run(ctx, {
      mutateAuthorityBeforeExecute: (authority) => authority.revokeLastGrant(),
    });
    expect(result.receipt.terminal).toBe('REFUSED');
    expect(await fsp.readdir(ctx.cacheDir)).toHaveLength(2);
  });

  it('refuses when policy was superseded between issuance and execution', async () => {
    const ctx = await setup('grant-stale-policy');
    const result = await run(ctx, {
      mutateAuthorityBeforeExecute: (authority) => authority.supersedePolicy('policy-rev-2'),
    });
    expect(result.receipt.terminal).toBe('REFUSED');
    expect(await fsp.readdir(ctx.cacheDir)).toHaveLength(2);
  });

  it('refuses when the currentness record is unresolvable (fail closed)', async () => {
    const ctx = await setup('grant-unresolvable');
    const result = await run(ctx, {
      mutateAuthorityBeforeExecute: (authority) => authority.breakCurrentness(),
    });
    expect(result.receipt.terminal).toBe('REFUSED');
    expect(await fsp.readdir(ctx.cacheDir)).toHaveLength(2);
  });

  it('refuses an action whose target escaped the declared scope (defense in depth)', async () => {
    const ctx = await setup('grant-scope');
    const outside = path.join(ctx.root, 'outside');
    await plantFiles(path.join(outside, 'cache'), [{ relativePath: 'x.bin', bytes: 64 }]);
    const escaped = buildPlanAction(path.join(outside, 'cache'));
    const { plan, action } = buildPlanAndAction(escaped);
    const grant = await ctx.authority.issueGrant({
      taskId: plan.taskId,
      planHash: plan.planHash,
      policySnapshotRevision: plan.policySnapshotRevision,
      actionScope: {
        actionIds: plan.actions.map((a) => a.actionId),
        privilegeLevel: 'USER',
        filesystem: { read: [path.join(outside, 'cache')], write: [path.join(outside, 'cache')] },
        network: { allowed: false },
      },
      authorizationKind: 'EXPLICIT_APPROVAL',
      approvalRef: 'approval-1',
    });
    // The action must reference the ACTUAL issued grant identity.
    action.authorizationRef = (grant as { grantId: string }).grantId;
    const clock = makeClock();
    // The grant covers the outside target, but the DECLARED scope roots do not.
    await expect(
      executeBoundedCleanup({
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
        providerId: 'p',
        providerVersion: '0',
      }),
    ).rejects.toThrow(StorageVerticalError);
    expect(await fsp.readdir(path.join(outside, 'cache'))).toHaveLength(1);
  });

  it('refuses a protected asset that sits inside the target directory', async () => {
    const ctx = await setup('grant-protected');
    const protectedInside = path.join(ctx.cacheDir, 'precious');
    await fsp.mkdir(protectedInside, { recursive: true });
    await fsp.writeFile(path.join(protectedInside, 'keep.txt'), 'user data', 'utf8');
    const result = await run(ctx, { protectedRealPaths: [protectedInside] });
    expect(result.receipt.terminal).toBe('REFUSED');
    expect(result.receipt.sideEffectEvidence.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
    // Refusal means nothing was deleted: the protected subtree AND the cache
    // files all remain.
    expect(await fsp.readFile(path.join(ctx.cacheDir, 'a.bin'), 'utf8')).toHaveLength(1024);
    expect(await fsp.readFile(path.join(ctx.cacheDir, 'b.bin'), 'utf8')).toHaveLength(512);
    expect(await fsp.readFile(path.join(protectedInside, 'keep.txt'), 'utf8')).toBe('user data');
  });

  it('rejects an action classified outside the eligible policy before any deletion', async () => {
    const ctx = await setup('gate-eligibility');
    await expect(run(ctx, { eligibleCategories: ['TEMP'] })).rejects.toThrow(
      /DATA_CLASSIFICATION_UNKNOWN/,
    );
    expect(await fsp.readdir(ctx.cacheDir)).toHaveLength(2);
  });
});
