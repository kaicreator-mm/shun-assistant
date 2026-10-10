// T03 required evidence — four-state recovery classification (L2 §9.4,
// closes P0-RECOVERY-01): NOT_STARTED / FAILED_BEFORE_EFFECT /
// MAY_HAVE_EXECUTED_UNCERTAIN / COMPLETED_VERIFIED, derived ONLY from the
// durable journal plus declared post-state verification. An UNCERTAIN
// destructive action is never blindly retried and never re-created under a
// fresh identity: recovery resumes the SAME actionId or escalates to
// NEEDS_INTERVENTION.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  type DestructiveReconcileProbe,
  DurableWorkflowKernel,
  KernelUnresolvedDestructiveActionError,
} from '../src/index.ts';
import { CountingStore, executionReceipt, goalContract, tempDir } from './helpers.ts';

let dir: string;
let store: CountingStore;
let kernel: DurableWorkflowKernel;

beforeEach(() => {
  dir = tempDir();
  store = new CountingStore();
  kernel = new DurableWorkflowKernel({ dataDir: dir, store });
});

afterEach(async () => {
  await kernel.close();
});

async function openExecutingTask(): Promise<void> {
  await kernel.open({ taskId: 'task-1', goal: goalContract() });
  await kernel.transition('task-1', 'INTERPRETING');
  await kernel.transition('task-1', 'RESOLVING');
  await kernel.transition('task-1', 'PLANNED');
  await kernel.transition('task-1', 'EXECUTING');
}

describe('four-state classification', () => {
  it('NOT_STARTED — an intent that never dispatched is proven safe to resume on the SAME actionId', async () => {
    await openExecutingTask();
    await kernel.beginAction('task-1', {
      actionId: 'action-1',
      planHash: 'p1',
      riskClass: 'R2',
      expectedState: { moved: 200 },
    });

    const recoveries = await kernel.listActionRecoveries('task-1');
    expect(recoveries).toHaveLength(1);
    expect(recoveries[0]).toMatchObject({
      actionId: 'action-1',
      classification: 'NOT_STARTED',
      resolved: true,
      canResume: true,
    });
  });

  it('MAY_HAVE_EXECUTED_UNCERTAIN — interruption inside the execution window, unresolved without verification', async () => {
    await openExecutingTask();
    await kernel.beginAction('task-1', {
      actionId: 'action-1',
      planHash: 'p1',
      riskClass: 'R2',
    });
    await expect(
      kernel.dispatchAction('task-1', 'action-1', async () => {
        throw new Error('helper vanished mid-run');
      }),
    ).rejects.toHaveProperty('code', 'KERNEL_ACTION_UNCERTAIN');

    const recoveries = await kernel.listActionRecoveries('task-1');
    expect(recoveries[0]).toMatchObject({
      classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      resolved: false,
      canResume: false,
    });

    // Reconcile with no probe available: stays honestly UNCERTAIN, escalates.
    const report = await kernel.reconcile('task-1');
    expect(report.unresolvedActionIds).toEqual(['action-1']);
    expect(report.interventionReason).toContain('action-1');
    await expect(kernel.query('task-1')).resolves.toMatchObject({ state: 'NEEDS_INTERVENTION' });
  });

  it('COMPLETED_VERIFIED — a journaled receipt closes the action', async () => {
    await openExecutingTask();
    await kernel.beginAction('task-1', {
      actionId: 'action-1',
      planHash: 'p1',
      riskClass: 'R2',
    });
    const receipt = executionReceipt({
      actionId: 'action-1',
      sideEffectEvidence: {
        sideEffectClass: 'R2',
        recoveryClassification: 'COMPLETED_VERIFIED',
        postStateVerified: true,
      },
    });
    await kernel.dispatchAction('task-1', 'action-1', async () => receipt);

    const recoveries = await kernel.listActionRecoveries('task-1');
    expect(recoveries[0]).toMatchObject({
      classification: 'COMPLETED_VERIFIED',
      resolved: true,
      receipt: { actionId: 'action-1' },
    });
  });

  it('reconcile-first resolves an uncertain destructive action through declared post-state verification', async () => {
    await openExecutingTask();
    await kernel.beginAction('task-1', {
      actionId: 'action-1',
      planHash: 'p1',
      riskClass: 'R2',
      expectedState: { moved: 200 },
    });
    await expect(
      kernel.dispatchAction('task-1', 'action-1', async () => {
        throw new Error('interrupted inside [DISPATCHED, RECEIPTED)');
      }),
    ).rejects.toBeInstanceOf(Error);

    const probe: DestructiveReconcileProbe = {
      verifyExpectedState: async () => ({
        outcome: 'CONFIRMED_EXECUTED',
        evidence: { moved: 200 },
      }),
    };
    const report = await kernel.reconcile('task-1', { destructiveProbe: probe });
    expect(report.actionRecoveries[0]).toMatchObject({
      classification: 'COMPLETED_VERIFIED',
      resolved: true,
    });
    expect(report.interventionReason).toBeUndefined();
  });

  it('post-state verification proving the effect never landed downgrades to FAILED_BEFORE_EFFECT and allows same-actionId resume', async () => {
    await openExecutingTask();
    await kernel.beginAction('task-1', {
      actionId: 'action-1',
      planHash: 'p1',
      riskClass: 'R2',
      expectedState: { moved: 200 },
    });
    await expect(
      kernel.dispatchAction('task-1', 'action-1', async () => {
        throw new Error('interrupted');
      }),
    ).rejects.toBeInstanceOf(Error);

    const probe: DestructiveReconcileProbe = {
      verifyExpectedState: async () => ({
        outcome: 'CONFIRMED_NOT_EXECUTED',
        evidence: { moved: 0 },
      }),
    };
    const report = await kernel.reconcile('task-1', { destructiveProbe: probe });
    expect(report.actionRecoveries[0]).toMatchObject({
      classification: 'FAILED_BEFORE_EFFECT',
      resolved: true,
      canResume: true,
    });
  });
});

describe('uncertain destructive actions are never blindly retried', () => {
  it('keeps the same actionId, refuses fresh identities and leaves user assets untouched', async () => {
    const userAsset = join(dir, 'user-asset.txt');
    writeFileSync(userAsset, 'precious user data', 'utf8');
    const before = readFileSync(userAsset, 'utf8');

    await openExecutingTask();
    await kernel.beginAction('task-1', {
      actionId: 'action-destructive',
      planHash: 'p1',
      riskClass: 'R2',
      expectedState: { moved: 200 },
    });
    let dispatchCount = 0;
    await expect(
      kernel.dispatchAction('task-1', 'action-destructive', async () => {
        dispatchCount += 1;
        throw new Error('crash mid-execution — receipt lost');
      }),
    ).rejects.toHaveProperty('code', 'KERNEL_ACTION_UNCERTAIN');

    // Recovery without a verification probe MUST NOT retry or re-create.
    await kernel.recover('task-1');
    await expect(kernel.query('task-1')).resolves.toMatchObject({ state: 'NEEDS_INTERVENTION' });

    // A NEW destructive identity for the unresolved prior one is refused.
    await expect(
      kernel.beginAction('task-1', {
        actionId: 'action-fresh-identity',
        planHash: 'p1',
        riskClass: 'R2',
      }),
    ).rejects.toBeInstanceOf(KernelUnresolvedDestructiveActionError);

    // Resume with the SAME actionId is the only execution path forward.
    await kernel.beginAction('task-1', {
      actionId: 'action-destructive',
      planHash: 'p1',
      riskClass: 'R2',
    });
    const resumed = await kernel.dispatchAction('task-1', 'action-destructive', async () =>
      executionReceipt({ actionId: 'action-destructive' }),
    );
    expect(resumed.terminal).toBe('SUCCEEDED');

    // The kernel itself never executed anything: exactly one dispatch attempt
    // happened, driven by the test executor — the user asset is untouched.
    expect(dispatchCount).toBe(1);
    expect(existsSync(userAsset)).toBe(true);
    expect(readFileSync(userAsset, 'utf8')).toBe(before);
  });

  it('an inconclusive probe keeps the action UNCERTAIN and the task in intervention', async () => {
    await openExecutingTask();
    await kernel.beginAction('task-1', {
      actionId: 'action-1',
      planHash: 'p1',
      riskClass: 'R3',
      expectedState: { removed: true },
    });
    await expect(
      kernel.dispatchAction('task-1', 'action-1', async () => {
        throw new Error('lost');
      }),
    ).rejects.toBeInstanceOf(Error);

    const probe: DestructiveReconcileProbe = {
      verifyExpectedState: async () => ({ outcome: 'UNKNOWN', evidence: {} }),
    };
    const report = await kernel.reconcile('task-1', { destructiveProbe: probe });
    expect(report.unresolvedActionIds).toEqual(['action-1']);
    expect(report.interventionReason).toContain('action-1');
    expect(report.actionRecoveries[0]).toMatchObject({
      classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
    });
  });

  it('a non-destructive uncertain action surfaces for same-actionId resume without forcing intervention', async () => {
    await openExecutingTask();
    await kernel.beginAction('task-1', {
      actionId: 'action-safe',
      planHash: 'p1',
      riskClass: 'R1',
    });
    await expect(
      kernel.dispatchAction('task-1', 'action-safe', async () => {
        throw new Error('interrupted');
      }),
    ).rejects.toBeInstanceOf(Error);

    const report = await kernel.reconcile('task-1');
    expect(report.interventionReason).toBeUndefined();
    // canResume stays false: retry requires a declared idempotency/currentness
    // guarantee (L2 §9.4) — the kernel only exposes the classification.
    expect(report.actionRecoveries[0]).toMatchObject({
      classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      canResume: false,
    });
    await expect(kernel.query('task-1')).resolves.toMatchObject({ state: 'EXECUTING' });
  });

  it('recovery after a hard restart classifies from the journal alone and resumes the same actionId', async () => {
    await openExecutingTask();
    await kernel.beginAction('task-1', {
      actionId: 'action-1',
      planHash: 'p1',
      riskClass: 'R2',
    });
    await expect(
      kernel.dispatchAction('task-1', 'action-1', async () => {
        throw new Error('crash');
      }),
    ).rejects.toBeInstanceOf(Error);
    await kernel.close();

    const reopened = new DurableWorkflowKernel({ dataDir: dir, store });
    try {
      const report = await reopened.reconcile('task-1');
      expect(report.actionRecoveries.map((recovery) => recovery.actionId)).toEqual(['action-1']);
      expect(report.actionRecoveries[0]).toMatchObject({
        classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        resolved: false,
      });

      // Same-actionId resume on the reopened kernel completes the action.
      const receipt = executionReceipt({ actionId: 'action-1' });
      await reopened.dispatchAction('task-1', 'action-1', async () => receipt);
      const recoveries = await reopened.listActionRecoveries('task-1');
      expect(recoveries[0]).toMatchObject({ classification: 'COMPLETED_VERIFIED', resolved: true });
    } finally {
      await reopened.close();
    }
  });
});
