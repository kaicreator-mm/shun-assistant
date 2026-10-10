// T03 post-merge security correction (Issue #36, C01): an UNCERTAIN
// destructive action is NEVER blindly re-dispatched — not on the SAME
// actionId, and not after a kernel restart. The only legal execution path
// forward is reconcile-first (declared post-state verification, L2 §9.4)
// that downgrades the action to FAILED_BEFORE_EFFECT; until then dispatch
// refuses fail-closed and the executor must not run again.
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

async function openExecutingTask(k: DurableWorkflowKernel): Promise<void> {
  await k.open({ taskId: 'task-1', goal: goalContract() });
  await k.transition('task-1', 'INTERPRETING');
  await k.transition('task-1', 'RESOLVING');
  await k.transition('task-1', 'PLANNED');
  await k.transition('task-1', 'EXECUTING');
}

describe('C01 — uncertain destructive actions are never blindly re-dispatched', () => {
  it('refuses re-dispatch on the SAME actionId while the action is MAY_HAVE_EXECUTED_UNCERTAIN', async () => {
    await openExecutingTask(kernel);
    await kernel.beginAction('task-1', {
      actionId: 'action-destructive',
      planHash: 'p1',
      riskClass: 'R2',
      expectedState: { moved: 200 },
    });
    let attempts = 0;
    await expect(
      kernel.dispatchAction('task-1', 'action-destructive', async () => {
        attempts += 1;
        throw new Error('crash mid-execution — receipt lost');
      }),
    ).rejects.toHaveProperty('code', 'KERNEL_ACTION_UNCERTAIN');
    expect(attempts).toBe(1);

    // Re-registering the same identity is resume preparation, NOT a
    // reconcile: it must not unlock execution either.
    await kernel.beginAction('task-1', {
      actionId: 'action-destructive',
      planHash: 'p1',
      riskClass: 'R2',
    });

    await expect(
      kernel.dispatchAction('task-1', 'action-destructive', async () => {
        attempts += 1;
        return executionReceipt({ actionId: 'action-destructive' });
      }),
    ).rejects.toBeInstanceOf(KernelUnresolvedDestructiveActionError);
    // The executor never ran a second time — no blind redispatch happened.
    expect(attempts).toBe(1);

    const recoveries = await kernel.listActionRecoveries('task-1');
    expect(recoveries[0]).toMatchObject({
      actionId: 'action-destructive',
      classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      resolved: false,
      canResume: false,
    });
  });

  it('the guard survives a kernel restart — the durable journal is the authority', async () => {
    await openExecutingTask(kernel);
    await kernel.beginAction('task-1', {
      actionId: 'action-destructive',
      planHash: 'p1',
      riskClass: 'R3',
      expectedState: { removed: true },
    });
    await expect(
      kernel.dispatchAction('task-1', 'action-destructive', async () => {
        throw new Error('crash mid-execution — receipt lost');
      }),
    ).rejects.toHaveProperty('code', 'KERNEL_ACTION_UNCERTAIN');
    await kernel.close();

    const reopened = new DurableWorkflowKernel({ dataDir: dir, store });
    try {
      let attempts = 0;
      // A restart must not reset the uncertainty: dispatch still refuses.
      await expect(
        reopened.dispatchAction('task-1', 'action-destructive', async () => {
          attempts += 1;
          return executionReceipt({ actionId: 'action-destructive' });
        }),
      ).rejects.toBeInstanceOf(KernelUnresolvedDestructiveActionError);
      expect(attempts).toBe(0);

      // Reconcile-first downgrade is the only door back to execution.
      const probe: DestructiveReconcileProbe = {
        verifyExpectedState: async () => ({
          outcome: 'CONFIRMED_NOT_EXECUTED',
          evidence: { removed: false },
        }),
      };
      const report = await reopened.reconcile('task-1', { destructiveProbe: probe });
      expect(report.actionRecoveries[0]).toMatchObject({
        classification: 'FAILED_BEFORE_EFFECT',
        resolved: true,
        canResume: true,
      });

      const receipt = await reopened.dispatchAction('task-1', 'action-destructive', async () => {
        attempts += 1;
        return executionReceipt({ actionId: 'action-destructive' });
      });
      expect(receipt.terminal).toBe('SUCCEEDED');
      expect(attempts).toBe(1);
    } finally {
      await reopened.close();
    }
  });

  it('non-destructive UNCERTAIN actions remain retryable on the same actionId (guard does not over-block)', async () => {
    await openExecutingTask(kernel);
    await kernel.beginAction('task-1', {
      actionId: 'action-safe',
      planHash: 'p1',
      riskClass: 'R1',
    });
    let attempts = 0;
    await expect(
      kernel.dispatchAction('task-1', 'action-safe', async () => {
        attempts += 1;
        throw new Error('interrupted');
      }),
    ).rejects.toHaveProperty('code', 'KERNEL_ACTION_UNCERTAIN');

    // R1 is outside the destructive guard: a same-actionId retry is legal.
    const receipt = await kernel.dispatchAction('task-1', 'action-safe', async () => {
      attempts += 1;
      return executionReceipt({ actionId: 'action-safe' });
    });
    expect(receipt.terminal).toBe('SUCCEEDED');
    expect(attempts).toBe(2);
  });
});
