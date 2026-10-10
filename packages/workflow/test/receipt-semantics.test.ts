// T03 post-merge security correction (Issue #36, C02): a schema-valid
// receipt whose OWN semantics say "unknown / unverified / failed before
// effect" must never close the action as COMPLETED_VERIFIED. Completion
// requires terminal SUCCEEDED + recoveryClassification COMPLETED_VERIFIED +
// postStateVerified, all three; every weaker or contradictory claim fails
// closed to MAY_HAVE_EXECUTED_UNCERTAIN (honest non-completion outcomes keep
// their FAILED_BEFORE_EFFECT / NOT_STARTED classification and stay resumable).
import { appendFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DurableWorkflowKernel, KernelActionUncertainError } from '../src/index.ts';
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

async function beginAction(actionId: string): Promise<void> {
  await kernel.beginAction('task-1', { actionId, planHash: 'p1', riskClass: 'R2' });
}

describe('C02 — receipt semantics, not schema validity alone, decide completion', () => {
  it('a schema-valid UNCERTAIN-terminal receipt does not close the action', async () => {
    await openExecutingTask();
    await beginAction('action-1');
    // The real backend mints exactly this shape when post-state verification
    // cannot confirm the effect (privileged-backend classify: SUCCEEDED but
    // unverifiable → terminal UNCERTAIN).
    const uncertainReceipt = executionReceipt({
      actionId: 'action-1',
      terminal: 'UNCERTAIN',
      sideEffectEvidence: {
        sideEffectClass: 'R2',
        recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        postStateVerified: false,
      },
    });

    await expect(
      kernel.dispatchAction('task-1', 'action-1', async () => uncertainReceipt),
    ).rejects.toBeInstanceOf(KernelActionUncertainError);

    const recoveries = await kernel.listActionRecoveries('task-1');
    expect(recoveries[0]).toMatchObject({
      classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      resolved: false,
      canResume: false,
    });
  });

  it('an SUCCEEDED receipt claiming COMPLETED_VERIFIED with postStateVerified:false fails closed to uncertain', async () => {
    await openExecutingTask();
    await beginAction('action-1');
    const unverifiedClaim = executionReceipt({
      actionId: 'action-1',
      terminal: 'SUCCEEDED',
      sideEffectEvidence: {
        sideEffectClass: 'R2',
        recoveryClassification: 'COMPLETED_VERIFIED',
        postStateVerified: false,
      },
    });

    await expect(
      kernel.dispatchAction('task-1', 'action-1', async () => unverifiedClaim),
    ).rejects.toBeInstanceOf(KernelActionUncertainError);

    const recoveries = await kernel.listActionRecoveries('task-1');
    expect(recoveries[0]).toMatchObject({
      classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
      resolved: false,
    });
  });

  it('an honest FAILED_BEFORE_EFFECT receipt resolves the action as resumable — never as completed', async () => {
    await openExecutingTask();
    await beginAction('action-1');
    const honestFailure = executionReceipt({
      actionId: 'action-1',
      terminal: 'FAILED',
      exitCode: 1,
      sideEffectEvidence: {
        sideEffectClass: 'R2',
        recoveryClassification: 'FAILED_BEFORE_EFFECT',
        postStateVerified: false,
      },
    });

    const receipt = await kernel.dispatchAction('task-1', 'action-1', async () => honestFailure);
    expect(receipt.terminal).toBe('FAILED');

    const recoveries = await kernel.listActionRecoveries('task-1');
    expect(recoveries[0]).toMatchObject({
      classification: 'FAILED_BEFORE_EFFECT',
      resolved: true,
      canResume: true,
    });

    // Resumable on the SAME actionId: a later verified success is the only
    // thing that may ever close this action as COMPLETED_VERIFIED.
    const verified = await kernel.dispatchAction('task-1', 'action-1', async () =>
      executionReceipt({ actionId: 'action-1' }),
    );
    expect(verified.terminal).toBe('SUCCEEDED');
    const after = await kernel.listActionRecoveries('task-1');
    expect(after[0]).toMatchObject({ classification: 'COMPLETED_VERIFIED', resolved: true });
  });

  it('a journaled UNCERTAIN receipt replays as UNCERTAIN, not COMPLETED_VERIFIED, across restarts', async () => {
    // Only the instance row may exist in the runtime store; the journal
    // itself is forged below with full control over seq numbers.
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    await kernel.close();

    // Simulate a legacy/defective journal that recorded an UNCERTAIN-terminal
    // receipt as ACTION_RECEIPTED: replay must not inflate it to completion.
    const defective = executionReceipt({
      actionId: 'action-1',
      terminal: 'UNCERTAIN',
      sideEffectEvidence: {
        sideEffectClass: 'R2',
        recoveryClassification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        postStateVerified: false,
      },
    });
    const journalFile = `${dir}/effect-journal.jsonl`;
    appendFileSync(
      journalFile,
      [
        JSON.stringify({
          seq: 1,
          ts: '2026-10-10T12:00:00.000Z',
          kind: 'ACTION_INTENT',
          taskId: 'task-1',
          actionId: 'action-1',
          payload: { planHash: 'p1', riskClass: 'R2' },
        }),
        JSON.stringify({
          seq: 2,
          ts: '2026-10-10T12:00:01.000Z',
          kind: 'ACTION_DISPATCHED',
          taskId: 'task-1',
          actionId: 'action-1',
          payload: {},
        }),
        JSON.stringify({
          seq: 3,
          ts: '2026-10-10T12:00:02.000Z',
          kind: 'ACTION_RECEIPTED',
          taskId: 'task-1',
          actionId: 'action-1',
          payload: { receipt: defective },
        }),
      ]
        .map((line) => `${line}\n`)
        .join(''),
      'utf8',
    );

    const reopened = new DurableWorkflowKernel({ dataDir: dir, store });
    try {
      const recoveries = await reopened.listActionRecoveries('task-1');
      expect(recoveries[0]).toMatchObject({
        classification: 'MAY_HAVE_EXECUTED_UNCERTAIN',
        resolved: false,
        canResume: false,
      });
    } finally {
      await reopened.close();
    }
  });
});
