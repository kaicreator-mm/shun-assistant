import type { GoalRequest } from '@shun/contracts';
import { beforeEach, describe, expect, it } from 'vitest';
import type { ReadableResidue, ResidueDetail, TaskSnapshot } from '../src/index.ts';
import { cleanupGoalRequest, startHarness, type TestHarness } from './helpers.ts';

let h: TestHarness;

beforeEach(async () => {
  h = await startHarness();
});

async function submit(goal: string): Promise<string> {
  const created = await h.post('/api/tasks', {
    ...cleanupGoalRequest(),
    goal,
  } satisfies GoalRequest);
  return (created.body as TaskSnapshot).taskId;
}

describe('goal intake and clarification (L2 §12)', () => {
  it('normalizes a goal through the frozen contract and reports readable progress', async () => {
    const taskId = await submit('clean up the DemoApp cache leftovers');
    const snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.state).toBe('AWAITING_AUTHORIZATION');
    const states = snapshot.progress.map((step) => step.state);
    expect(states[0]).toBe('RECEIVED');
    expect(states).toContain('INTERPRETING');
    expect(snapshot.progress.every((step) => step.at.endsWith('Z'))).toBe(true);
  });

  it('asks a clarification question and resumes after an answer', async () => {
    const taskId = await submit('clean up — but which folder?');
    let snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.state).toBe('CLARIFICATION');
    expect(snapshot.clarification?.question).toContain('Which files');
    const answered = await h.post(`/api/tasks/${taskId}/clarification`, {
      answer: 'clean up the DemoApp cache',
    });
    expect(answered.status).toBe(200);
    snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.state).toBe('AWAITING_AUTHORIZATION');
  });

  it('answering when no clarification is pending is a typed 409', async () => {
    const taskId = await submit('clean up the DemoApp cache leftovers');
    const answer = await h.post(`/api/tasks/${taskId}/clarification`, { answer: 'anything' });
    expect(answer.status).toBe(409);
    expect((answer.body as { error: { code: string } }).error.code).toBe(
      'CLARIFICATION_NOT_PENDING',
    );
  });

  it('a goal outside the registry is a typed failure — the surface never improvises', async () => {
    const taskId = await submit('do unknown-capability magic for me');
    const snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.state).toBe('FAILED');
    expect(snapshot.failure?.code).toBe('CAPABILITY_UNRESOLVED');
    expect(snapshot.failure?.message).toContain('will not improvise');
    const preview = await h.get(`/api/tasks/${taskId}/preview`);
    expect(preview.status).toBe(409);
  });
});

describe('cancellation (cancel where supported)', () => {
  it('cancels a task that is waiting for approval and voids the pending approval', async () => {
    const taskId = await submit('clean up the DemoApp cache leftovers');
    const cancelled = await h.post(`/api/tasks/${taskId}/cancel`);
    expect(cancelled.status).toBe(200);
    const snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.state).toBe('CANCELLED');
    expect(snapshot.execution).toBeUndefined();
  });

  it('cancelling a finished task is a typed invalid-state refusal', async () => {
    const taskId = await submit('resize my holiday pictures');
    const snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.state).toBe('SUCCEEDED');
    const cancelled = await h.post(`/api/tasks/${taskId}/cancel`);
    expect(cancelled.status).toBe(409);
    expect((cancelled.body as { error: { code: string } }).error.code).toBe('CANCEL_INVALID_STATE');
  });

  it('cancelling an unknown task is a typed 404', async () => {
    const cancelled = await h.post('/api/tasks/task-does-not-exist/cancel');
    expect(cancelled.status).toBe(404);
    expect((cancelled.body as { error: { code: string } }).error.code).toBe('TASK_NOT_FOUND');
  });
});

describe('failure and recovery state model (L2 §9.4)', () => {
  it('failed semantic verification is reported honestly, never as success', async () => {
    const taskId = await submit('resize pictures but fail-verify deliberately');
    const snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.state).toBe('FAILED');
    expect(snapshot.verification?.status).toBe('FAIL');
    expect(snapshot.failure?.message).toContain('failed semantic verification');
    expect(snapshot.recovery?.classification).toBe('COMPLETED_VERIFIED');
  });

  it('an uncertain interruption blocks retry until reconciliation (reconcile-first)', async () => {
    const taskId = await submit('cleanup with interrupt mid-run');
    const snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.state).toBe('AWAITING_AUTHORIZATION');
    const approvalId = snapshot.approval!.approvalId;
    const planHash = snapshot.approval!.planHash;

    const approved = await h.post(`/api/approvals/${approvalId}/decision`, {
      approved: true,
      planHash,
    });
    expect((approved.body as { taskState: string }).taskState).toBe('NEEDS_INTERVENTION');

    const detail = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(detail.recovery?.classification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');

    // Retry before reconciliation is refused — an uncertain destructive action
    // is never blindly retried.
    const blocked = await h.post(`/api/tasks/${taskId}/retry`);
    expect(blocked.status).toBe(409);
    expect((blocked.body as { error: { code: string } }).error.code).toBe(
      'RETRY_BLOCKED_UNCERTAIN',
    );

    // Reconcile first: journal + post-state prove the step never took effect.
    const reconciled = await h.post(`/api/tasks/${taskId}/recovery`);
    expect(reconciled.status).toBe(200);
    expect((reconciled.body as { classification: string }).classification).toBe(
      'FAILED_BEFORE_EFFECT',
    );

    const retried = await h.post(`/api/tasks/${taskId}/retry`);
    expect(retried.status).toBe(200);
    const done = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(done.state).toBe('SUCCEEDED');
    expect(done.verification?.status).toBe('PASS');
  });

  it('recovery on a task without an uncertain side effect is typed not-applicable', async () => {
    const taskId = await submit('resize my holiday pictures');
    const recovery = await h.post(`/api/tasks/${taskId}/recovery`);
    expect(recovery.status).toBe(409);
    expect((recovery.body as { error: { code: string } }).error.code).toBe(
      'RECOVERY_NOT_APPLICABLE',
    );
  });
});

describe('readable residue summary with evidence on demand (L2 §12)', () => {
  it('summarizes residue readably by default and never dumps items', async () => {
    const taskId = await submit('clean up the DemoApp cache leftovers');
    const residue = (await h.get(`/api/tasks/${taskId}/residue`)).body as ReadableResidue;
    expect(residue.headline).toContain('6 leftover items');
    expect(residue.headline).toContain('protected');
    expect(residue.protectedUntouchedCount).toBe(1);
    expect(residue.groups.length).toBeGreaterThan(0);
    expect(residue.detailAvailable).toBe(true);
    expect((residue as ResidueDetail).items).toBeUndefined();
  });

  it('itemized evidence exists but only behind the explicit detail flag', async () => {
    const taskId = await submit('clean up the DemoApp cache leftovers');
    const detail = (await h.get(`/api/tasks/${taskId}/residue?detail=true`)).body as ResidueDetail;
    expect(detail.items).toHaveLength(7);
    expect(detail.items?.every((item) => item.evidenceRef.startsWith('local:'))).toBe(true);
    const protectedItem = detail.items?.find((item) => item.classification.startsWith('PROTECTED'));
    expect(protectedItem?.path).toContain('budget-2026.xlsx');
  });
});
