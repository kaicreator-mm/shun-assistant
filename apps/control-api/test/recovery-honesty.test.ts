import type { GoalRequest } from '@shun/contracts';
import { beforeEach, describe, expect, it } from 'vitest';
import type { TaskSnapshot } from '../src/index.ts';
import { cleanupGoalRequest, startHarness, type TestHarness } from './helpers.ts';

// Negative controls for Issue #41 / VC-P1-03: reconciliation must classify
// from journal + post-state ONLY (L2 §9.4). The merged demo reconciler
// unconditionally rewrote MAY_HAVE_EXECUTED_UNCERTAIN into
// FAILED_BEFORE_EFFECT ("a retry is now provably safe") without consulting
// any post-state — laundering honest uncertainty into a safe-retry claim.
// The demo cannot inspect a real filesystem, so unless a post-state proof is
// explicitly scripted, reconciliation must keep the uncertain classification
// and the retry gate stays shut.
let h: TestHarness;

beforeEach(async () => {
  h = await startHarness();
});

async function interruptedCleanupTask(goal: string): Promise<TaskSnapshot> {
  const created = await h.post('/api/tasks', {
    ...cleanupGoalRequest(),
    goal,
  } satisfies GoalRequest);
  const snapshot = created.body as TaskSnapshot;
  const approved = await h.post(`/api/approvals/${snapshot.approval!.approvalId}/decision`, {
    approved: true,
    planHash: snapshot.approval!.planHash,
  });
  expect((approved.body as { taskState: string }).taskState).toBe('NEEDS_INTERVENTION');
  return (await h.get(`/api/tasks/${snapshot.taskId}`)).body as TaskSnapshot;
}

describe('reconciliation never launders uncertainty (VC-P1-03)', () => {
  it('keeps MAY_HAVE_EXECUTED_UNCERTAIN when no post-state proof exists', async () => {
    const snapshot = await interruptedCleanupTask('cleanup with interrupt mid-run');
    expect(snapshot.recovery?.classification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');

    const reconciled = await h.post(`/api/tasks/${snapshot.taskId}/recovery`);
    expect(reconciled.status).toBe(200);
    expect((reconciled.body as { classification: string }).classification).toBe(
      'MAY_HAVE_EXECUTED_UNCERTAIN',
    );

    const after = (await h.get(`/api/tasks/${snapshot.taskId}`)).body as TaskSnapshot;
    expect(after.recovery?.classification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(after.recovery?.reconciled).toBe(false);
    // The detail must say what actually happened: proof was NOT established.
    expect(after.recovery?.detail).toContain('could not prove');
    expect(after.recovery?.detail).not.toContain('provably safe');

    // And the retry gate stays shut.
    const blocked = await h.post(`/api/tasks/${snapshot.taskId}/retry`);
    expect(blocked.status).toBe(409);
    expect((blocked.body as { error: { code: string } }).error.code).toBe(
      'RETRY_BLOCKED_UNCERTAIN',
    );
  });

  it('keeps MAY_HAVE_EXECUTED_UNCERTAIN when the post-state proves the effect took effect', async () => {
    // Audit recipe VC-P1-03: a post-state inspection that finds the plan's
    // declared effect PRESENT (the step actually ran) must not be laundered
    // into FAILED_BEFORE_EFFECT or any "safe retry" claim. The frozen
    // taxonomy has no "completed but unverified" class, so the honest outcome
    // is: the uncertain classification stands, the task stays in
    // NEEDS_INTERVENTION, and retry stays blocked.
    const snapshot = await interruptedCleanupTask(
      'cleanup with interrupt mid-run and a proven-present post-state',
    );
    expect(snapshot.recovery?.classification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');

    const reconciled = await h.post(`/api/tasks/${snapshot.taskId}/recovery`);
    expect(reconciled.status).toBe(200);
    expect((reconciled.body as { classification: string }).classification).toBe(
      'MAY_HAVE_EXECUTED_UNCERTAIN',
    );

    const after = (await h.get(`/api/tasks/${snapshot.taskId}`)).body as TaskSnapshot;
    expect(after.state).toBe('NEEDS_INTERVENTION');
    expect(after.recovery?.classification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(after.recovery?.reconciled).toBe(false);
    // The detail must state what the inspection actually found: the declared
    // effect IS present — never "could not prove", never "provably safe".
    expect(after.recovery?.detail).toContain('present');
    expect(after.recovery?.detail).not.toContain('could not prove');
    expect(after.recovery?.detail).not.toContain('provably safe');

    // And the retry gate stays shut.
    const blocked = await h.post(`/api/tasks/${snapshot.taskId}/retry`);
    expect(blocked.status).toBe(409);
    expect((blocked.body as { error: { code: string } }).error.code).toBe(
      'RETRY_BLOCKED_UNCERTAIN',
    );
  });

  it('records FAILED_BEFORE_EFFECT only from an explicit proven-absent post-state', async () => {
    // Demo marker: the scripted post-state inspection finds the plan's
    // declared expected outputs provably absent.
    const snapshot = await interruptedCleanupTask(
      'cleanup with interrupt mid-run and a proven-absent post-state',
    );
    const reconciled = await h.post(`/api/tasks/${snapshot.taskId}/recovery`);
    expect(reconciled.status).toBe(200);
    expect((reconciled.body as { classification: string }).classification).toBe(
      'FAILED_BEFORE_EFFECT',
    );
    const after = (await h.get(`/api/tasks/${snapshot.taskId}`)).body as TaskSnapshot;
    expect(after.recovery?.reconciled).toBe(true);
    expect(after.recovery?.detail).toContain('declared expected state');

    // Only now is the retry provably safe.
    const retried = await h.post(`/api/tasks/${snapshot.taskId}/retry`);
    expect(retried.status).toBe(200);
    const done = (await h.get(`/api/tasks/${snapshot.taskId}`)).body as TaskSnapshot;
    expect(done.state).toBe('SUCCEEDED');
    expect(done.verification?.status).toBe('PASS');
  });
});
