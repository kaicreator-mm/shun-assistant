import { beforeEach, describe, expect, it } from 'vitest';
import type { PendingApproval, TaskSnapshot } from '../src/index.ts';
import { cleanupGoalRequest, startHarness, type TestHarness } from './helpers.ts';

let h: TestHarness;

beforeEach(async () => {
  h = await startHarness();
});

async function submitCleanupTask(): Promise<{
  taskId: string;
  approvalId: string;
  planHash: string;
}> {
  const created = await h.post('/api/tasks', cleanupGoalRequest());
  const snapshot = created.body as TaskSnapshot;
  const detail = (await h.get(`/api/tasks/${snapshot.taskId}`)).body as TaskSnapshot;
  return {
    taskId: snapshot.taskId,
    approvalId: detail.approval!.approvalId,
    planHash: detail.approval!.planHash,
  };
}

describe('R2 approval flow (L2 §12 approve/reject)', () => {
  it('surfaces a pending approval bound to the exact plan hash', async () => {
    const { taskId } = await submitCleanupTask();
    const snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.state).toBe('AWAITING_AUTHORIZATION');
    expect(snapshot.approval?.status).toBe('PENDING');
    const inbox = (await h.get('/api/approvals')).body as { approvals: PendingApproval[] };
    expect(inbox.approvals).toHaveLength(1);
    expect(inbox.approvals[0]?.taskId).toBe(taskId);
    expect(inbox.approvals[0]?.planHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('approving with the seen plan hash executes and verifies the task', async () => {
    const { approvalId, planHash } = await submitCleanupTask();
    const decided = (
      await h.post(`/api/approvals/${approvalId}/decision`, {
        approved: true,
        planHash,
      })
    ).body as {
      decision: { approved: boolean; approvedBy: string; planHash: string };
      taskState: string;
    };
    // The durable decision is a user approval bound to the exact plan identity.
    expect(decided.decision.approved).toBe(true);
    expect(decided.decision.approvedBy).toBe('USER_APPROVAL');
    expect(decided.decision.planHash).toBe(planHash);
    expect(decided.taskState).toBe('SUCCEEDED');
  });

  it('declining cancels the task and nothing executes', async () => {
    const { taskId, approvalId, planHash } = await submitCleanupTask();
    const declined = await h.post(`/api/approvals/${approvalId}/decision`, {
      approved: false,
      planHash,
      reason: 'Not today.',
    });
    expect(declined.status).toBe(200);
    const snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.state).toBe('CANCELLED');
    expect(snapshot.execution).toBeUndefined();
    expect(snapshot.approval?.status).toBe('DECLINED');
  });

  it('refuses a decision whose plan hash differs from the previewed plan (misleading-preview prevention)', async () => {
    const { taskId, approvalId, planHash } = await submitCleanupTask();
    const otherHash = 'a'.repeat(64);
    expect(otherHash).not.toBe(planHash);
    const refused = await h.post(`/api/approvals/${approvalId}/decision`, {
      approved: true,
      planHash: otherHash,
    });
    expect(refused.status).toBe(409);
    expect((refused.body as { error: { code: string } }).error.code).toBe('PLAN_HASH_MISMATCH');
    // Nothing was recorded: the approval stays pending and decidable.
    const snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.state).toBe('AWAITING_AUTHORIZATION');
    expect(snapshot.approval?.status).toBe('PENDING');
    const retry = await h.post(`/api/approvals/${approvalId}/decision`, {
      approved: true,
      planHash,
    });
    expect(retry.status).toBe(200);
  });

  it('refuses a second decision on an already-decided approval', async () => {
    const { approvalId, planHash } = await submitCleanupTask();
    await h.post(`/api/approvals/${approvalId}/decision`, { approved: true, planHash });
    const again = await h.post(`/api/approvals/${approvalId}/decision`, {
      approved: false,
      planHash,
    });
    expect(again.status).toBe(409);
    expect((again.body as { error: { code: string } }).error.code).toBe('APPROVAL_ALREADY_DECIDED');
  });

  it('returns typed 404 for an unknown approval', async () => {
    const missing = await h.post('/api/approvals/approval-does-not-exist/decision', {
      approved: true,
      planHash: 'b'.repeat(64),
    });
    expect(missing.status).toBe(404);
    expect((missing.body as { error: { code: string } }).error.code).toBe('APPROVAL_NOT_FOUND');
  });

  it('refuses an approval decided after its window closed (fail closed)', async () => {
    const { taskId, approvalId, planHash } = await submitCleanupTask();
    h.setNow('2026-10-10T09:00:00.000Z'); // past the 15-minute approval window
    const late = await h.post(`/api/approvals/${approvalId}/decision`, {
      approved: true,
      planHash,
    });
    expect(late.status).toBe(423);
    expect((late.body as { error: { code: string } }).error.code).toBe('APPROVAL_EXPIRED');
    const snapshot = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(snapshot.approval?.status).toBe('EXPIRED');
    expect(snapshot.state).toBe('AWAITING_AUTHORIZATION');
  });

  it('rejects decision bodies that carry authorization-like material (UI cannot create grants)', async () => {
    const { approvalId, planHash } = await submitCleanupTask();
    const forged = await h.post(`/api/approvals/${approvalId}/decision`, {
      approved: true,
      planHash,
      grant: {
        grantId: 'grant-forged',
        issuer: { authorityId: 'shun.action-controller', authorityRevision: 'auth-r5' },
      },
    });
    expect(forged.status).toBe(400);
    const stillPending = (await h.get(`/api/approvals/${approvalId}`)).body as {
      approval: PendingApproval;
    };
    expect(stillPending.approval.planHash).toBe(planHash);
  });
});
