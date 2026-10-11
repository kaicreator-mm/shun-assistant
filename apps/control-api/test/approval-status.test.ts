import { beforeEach, describe, expect, it } from 'vitest';
import type { PendingApproval, TaskSnapshot } from '../src/index.ts';
import { cleanupGoalRequest, startHarness, type TestHarness } from './helpers.ts';

// Negative control for Issue #41 / VC-P1-01: the approval inbox DTO must carry
// the approval's actual status. The control-ui gates the Approve/Decline
// buttons on that status, so a DTO without it renders buttons for nothing —
// or (as merged) never renders them at all.
let h: TestHarness;

beforeEach(async () => {
  h = await startHarness();
});

async function submitCleanupTask(): Promise<TaskSnapshot> {
  const created = await h.post('/api/tasks', cleanupGoalRequest());
  return created.body as TaskSnapshot;
}

describe('approval DTO carries the actual status (VC-P1-01)', () => {
  it('lists inbox approvals with an explicit PENDING status', async () => {
    await submitCleanupTask();
    const inbox = (await h.get('/api/approvals')).body as { approvals: PendingApproval[] };
    expect(inbox.approvals).toHaveLength(1);
    expect(inbox.approvals[0]?.status).toBe('PENDING');
  });

  it('exposes the decided status when an already-decided approval is fetched', async () => {
    const snapshot = await submitCleanupTask();
    const approvalId = snapshot.approval!.approvalId;
    const planHash = snapshot.approval!.planHash;
    await h.post(`/api/approvals/${approvalId}/decision`, { approved: true, planHash });
    const found = (await h.get(`/api/approvals/${approvalId}`)).body as {
      approval: PendingApproval;
    };
    expect(found.approval.status).toBe('APPROVED');
  });

  it('exposes DECLINED status after a decline', async () => {
    const snapshot = await submitCleanupTask();
    const approvalId = snapshot.approval!.approvalId;
    const planHash = snapshot.approval!.planHash;
    await h.post(`/api/approvals/${approvalId}/decision`, { approved: false, planHash });
    const found = (await h.get(`/api/approvals/${approvalId}`)).body as {
      approval: PendingApproval;
    };
    expect(found.approval.status).toBe('DECLINED');
  });
});
