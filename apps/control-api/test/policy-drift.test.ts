import { beforeEach, describe, expect, it } from 'vitest';
import type { TaskSnapshot } from '../src/index.ts';
import { cleanupGoalRequest, startHarness, type TestHarness } from './helpers.ts';

// Negative control for Issue #41 / VC-P1-02: an approval must be refused when
// the ACTIVE policy snapshot has drifted from the snapshot the plan was
// resolved under. The plan's policySnapshotRevision is part of the plan hash,
// so approving under a different active revision would authorize a plan
// against a policy the user never reviewed.
let h: TestHarness;

beforeEach(async () => {
  h = await startHarness(); // plans are built under 'pol-snap-2026-10-10-a'
});

async function pendingApproval(): Promise<{
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

describe('active policy revision drift fails closed (VC-P1-02)', () => {
  it('refuses an approval decided under a drifted ACTIVE policy revision', async () => {
    const { taskId, approvalId, planHash } = await pendingApproval();

    // The active snapshot moved on after the plan was resolved: still ACTIVE,
    // but a different revision.
    h.backend.setPolicy({ kind: 'ACTIVE', revision: 'pol-snap-2026-10-11-b' });
    const health = (await h.get('/api/health')).body as { policy: { kind: string } };
    expect(health.policy.kind).toBe('ACTIVE'); // not UNKNOWN, not EXPIRED — plain drift

    const refused = await h.post(`/api/approvals/${approvalId}/decision`, {
      approved: true,
      planHash,
    });
    expect(refused.status).toBe(409);
    expect((refused.body as { error: { code: string } }).error.code).toBe('POLICY_REVISION_DRIFT');
    expect((refused.body as { error: { detail: string } }).error.detail).toContain(
      'pol-snap-2026-10-11-b',
    );

    // Nothing was recorded: the approval stays pending and the task unexecuted.
    const after = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(after.state).toBe('AWAITING_AUTHORIZATION');
    expect(after.approval?.status).toBe('PENDING');
  });

  it('still allows declining under drift — refusal only blocks moving forward', async () => {
    const { taskId, approvalId, planHash } = await pendingApproval();
    h.backend.setPolicy({ kind: 'ACTIVE', revision: 'pol-snap-2026-10-11-b' });
    const declined = await h.post(`/api/approvals/${approvalId}/decision`, {
      approved: false,
      planHash,
    });
    expect(declined.status).toBe(200);
    const after = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(after.state).toBe('CANCELLED');
    expect(after.approval?.status).toBe('DECLINED');
  });

  it('approves normally once the active revision matches the planned snapshot again', async () => {
    const { taskId, approvalId, planHash } = await pendingApproval();
    h.backend.setPolicy({ kind: 'ACTIVE', revision: 'pol-snap-2026-10-11-b' });
    const drift = await h.post(`/api/approvals/${approvalId}/decision`, {
      approved: true,
      planHash,
    });
    expect(drift.status).toBe(409);

    h.backend.setPolicy({ kind: 'ACTIVE', revision: 'pol-snap-2026-10-10-a' });
    const approved = await h.post(`/api/approvals/${approvalId}/decision`, {
      approved: true,
      planHash,
    });
    expect(approved.status).toBe(200);
    const after = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(after.state).toBe('SUCCEEDED');
  });
});
