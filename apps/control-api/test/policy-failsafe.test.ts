import { describe, expect, it } from 'vitest';
import type { PendingApproval, TaskSnapshot } from '../src/index.ts';
import { cleanupGoalRequest, startHarness, type TestHarness } from './helpers.ts';

async function pendingApprovalId(
  target: TestHarness,
): Promise<{ approvalId: string; planHash: string }> {
  const created = await target.post('/api/tasks', cleanupGoalRequest());
  const approval = (created.body as TaskSnapshot).approval!;
  return { approvalId: approval.approvalId, planHash: approval.planHash };
}

describe('unknown/expired policy fails closed (override forbidden)', () => {
  it('refuses approval while the policy snapshot is unresolvable', async () => {
    const unresolvable = await startHarness({
      policy: { kind: 'UNKNOWN', reason: 'policy snapshot record unreadable' },
    });
    try {
      const created = await unresolvable.post('/api/tasks', cleanupGoalRequest());
      const snapshot = created.body as TaskSnapshot;
      const approvalId = snapshot.approval!.approvalId;
      const planHash = snapshot.approval!.planHash;
      const health = (await unresolvable.get('/api/health')).body as { policy: { kind: string } };
      expect(health.policy.kind).toBe('UNKNOWN');
      const refused = await unresolvable.post(`/api/approvals/${approvalId}/decision`, {
        approved: true,
        planHash,
      });
      expect(refused.status).toBe(423);
      expect((refused.body as { error: { code: string } }).error.code).toBe('POLICY_STATE_UNKNOWN');
      // The click never consumed the approval and never moved the task.
      const after = (await unresolvable.get(`/api/tasks/${snapshot.taskId}`)).body as TaskSnapshot;
      expect(after.state).toBe('AWAITING_AUTHORIZATION');
      expect(after.approval?.status).toBe('PENDING');
    } finally {
      await unresolvable.close();
    }
  });

  it('refuses approval under an expired policy snapshot', async () => {
    const expired = await startHarness({
      policy: { kind: 'EXPIRED', revision: 'pol-snap-old', expiredAt: '2026-10-10T07:00:00.000Z' },
    });
    try {
      const { approvalId, planHash } = await pendingApprovalId(expired);
      const refused = await expired.post(`/api/approvals/${approvalId}/decision`, {
        approved: true,
        planHash,
      });
      expect(refused.status).toBe(423);
      expect((refused.body as { error: { code: string } }).error.code).toBe('POLICY_EXPIRED');
    } finally {
      await expired.close();
    }
  });

  it('an approval click cannot override an active trust failure (Loop B rule)', async () => {
    const trust = await startHarness();
    try {
      // Demo marker: an untrusted-provider trust failure is active for this goal.
      const created = await trust.post('/api/tasks', {
        ...cleanupGoalRequest(),
        goal: 'cleanup DemoApp cache for untrusted-provider',
      });
      const snapshot = created.body as TaskSnapshot;
      const approvalId = snapshot.approval!.approvalId;
      const planHash = snapshot.approval!.planHash;
      const refused = await trust.post(`/api/approvals/${approvalId}/decision`, {
        approved: true,
        planHash,
      });
      expect(refused.status).toBe(423);
      expect((refused.body as { error: { code: string } }).error.code).toBe('TRUST_BLOCKED');
      const after = (await trust.get(`/api/tasks/${snapshot.taskId}`)).body as TaskSnapshot;
      expect(after.state).toBe('AWAITING_AUTHORIZATION');
      expect(after.approval?.status).toBe('PENDING');
      // Declining is still available — refusal only blocks moving forward.
      const decline = await trust.post(`/api/approvals/${approvalId}/decision`, {
        approved: false,
        planHash,
      });
      expect(decline.status).toBe(200);
    } finally {
      await trust.close();
    }
  });

  it('the inbox still lists a blocked approval instead of hiding it (readability)', async () => {
    const unresolvable = await startHarness({
      policy: { kind: 'UNKNOWN', reason: 'policy snapshot record unreadable' },
    });
    try {
      await unresolvable.post('/api/tasks', cleanupGoalRequest());
      const inbox = (await unresolvable.get('/api/approvals')).body as {
        approvals: PendingApproval[];
      };
      expect(inbox.approvals).toHaveLength(1);
    } finally {
      await unresolvable.close();
    }
  });
});
