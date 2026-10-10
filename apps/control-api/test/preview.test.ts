import type { GoalRequest } from '@shun/contracts';
import { beforeEach, describe, expect, it } from 'vitest';
import type { TaskSnapshot } from '../src/index.ts';
import {
  buildImageBatchPlan,
  buildStorageCleanupPlan,
  type PlanPreview,
  previewForPlan,
  riskStatement,
} from '../src/index.ts';
import {
  cleanupGoalRequest,
  imageGoalRequest,
  startHarness,
  T0,
  type TestHarness,
} from './helpers.ts';

let h: TestHarness;

beforeEach(async () => {
  h = await startHarness();
});

async function cleanupPreview(): Promise<PlanPreview> {
  const created = await h.post('/api/tasks', cleanupGoalRequest());
  const taskId = (created.body as TaskSnapshot).taskId;
  const preview = await h.get(`/api/tasks/${taskId}/preview`);
  expect(preview.status).toBe(200);
  return preview.body as PlanPreview;
}

describe('human-comprehensible plan preview (L2 §12)', () => {
  it('renders the fixed R2 risk statement regardless of action naming', async () => {
    const preview = await cleanupPreview();
    expect(preview.riskClass).toBe('R2');
    expect(preview.riskStatement).toBe(riskStatement('R2'));
    expect(preview.requiresExplicitApproval).toBe(true);
    expect(preview.actions[0]?.description).toContain('Network access is disabled');
  });

  it('never leaks raw plan parameters or free-form instructions into the preview', async () => {
    const preview = await cleanupPreview();
    const text = JSON.stringify(preview);
    // Parameter values (the delete manifest ref) are not rendered at all.
    expect(text).not.toContain('targetRefs');
    expect(text).not.toContain('cache-manifest');
    // The op is rendered as an opaque identifier, not as prose.
    expect(preview.actions[0]?.op).toBe('file.delete');
  });

  it('is deterministic for the same plan and clock (same bytes)', async () => {
    const created = await h.post('/api/tasks', cleanupGoalRequest());
    const taskId = (created.body as TaskSnapshot).taskId;
    const first = await h.get(`/api/tasks/${taskId}/preview`);
    const second = await h.get(`/api/tasks/${taskId}/preview`);
    expect(first.body).toEqual(second.body);
  });

  it('binds the preview to the exact plan hash the approval will check', async () => {
    const preview = await cleanupPreview();
    const inbox = (await h.get('/api/approvals')).body as {
      approvals: { planHash: string }[];
    };
    expect(inbox.approvals[0]?.planHash).toBe(preview.planHash);
  });

  it('typed 409 when there is no plan to preview yet', async () => {
    const created = await h.post('/api/tasks', {
      ...cleanupGoalRequest(),
      goal: 'what should I clean here?',
    } satisfies GoalRequest);
    const taskId = (created.body as TaskSnapshot).taskId;
    const preview = await h.get(`/api/tasks/${taskId}/preview`);
    expect(preview.status).toBe(409);
    expect((preview.body as { error: { code: string } }).error.code).toBe('PREVIEW_NOT_AVAILABLE');
  });

  it('a crafted “harmless” action name cannot soften an R2 plan', () => {
    // Unit-level: the R2 sentence derives from the declared class, not the op.
    const plan = buildStorageCleanupPlan('task-crafted');
    plan.actions[0]!.op = 'no-op (already approved, nothing will happen)';
    const preview = previewForPlan(plan, { generatedAt: T0 });
    expect(preview.riskStatement).toBe(riskStatement('R2'));
    expect(preview.requiresExplicitApproval).toBe(true);
  });

  it('R1 plans are previewed as bounded and need no explicit approval', async () => {
    const created = await h.post('/api/tasks', imageGoalRequest());
    const snapshot = created.body as TaskSnapshot;
    // Automatic R1 under policy runs to completion without an approval record.
    expect(snapshot.state).toBe('SUCCEEDED');
    expect(snapshot.approval).toBeUndefined();
    const plan = buildImageBatchPlan(snapshot.taskId);
    expect(plan.actions[0]?.sideEffectClass).toBe('R1');
    const inbox = (await h.get('/api/approvals')).body as { approvals: unknown[] };
    expect(inbox.approvals).toHaveLength(0);
  });
});
