import { beforeEach, describe, expect, it } from 'vitest';
import type { TaskSnapshot } from '../src/index.ts';
import { cleanupGoalRequest, startHarness, T0, type TestHarness } from './helpers.ts';

let h: TestHarness;

beforeEach(async () => {
  h = await startHarness();
});

describe('API surface behavior', () => {
  it('health reports the API revision, local-only posture and policy state', async () => {
    const health = await h.get('/api/health');
    expect(health.status).toBe(200);
    expect(health.body).toMatchObject({ ok: true, localOnly: true, policy: { kind: 'ACTIVE' } });
  });

  it('strict goal validation: no unknown fields, no empty goal', async () => {
    const extraField = await h.post('/api/tasks', {
      ...cleanupGoalRequest(),
      plannerEvidence: { operationId: 'op-1', modelEvidence: 'model-x' },
    });
    expect(extraField.status).toBe(400);
    expect((extraField.body as { error: { code: string } }).error.code).toBe('TASK_INVALID_BODY');

    const empty = await h.post('/api/tasks', { ...cleanupGoalRequest(), goal: '' });
    expect(empty.status).toBe(400);

    const notJson = await fetch(`${h.baseUrl}/api/tasks`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{not json',
    });
    expect(notJson.status).toBe(400);
    expect(((await notJson.json()) as { error: { code: string } }).error.code).toBe(
      'INVALID_JSON_BODY',
    );
  });

  it('unknown task and unknown routes are typed 404s', async () => {
    const task = await h.get('/api/tasks/task-does-not-exist');
    expect(task.status).toBe(404);
    expect((task.body as { error: { code: string } }).error.code).toBe('TASK_NOT_FOUND');

    const route = await h.get('/api/definitely-not-a-route');
    expect(route.status).toBe(404);
  });

  it('bodies beyond the configured cap are a typed 413', async () => {
    const small = await startHarness({ maxBodyBytes: 64 });
    try {
      const response = await small.post('/api/tasks', cleanupGoalRequest());
      expect(response.status).toBe(413);
      expect((response.body as { error: { code: string } }).error.code).toBe('BODY_TOO_LARGE');
    } finally {
      await small.close();
    }
  });

  it('lists tasks the surface knows about', async () => {
    await h.post('/api/tasks', cleanupGoalRequest());
    const list = (await h.get('/api/tasks')).body as { tasks: TaskSnapshot[] };
    expect(list.tasks).toHaveLength(1);
    expect(list.tasks[0]?.createdAt).toBe(T0);
  });
});
