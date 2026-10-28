// T10 #221: current accepted GOAL_TEXT-only cloud contract returns untrusted
// *advisory text*, not a typed host-private task / action admission.
// This test observes the actual current Control API with a deterministic
// fake cloud PORT only: it is NOT real Windows broker, paid LLM, or poststate.
// Run: node --experimental-transform-types --test tests/integration/v02/advisory-no-promotion.test.mjs
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createControlServer } from '../../../apps/control-api/src/server.ts';
import { DemoShunBackend } from '../../../apps/control-api/src/demo/backend.ts';

const goals = [
  ['请只解释这个文件夹的空间占用，不要删除文件。', '建议先查看文件大小，暂不执行删除。'],
  ['Explain folder disk usage only; never delete files.', 'I recommend checking usage first; no deletion.'],
];

test('actual GOAL_TEXT-only Control API returns plain CN/EN advice, never a task or approval', async () => {
  let cloudCalls = 0;
  const cloud = {
    status: () => ({
      enabled: true,
      provider: 'deepseek',
      model: 'deepseek-flash',
      osConsentRequired: true,
    }),
    interpretGoal: async (goalText) => {
      cloudCalls += 1;
      const [_, message] = goals.find(([goal]) => goal === goalText) ?? [];
      assert.ok(message, 'test-only cloud port received unexpected input');
      return {
        ok: true,
        taskId: 'cloud-host-private-not-known-to-model',
        status: 'UNTRUSTED_REMOTE_PROPOSAL',
        proposalText: message,
        model: 'deepseek-flash',
        costState: 'UNKNOWN_COST',
        executed: false,
      };
    },
  };
  const server = createControlServer({ backend: new DemoShunBackend(), cloud });
  const port = await server.start();
  const origin = `http://127.0.0.1:${port}`;
  try {
    for (const [goalText, message] of goals) {
      const response = await fetch(`${origin}/api/cloud/interpret`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ goalText }),
      });
      assert.equal(response.status, 200);
      const result = await response.json();
      assert.equal(result.status, 'UNTRUSTED_REMOTE_PROPOSAL');
      assert.equal(result.proposalText, message);
      assert.equal(result.executed, false);
      assert.equal(result.costState, 'UNKNOWN_COST');
      assert.equal(result.model, 'deepseek-flash');
      // The cloud's private task correlation ID is NOT a locally admitted
      // GoalRequest, planHash, approval, or authority.
      const tasksResponse = await fetch(`${origin}/api/tasks`);
      assert.equal(tasksResponse.status, 200);
      const tasks = await tasksResponse.json();
      assert.deepEqual(tasks.tasks, []);
    }
    assert.equal(cloudCalls, 2, 'test stub only; no real HTTP provider calls');
  } finally {
    await server.close();
  }
});

test('model/browser supplied cloud approval and action fields refuse before cloud port call', async () => {
  let cloudCalls = 0;
  const cloud = {
    status: () => ({
      enabled: true,
      provider: 'deepseek',
      model: 'deepseek-flash',
      osConsentRequired: true,
    }),
    interpretGoal: async () => {
      cloudCalls += 1;
      throw new Error('test must not reach the cloud port');
    },
  };
  const server = createControlServer({ backend: new DemoShunBackend(), cloud });
  const port = await server.start();
  const origin = `http://127.0.0.1:${port}`;
  try {
    for (const field of ['approved', 'approval', 'grant', 'planHash', 'candidateId']) {
      const response = await fetch(`${origin}/api/cloud/interpret`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ goalText: goals[0][0], [field]: 'fake-model-authority' }),
      });
      assert.equal(response.status, 400);
      const json = await response.json();
      assert.deepEqual(json, { error: { code: 'CLOUD_GOAL_INVALID' } });
    }
    assert.equal(cloudCalls, 0);
  } finally {
    await server.close();
  }
});
