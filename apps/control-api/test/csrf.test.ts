import { beforeEach, describe, expect, it } from 'vitest';
import type { TaskSnapshot } from '../src/index.ts';
import { cleanupGoalRequest, startHarness, type TestHarness } from './helpers.ts';

// Negative controls for Issue #41 / VC-P1-04, sent as real HTTP requests.
//
// A loopback bind is not CSRF protection: any web page the user has open can
// fire cross-site POSTs at 127.0.0.1 — form posts (enctype=text/plain) and
// no-cors fetches are "simple requests" that skip CORS preflight entirely, so
// the browser delivers them and the merged server parsed the body regardless
// of content type and never looked at Origin. A hostile page could therefore
// submit goals and approve/decline R2 plan executions on the user's machine.
let h: TestHarness;

beforeEach(async () => {
  h = await startHarness();
});

const ATTACKER_ORIGIN = 'http://evil.example';

/** Body of a cleanup GoalRequest, as an attacker's page would stringify it. */
const goalBody = JSON.stringify(cleanupGoalRequest());

async function taskCount(): Promise<number> {
  const list = (await h.get('/api/tasks')).body as { tasks: unknown[] };
  return list.tasks.length;
}

describe('cross-site mutations are refused (CSRF, VC-P1-04)', () => {
  it('refuses a text/plain form-style POST with a hostile Origin (no preflight needed)', async () => {
    const before = await taskCount();
    const attack = await h.raw(
      '/api/tasks',
      { host: '127.0.0.1', 'content-type': 'text/plain', origin: ATTACKER_ORIGIN },
      { method: 'POST', body: goalBody },
    );
    expect(attack.status).toBe(403);
    expect((attack.body as { error: { code: string } }).error.code).toBe('CSRF_REFUSED');
    expect(await taskCount()).toBe(before); // nothing was mutated
  });

  it('refuses a text/plain POST even without an Origin header', async () => {
    const attack = await h.raw(
      '/api/tasks',
      { host: '127.0.0.1', 'content-type': 'text/plain' },
      { method: 'POST', body: goalBody },
    );
    expect(attack.status).toBe(403);
    expect((attack.body as { error: { code: string } }).error.code).toBe('CSRF_REFUSED');
  });

  it('refuses a well-formed JSON POST when the Origin is not this loopback origin', async () => {
    const attack = await h.raw(
      '/api/tasks',
      { host: '127.0.0.1', 'content-type': 'application/json', origin: ATTACKER_ORIGIN },
      { method: 'POST', body: goalBody },
    );
    expect(attack.status).toBe(403);
    expect((attack.body as { error: { code: string } }).error.code).toBe('CSRF_REFUSED');
  });

  it('refuses the opaque Origin "null" (sandboxed frames, redirects)', async () => {
    const attack = await h.raw(
      '/api/tasks',
      { host: '127.0.0.1', 'content-type': 'application/json', origin: 'null' },
      { method: 'POST', body: goalBody },
    );
    expect(attack.status).toBe(403);
  });

  it('refuses an approval decision fired from a hostile Origin (JSON)', async () => {
    const created = await h.post('/api/tasks', cleanupGoalRequest());
    const { taskId, approvalId, planHash } = {
      taskId: (created.body as TaskSnapshot).taskId,
      approvalId: (created.body as TaskSnapshot).approval!.approvalId,
      planHash: (created.body as TaskSnapshot).approval!.planHash,
    };
    const attack = await h.raw(
      `/api/approvals/${approvalId}/decision`,
      { host: '127.0.0.1', 'content-type': 'application/json', origin: ATTACKER_ORIGIN },
      { method: 'POST', body: JSON.stringify({ approved: true, planHash }) },
    );
    expect(attack.status).toBe(403);
    // The click never recorded a decision and never executed the plan.
    const after = (await h.get(`/api/tasks/${taskId}`)).body as TaskSnapshot;
    expect(after.state).toBe('AWAITING_AUTHORIZATION');
    expect(after.approval?.status).toBe('PENDING');
  });

  it('still accepts same-origin mutations (the UI origin) and non-mutating GETs', async () => {
    // The served UI lives on this exact origin, so a same-origin POST is fine.
    const own = await h.raw(
      '/api/tasks',
      { host: '127.0.0.1', 'content-type': 'application/json', origin: 'http://127.0.0.1' },
      { method: 'POST', body: goalBody },
    );
    expect(own.status).toBe(201);

    // Reads are never mutations: a hostile Origin on a GET is not CSRF.
    const read = await h.raw('/api/health', { host: '127.0.0.1', origin: ATTACKER_ORIGIN }, {});
    expect(read.status).toBe(200);
  });
});
