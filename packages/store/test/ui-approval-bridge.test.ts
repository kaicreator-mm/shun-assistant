import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ShunStore, ShunStoreUiApprovalBridge } from '../src/index.ts';

const roots: string[] = [];
const CLOCK = '2026-10-12T12:00:00.000Z';
const HASH = 'a'.repeat(64);

function path() {
  const root = mkdtempSync(join(tmpdir(), 'shun-ui-real-approval-'));
  roots.push(root);
  return join(root, 'shun.sqlite');
}
function request() {
  return {
    taskId: 'task-real-controller',
    planHash: HASH,
    summary: 'Delete only classified disposable cache under the approved root.',
    evidenceRefs: ['local:evidence/preview'],
  };
}
afterEach(() => {
  while (roots.length) {
    const root = roots.pop();
    if (root) rmSync(root, { recursive: true, force: true });
  }
});

describe('real UI approval bridge over durable ShunStore', () => {
  it('lets a live human-bound decision resume the controller with exact plan identity', async () => {
    const store = new ShunStore({ file: path() });
    const bridge = new ShunStoreUiApprovalBridge(store, { clock: () => CLOCK });
    const decisionPromise = bridge.requestApproval(request());
    const pending = bridge.listPending();
    expect(pending).toHaveLength(1);
    const item = pending[0];
    if (!item) throw new Error('missing pending approval');
    expect(item).toMatchObject({ taskId: request().taskId, planHash: HASH, status: 'PENDING' });
    expect(
      bridge.decide({
        approvalId: item.approvalId,
        taskId: item.taskId,
        planHash: 'b'.repeat(64),
        approved: true,
      }),
    ).toEqual({ ok: false, code: 'HASH_MISMATCH' });
    expect(bridge.get(item.approvalId)?.status).toBe('PENDING');
    expect(
      bridge.decide({
        approvalId: item.approvalId,
        taskId: item.taskId,
        planHash: HASH,
        approved: true,
      }),
    ).toMatchObject({ ok: true, decision: { approved: true, approvedBy: 'USER_APPROVAL' } });
    expect(await decisionPromise).toMatchObject({
      taskId: request().taskId,
      planHash: HASH,
      approved: true,
      approvedBy: 'USER_APPROVAL',
    });
    expect(bridge.listPending()).toHaveLength(0);
    expect(bridge.get(item.approvalId)?.status).toBe('APPROVED');
    expect(
      bridge.decide({
        approvalId: item.approvalId,
        taskId: item.taskId,
        planHash: HASH,
        approved: false,
      }),
    ).toEqual({ ok: false, code: 'ALREADY_DECIDED' });
    await store.close();
  });

  it('persists decided status across SQLite restart and never re-authorizes it', async () => {
    const file = path();
    const store = new ShunStore({ file });
    const bridge = new ShunStoreUiApprovalBridge(store, { clock: () => CLOCK });
    const wait = bridge.requestApproval(request());
    const item = bridge.listPending()[0];
    if (!item) throw new Error('missing pending approval');
    expect(
      bridge.decide({
        approvalId: item.approvalId,
        taskId: item.taskId,
        planHash: HASH,
        approved: false,
      }),
    ).toMatchObject({ ok: true });
    expect((await wait).approved).toBe(false);
    await store.close();

    const reopened = new ShunStore({ file });
    const next = new ShunStoreUiApprovalBridge(reopened, { clock: () => CLOCK });
    expect(next.get(item.approvalId)?.status).toBe('DECLINED');
    expect(next.listPending()).toEqual([]);
    expect(
      next.decide({
        approvalId: item.approvalId,
        taskId: item.taskId,
        planHash: HASH,
        approved: true,
      }),
    ).toEqual({ ok: false, code: 'ALREADY_DECIDED' });
    await reopened.close();
  });

  it('denies a stale controller wait in a different process/connection', async () => {
    const file = path();
    const store1 = new ShunStore({ file });
    const store2 = new ShunStore({ file });
    const owner = new ShunStoreUiApprovalBridge(store1, { clock: () => CLOCK });
    const outsider = new ShunStoreUiApprovalBridge(store2, { clock: () => CLOCK });
    const wait = owner.requestApproval(request());
    const item = owner.listPending()[0];
    if (!item) throw new Error('missing pending approval');
    expect(outsider.listPending()).toEqual([]);
    expect(
      outsider.decide({
        approvalId: item.approvalId,
        taskId: item.taskId,
        planHash: HASH,
        approved: true,
      }),
    ).toEqual({ ok: false, code: 'NOT_LIVE' });
    expect(owner.get(item.approvalId)?.status).toBe('PENDING');
    owner.abortPending();
    expect((await wait).approved).toBe(false);
    expect(outsider.get(item.approvalId)?.status).toBe('EXPIRED');
    await store2.close();
    await store1.close();
  });

  it('refuses duplicate task/plan identities rather than replacing a pending approval', async () => {
    const store = new ShunStore({ file: path() });
    const bridge = new ShunStoreUiApprovalBridge(store, { clock: () => CLOCK });
    const wait = bridge.requestApproval(request());
    await expect(bridge.requestApproval(request())).rejects.toThrow();
    expect(bridge.listPending()).toHaveLength(1);
    bridge.abortPending();
    expect((await wait).approved).toBe(false);
    await store.close();
  });

  it('refuses approval exactly at the expiry boundary', async () => {
    const store = new ShunStore({ file: path() });
    let now = CLOCK;
    const bridge = new ShunStoreUiApprovalBridge(store, {
      clock: () => now,
      ttlMs: 60_000,
    });
    const wait = bridge.requestApproval(request());
    const item = bridge.listPending()[0];
    if (!item) throw new Error('missing pending approval');

    now = '2026-10-12T12:01:00.000Z';
    expect(
      bridge.decide({
        approvalId: item.approvalId,
        taskId: item.taskId,
        planHash: HASH,
        approved: true,
      }),
    ).toEqual({ ok: false, code: 'EXPIRED' });
    expect((await wait).approved).toBe(false);
    expect(bridge.get(item.approvalId)?.status).toBe('EXPIRED');
    await store.close();
  });

  it('settles a pending controller denial even when storage is already closed', async () => {
    const store = new ShunStore({ file: path() });
    const bridge = new ShunStoreUiApprovalBridge(store, { clock: () => CLOCK });
    const wait = bridge.requestApproval(request());
    expect(bridge.listPending()).toHaveLength(1);

    await store.close();
    expect(() => bridge.abortPending()).not.toThrow();
    expect(await wait).toMatchObject({
      taskId: request().taskId,
      planHash: HASH,
      approved: false,
      approvedBy: 'USER_APPROVAL',
    });
  });

  it('refuses expired and wrong-task decisions without minting approval', async () => {
    const store = new ShunStore({ file: path() });
    let now = CLOCK;
    const bridge = new ShunStoreUiApprovalBridge(store, {
      clock: () => now,
      ttlMs: 60_000,
    });
    const wait = bridge.requestApproval(request());
    const item = bridge.listPending()[0];
    if (!item) throw new Error('missing pending approval');
    expect(
      bridge.decide({
        approvalId: item.approvalId,
        taskId: 'not-the-task',
        planHash: HASH,
        approved: true,
      }),
    ).toEqual({ ok: false, code: 'NOT_FOUND' });
    now = '2026-10-12T12:02:00.000Z';
    expect(
      bridge.decide({
        approvalId: item.approvalId,
        taskId: item.taskId,
        planHash: HASH,
        approved: true,
      }),
    ).toEqual({ ok: false, code: 'EXPIRED' });
    expect((await wait).approved).toBe(false);
    expect(bridge.get(item.approvalId)?.status).toBe('EXPIRED');
    await store.close();
  });
});
