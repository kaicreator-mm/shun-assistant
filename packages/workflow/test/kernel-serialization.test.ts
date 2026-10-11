// T03 post-merge security correction (Issue #36, C03): per-task serialization
// must be owned by the async context that holds the lock, not by a shared
// numeric depth counter. An UNRELATED concurrent invocation for a task whose
// lock is held (the holder suspended at an await inside its critical section)
// must queue behind the holder — never run interleaved with it.
//
// Ownership must additionally be LIFETIME-SCOPED: an async context that
// outlives its holder (a detached descendant or a deferred subscriber
// callback spawned inside the holder's scope) carries only an EXPIRED owner
// identity and must queue like any unrelated caller — never re-enter the
// critical section of a NEW holder that acquired the lock in between.
import type { TaskWorkflowState } from '@shun/contracts';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DurableWorkflowKernel } from '../src/index.ts';
import { CountingStore, goalContract, tempDir } from './helpers.ts';

let dir: string;
let store: CountingStore;
let kernel: DurableWorkflowKernel;

beforeEach(() => {
  dir = tempDir();
  store = new CountingStore();
  kernel = new DurableWorkflowKernel({ dataDir: dir, store });
});

afterEach(async () => {
  await kernel.close();
});

describe('C03 — unrelated concurrent invocations never interpenetrate a held task lock', () => {
  it('a same-task call made while the holder is suspended queues instead of bypassing', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    let release!: () => void;
    let handlerEntered = false;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    kernel.registerHandler('BLOCK', async () => {
      handlerEntered = true;
      await gate;
    });

    // The send runs under the task-1 lock and suspends inside the handler.
    const sendPromise = kernel.send({
      messageId: 'm1',
      taskId: 'task-1',
      kind: 'BLOCK',
      payload: {},
    });
    while (!handlerEntered) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    // Unrelated invocation, same task, holder still inside its critical
    // section: with the old depth-counter lock this ran immediately and
    // mutated the instance row mid-handler; it must queue instead.
    const transitionPromise = kernel.transition('task-1', 'INTERPRETING');
    await new Promise((resolve) => setTimeout(resolve, 25));
    await expect(kernel.query('task-1')).resolves.toMatchObject({
      state: 'RECEIVED',
      revision: 0,
    });

    release();
    await sendPromise;
    await expect(transitionPromise).resolves.toMatchObject({
      state: 'INTERPRETING',
      revision: 1,
    });
  });

  it('a nested same-task call from inside the locked flow still joins without deadlock', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    const handled: string[] = [];
    kernel.registerHandler('DO_THING', async (message) => {
      handled.push(message.messageId);
      await kernel.transition('task-1', 'INTERPRETING');
    });

    await kernel.send({ messageId: 'm1', taskId: 'task-1', kind: 'DO_THING', payload: {} });
    expect(handled).toEqual(['m1']);
    await expect(kernel.query('task-1')).resolves.toMatchObject({ state: 'INTERPRETING' });
  });

  it('different tasks stay concurrent — the serialization boundary is per task', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    await kernel.open({ taskId: 'task-2', goal: goalContract({ taskId: 'task-2' }) });
    kernel.registerHandler('BLOCK', async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    const task1 = kernel.send({ messageId: 'm1', taskId: 'task-1', kind: 'BLOCK', payload: {} });
    // While task-1's lock is held, task-2 must not be blocked behind it.
    await expect(kernel.transition('task-2', 'INTERPRETING')).resolves.toMatchObject({
      state: 'INTERPRETING',
    });
    await task1;
  });
});

describe('C03 — expired-owner contexts queue behind the new holder, never join its critical section', () => {
  it('a detached descendant of a released holder queues instead of mutating mid-critical-section', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });

    // New holder B: acquires the lock after A released and suspends inside
    // its critical section on this gate.
    let releaseB!: () => void;
    let bEntered = false;
    const bGate = new Promise<void>((resolve) => {
      releaseB = resolve;
    });
    kernel.registerHandler('BLOCK', async () => {
      bEntered = true;
      await bGate;
    });

    let fireDetached!: () => void;
    const detachedGate = new Promise<void>((resolve) => {
      fireDetached = resolve;
    });
    const trace: string[] = [];
    let detachedTransition!: Promise<TaskWorkflowState>;
    kernel.registerHandler('SPAWN_DETACHED', async () => {
      // Spawned inside holder A's critical section: the detached descendant
      // inherits A's owner context but is held back until A has released the
      // lock AND a new holder B is suspended mid-critical-section.
      detachedTransition = (async () => {
        await detachedGate;
        trace.push('detached:start');
        const next = await kernel.transition('task-1', 'INTERPRETING');
        trace.push('detached:done');
        return next;
      })();
      // Holder A releases the task lock when this handler returns.
    });

    await kernel.send({ messageId: 'm1', taskId: 'task-1', kind: 'SPAWN_DETACHED', payload: {} });
    const bPromise = kernel.send({ messageId: 'm2', taskId: 'task-1', kind: 'BLOCK', payload: {} });
    while (!bEntered) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    // B holds the lock (suspended in its handler). Fire the expired-owner
    // descendant and give any bypass ample opportunity to land.
    fireDetached();
    await new Promise((resolve) => setTimeout(resolve, 25));

    // The expired-owner descendant must NOT have transitioned the task inside
    // B's critical section. (Pre-fix it takes the reentrant path immediately:
    // the instance reads INTERPRETING/1 while B still holds the lock.)
    await expect(kernel.query('task-1')).resolves.toMatchObject({
      state: 'RECEIVED',
      revision: 0,
    });
    expect(trace).toEqual(['detached:start']);

    releaseB();
    await bPromise;
    // The descendant runs queued — after B released, not inside it.
    await expect(detachedTransition).resolves.toMatchObject({
      state: 'INTERPRETING',
      revision: 1,
    });
    expect(trace).toEqual(['detached:start', 'detached:done']);
  });

  it('a deferred subscriber callback scheduled under a released owner queues behind the new holder', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });

    let releaseB!: () => void;
    let bEntered = false;
    const bGate = new Promise<void>((resolve) => {
      releaseB = resolve;
    });
    kernel.registerHandler('BLOCK', async () => {
      bEntered = true;
      await bGate;
    });

    let fireDeferred!: () => void;
    const deferredGate = new Promise<void>((resolve) => {
      fireDeferred = resolve;
    });
    const trace: string[] = [];
    let deferredTransition!: Promise<TaskWorkflowState>;
    kernel.registerHandler('NOTIFY_DEFER', async () => {
      // Runs inside holder A's critical section. notify() invokes the
      // subscriber callback synchronously within A's owner context; the
      // deferred work it schedules inherits that context but is held back
      // until A has released the lock AND B is mid-critical-section.
      const unsubscribe = kernel.subscribe('task-1', (state) => {
        if (state.state === 'RECEIVED') {
          return; // skip the synchronous initial callback from subscribe()
        }
        deferredTransition = (async () => {
          await deferredGate;
          trace.push('deferred:start');
          const next = await kernel.transition('task-1', 'RESOLVING');
          trace.push('deferred:done');
          return next;
        })();
      });
      // Reentrant join (live holder) + notify() under A's scope.
      await kernel.transition('task-1', 'INTERPRETING');
      unsubscribe();
      // Holder A releases the task lock when this handler returns.
    });

    await kernel.send({ messageId: 'm1', taskId: 'task-1', kind: 'NOTIFY_DEFER', payload: {} });
    const bPromise = kernel.send({ messageId: 'm2', taskId: 'task-1', kind: 'BLOCK', payload: {} });
    while (!bEntered) {
      await new Promise((resolve) => setImmediate(resolve));
    }

    fireDeferred();
    await new Promise((resolve) => setTimeout(resolve, 25));

    // Pre-fix the deferred callback takes the stale reentrant path: the
    // instance reads RESOLVING/2 while B still holds the lock.
    await expect(kernel.query('task-1')).resolves.toMatchObject({
      state: 'INTERPRETING',
      revision: 1,
    });
    expect(trace).toEqual(['deferred:start']);

    releaseB();
    await bPromise;
    await expect(deferredTransition).resolves.toMatchObject({
      state: 'RESOLVING',
      revision: 2,
    });
    expect(trace).toEqual(['deferred:start', 'deferred:done']);
  });
});
