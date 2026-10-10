// T03 post-merge security correction (Issue #36, C03): per-task serialization
// must be owned by the async context that holds the lock, not by a shared
// numeric depth counter. An UNRELATED concurrent invocation for a task whose
// lock is held (the holder suspended at an await inside its critical section)
// must queue behind the holder — never run interleaved with it.
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
