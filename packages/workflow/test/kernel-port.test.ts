// T03 — WorkflowKernelPort mechanics (L2 §5.2/§5.3): durable open/query,
// serialized legal-only transitions, durable message acceptance with
// idempotent disposition, subscription and restart persistence.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  KernelInvalidTransitionError,
  KernelMessageConflictError,
  KernelUnknownTaskError,
} from '../src/index.ts';
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

describe('open / query', () => {
  it('opens a task at RECEIVED revision 0', async () => {
    const taskId = await kernel.open({ taskId: 'task-1', goal: goalContract() });
    expect(taskId).toBe('task-1');
    await expect(kernel.query('task-1')).resolves.toEqual({
      taskId: 'task-1',
      state: 'RECEIVED',
      revision: 0,
    });
  });

  it('is idempotent for the same task+goal and conflicts on a different goal', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    await expect(kernel.open({ taskId: 'task-1', goal: goalContract() })).resolves.toBe('task-1');
    await expect(
      kernel.open({ taskId: 'task-1', goal: goalContract({ objective: 'something else' }) }),
    ).rejects.toHaveProperty('code', 'KERNEL_CONFLICT');
  });

  it('rejects query for an unknown task', async () => {
    await expect(kernel.query('nope')).rejects.toBeInstanceOf(KernelUnknownTaskError);
  });
});

describe('transitions', () => {
  it('follows the frozen L2 §5.1 flow and bumps the revision', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    await kernel.transition('task-1', 'INTERPRETING');
    await kernel.transition('task-1', 'RESOLVING');
    await kernel.transition('task-1', 'PLANNED');
    const state = await kernel.transition('task-1', 'EXECUTING');
    expect(state).toEqual({ taskId: 'task-1', state: 'EXECUTING', revision: 4 });
  });

  it('refuses transitions outside the frozen flow with a typed error', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    await expect(kernel.transition('task-1', 'EXECUTING')).rejects.toBeInstanceOf(
      KernelInvalidTransitionError,
    );
  });

  it('freezes terminal states', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    await kernel.transition('task-1', 'INTERPRETING');
    await kernel.transition('task-1', 'RESOLVING');
    await kernel.transition('task-1', 'PLANNED');
    await kernel.transition('task-1', 'EXECUTING');
    await kernel.transition('task-1', 'VERIFYING');
    await kernel.transition('task-1', 'LIFECYCLE_RECONCILIATION');
    await kernel.transition('task-1', 'SUCCEEDED');
    await expect(kernel.transition('task-1', 'FAILED')).rejects.toBeInstanceOf(
      KernelInvalidTransitionError,
    );
    // A frozen task can no longer be moved by any message-driven transition.
    await expect(kernel.transition('task-1', 'INTERPRETING')).rejects.toBeInstanceOf(
      KernelInvalidTransitionError,
    );
  });
});

describe('subscribe', () => {
  it('replays the current state once and then every transition until unsubscribed', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    const listener = vi.fn();
    const unsubscribe = kernel.subscribe('task-1', listener);
    expect(listener).toHaveBeenCalledWith({ taskId: 'task-1', state: 'RECEIVED', revision: 0 });

    await kernel.transition('task-1', 'INTERPRETING');
    expect(listener).toHaveBeenLastCalledWith({ taskId: 'task-1', state: 'INTERPRETING', revision: 1 });

    unsubscribe();
    await kernel.transition('task-1', 'RESOLVING');
    expect(listener).toHaveBeenCalledTimes(2);
  });
});

describe('send — durable message acceptance', () => {
  it('accepts a message durably and dispatches it to the registered handler', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    const handled: string[] = [];
    kernel.registerHandler('DO_THING', async (message) => {
      handled.push(message.messageId);
      await kernel.transition('task-1', 'INTERPRETING');
    });

    const disposition = await kernel.send({
      messageId: 'm1',
      taskId: 'task-1',
      kind: 'DO_THING',
      payload: { x: 1 },
    });
    expect(disposition.accepted).toBe(true);
    expect(handled).toEqual(['m1']);
    await expect(kernel.query('task-1')).resolves.toMatchObject({ state: 'INTERPRETING' });
  });

  it('replays the recorded disposition for a duplicate messageId without re-handling', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    const handled: string[] = [];
    kernel.registerHandler('DO_THING', async (message) => {
      handled.push(message.messageId);
    });

    await kernel.send({ messageId: 'm1', taskId: 'task-1', kind: 'DO_THING', payload: { x: 1 } });
    const replay = await kernel.send({
      messageId: 'm1',
      taskId: 'task-1',
      kind: 'DO_THING',
      payload: { x: 1 },
    });

    expect(replay.accepted).toBe(true);
    expect(handled).toEqual(['m1']);
  });

  it('rejects a duplicate messageId with different content', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    await kernel.send({ messageId: 'm1', taskId: 'task-1', kind: 'DO_THING', payload: { x: 1 } });
    await expect(
      kernel.send({ messageId: 'm1', taskId: 'task-1', kind: 'DO_THING', payload: { x: 2 } }),
    ).rejects.toBeInstanceOf(KernelMessageConflictError);
  });

  it('keeps a message durably pending when no handler is registered', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    const disposition = await kernel.send({
      messageId: 'm1',
      taskId: 'task-1',
      kind: 'SOMETHING_LATER',
      payload: {},
    });
    expect(disposition.accepted).toBe(true);
    await expect(kernel.pendingMessages('task-1')).resolves.toHaveLength(1);
  });

  it('redelivers a message whose handler failed, after the handler is fixed', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    let calls = 0;
    kernel.registerHandler('FLAKY', async () => {
      calls += 1;
      if (calls === 1) {
        throw new Error('transient handler failure');
      }
    });

    await expect(
      kernel.send({ messageId: 'm1', taskId: 'task-1', kind: 'FLAKY', payload: {} }),
    ).rejects.toHaveProperty('code', 'KERNEL_HANDLER_FAILED');
    await expect(kernel.pendingMessages('task-1')).resolves.toHaveLength(1);

    const report = await kernel.redeliverPending('task-1');
    expect(report.redeliveredMessageIds).toEqual(['m1']);
    expect(calls).toBe(2);
    await expect(kernel.pendingMessages('task-1')).resolves.toHaveLength(0);
  });

  it('rejects messages for an unknown task', async () => {
    await expect(
      kernel.send({ messageId: 'm1', taskId: 'ghost', kind: 'DO_THING', payload: {} }),
    ).rejects.toBeInstanceOf(KernelUnknownTaskError);
  });
});

describe('restart persistence', () => {
  it('restores instance state, revision and pending messages from the runtime store', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    await kernel.transition('task-1', 'INTERPRETING');
    await kernel.transition('task-1', 'RESOLVING');
    await kernel.send({ messageId: 'm1', taskId: 'task-1', kind: 'LATER', payload: { n: 1 } });
    await kernel.close();

    const reopened = new DurableWorkflowKernel({ dataDir: dir, store });
    try {
      await expect(reopened.query('task-1')).resolves.toEqual({
        taskId: 'task-1',
        state: 'RESOLVING',
        revision: 2,
      });
      await expect(reopened.pendingMessages('task-1')).resolves.toHaveLength(1);
      // Duplicate open after restart stays idempotent (goal identity persisted).
      await expect(reopened.open({ taskId: 'task-1', goal: goalContract() })).resolves.toBe('task-1');
      // The revision keeps counting across restarts.
      const state = await reopened.transition('task-1', 'PLANNED');
      expect(state.revision).toBe(3);
    } finally {
      await reopened.close();
    }
  });

  it('keeps business records out of the runtime store (store separation, L2 §5.4)', async () => {
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    const tables = kernel.database
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
      .all() as Array<{ name: string }>;
    const names = tables.map((table) => table.name).sort();
    expect(names).toEqual(['instances', 'messages']);
  });
});
