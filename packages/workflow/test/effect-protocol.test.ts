// T03 required evidence — idempotent application-effect protocol through the
// kernel (L2 §5.4): intent → journal → ShunStore apply → durable receipt →
// continuation. Uncertain applications stay uncommitted and are reconciled
// from the journal by re-driving the SAME effectId.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ShunStore } from '@shun/store';
import { beforeEach, describe, expect, it } from 'vitest';
import { DurableWorkflowKernel, KernelEffectUncertainError } from '../src/index.ts';
import { CountingStore, goalContract, mutation, tempDir } from './helpers.ts';

let dir: string;

beforeEach(() => {
  dir = tempDir();
});

describe('applyStoreEffect', () => {
  it('journals intent, applies through the store and records the receipt', async () => {
    const store = new CountingStore();
    const kernel = new DurableWorkflowKernel({ dataDir: dir, store });
    await kernel.open({ taskId: 'task-1', goal: goalContract() });

    const receipt = await kernel.applyStoreEffect('task-1', 'effect-1', mutation('r1', { a: 1 }));
    expect(receipt.applied).toBe(true);
    expect(store.appliedEffects).toEqual(['effect-1']);

    // Duplicate call with the same effectId: store replays, kernel does not re-apply.
    const replay = await kernel.applyStoreEffect('task-1', 'effect-1', mutation('r1', { a: 1 }));
    expect(replay.applied).toBe(false);
    expect(store.appliedEffects).toEqual(['effect-1']);
    await kernel.close();
  });

  it('marks the effect uncertain and refuses to claim success when the store call is ambiguous', async () => {
    const store = new CountingStore();
    store.failing.add('effect-1');
    const kernel = new DurableWorkflowKernel({ dataDir: dir, store });
    await kernel.open({ taskId: 'task-1', goal: goalContract() });

    await expect(
      kernel.applyStoreEffect('task-1', 'effect-1', mutation('r1', { a: 1 })),
    ).rejects.toBeInstanceOf(KernelEffectUncertainError);
    // The store provably never applied (it threw before any effect).
    expect(store.appliedEffects).toEqual([]);

    // Recovery re-drives the SAME effectId from the journal once the store heals.
    store.failing.delete('effect-1');
    const report = await kernel.reconcile('task-1');
    expect(report.resolvedEffectIds).toEqual(['effect-1']);
    expect(store.appliedEffects).toEqual(['effect-1']);
    expect(report.interventionReason).toBeUndefined();
    await kernel.close();
  });

  it('surfaces an effect identity conflict as an intervention, never a silent overwrite', async () => {
    // The store has recorded effect-1 with DIFFERENT content than the journal intent.
    const realStore = new ShunStore({
      file: join(mkdtempSync(join(tmpdir(), 'shun-store-')), 'shunstore.db'),
    });
    try {
      await realStore.apply('effect-1', mutation('r1', { a: 999 }));
      const kernel = new DurableWorkflowKernel({ dataDir: dir, store: realStore });
      await kernel.open({ taskId: 'task-1', goal: goalContract() });
      // Simulate a journaled intent from a previous run that conflicts with the store.
      await expect(
        kernel.applyStoreEffect('task-1', 'effect-1', mutation('r1', { a: 1 })),
      ).rejects.toHaveProperty('code', 'KERNEL_EFFECT_CONFLICT');

      const report = await kernel.reconcile('task-1');
      expect(report.unresolvedEffectIds).toEqual(['effect-1']);
      expect(report.interventionReason).toContain('effect-1');
      await expect(kernel.query('task-1')).resolves.toMatchObject({ state: 'NEEDS_INTERVENTION' });
      await kernel.close();
    } finally {
      await realStore.close();
    }
  });

  it('applies each restart-recovered effect exactly once across kernel restarts', async () => {
    const store = new CountingStore();
    store.failing.add('effect-1');
    const kernel = new DurableWorkflowKernel({ dataDir: dir, store });
    await kernel.open({ taskId: 'task-1', goal: goalContract() });
    await expect(
      kernel.applyStoreEffect('task-1', 'effect-1', mutation('r1', { a: 1 })),
    ).rejects.toBeInstanceOf(KernelEffectUncertainError);
    await kernel.close();

    // Hard restart: fresh kernel over the same dataDir and store, now healed.
    store.failing.delete('effect-1');
    const reopened = new DurableWorkflowKernel({ dataDir: dir, store });
    try {
      const report = await reopened.reconcile('task-1');
      expect(report.resolvedEffectIds).toEqual(['effect-1']);
      // Second recovery pass is a no-op: nothing is applied twice.
      const second = await reopened.reconcile('task-1');
      expect(second.resolvedEffectIds).toEqual([]);
      expect(second.unresolvedEffectIds).toEqual([]);
      expect(store.appliedEffects).toEqual(['effect-1']);
    } finally {
      await reopened.close();
    }
  });
});
