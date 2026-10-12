import { describe, expect, it } from 'vitest';
import { buildHarness } from '../src/mocks.ts';
import { resumeJitRemovalFromCheckpoint, runJitLifecycle } from '../src/orchestrator.ts';
import { CACHE_DIR, INSTALL_DIR, installWorld, jitInput, withDeps } from './helpers.ts';

const REMOVE_INPUT = jitInput({ retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' });
const CHECKPOINT_ID = 'jit:task-2026-10-10-002:lifecycle:checkpoint';

function durablePolicy() {
  return {
    policyId: 'pol.jit-removal',
    revision: 'r1',
    jitRemoveAfterVerifiedUse: true,
    forbidUserAssetDeletion: true as const,
  };
}

async function stopAfterCheckpoint() {
  const first = buildHarness();
  installWorld(first);
  const crash = withDeps(first, {
    approval: {
      requestApproval: async () => {
        throw new Error('simulated process death after durable checkpoint');
      },
    },
  });
  await expect(runJitLifecycle(REMOVE_INPUT, crash)).rejects.toThrow(/simulated process death/);
  const checkpoint = await first.store.getLifecycleRecord(CHECKPOINT_ID);
  expect(checkpoint?.payload).toMatchObject({
    taskId: 'task-2026-10-10-002',
    state: 'CHECKPOINT',
  });
  expect(checkpoint?.payload.verification).toBeDefined();
  expect(checkpoint?.payload.providerOwnedFiles).toBeDefined();
  expect(await first.fs.exists(INSTALL_DIR)).toBe(true);
  return first;
}

describe('durable process-restart removal recovery', () => {
  it('rehydrates authoritative CHECKPOINT in a new composition and resumes R2 without reinstall', async () => {
    const first = await stopAfterCheckpoint();

    // New harness = new acquisition/authority/ledger process composition.
    // Only the filesystem and authoritative durable store survive the restart.
    const restarted = buildHarness({
      fs: first.fs,
      store: first.store,
      durableJitPolicy: durablePolicy(),
    });
    installWorld(restarted);

    const output = await resumeJitRemovalFromCheckpoint(REMOVE_INPUT, restarted.deps);

    expect(output.finalState).toBe('REMOVED');
    expect(output.r2Gate).toMatchObject({ approvedBy: 'DURABLE_POLICY' });
    expect(await restarted.fs.exists(INSTALL_DIR)).toBe(false);
    expect(await restarted.fs.exists(CACHE_DIR)).toBe(false);
    expect(restarted.traces.some((event) => event.kind === 'RESTART_CHECKPOINT_REHYDRATED')).toBe(
      true,
    );
    expect(restarted.traces.some((event) => event.kind === 'INSTALL_EXECUTED')).toBe(false);
  });

  it('refuses restart when the authoritative checkpoint is missing', async () => {
    const restarted = buildHarness({ durableJitPolicy: durablePolicy() });
    installWorld(restarted);

    await expect(
      resumeJitRemovalFromCheckpoint(REMOVE_INPUT, restarted.deps),
    ).rejects.toMatchObject({
      code: 'POLICY_BLOCKED',
    });
  });

  it('refuses a checkpoint whose persisted ownership manifest escapes its durable roots', async () => {
    const first = await stopAfterCheckpoint();
    const mutation = first.store.records.get(CHECKPOINT_ID);
    if (!mutation) throw new Error('checkpoint mutation missing');
    first.store.records.set(CHECKPOINT_ID, {
      ...mutation,
      payload: {
        ...mutation.payload,
        providerOwnedFiles: [
          ...(mutation.payload.providerOwnedFiles as string[]),
          'C:\\Users\\dev\\Documents\\must-not-delete.txt',
        ],
      },
    });

    const restarted = buildHarness({
      fs: first.fs,
      store: first.store,
      durableJitPolicy: durablePolicy(),
    });
    installWorld(restarted);

    await expect(
      resumeJitRemovalFromCheckpoint(REMOVE_INPUT, restarted.deps),
    ).rejects.toMatchObject({
      code: 'POLICY_BLOCKED',
    });
    expect(await restarted.fs.exists(INSTALL_DIR)).toBe(true);
  });

  it('refuses stale catalog provenance instead of trusting the old checkpoint', async () => {
    const first = await stopAfterCheckpoint();
    const mutation = first.store.records.get(CHECKPOINT_ID);
    if (!mutation) throw new Error('checkpoint mutation missing');
    first.store.records.set(CHECKPOINT_ID, {
      ...mutation,
      payload: {
        ...mutation.payload,
        provenance: {
          ...(mutation.payload.provenance as Record<string, unknown>),
          source: 'winget:https://stale.example.invalid/package.zip',
        },
      },
    });

    const restarted = buildHarness({
      fs: first.fs,
      store: first.store,
      durableJitPolicy: durablePolicy(),
    });
    installWorld(restarted);

    await expect(
      resumeJitRemovalFromCheckpoint(REMOVE_INPUT, restarted.deps),
    ).rejects.toMatchObject({
      code: 'PROVENANCE_UNKNOWN',
    });
    expect(await restarted.fs.exists(INSTALL_DIR)).toBe(true);
  });
});
