// VJ-P1-02 negative control: INSTALLED and CHECKPOINT are distinct state
// transitions of the durable lifecycle record. Sharing one effectId lets the
// store's idempotent replay swallow the CHECKPOINT (the memory Store dedups
// by effectId), so the checkpoint that R2 approval relies on never becomes
// durable. Each transition must carry its own append-only revision identity
// and be read back before the gate proceeds.
import { describe, expect, it } from 'vitest';
import { buildHarness } from '../src/mocks.ts';
import { runJitLifecycle } from '../src/orchestrator.ts';
import { installWorld, jitInput } from './helpers.ts';

const DURABLE_POLICY = {
  policyId: 'pol.jit-removal',
  revision: 'r1',
  jitRemoveAfterVerifiedUse: true,
  forbidUserAssetDeletion: true as const,
};

const REMOVE_INPUT = jitInput({ retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' });

describe('lifecycle state persistence (VJ-P1-02)', () => {
  it('persists INSTALLED and CHECKPOINT as two distinct durable records', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);

    await runJitLifecycle(REMOVE_INPUT, harness.deps);

    const lifecycleRecords = [...harness.store.records.entries()].filter(
      ([, mutation]) => mutation.recordKind === 'lifecycle_record',
    );
    const states = lifecycleRecords.map(([, mutation]) => mutation.payload.state);
    expect(states).toContain('INSTALLED');
    expect(states).toContain('CHECKPOINT');
    // Distinct append-only revision identities — no idempotent replay can
    // swallow the checkpoint.
    expect(new Set(lifecycleRecords.map(([effectId]) => effectId)).size).toBe(
      lifecycleRecords.length,
    );
  });

  it('durably records the CHECKPOINT before the approval surface is consulted', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);

    await runJitLifecycle(REMOVE_INPUT, harness.deps);

    const persistEvents = harness.traces
      .map((event, index) => ({ ...event, index }))
      .filter((event) => event.kind === 'LIFECYCLE_PERSISTED');
    const checkpointEvent = persistEvents.find((event) => event.detail?.startsWith('CHECKPOINT'));
    expect(checkpointEvent).toBeDefined();
    const approvalIndex = harness.traces.findIndex((event) => event.kind === 'R2_APPROVAL');
    expect(approvalIndex).toBeGreaterThanOrEqual(0);
    expect((checkpointEvent as { index: number }).index).toBeLessThan(approvalIndex);
  });

  it('keeps the RETAIN-path INSTALLED record durable as its own revision', async () => {
    const harness = buildHarness();
    installWorld(harness);

    await runJitLifecycle(jitInput({ retention: 'RETAIN' }), harness.deps);

    const lifecycleRecords = [...harness.store.records.values()].filter(
      (mutation) => mutation.recordKind === 'lifecycle_record',
    );
    expect(lifecycleRecords.map((mutation) => mutation.payload.state)).toEqual(['INSTALLED']);
  });
});
