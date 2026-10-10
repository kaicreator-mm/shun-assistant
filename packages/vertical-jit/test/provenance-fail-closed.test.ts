// Provenance is fail-closed (C-002): unknown provenance is never trusted, and
// no approval surface is even consulted when trust fails.
import { describe, expect, it } from 'vitest';
import { buildHarness } from '../src/mocks.ts';
import { runJitLifecycle } from '../src/orchestrator.ts';
import { INSTALL_DIR, installWorld, jitInput, run, withDeps } from './helpers.ts';

describe('JIT lifecycle — provenance fail-closed gate', () => {
  it('refuses PROVENANCE_UNKNOWN when the only binding is a non-official provider', async () => {
    const harness = buildHarness();
    installWorld(harness, { untrustedOnly: true });

    await expect(run(harness, jitInput({ retention: 'RETAIN' }))).rejects.toMatchObject({
      code: 'PROVENANCE_UNKNOWN',
    });

    // Nothing was acquired or installed; the approval surface was never asked.
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
    expect(harness.approval.requests).toHaveLength(0);
  });

  it('records no lifecycle state when provenance fails', async () => {
    const harness = buildHarness();
    installWorld(harness, { untrustedOnly: true });
    await expect(run(harness, jitInput({ retention: 'RETAIN' }))).rejects.toMatchObject({
      code: 'PROVENANCE_UNKNOWN',
    });
    expect(harness.store.records.size).toBe(0);
    expect(harness.ledger.size).toBe(0);
  });

  it('refuses a candidate that turns out non-official at acquisition resolution', async () => {
    const harness = buildHarness();
    installWorld(harness);
    // A tampered acquisition port resolves a non-official candidate.
    const acquisition = harness.deps.acquisition;
    const deps = withDeps(harness, {
      acquisition: {
        ...acquisition,
        resolveExact: async (request: { packageId: string; version?: string }) => {
          const candidate = await acquisition.resolveExact(request);
          return { ...candidate, official: false, source: 'mirror.example.net' };
        },
      },
    });

    await expect(runJitLifecycle(jitInput({ retention: 'RETAIN' }), deps)).rejects.toMatchObject({
      code: 'PROVENANCE_UNKNOWN',
    });
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
  });
});
