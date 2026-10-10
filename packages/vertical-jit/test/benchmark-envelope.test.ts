// Benchmark envelope (L2 §4.2): canaries are harness truth — the production
// entry refuses them, the benchmark entry plants them, and the R2 preview
// either retains them outside the deletion scope or blocks removal entirely
// when they sit inside it (USER_ASSET_AT_RISK).
import { describe, expect, it } from 'vitest';
import { buildHarness } from '../src/mocks.ts';
import { runJitBenchmarkLifecycle } from '../src/orchestrator.ts';
import { EXECUTABLE, INSTALL_DIR, installWorld, jitInput } from './helpers.ts';

const CANARY_OUTSIDE = 'C:\\fixtures\\user-assets\\notes.txt';
const CANARY_INSIDE = `${INSTALL_DIR}\\notes.txt`;

const REMOVE_ENVELOPE = {
  ...jitInput({ retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' }),
  preExistingUserAssets: [{ path: CANARY_OUTSIDE }],
};

const DURABLE_POLICY = {
  policyId: 'pol.jit-removal',
  revision: 'r1',
  jitRemoveAfterVerifiedUse: true,
  forbidUserAssetDeletion: true as const,
};

describe('benchmark envelope vs production input', () => {
  it('plants outside-root canaries, reports them as USER_CREATED_UNKNOWN/RETAIN and keeps them intact', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);

    const output = await runJitBenchmarkLifecycle(REMOVE_ENVELOPE, harness.deps, {
      providerOwnedFiles: [EXECUTABLE],
    });

    expect(output.finalState).toBe('REMOVED');
    const canary = output.residueReport.candidates.find(
      (candidate) => candidate.path === CANARY_OUTSIDE,
    );
    expect(canary).toMatchObject({
      classification: 'USER_CREATED_UNKNOWN',
      disposition: 'RETAIN',
    });
    expect(output.residueReport.unknownOrProtectedDeleted).toBe(false);
    // Independent post-run integrity: the canary still exists with its content.
    expect(await harness.fs.readText(CANARY_OUTSIDE)).toContain('canary 0');
  });

  it('blocks automatic removal when a canary sits inside the deletion scope', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);
    const envelope = {
      ...REMOVE_ENVELOPE,
      preExistingUserAssets: [{ path: CANARY_INSIDE }],
    };

    const error = await runJitBenchmarkLifecycle(envelope, harness.deps, {
      providerOwnedFiles: [EXECUTABLE],
    }).catch((caught: unknown) => caught);

    expect(error).toMatchObject({ code: 'USER_ASSET_AT_RISK' });
    // Fail-closed: provider retained, canary intact, no R2 gate completed.
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(true);
    expect(await harness.fs.readText(CANARY_INSIDE)).toContain('canary 0');
    expect(harness.traces.map((event) => event.kind)).not.toContain('R2_APPROVAL');
  });
});
