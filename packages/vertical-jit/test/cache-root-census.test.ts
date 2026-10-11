// VJ-P1-01 cache census negatives: cache roots sit inside the R2 deletion
// scope, so the install-owned manifest must census them exactly like install
// roots. An unrecorded user file nested inside a provider cache root must be
// discovered, classified USER_CREATED_UNKNOWN, and block the uninstall BEFORE
// any privileged removal effect — never root-trusted into CACHE/DELETE.
import { describe, expect, it } from 'vitest';
import { buildHarness } from '../src/mocks.ts';
import { runJitLifecycle } from '../src/orchestrator.ts';
import { CACHE_DIR, EXECUTABLE, INSTALL_DIR, installWorld, jitInput } from './helpers.ts';

const DURABLE_POLICY = {
  policyId: 'pol.jit-removal',
  revision: 'r1',
  jitRemoveAfterVerifiedUse: true,
  forbidUserAssetDeletion: true as const,
};

const REMOVE_INPUT = jitInput({ retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' });
const UNINSTALL_ACTION_ID = 'task-2026-10-10-002-uninstall';
const NESTED_CACHE_USER_FILE = `${CACHE_DIR}\\userdata\\profile\\mine.txt`;

describe('cache root ownership census (VJ-P1-01)', () => {
  it('blocks removal when an unrecorded user file sits two levels inside a cache root — never root-trusted to DELETE', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);
    // The user drops a file into the provider cache directory before
    // acquisition; the installer never recorded it as its own.
    harness.fs.putTree([`${CACHE_DIR}\\userdata\\profile`], {
      [NESTED_CACHE_USER_FILE]: 'my cache data',
    });

    const error = await runJitLifecycle(REMOVE_INPUT, harness.deps).catch(
      (caught: unknown) => caught,
    );

    expect(error).toMatchObject({ code: 'USER_ASSET_AT_RISK' });
    // Fail-closed: provider retained, nested user file intact.
    expect(await harness.fs.exists(CACHE_DIR)).toBe(true);
    expect(await harness.fs.readText(NESTED_CACHE_USER_FILE)).toBe('my cache data');
    // The privileged removal never executed: the uninstall journal holds no
    // EXEC_START.
    const entries = await harness.deps.journals(UNINSTALL_ACTION_ID).replay();
    expect(entries.filter((entry) => entry.phase === 'EXEC_START')).toHaveLength(0);
    // No R2 approval was ever requested for a blocked removal.
    expect(harness.approval.requests).toHaveLength(0);
  });

  it('censuses the cache root into the install-owned manifest recorded at install time', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);

    await runJitLifecycle(REMOVE_INPUT, harness.deps);

    const installed = [...harness.store.records.values()].find(
      (mutation) => mutation.payload.state === 'INSTALLED',
    );
    expect(installed).toBeDefined();
    const owned = installed?.payload.providerOwnedFiles;
    expect(Array.isArray(owned)).toBe(true);
    // The manifest names exactly what the installer created — the install
    // root, the executable, and the cache root — nothing more.
    expect(owned).toEqual([INSTALL_DIR, EXECUTABLE, CACHE_DIR]);
  });

  it('still removes cleanly when only installer-recorded paths occupy install and cache roots', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);

    const output = await runJitLifecycle(REMOVE_INPUT, harness.deps);

    expect(output.finalState).toBe('REMOVED');
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
    expect(await harness.fs.exists(CACHE_DIR)).toBe(false);
  });
});
