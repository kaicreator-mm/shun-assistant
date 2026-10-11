// VJ-P1-01 negative control: the production path must record the exact
// install-owned manifest (installer-created paths only) and re-enumerate the
// install root RECURSIVELY at removal time. An unrecorded user file nested
// two levels deep inside the install root must be discovered, classified
// USER_CREATED_UNKNOWN, and block the uninstall BEFORE any privileged
// removal effect.
import { describe, expect, it } from 'vitest';
import { buildHarness } from '../src/mocks.ts';
import { runJitLifecycle } from '../src/orchestrator.ts';
import { INSTALL_DIR, installWorld, jitInput } from './helpers.ts';

const DURABLE_POLICY = {
  policyId: 'pol.jit-removal',
  revision: 'r1',
  jitRemoveAfterVerifiedUse: true,
  forbidUserAssetDeletion: true as const,
};

const REMOVE_INPUT = jitInput({ retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' });
const UNINSTALL_ACTION_ID = 'task-2026-10-10-002-uninstall';
const NESTED_USER_FILE = `${INSTALL_DIR}\\userdata\\profile\\mine.txt`;

describe('nested user asset ownership (VJ-P1-01)', () => {
  it('blocks removal before uninstall when an unrecorded user file sits two levels inside the install root', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);
    // The user drops a file into the provider directory before acquisition;
    // the installer never recorded it as its own.
    harness.fs.putTree([`${INSTALL_DIR}\\userdata\\profile`], {
      [NESTED_USER_FILE]: 'my data',
    });

    const error = await runJitLifecycle(REMOVE_INPUT, harness.deps).catch(
      (caught: unknown) => caught,
    );

    expect(error).toMatchObject({ code: 'USER_ASSET_AT_RISK' });
    // Fail-closed: provider retained, nested user file intact.
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(true);
    expect(await harness.fs.readText(NESTED_USER_FILE)).toBe('my data');
    // The privileged removal never executed: the uninstall journal holds no
    // EXEC_START.
    const entries = await harness.deps.journals(UNINSTALL_ACTION_ID).replay();
    expect(entries.filter((entry) => entry.phase === 'EXEC_START')).toHaveLength(0);
    // No R2 approval was ever requested for a blocked removal.
    expect(harness.approval.requests).toHaveLength(0);
  });

  it('records the exact install-owned manifest durably at install time', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);

    await runJitLifecycle(REMOVE_INPUT, harness.deps);

    const installed = [...harness.store.records.values()].find(
      (mutation) => mutation.payload.state === 'INSTALLED',
    );
    expect(installed).toBeDefined();
    const owned = installed?.payload.providerOwnedFiles;
    expect(Array.isArray(owned)).toBe(true);
    // The manifest names exactly what the installer wrote — nothing more.
    expect(owned).toEqual([`${INSTALL_DIR}\\pdftool.exe`]);
  });

  it('still removes cleanly when only installer-recorded paths occupy the install root', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);

    const output = await runJitLifecycle(REMOVE_INPUT, harness.deps);

    expect(output.finalState).toBe('REMOVED');
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
  });
});
