// VJ-P1-01 depth negatives: the pre/post-install tree enumeration must NOT
// carry a fixed depth cap. A user file nested deeper than a hard depth bound
// is invisible to the R2 removal preview — and what the preview cannot see
// cannot block deletion, so the privileged uninstall would wipe it. The walk
// must descend without a depth limit (a visited set guards termination).
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
// Twelve levels deep — far beyond any reasonable fixed depth cap.
const DEEP_NESTING = ['l1', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7', 'l8', 'l9', 'l10', 'l11'];
const DEEP_USER_FILE = `${INSTALL_DIR}\\${DEEP_NESTING.join('\\')}\\deep-user-notes.txt`;

describe('tree walk depth (VJ-P1-01)', () => {
  it('blocks removal when an unrecorded user file sits deeper than eight levels inside the install root', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);
    // The user drops a file twelve levels deep before acquisition; the
    // installer never recorded it as its own.
    harness.fs.putTree([`${INSTALL_DIR}\\${DEEP_NESTING.join('\\')}`], {
      [DEEP_USER_FILE]: 'deep data',
    });

    const error = await runJitLifecycle(REMOVE_INPUT, harness.deps).catch(
      (caught: unknown) => caught,
    );

    expect(error).toMatchObject({ code: 'USER_ASSET_AT_RISK' });
    // The load-bearing assertion: the block reason must NAME the deep file
    // itself. With a fixed depth cap the file lives beyond the cap — only the
    // shallow intermediate directories (which also block, masking the file's
    // invisibility) appear in the preview, so this assertion is red on any
    // depth-capped enumeration.
    expect((error as { detail: string }).detail).toContain('deep-user-notes.txt');
    // Fail-closed: provider retained, deep user file intact.
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(true);
    expect(await harness.fs.readText(DEEP_USER_FILE)).toBe('deep data');
    // The privileged removal never executed.
    const entries = await harness.deps.journals(UNINSTALL_ACTION_ID).replay();
    expect(entries.filter((entry) => entry.phase === 'EXEC_START')).toHaveLength(0);
  });
});
