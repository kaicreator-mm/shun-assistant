// Effect atomicity negatives (VJ-P1-01 R4 post-recensus mutation windows).
//
// The R3 effect-boundary re-census closed the PRE-approval windows, but the
// census is still followed by caller-reachable seams: the `trace('R2_RECENSUS')`
// hook is caller-supplied synchronous code, and `runPrivileged` awaits the
// grant issuance BEFORE the privileged effect executes. Content planted in
// either window is invisible to every census, and a whole-root uninstaller
// destroys it while the lifecycle reports REMOVED.
//
// Each negative injects a byte-exact canary INSIDE the deletion scope in
// exactly such a window and demands effect atomicity: the canary survives
// byte-for-byte, NOTHING inside the scope is deleted (zero external effect),
// and the lifecycle never claims REMOVED — no output, store record or trace.
// The positive control proves the removal path still completes when no
// injection happens.
import { describe, expect, it } from 'vitest';
import { buildHarness, type JitHarness } from '../src/mocks.ts';
import type { ImportableAuthorizationPort } from '../src/orchestrator.ts';
import { runJitLifecycle } from '../src/orchestrator.ts';
import { CACHE_DIR, EXECUTABLE, INSTALL_DIR, installWorld, jitInput, withDeps } from './helpers.ts';

const REMOVE_INPUT = jitInput({ retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' });
const UNINSTALL_ACTION_ID = 'task-2026-10-10-002-uninstall';
const LATE_DROP_DIR = `${INSTALL_DIR}\\late-drop`;
const LATE_USER_FILE = `${LATE_DROP_DIR}\\notes.txt`;
const LATE_USER_CONTENT = 'R4 canary — planted after every census, must survive byte-exact';

const DURABLE_POLICY = {
  policyId: 'pol.jit-removal',
  revision: 'r1',
  jitRemoveAfterVerifiedUse: true,
  forbidUserAssetDeletion: true as const,
};

/** Plant a nested user asset inside the install root (in-window injection). */
function plantLateUserAsset(harness: JitHarness): void {
  harness.fs.putTree([LATE_DROP_DIR], { [LATE_USER_FILE]: LATE_USER_CONTENT });
}

/** The lifecycle store must never claim a REMOVED state for a refused removal. */
async function assertNoRemovedClaim(harness: JitHarness): Promise<void> {
  const removed = [...harness.store.records.values()].filter(
    (mutation) => mutation.payload.state === 'REMOVED',
  );
  expect(removed).toHaveLength(0);
}

/**
 * Effect atomicity: the injected canary survived byte-exact, nothing at all
 * was deleted inside the scope (zero external effect — the installer-owned
 * files are still on disk), and no surface claims REMOVED.
 */
async function assertInjectionSurvived(
  harness: JitHarness,
  error: unknown,
  options: { viaRetry?: boolean } = {},
): Promise<void> {
  expect(error).toMatchObject({ code: 'REMOVE_FAILED' });
  expect((error as { recovery?: { recoveryClassification: string } }).recovery).toMatchObject({
    recoveryClassification: 'NOT_STARTED',
  });
  // Byte-exact canary survival.
  expect(await harness.fs.exists(LATE_USER_FILE)).toBe(true);
  expect(await harness.fs.readText(LATE_USER_FILE)).toBe(LATE_USER_CONTENT);
  // Zero external effect: the privileged effect refused before ANY deletion,
  // so the installer-owned content is untouched as well.
  expect(await harness.fs.exists(EXECUTABLE)).toBe(true);
  expect(await harness.fs.exists(INSTALL_DIR)).toBe(true);
  expect(await harness.fs.exists(CACHE_DIR)).toBe(true);
  // No REMOVED claim anywhere: store, trace, or output (the run threw).
  await assertNoRemovedClaim(harness);
  expect(
    harness.traces.some(
      (event) => event.kind === 'OUTPUT_EMITTED' && event.detail === 'finalState=REMOVED',
    ),
  ).toBe(false);
  expect(harness.traces.some((event) => event.kind === 'R2_VERIFY')).toBe(false);
  // The refusal happened at the privileged effect boundary itself: the
  // executor opened the effect (EXEC_START) and refused before destroying
  // anything, with the canary named in the honest NO_EFFECT journal marker.
  const entries = await harness.deps.journals(UNINSTALL_ACTION_ID).replay();
  const expectedExecStarts = options.viaRetry ? 2 : 1;
  expect(entries.filter((entry) => entry.phase === 'EXEC_START')).toHaveLength(expectedExecStarts);
  const noEffect = entries.filter(
    (entry) => entry.phase === 'RECEIPT_WRITTEN' && entry.detail?.startsWith('NO_EFFECT:'),
  );
  expect(noEffect.length).toBeGreaterThan(0);
  expect(noEffect.some((entry) => entry.detail?.includes('late-drop'))).toBe(true);
}

describe('post-recensus trace-callback injection (VJ-P1-01 R4 window 1)', () => {
  it('explicit approval: an asset planted on the R2_RECENSUS trace survives byte-exact and no REMOVED is claimed', async () => {
    const harness = buildHarness({ approvalMode: 'approve' });
    installWorld(harness);
    // The R2_RECENSUS trace fires AFTER the effect-boundary re-census and is
    // caller-supplied code — planting inside it is exactly the seam between
    // the last validation and the privileged effect.
    const baseTrace = harness.deps.trace;
    const deps = withDeps(harness, {
      trace: (event) => {
        baseTrace?.(event);
        if (event.kind === 'R2_RECENSUS') plantLateUserAsset(harness);
      },
    });

    const error = await runJitLifecycle(REMOVE_INPUT, deps).catch((caught: unknown) => caught);

    await assertInjectionSurvived(harness, error);
  });

  it('durable policy: an asset planted on the R2_RECENSUS trace survives byte-exact and no REMOVED is claimed', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);
    const baseTrace = harness.deps.trace;
    const deps = withDeps(harness, {
      trace: (event) => {
        baseTrace?.(event);
        if (event.kind === 'R2_RECENSUS') plantLateUserAsset(harness);
      },
    });

    const error = await runJitLifecycle(REMOVE_INPUT, deps).catch((caught: unknown) => caught);

    await assertInjectionSurvived(harness, error);
  });
});

describe('issueGrant async-window injection (VJ-P1-01 R4 window 2)', () => {
  it('explicit approval: an asset planted while the uninstall grant is issued survives byte-exact and no REMOVED is claimed', async () => {
    const harness = buildHarness({ approvalMode: 'approve' });
    installWorld(harness);
    // issueGrant awaits the authority before the privileged backend executes:
    // planting inside the uninstall-grant issuance is a window AFTER the
    // R2_RECENSUS census and its trace.
    const inner = harness.deps.authorization;
    const windowed: ImportableAuthorizationPort = {
      currentAuthority: () => inner.currentAuthority(),
      issue: async (request) => {
        if (request.actionScope.actionIds.includes(UNINSTALL_ACTION_ID)) {
          plantLateUserAsset(harness);
        }
        return inner.issue(request);
      },
    };
    const deps = withDeps(harness, { authorization: windowed });

    const error = await runJitLifecycle(REMOVE_INPUT, deps).catch((caught: unknown) => caught);

    await assertInjectionSurvived(harness, error);
  });

  it('durable policy: an asset planted while the uninstall grant is issued survives byte-exact and no REMOVED is claimed', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);
    const inner = harness.deps.authorization;
    const windowed: ImportableAuthorizationPort = {
      currentAuthority: () => inner.currentAuthority(),
      issue: async (request) => {
        if (request.actionScope.actionIds.includes(UNINSTALL_ACTION_ID)) {
          plantLateUserAsset(harness);
        }
        return inner.issue(request);
      },
    };
    const deps = withDeps(harness, { authorization: windowed });

    const error = await runJitLifecycle(REMOVE_INPUT, deps).catch((caught: unknown) => caught);

    await assertInjectionSurvived(harness, error);
  });
});

describe('reconcile-first retry injection (VJ-P1-01 R4 window 3)', () => {
  it('an asset planted in the retry grant window — after the pre-retry re-census — survives byte-exact and the retry effect refuses', async () => {
    let interrupts = 0;
    const harness = buildHarness({
      approvalMode: 'approve',
      backendFaults: [
        {
          kind: 'INTERRUPT',
          when: (action) => action.action.op === 'software.uninstall' && interrupts++ === 0,
        },
      ],
    });
    installWorld(harness);
    // The retry is its OWN privileged effect. Its window runs from the
    // pre-retry re-census to the retry execute; the caller-reachable seam
    // inside it is the attempt-2 grant issuance — the SECOND issue of the
    // uninstall grant, which happens strictly after that re-census.
    let uninstallIssues = 0;
    const inner = harness.deps.authorization;
    const windowed: ImportableAuthorizationPort = {
      currentAuthority: () => inner.currentAuthority(),
      issue: async (request) => {
        const isUninstall = request.actionScope.actionIds.includes(UNINSTALL_ACTION_ID);
        if (isUninstall && ++uninstallIssues === 2) plantLateUserAsset(harness);
        return inner.issue(request);
      },
    };
    const deps = withDeps(harness, { authorization: windowed });

    const error = await runJitLifecycle(REMOVE_INPUT, deps).catch((caught: unknown) => caught);

    expect(
      harness.traces.some(
        (event) => event.kind === 'R2_RECONCILE' && event.detail?.includes('retry SAME actionId'),
      ),
    ).toBe(true);
    expect(uninstallIssues).toBe(2);
    await assertInjectionSurvived(harness, error, { viaRetry: true });
  });
});

describe('positive control — no injection', () => {
  it('completes the removal: provider and cache content gone, REMOVED claimed', async () => {
    const harness = buildHarness({ approvalMode: 'approve' });
    installWorld(harness);

    const output = await runJitLifecycle(REMOVE_INPUT, harness.deps);

    expect(output.finalState).toBe('REMOVED');
    // The manifest-restricted removal still eliminates every installer-created
    // path inside the deletion scope.
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
    expect(await harness.fs.exists(CACHE_DIR)).toBe(false);
  });
});
