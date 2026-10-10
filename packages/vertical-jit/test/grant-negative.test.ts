// Grant/authorization negatives: the privileged boundary re-validates every
// presentation against CURRENT state and refuses fail-closed BEFORE any side
// effect; the orchestrator maps refusals to typed failures with recovery
// classification NOT_STARTED and never retries.
import { describe, expect, it } from 'vitest';
import { isJitLifecycleError, type JitLifecycleError } from '../src/failures.ts';
import { classifyFromJournal } from '../src/journal.ts';
import { buildHarness } from '../src/mocks.ts';
import { runJitLifecycle } from '../src/orchestrator.ts';
import { INSTALL_DIR, installWorld, jitInput } from './helpers.ts';

describe('JIT lifecycle — grant negatives (fail-closed boundary)', () => {
  it('refuses a stale policy snapshot between grant issuance and privileged execution', async () => {
    const harness = buildHarness();
    installWorld(harness);
    const inner = harness.deps.privileged;
    const deps = {
      ...harness.deps,
      privileged: {
        execute: async (
          action: Parameters<typeof inner.execute>[0],
          grant: Parameters<typeof inner.execute>[1],
        ) => {
          // The policy snapshot changes after the grant was issued, before the
          // boundary sees the presentation.
          harness.authority.supersedePolicy('pol-snap-r2');
          return inner.execute(action, grant);
        },
      },
    };

    const error = await runJitLifecycle(jitInput({ retention: 'RETAIN' }), deps).catch(
      (caught: unknown) => caught,
    );

    expect(isJitLifecycleError(error)).toBe(true);
    const jitError = error as JitLifecycleError;
    expect(jitError.code).toBe('INSTALL_FAILED');
    expect(jitError.detail).toContain('GRANT_POLICY_STALE');
    expect(jitError.recovery?.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
  });

  it('refuses a forged presentation whose integrity envelope was stripped', async () => {
    const harness = buildHarness();
    installWorld(harness);
    const inner = harness.deps.privileged;
    const deps = {
      ...harness.deps,
      privileged: {
        execute: async (
          action: Parameters<typeof inner.execute>[0],
          grant: Parameters<typeof inner.execute>[1],
        ) => {
          const { integrity: _stripped, ...withoutIntegrity } = grant;
          void _stripped;
          return inner.execute(action, withoutIntegrity);
        },
      },
    };

    const error = await runJitLifecycle(jitInput({ retention: 'RETAIN' }), deps).catch(
      (caught: unknown) => caught,
    );

    expect((error as JitLifecycleError).detail).toContain('GRANT_NOT_AUTHENTIC');
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
  });

  it('refuses a grant revoked after issuance', async () => {
    const harness = buildHarness();
    installWorld(harness);
    const inner = harness.deps.privileged;
    const deps = {
      ...harness.deps,
      privileged: {
        execute: async (
          action: Parameters<typeof inner.execute>[0],
          grant: Parameters<typeof inner.execute>[1],
        ) => {
          harness.authority.revokeGrant(grant.grantId);
          return inner.execute(action, grant);
        },
      },
    };

    const error = await runJitLifecycle(jitInput({ retention: 'RETAIN' }), deps).catch(
      (caught: unknown) => caught,
    );

    expect((error as JitLifecycleError).detail).toContain('GRANT_REVOKED');
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
  });

  it('blocks all planning when the authority currentness record is unresolvable', async () => {
    const harness = buildHarness();
    installWorld(harness);
    harness.authority.corruptCurrentness('currentness record unreadable');

    await expect(
      runJitLifecycle(jitInput({ retention: 'RETAIN' }), harness.deps),
    ).rejects.toMatchObject({ code: 'POLICY_BLOCKED' });

    expect(harness.ledger.size).toBe(0);
    expect(harness.store.records.size).toBe(0);
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
  });

  it('classifies the refused install journal as FAILED_BEFORE_EFFECT (validation precedes any side effect)', async () => {
    const harness = buildHarness();
    installWorld(harness);
    const inner = harness.deps.privileged;
    const deps = {
      ...harness.deps,
      privileged: {
        execute: async (
          action: Parameters<typeof inner.execute>[0],
          grant: Parameters<typeof inner.execute>[1],
        ) => {
          harness.authority.supersedePolicy('pol-snap-r2');
          return inner.execute(action, grant);
        },
      },
    };
    await runJitLifecycle(jitInput({ retention: 'RETAIN' }), deps).catch(() => undefined);

    const entries = await harness.deps.journals('task-2026-10-10-002-install').replay();
    expect(classifyFromJournal(entries, 'task-2026-10-10-002-install')).toBe(
      'FAILED_BEFORE_EFFECT',
    );
  });
});
