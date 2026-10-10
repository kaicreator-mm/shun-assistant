// Declined-elevation and interrupted-removal scenarios (B-038 negatives):
// UAC_DECLINED leaves the journal at NOT_STARTED with no side effect and no
// automatic retry; a mid-effect interruption classifies
// MAY_HAVE_EXECUTED_UNCERTAIN from the journal and resolves reconcile-first
// against the SAME stable actionId.
import { describe, expect, it } from 'vitest';
import { classifyFromJournal } from '../src/journal.ts';
import { BackendInterruptError } from '../src/local-backend.ts';
import { buildHarness } from '../src/mocks.ts';
import { runJitLifecycle } from '../src/orchestrator.ts';
import {
  CACHE_DIR,
  INSTALL_DIR,
  installWorld,
  jitInput,
  PROVIDER_ID,
  VERSION,
  withDeps,
} from './helpers.ts';

const REMOVE_INPUT = jitInput({ retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' });

function durablePolicy() {
  return {
    policyId: 'pol.jit-removal',
    revision: 'r1',
    jitRemoveAfterVerifiedUse: true,
    forbidUserAssetDeletion: true as const,
  };
}

describe('JIT lifecycle — declined elevation (UAC)', () => {
  it('fails the install with NOT_STARTED recovery and never retries', async () => {
    const harness = buildHarness({
      backendFaults: [
        { kind: 'UAC_DECLINED', when: (action) => action.action.op === 'software.install' },
      ],
    });
    installWorld(harness);

    const error = await runJitLifecycle(jitInput({ retention: 'RETAIN' }), harness.deps).catch(
      (caught: unknown) => caught,
    );

    expect(error).toMatchObject({ code: 'INSTALL_FAILED' });
    expect((error as { recovery?: { recoveryClassification: string } }).recovery).toMatchObject({
      recoveryClassification: 'NOT_STARTED',
    });
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
    // The journal carries the explicit NO_EFFECT marker.
    const entries = await harness.deps.journals('task-2026-10-10-002-install').replay();
    expect(entries.some((entry) => entry.detail?.startsWith('NO_EFFECT:'))).toBe(true);
    expect(classifyFromJournal(entries, 'task-2026-10-10-002-install')).toBe('NOT_STARTED');
  });

  it('fails the removal with the provider retained when elevation is declined at uninstall', async () => {
    const harness = buildHarness({
      durableJitPolicy: durablePolicy(),
      backendFaults: [
        { kind: 'UAC_DECLINED', when: (action) => action.action.op === 'software.uninstall' },
      ],
    });
    installWorld(harness);

    const error = await runJitLifecycle(REMOVE_INPUT, harness.deps).catch(
      (caught: unknown) => caught,
    );

    expect(error).toMatchObject({ code: 'REMOVE_FAILED' });
    expect((error as { recovery?: { recoveryClassification: string } }).recovery).toMatchObject({
      recoveryClassification: 'NOT_STARTED',
    });
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(true);
  });
});

describe('JIT lifecycle — interrupted removal (reconcile-first)', () => {
  it('resolves an uncertain interruption by post-state and retries the SAME actionId', async () => {
    let interrupts = 0;
    const harness = buildHarness({
      durableJitPolicy: durablePolicy(),
      backendFaults: [
        {
          kind: 'INTERRUPT',
          when: (action) => action.action.op === 'software.uninstall' && interrupts++ === 0, // first removal attempt dies mid-effect
        },
      ],
    });
    installWorld(harness);

    const output = await runJitLifecycle(REMOVE_INPUT, harness.deps);

    expect(output.finalState).toBe('REMOVED');
    expect(output.r2Gate).toMatchObject({ approvedBy: 'DURABLE_POLICY' });
    // Provider files really are gone after the reconciled retry.
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
    expect(await harness.fs.exists(CACHE_DIR)).toBe(false);
    // Stable identity: both attempts share one actionId; the journal records
    // two EXEC_START phases under it with a completed receipt afterwards.
    const actionId = `task-2026-10-10-002-uninstall`;
    const entries = await harness.deps.journals(actionId).replay();
    const execStarts = entries.filter((entry) => entry.phase === 'EXEC_START');
    expect(execStarts.length).toBe(2);
    expect(new Set(execStarts.map((entry) => entry.actionId))).toEqual(new Set([actionId]));
    expect(entries.some((entry) => entry.phase === 'RECEIPT_WRITTEN')).toBe(true);
  });

  it('resolves an uncertain interruption without retry when post-state proves removal', async () => {
    let interrupts = 0;
    const harness = buildHarness({
      durableJitPolicy: durablePolicy(),
      backendFaults: [
        {
          kind: 'INTERRUPT',
          when: (action) => action.action.op === 'software.uninstall' && interrupts++ === 0,
        },
      ],
    });
    installWorld(harness);
    // The interrupted worker actually performed the removal, then crashed
    // before journaling EXEC_DONE: on interrupt, the provider is gone.
    const inner = harness.deps.privileged;
    const deps = withDeps(harness, {
      privileged: {
        execute: async (action, grant) => {
          try {
            return await inner.execute(action, grant);
          } catch (error) {
            if (error instanceof BackendInterruptError) {
              harness.acquisition.uninstallByPlan('ExampleSoft.PdfTool');
            }
            throw error;
          }
        },
      },
    });

    const output = await runJitLifecycle(REMOVE_INPUT, deps);

    expect(output.finalState).toBe('REMOVED');
    const actionId = 'task-2026-10-10-002-uninstall';
    const entries = await harness.deps.journals(actionId).replay();
    expect(entries.filter((entry) => entry.phase === 'EXEC_START').length).toBe(1);
    expect(
      harness.traces.some(
        (event) => event.kind === 'R2_RECONCILE' && event.detail?.includes('proves removal'),
      ),
    ).toBe(true);
  });

  it('reports REMOVE_FAILED when the reconciled retry still does not complete', async () => {
    const harness = buildHarness({
      durableJitPolicy: durablePolicy(),
      backendFaults: [
        { kind: 'FAIL_EXEC', when: (action) => action.action.op === 'software.uninstall' },
      ],
    });
    installWorld(harness);

    const error = await runJitLifecycle(REMOVE_INPUT, harness.deps).catch(
      (caught: unknown) => caught,
    );

    expect(error).toMatchObject({ code: 'REMOVE_FAILED' });
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(true);
    void PROVIDER_ID;
    void VERSION;
  });
});
