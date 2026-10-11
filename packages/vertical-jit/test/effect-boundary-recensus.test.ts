// Effect-boundary re-census negatives (VJ-P1-01 post-preview race, R3):
// the preview census is a PRE-approval snapshot. A user asset planted AFTER
// R2_PREVIEW — inside the async approval wait, or between preview and effect
// under a pre-existing durable policy — is absent from that snapshot, and a
// whole-root uninstaller would recursively destroy it while the lifecycle
// reported REMOVED. Each negative plants a nested user asset inside the
// deletion scope in exactly that window and demands: the privileged effect
// refuses with ZERO deletions and the lifecycle never claims REMOVED.
import type { ApprovalPort, AuthorizedAction } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { CliTaskBackend } from '../src/adapters/cli-backend.ts';
import { LocalAuthority } from '../src/local-authority.ts';
import {
  buildHarness,
  type JitHarness,
  MemoryFilesystem,
  ScriptedProcessPort,
  windowsFacts,
} from '../src/mocks.ts';
import { runJitLifecycle } from '../src/orchestrator.ts';
import { buildActionPlan, taskAction } from '../src/plans.ts';
import { INSTALL_DIR, installWorld, jitInput, withDeps } from './helpers.ts';

const REMOVE_INPUT = jitInput({ retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' });
const UNINSTALL_ACTION_ID = 'task-2026-10-10-002-uninstall';
const LATE_DROP_DIR = `${INSTALL_DIR}\\late-drop`;
const LATE_USER_FILE = `${LATE_DROP_DIR}\\notes.txt`;
const LATE_USER_CONTENT = 'planted inside the post-preview window';

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

/** Zero deletions: injection survived, provider retained, effect never ran. */
async function assertZeroDeletionRefusal(harness: JitHarness, error: unknown): Promise<void> {
  expect(error).toMatchObject({ code: 'USER_ASSET_AT_RISK' });
  expect((error as { detail?: string }).detail).toContain(LATE_USER_FILE);
  expect(await harness.fs.exists(INSTALL_DIR)).toBe(true);
  expect(await harness.fs.exists(LATE_USER_FILE)).toBe(true);
  expect(await harness.fs.readText(LATE_USER_FILE)).toBe(LATE_USER_CONTENT);
  const entries = await harness.deps.journals(UNINSTALL_ACTION_ID).replay();
  expect(entries.filter((entry) => entry.phase === 'EXEC_START')).toHaveLength(0);
  expect(harness.traces.some((event) => event.kind === 'R2_EXECUTE')).toBe(false);
  await assertNoRemovedClaim(harness);
}

describe('post-preview injection during the approval window (VJ-P1-01)', () => {
  it('refuses the removal with zero deletions when a user asset appears between the approval request and the effect', async () => {
    const harness = buildHarness({ approvalMode: 'approve' });
    installWorld(harness);
    // Interception seam: the harness approval answers synchronously, a real
    // approval surface waits on a human. Planting INSIDE requestApproval is
    // exactly the async window between the preview snapshot/atRisk gate and
    // the privileged effect — content the preview census never saw.
    const inner = harness.deps.approval;
    const windowed: ApprovalPort = {
      requestApproval: async (request) => {
        plantLateUserAsset(harness);
        return inner.requestApproval(request);
      },
    };
    const deps = withDeps(harness, { approval: windowed });

    const error = await runJitLifecycle(REMOVE_INPUT, deps).catch((caught: unknown) => caught);

    await assertZeroDeletionRefusal(harness, error);
  });
});

describe('durable-policy window variant (VJ-P1-01)', () => {
  it('refuses the removal with zero deletions under a durable policy when a user asset appears between preview and effect', async () => {
    const harness = buildHarness({ durableJitPolicy: DURABLE_POLICY });
    installWorld(harness);
    // The durable-policy path consults no approval surface: the privileged
    // effect follows the preview directly. Plant inside that policy window —
    // after the R2_APPROVAL policy evaluation, before the effect boundary.
    const baseTrace = harness.deps.trace;
    const deps = withDeps(harness, {
      trace: (event) => {
        baseTrace?.(event);
        if (event.kind === 'R2_APPROVAL') plantLateUserAsset(harness);
      },
    });

    const error = await runJitLifecycle(REMOVE_INPUT, deps).catch((caught: unknown) => caught);

    await assertZeroDeletionRefusal(harness, error);
  });
});

describe('FAIL_EXEC journal completeness (RECEIPT_WRITTEN attemptId)', () => {
  it('carries the attempt id on every RECEIPT_WRITTEN entry of a failed execution', async () => {
    const harness = buildHarness({
      durableJitPolicy: DURABLE_POLICY,
      backendFaults: [
        { kind: 'FAIL_EXEC', when: (action) => action.action.op === 'software.uninstall' },
      ],
    });
    installWorld(harness);

    await runJitLifecycle(REMOVE_INPUT, harness.deps).catch(() => undefined);

    const entries = await harness.deps.journals(UNINSTALL_ACTION_ID).replay();
    const receiptWritten = entries.filter((entry) => entry.phase === 'RECEIPT_WRITTEN');
    expect(receiptWritten.length).toBeGreaterThan(0);
    // One executed attempt ⇒ one attempt identity across ALL of its entries;
    // a RECEIPT_WRITTEN without it breaks the per-attempt invariant the
    // latest-attempt classification relies on (VJ-P1-04).
    for (const entry of receiptWritten) {
      expect(entry.attemptId).toEqual(expect.any(String));
    }
    expect(new Set(entries.map((entry) => entry.attemptId))).toHaveLength(1);
  });
});

describe('authorization expiry uses real time semantics (fail-closed parsing)', () => {
  const NOW = '2026-10-10T08:00:00.000Z';

  async function expiryWorld(expiresAt: string): Promise<{
    receipt: { terminal: string };
    process: ScriptedProcessPort;
  }> {
    const authority = new LocalAuthority({ now: () => NOW });
    const action = taskAction({
      actionId: 't1-task',
      bindingId: 'b1',
      executable: 'C:\\tools\\pdftool.exe',
      argv: ['--version'],
      outputDir: 'C:\\work\\out',
      timeoutMs: 60_000,
    });
    const plan = buildActionPlan({
      taskId: 't1',
      capabilityId: 'pdf.convert',
      bindingId: 'b1',
      rankingPolicyRevision: 'rank-v1',
      policySnapshotRevision: 'pol-snap-r1',
      action,
      verificationPlan: { verifierId: 'v', verifierRevision: 'r1', checks: [{ checkId: 'c1' }] },
      recoveryPlan: {
        classificationStrategy: 'JOURNAL_AND_POST_STATE',
        reconcileBeforeRetry: true,
        retryAllowedWhen: 'DECLARED_IDEMPOTENT',
      },
    });
    await authority.ledger.register(plan);
    const presented: AuthorizedAction = {
      taskId: 't1',
      actionId: 't1-task',
      planHash: plan.planHash,
      policySnapshotRevision: 'pol-snap-r1',
      authorizationKind: 'AUTOMATIC',
      authorizationRef: 'grant-0001',
      expiresAt,
      action,
    };
    const process = new ScriptedProcessPort([]);
    const backend = new CliTaskBackend({
      process,
      fs: new MemoryFilesystem(),
      facts: windowsFacts(),
      clock: () => NOW,
      taskOutputDir: 'C:\\work\\out',
      ledger: authority.ledger,
    });
    return { receipt: await backend.execute(presented), process };
  }

  it('refuses an expiry that already passed in real time even when its spelling sorts after the clock', async () => {
    // 09:00+02:00 == 07:00Z — one hour PAST the 08:00Z clock — yet the raw
    // string '2026-10-10T09:…' sorts AFTER '2026-10-10T08:…' lexicographically.
    const { receipt, process } = await expiryWorld('2026-10-10T09:00:00.000+02:00');

    expect(receipt.terminal).toBe('REFUSED');
    expect(process.calls).toHaveLength(0);
  });

  it('refuses an unparseable expiry instead of falling back to string order', async () => {
    const { receipt, process } = await expiryWorld('whenever the operator gets around to it');

    expect(receipt.terminal).toBe('REFUSED');
    expect(process.calls).toHaveLength(0);
  });

  it('honors a genuinely in-window expiry expressed in another timezone (positive control)', async () => {
    // 11:00+02:00 == 09:00Z — one hour AHEAD of the 08:00Z clock.
    const { receipt, process } = await expiryWorld('2026-10-10T11:00:00.000+02:00');

    expect(receipt.terminal).toBe('SUCCEEDED');
    expect(process.calls).toHaveLength(1);
  });
});
