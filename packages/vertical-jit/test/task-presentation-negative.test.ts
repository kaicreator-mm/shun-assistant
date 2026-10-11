// VJ-P1-03 negative controls: every executable step must cross a trusted
// boundary validation with its grant presentation — never the caller's
// say-so. A forged/stale AuthorizedAction handed DIRECTLY to the CLI task
// environment must be refused BEFORE any process spawn, and the
// orchestrator must present the task grant to the trusted gate before the
// environment is ever invoked.
import type { AuthorizedAction } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { CliTaskBackend } from '../src/adapters/cli-backend.ts';
import { isJitLifecycleError } from '../src/failures.ts';
import { LocalAuthority } from '../src/local-authority.ts';
import { buildHarness, MemoryFilesystem, ScriptedProcessPort, windowsFacts } from '../src/mocks.ts';
import { runJitLifecycle } from '../src/orchestrator.ts';
import { buildActionPlan, taskAction } from '../src/plans.ts';
import { INSTALL_DIR, installWorld, jitInput } from './helpers.ts';

const NOW = '2026-10-10T08:00:00.000Z';
const SOON = '2026-10-10T08:00:01.000Z';
const EXPIRED = '2026-10-10T07:59:59.000Z';

async function cliWorld() {
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
  const authorized = (overrides: Partial<AuthorizedAction> = {}): AuthorizedAction => ({
    taskId: 't1',
    actionId: 't1-task',
    planHash: plan.planHash,
    policySnapshotRevision: 'pol-snap-r1',
    authorizationKind: 'AUTOMATIC',
    authorizationRef: 'grant-0001',
    expiresAt: SOON,
    action,
    ...overrides,
  });
  const process = new ScriptedProcessPort([]);
  const backend = new CliTaskBackend({
    process,
    fs: new MemoryFilesystem(),
    facts: windowsFacts(),
    clock: () => NOW,
    taskOutputDir: 'C:\\work\\out',
    ledger: authority.ledger,
  });
  return { backend, process, authorized, plan };
}

describe('CLI task backend — trusted boundary validation (VJ-P1-03)', () => {
  it('refuses a forged action whose plan never entered the trusted ledger — zero process spawns', async () => {
    const { backend, process, authorized } = await cliWorld();
    const forged = authorized({ planHash: `${'ab'.repeat(32)}` });

    const receipt = await backend.execute(forged);

    expect(receipt.terminal).toBe('REFUSED');
    expect(process.calls).toHaveLength(0);
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
  });

  it('refuses a tampered action body that diverges from the ledger plan — zero process spawns', async () => {
    const { backend, process, authorized } = await cliWorld();
    const genuine = authorized();
    const tampered = authorized({
      action: {
        ...genuine.action,
        parameters: {
          ...genuine.action.parameters,
          argv: ['--steal', 'C:\\Users\\dev\\Documents'],
        },
      },
    });

    const receipt = await backend.execute(tampered);

    expect(receipt.terminal).toBe('REFUSED');
    expect(process.calls).toHaveLength(0);
  });

  it('refuses an expired authorization window — zero process spawns', async () => {
    const { backend, process, authorized } = await cliWorld();
    const stale = authorized({ expiresAt: EXPIRED });

    const receipt = await backend.execute(stale);

    expect(receipt.terminal).toBe('REFUSED');
    expect(process.calls).toHaveLength(0);
  });

  it('executes a ledger-bound, in-window action (positive control)', async () => {
    const { backend, process, authorized } = await cliWorld();

    const receipt = await backend.execute(authorized());

    expect(receipt.terminal).toBe('SUCCEEDED');
    expect(process.calls).toHaveLength(1);
  });

  it('fail-closed wiring seam: refuses to spawn ANY argv when no trusted ledger is wired', async () => {
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
    const process = new ScriptedProcessPort([]);
    const backend = new CliTaskBackend({
      process,
      fs: new MemoryFilesystem(),
      facts: windowsFacts(),
      clock: () => NOW,
      taskOutputDir: 'C:\\work\\out',
      // No ledger wired: an unwired trusted boundary is a wiring fault and
      // must refuse before any spawn — never a silent fail-open.
    });
    const presented: AuthorizedAction = {
      taskId: 't1',
      actionId: 't1-task',
      planHash: plan.planHash,
      policySnapshotRevision: 'pol-snap-r1',
      authorizationKind: 'AUTOMATIC',
      authorizationRef: 'grant-0001',
      expiresAt: SOON,
      action,
    };

    const receipt = await backend.execute(presented);

    expect(receipt.terminal).toBe('REFUSED');
    expect(process.calls).toHaveLength(0);
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
  });
});

describe('orchestrator — task grant presentation (VJ-P1-03)', () => {
  it('fails the task before any environment execution when the trusted gate refuses the presentation', async () => {
    const harness = buildHarness();
    installWorld(harness);
    let environmentCalls = 0;
    const innerEnvironment = harness.deps.environment;
    const deps = {
      ...harness.deps,
      taskPresentationGate: {
        validate: () => ({
          ok: false as const,
          code: 'GRANT_NOT_AUTHENTIC',
          detail: 'simulated hostile gate',
        }),
      },
      environment: {
        observe: () => innerEnvironment.observe(),
        canPrepare: (requirements: Parameters<typeof innerEnvironment.canPrepare>[0]) =>
          innerEnvironment.canPrepare(requirements),
        prepare: (binding: Parameters<typeof innerEnvironment.prepare>[0]) =>
          innerEnvironment.prepare(binding),
        execute: (action: Parameters<typeof innerEnvironment.execute>[0]) => {
          environmentCalls += 1;
          return innerEnvironment.execute(action);
        },
        cancel: (actionId: string) => innerEnvironment.cancel(actionId),
        cleanup: (prepared: Parameters<typeof innerEnvironment.cleanup>[0]) =>
          innerEnvironment.cleanup(prepared),
      },
    };

    const error = await runJitLifecycle(jitInput({ retention: 'RETAIN' }), deps).catch(
      (caught: unknown) => caught,
    );

    expect(isJitLifecycleError(error)).toBe(true);
    expect((error as { code: string }).code).toBe('TASK_FAILED');
    expect((error as { detail: string }).detail).toContain('GRANT_NOT_AUTHENTIC');
    expect(environmentCalls).toBe(0);
    // The install already happened; the task step was refused at the gate.
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(true);
  });

  it('refuses the executable lifecycle entry when the task presentation gate is not wired — never a silent fail-open', async () => {
    const harness = buildHarness();
    installWorld(harness);
    let environmentCalls = 0;
    const innerEnvironment = harness.deps.environment;
    const deps = {
      ...harness.deps,
      taskPresentationGate: undefined,
      environment: {
        observe: () => innerEnvironment.observe(),
        canPrepare: (requirements: Parameters<typeof innerEnvironment.canPrepare>[0]) =>
          innerEnvironment.canPrepare(requirements),
        prepare: (binding: Parameters<typeof innerEnvironment.prepare>[0]) =>
          innerEnvironment.prepare(binding),
        execute: (action: Parameters<typeof innerEnvironment.execute>[0]) => {
          environmentCalls += 1;
          return innerEnvironment.execute(action);
        },
        cancel: (actionId: string) => innerEnvironment.cancel(actionId),
        cleanup: (prepared: Parameters<typeof innerEnvironment.cleanup>[0]) =>
          innerEnvironment.cleanup(prepared),
      },
    };

    const error = await runJitLifecycle(jitInput({ retention: 'RETAIN' }), deps).catch(
      (caught: unknown) => caught,
    );

    expect(isJitLifecycleError(error)).toBe(true);
    expect((error as { code: string }).code).toBe('POLICY_BLOCKED');
    // Nothing executed at all: neither install nor task side effects.
    expect(environmentCalls).toBe(0);
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
  });

  it('presents the task grant to the trusted gate on the happy path (positive control)', async () => {
    const harness = buildHarness();
    installWorld(harness);
    const output = await runJitLifecycle(jitInput({ retention: 'RETAIN' }), harness.deps);
    expect((output as { finalState: string }).finalState).toBe('RETAINED');
  });
});
