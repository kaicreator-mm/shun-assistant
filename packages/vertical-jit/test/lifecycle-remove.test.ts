// Loop B removal path: the observable R2 gate, durable-policy and
// explicit-approval dispositions, denial retention and verify-failed refusal.

import type { JitLifecycleOutput, VerifierPort } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { buildHarness, type JitHarness } from '../src/mocks.ts';
import { runJitLifecycle } from '../src/orchestrator.ts';
import {
  CACHE_DIR,
  CONFIG_DIR,
  INSTALL_DIR,
  installWorld,
  jitInput,
  run,
  VERSION,
  withDeps,
} from './helpers.ts';

async function removalRun(harness: JitHarness): Promise<JitLifecycleOutput> {
  return run(harness, jitInput({ retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' })).then(
    (output) => output as JitLifecycleOutput,
  );
}

describe('JIT lifecycle — R2 removal gate', () => {
  it('removes after verified use under a durable JIT policy, with classified residue', async () => {
    const harness = buildHarness({
      durableJitPolicy: {
        policyId: 'pol.jit-removal',
        revision: 'r1',
        jitRemoveAfterVerifiedUse: true,
        forbidUserAssetDeletion: true,
      },
    });
    installWorld(harness);
    // Pre-existing provider configuration on disk — classified, retained.
    const settingsPath = `${CONFIG_DIR}${'\\'}settings.json`;
    harness.fs.putTree([CONFIG_DIR], { [settingsPath]: '{}' });

    const output = await removalRun(harness);

    expect(output.finalState).toBe('REMOVED');
    expect(output.lifecycleState.state).toBe('REMOVED');
    expect(output.r2Gate).toEqual({
      phases: ['PLAN', 'PREVIEW', 'CHECKPOINT', 'APPROVAL', 'EXECUTE', 'VERIFY'],
      approvedBy: 'DURABLE_POLICY',
    });
    // Provider files are gone; configuration is retained.
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(false);
    expect(await harness.fs.exists(CACHE_DIR)).toBe(false);
    expect(await harness.fs.exists(CONFIG_DIR)).toBe(true);
    // Residue report classifies every discovered path; nothing unknown/protected deleted.
    expect(output.residueReport.unknownOrProtectedDeleted).toBe(false);
    const classifications = new Map(
      output.residueReport.candidates.map((candidate) => [candidate.path, candidate]),
    );
    expect(classifications.get(INSTALL_DIR)).toMatchObject({
      classification: 'PROGRAM_OWNED',
      disposition: 'DELETE',
    });
    expect(classifications.get(CACHE_DIR)).toMatchObject({
      classification: 'CACHE',
      disposition: 'DELETE',
    });
    expect(classifications.get(CONFIG_DIR)).toMatchObject({
      classification: 'CONFIGURATION',
      disposition: 'RETAIN',
    });
    // Durable policy authorized removal: the approval surface was not consulted.
    expect(harness.approval.requests).toHaveLength(0);
    // Observable gate trace shows the ordered phases.
    expect(harness.traces.map((event) => event.kind)).toEqual(
      expect.arrayContaining(['R2_PLAN', 'R2_PREVIEW', 'R2_APPROVAL', 'R2_EXECUTE', 'R2_VERIFY']),
    );
  });

  it('obtains explicit user approval bound to the uninstall plan hash when no durable policy exists', async () => {
    const harness = buildHarness();
    installWorld(harness);

    const output = await removalRun(harness);

    expect(output.r2Gate).toMatchObject({ approvedBy: 'USER_APPROVAL' });
    expect(harness.approval.requests).toHaveLength(1);
    const request = harness.approval.requests[0];
    if (!request) throw new Error('approval request missing');
    // The approval references a plan that is actually in the trusted ledger.
    const plan = await harness.ledger.byHash(request.planHash);
    expect(plan?.actions[0]).toMatchObject({ op: 'software.uninstall' });
    expect(request.summary).toContain(VERSION);
    expect(request.summary).toContain('official');
  });

  it('retains the provider when the user declines the removal preview', async () => {
    const harness = buildHarness({ approvalMode: 'deny' });
    installWorld(harness);

    const output = await removalRun(harness);

    expect(output.finalState).toBe('RETAINED');
    expect(output.lifecycleState.state).toBe('INSTALLED');
    expect(output.r2Gate).toBeUndefined();
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(true);
  });

  it('refuses JIT removal when semantic verification failed', async () => {
    const harness = buildHarness({
      durableJitPolicy: {
        policyId: 'pol.jit-removal',
        revision: 'r1',
        jitRemoveAfterVerifiedUse: true,
        forbidUserAssetDeletion: true,
      },
    });
    installWorld(harness);
    const deps = withDeps(harness, {
      verifier: {
        verify: async (input: Parameters<VerifierPort['verify']>[0]) => ({
          taskId: input.taskId,
          verifierId: input.verificationPlan.verifierId,
          verifierRevision: input.verificationPlan.verifierRevision,
          status: 'FAIL',
          checks: [
            { checkId: 'provider-task-observable', status: 'FAIL', detail: 'oracle mismatch' },
          ],
          oracleInputs: { ...input.oracleInputs },
          evidenceRefs: [],
        }),
      } satisfies VerifierPort,
    });

    await expect(
      runJitLifecycle(jitInput({ retention: 'JIT_REMOVE_AFTER_VERIFIED_USE' }), deps),
    ).rejects.toMatchObject({
      code: 'TASK_VERIFY_FAILED',
    });
    expect(await harness.fs.exists(INSTALL_DIR)).toBe(true);
  });
});
