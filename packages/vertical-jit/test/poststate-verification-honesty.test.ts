// VJ-P2-06 negative controls: an effect completing (process exit 0, worker
// self-report) is NOT a verified post-state. Backends must distinguish
// effect completion from independent expected-state verification: until an
// independent verification exists, no receipt may claim
// COMPLETED_VERIFIED / postStateVerified=true.
import type { AuthorizedAction } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { CliTaskBackend } from '../src/adapters/cli-backend.ts';
import { LocalAuthority } from '../src/local-authority.ts';
import { LocalPrivilegedBackend, type PrivilegedFault } from '../src/local-backend.ts';
import { MemoryFilesystem, ScriptedProcessPort, windowsFacts } from '../src/mocks.ts';
import { buildActionPlan, installAction } from '../src/plans.ts';

const NOW = '2026-10-10T08:00:00.000Z';

function cliBackend(scripted: ScriptedProcessPort) {
  return new CliTaskBackend({
    process: scripted,
    fs: new MemoryFilesystem(),
    facts: windowsFacts(),
    clock: () => NOW,
    taskOutputDir: 'C:\\work\\out',
  });
}

function cliAction(): AuthorizedAction {
  return {
    taskId: 't1',
    actionId: 't1-task',
    planHash: `${'cd'.repeat(32)}`,
    policySnapshotRevision: 'pol-snap-r1',
    authorizationKind: 'AUTOMATIC',
    authorizationRef: 'grant-1',
    expiresAt: '2026-10-10T08:00:01.000Z',
    action: {
      actionId: 't1-task',
      bindingRef: 'b1',
      op: 'process.argv',
      parameters: { executable: 'C:\\tools\\tool.exe', argv: [] },
      sideEffectClass: 'R1',
      requiredPrivilege: 'USER',
      filesystemScope: { read: ['C:\\tools\\tool.exe'], write: ['C:\\work\\out'] },
      timeoutMs: 60_000,
      cancellation: { supported: true, mode: 'COOPERATIVE' },
      expectedState: { outputWritten: true },
    },
  };
}

async function privilegedWorld(faults?: readonly PrivilegedFault[]) {
  const authority = new LocalAuthority({ now: () => NOW });
  const action = installAction({
    actionId: 'a1-install',
    bindingId: 'b1',
    packageId: 'ExampleSoft.PdfTool',
    version: '2.4.1',
    installRoots: ['C:\\Program Files\\ExampleSoftware'],
    networkDomains: ['cdn.winget.microsoft.com'],
    elevated: false,
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
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
  });
  await authority.ledger.register(plan);
  const grant = await authority.issue({
    taskId: 't1',
    planHash: plan.planHash,
    policySnapshotRevision: 'pol-snap-r1',
    actionScope: {
      actionIds: [action.actionId],
      privilegeLevel: 'USER',
      filesystem: { read: [], write: ['C:\\Program Files\\ExampleSoftware'] },
      network: { allowed: true, domains: ['cdn.winget.microsoft.com'] },
    },
    authorizationKind: 'AUTOMATIC',
  });
  const backend = new LocalPrivilegedBackend({
    authority,
    clock: () => NOW,
    journals: () => ({ append: async () => undefined, replay: async () => [] }),
    environmentId: 'local-windows-1',
    providerId: () => 'tool.pdftool',
    providerVersion: () => '2.4.1',
    perform: async () => ({ ok: true, note: 'simulated' }),
    ...(faults ? { faults } : {}),
  });
  const authorized: AuthorizedAction = {
    taskId: 't1',
    actionId: action.actionId,
    planHash: plan.planHash,
    policySnapshotRevision: 'pol-snap-r1',
    authorizationKind: 'AUTOMATIC',
    authorizationRef: grant.grantId,
    expiresAt: grant.expiresAt,
    action,
  };
  return { backend, authorized, grant };
}

describe('post-state verification honesty (VJ-P2-06)', () => {
  it('CLI task exit-0 reports completion WITHOUT claiming verified post-state', async () => {
    const scripted = new ScriptedProcessPort([
      () => ({ exitCode: 0, stdout: 'ok', stderr: '', timedOut: false }),
    ]);
    const receipt = await cliBackend(scripted).execute(cliAction());

    expect(receipt.terminal).toBe('SUCCEEDED');
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(receipt.sideEffectEvidence.postStateVerified).toBe(false);
  });

  it('CLI task executable-absent failure does not claim a verified state either', async () => {
    const action = cliAction();
    action.action.parameters = { executable: '', argv: [] };
    const receipt = await cliBackend(new ScriptedProcessPort([])).execute(action);

    expect(receipt.terminal).toBe('FAILED');
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
    expect(receipt.sideEffectEvidence.postStateVerified).toBe(false);
  });

  it('privileged success self-report is not certified COMPLETED_VERIFIED', async () => {
    const { backend, authorized, grant } = await privilegedWorld();
    const receipt = await backend.execute(authorized, grant);

    expect(receipt.terminal).toBe('SUCCEEDED');
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(receipt.sideEffectEvidence.postStateVerified).toBe(false);
  });

  it('privileged failed-outcome self-report is not certified COMPLETED_VERIFIED', async () => {
    const { backend, authorized, grant } = await privilegedWorld([
      { kind: 'FAIL_EXEC', when: (a) => a.action.op === 'software.install' },
    ]);
    const receipt = await backend.execute(authorized, grant);

    expect(receipt.terminal).toBe('FAILED');
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(receipt.sideEffectEvidence.postStateVerified).toBe(false);
  });
});
