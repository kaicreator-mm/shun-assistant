// Independent regression for the external WinGet uninstall trust boundary.
// An unbounded third-party remover can delete new user files after Shun's
// pre-spawn census. No point-in-time manifest check proves exclusivity for
// the full lifetime of the external process (VJ-P1-01 / R5).
import { describe, expect, it } from 'vitest';
import { WingetPrivilegedBackend } from '../src/adapters/winget.ts';
import { MemoryJournal } from '../src/journal.ts';
import { LocalAuthority } from '../src/local-authority.ts';
import { MemoryFilesystem, ScriptedProcessPort } from '../src/mocks.ts';
import { buildActionPlan, uninstallAction } from '../src/plans.ts';

async function attemptExternalUninstall(options: { plantLateUserFile: boolean }) {
  const root = 'C:\\Tools\\ExampleSoft';
  const owned = `${root}\\app.exe`;
  const userFile = `${root}\\late-user-notes.txt`;
  const fs = new MemoryFilesystem();
  fs.putTree([root], { [owned]: 'original vendor bytes' });
  let invokedExternalUninstaller = false;
  const process = new ScriptedProcessPort([
    async () => {
      invokedExternalUninstaller = true;
      // The simulated outside actor writes AFTER the last Shun census but
      // BEFORE this unbounded process recursively deletes the install tree.
      if (options.plantLateUserFile) {
        fs.putTree([root], { [userFile]: 'customer document must survive' });
      }
      fs.removeTree(root);
      return { exitCode: 0, stdout: 'Uninstalled', stderr: '', timedOut: false };
    },
  ]);
  const authority = new LocalAuthority({ now: () => '2026-10-10T08:00:00.000Z' });
  const journals = new Map<string, MemoryJournal>();
  const journalFor = (id: string) => {
    let journal = journals.get(id);
    if (!journal) {
      journal = new MemoryJournal();
      journals.set(id, journal);
    }
    return journal;
  };
  const action = uninstallAction({
    actionId: 'external-winget-uninstall',
    bindingId: 'binding-example',
    packageId: 'ExampleSoft.PdfTool',
    version: '2.4.1',
    deleteRoots: [root],
    deletionManifest: [owned],
    elevated: true,
    timeoutMs: 60_000,
  });
  const plan = buildActionPlan({
    taskId: 'external-removal-case',
    capabilityId: 'pdf.convert',
    bindingId: 'binding-example',
    rankingPolicyRevision: 'rank-v1',
    policySnapshotRevision: 'pol-snap-r1',
    action,
    verificationPlan: {
      verifierId: 'v',
      verifierRevision: 'r1',
      checks: [{ checkId: 'c1' }],
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
  });
  await authority.ledger.register(plan);
  const grant = await authority.issue({
    taskId: plan.taskId,
    planHash: plan.planHash,
    policySnapshotRevision: plan.policySnapshotRevision,
    actionScope: {
      actionIds: [action.actionId],
      privilegeLevel: 'ELEVATED',
      filesystem: { read: [root], write: [root] },
    },
    authorizationKind: 'AUTOMATIC',
  });
  const backend = new WingetPrivilegedBackend({
    authority,
    clock: () => '2026-10-10T08:00:01.000Z',
    journals: journalFor,
    process,
    fs,
    machineScope: true,
  });
  const receipt = await backend.execute({
    taskId: plan.taskId,
    actionId: action.actionId,
    planHash: plan.planHash,
    policySnapshotRevision: plan.policySnapshotRevision,
    authorizationKind: 'AUTOMATIC',
    authorizationRef: grant.grantId,
    expiresAt: grant.expiresAt,
    action,
  }, grant);
  return { fs, process, receipt, owned, userFile, invokedExternalUninstaller,
    entries: await journalFor(action.actionId).replay() };
}

describe('VJ R5: external WinGet removal is not authorized by a pre-spawn snapshot', () => {
  it('refuses unbounded external uninstall even if the manifest is currently clean', async () => {
    const result = await attemptExternalUninstall({ plantLateUserFile: false });
    expect(result.process.calls).toHaveLength(0);
    expect(result.invokedExternalUninstaller).toBe(false);
    expect(result.receipt.terminal).toBe('REFUSED');
    expect(result.receipt.sideEffectEvidence.recoveryClassification).toBe('NOT_STARTED');
    expect(result.receipt.sideEffectEvidence.postStateVerified).toBe(false);
    expect(await result.fs.readText(result.owned)).toBe('original vendor bytes');
    expect(result.entries.some((entry) => entry.detail?.includes('NO_EFFECT:'))).toBe(true);
    expect(result.entries.some((entry) => entry.phase === 'EXEC_DONE')).toBe(false);
  });

  it('never gives the external process a chance to delete a late user-owned file', async () => {
    const result = await attemptExternalUninstall({ plantLateUserFile: true });
    expect(result.invokedExternalUninstaller).toBe(false);
    expect(result.process.calls).toHaveLength(0);
    expect(result.receipt.terminal).toBe('REFUSED');
    expect(await result.fs.readText(result.owned)).toBe('original vendor bytes');
    // The production guard must stop the external process, not race a
    // post-uninstall check against a file already deleted by that process.
    expect(result.entries.some((entry) => entry.phase === 'EXEC_DONE')).toBe(false);
  });
});
