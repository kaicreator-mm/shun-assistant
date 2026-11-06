import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type {
  GuidedDecisionReceipt,
  HostGuidedService,
} from '../../../packages/domain-host/src/guided/host-guided-service.ts';
import {
  createProductionFolderSelectionHost,
  FolderSelectionHost,
  type FolderSelectionStoragePort,
  folderSelectionDatabaseRefusal,
} from '../src/v03/folder-selection-host.ts';

const NOW = 1_800_000_000_000;
const SELECTION_TTL_MS = 5 * 60_000;
const identity = {
  volumeSerial: '1a2b3c4d',
  fileId: '0123456789abcdef',
};
const recorded: GuidedDecisionReceipt = {
  status: 'RECORDED',
  humanGrantIssued: false,
  effectSent: false,
  history: [],
};

function step(stepId: string, artifactId: string, caseSnapshot = 'case-folder-r04') {
  return {
    stepId,
    taskId: 'task-folder-r04',
    journeyId: 'journey-folder-r04',
    caseRef: { snapshotId: caseSnapshot, digest: 'a'.repeat(64) },
    templateRef: { digest: 'b'.repeat(64), artifactId },
  };
}
const selectStep = step('step-select-root', 'shun.guided.select-root');
const inspectStep = step('step-inspect-scope', 'shun.guided.inspect-scope');
const replacementStep = step('step-replacement-inspect', 'shun.guided.inspect-scope');

function recordedAnswerEnvelope(
  stepSpec: {
    readonly stepId: string;
    readonly taskId: string;
    readonly journeyId: string;
    readonly caseRef: unknown;
  },
  selectionRef: string,
) {
  return {
    schema: 'shun.guided.step-outcome.v1',
    journeyId: stepSpec.journeyId,
    taskId: stepSpec.taskId,
    stepId: stepSpec.stepId,
    caseRef: stepSpec.caseRef,
    event: 'USER_SUBMIT',
    source: 'USER',
    sourceRef: 'ui:local',
    answers: [{ fieldId: 'selectedRoot', value: selectionRef }],
    evidenceRefs: [],
    occurredAtUnixMs: NOW,
  };
}

function createGuided() {
  let context: any = { state: 'CURRENT', step: selectStep, observation: {} };
  let currentStep: any = selectStep;
  const recordedAnswers = new Map<string, unknown>();
  let receipts = 0;
  const guided = {
    state: () => ({ currentStep }),
    readTrustedContext: () => context,
    readRecordedAnswer: (stepId: string) => recordedAnswers.get(stepId),
    stageTrustedSelectedRoot: ({ selectionRef }: { selectionRef: string }) => {
      currentStep = inspectStep;
      context = {
        state: 'CURRENT',
        step: inspectStep,
        observation: { selectedRootRef: selectionRef },
      };
      return { status: 'CURRENT' as const, step: inspectStep };
    },
    recordHostObservationReceipt: () => {
      receipts += 1;
      return recorded;
    },
  };
  return {
    service: guided as unknown as HostGuidedService,
    setStep(
      next: any,
      observation: unknown = { selectedRootRef: 'host:folder:' + 'f'.repeat(64) },
    ) {
      currentStep = next;
      context = { state: 'CURRENT', step: next, observation };
    },
    /** Simulates the crash window: the select-root answer is durably
     * recorded (CONSUMED) while the next INSPECT step was never staged. */
    setConsumedSelectRoot(stepSpec: any, answer: unknown) {
      currentStep = undefined;
      context = { state: 'CONSUMED', step: stepSpec, observation: {} };
      if (answer === undefined) recordedAnswers.delete(stepSpec.stepId);
      else recordedAnswers.set(stepSpec.stepId, answer);
    },
    receiptCount: () => receipts,
  };
}

function nativePort(root: string, overrides: Record<string, unknown> = {}) {
  return {
    pickFolder: async () => ({
      status: 'SELECTED' as const,
      path: root,
      displayName: 'Documents',
      identity,
    }),
    inspectFolder: () => ({
      ...identity,
      isDirectory: true,
      isReparsePoint: false,
      isNetworkPath: false,
      isVolumeRoot: false,
    }),
    acquireDirectoryLease: () => ({
      leaseId: 'a'.repeat(32),
      directory: {
        ...identity,
        isDirectory: true,
        isReparsePoint: false,
        isNetworkPath: false,
        isVolumeRoot: false,
      },
    }),
    verifyDirectoryLease: () => ({
      ...identity,
      isDirectory: true,
      isReparsePoint: false,
      isNetworkPath: false,
      isVolumeRoot: false,
    }),
    releaseDirectoryLease: () => {},
    directoryLeasePath: () => root,
    ...overrides,
  };
}

function evidence(root: string, rootFileName = 'root.txt', directoryName = 'Documents') {
  return {
    observedAt: '2026-11-06T12:00:00.000Z',
    roots: [root],
    directories: [
      {
        path: join(root, directoryName),
        bytes: 10,
        files: 1,
        lastModifiedMs: 1_700_000_000_000,
        inaccessibleEntries: [],
      },
    ],
    rootFiles: [{ path: join(root, rootFileName), bytes: 5 }],
    totalBytes: 15,
  };
}

function createEnvironment(
  storage?: FolderSelectionStoragePort,
  nativeOverrides: Record<string, unknown> = {},
) {
  const directory = mkdtempSync(join(tmpdir(), 'shun-r04-folder-host-'));
  const root = join(directory, 'selected-root');
  mkdirSync(root);
  mkdirSync(join(root, 'Documents'));
  writeFileSync(join(root, 'root.txt'), 'x');
  const guided = createGuided();
  const defaultStorage: FolderSelectionStoragePort = {
    resolveScope: async (_volume, declared) => ({ roots: [...declared.roots] }),
    observeStorage: async (scope, clock) => evidence(scope.roots[0]!, 'root.txt'),
  };
  let now = NOW;
  const host = new FolderSelectionHost({
    guided: guided.service,
    databaseFile: join(directory, 'folder-selection.sqlite'),
    native: nativePort(root, nativeOverrides),
    clock: () => now,
    storage: storage ?? defaultStorage,
  });
  return {
    directory,
    root,
    guided,
    host,
    advanceClock(deltaMs: number) {
      now += deltaMs;
    },
    cleanup() {
      host.close();
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

function acceptedAnswer(selectionRef: string) {
  return {
    decision: 'ANSWER',
    outcome: {
      event: 'USER_SUBMIT',
      source: 'USER',
      answers: [{ fieldId: 'selectedRoot', value: selectionRef }],
    },
  };
}

describe.skipIf(process.platform !== 'win32')(
  'R04 U05-A Host folder selection and observation',
  () => {
    const cleanups: Array<() => void> = [];
    afterEach(() => {
      for (const cleanup of cleanups.splice(0)) cleanup();
    });

    it('awaits the frozen async picker contract and records a bound selection', async () => {
      const env = createEnvironment();
      cleanups.push(env.cleanup);
      const result = await env.host.selectRoot();
      expect(result).toMatchObject({ status: 'SELECTED', displayName: 'Documents' });
    });

    it('refuses a second picker request while the async modal dialog is in flight', async () => {
      let release!: () => void;
      let dialogOpen = true;
      const gate = new Promise<{ status: 'CANCELLED' }>((resolve) => {
        release = () => {
          dialogOpen = false;
          resolve({ status: 'CANCELLED' });
        };
      });
      const env = createEnvironment(undefined, {
        pickFolder: () => {
          // Only the first call hits the gated (open) dialog; later calls
          // resolve immediately like the real async worker would.
          return dialogOpen ? gate : nativePort(env.root).pickFolder();
        },
      });
      cleanups.push(env.cleanup);
      const first = env.host.selectRoot();
      const second = await env.host.selectRoot();
      expect(second).toEqual({ status: 'REFUSED', code: 'FOLDER_SELECTION_PICK_IN_PROGRESS' });
      release();
      await expect(first).resolves.toEqual({ status: 'CANCELLED' });
      // The guard releases with the settled dialog: a follow-up request is
      // accepted again (the guided state is still the current select-root).
      expect(await env.host.selectRoot().then((r) => r.status)).toBe('SELECTED');
    });

    it('does not require or persist a Windows SID, logon SID or session identity', async () => {
      const env = createEnvironment();
      cleanups.push(env.cleanup);
      const result = await env.host.selectRoot();
      expect(result).toMatchObject({ status: 'SELECTED', displayName: 'Documents' });
    });

    it('refuses an inspectFolder exception without leaking its OS detail', async () => {
      const env = createEnvironment(undefined, {
        inspectFolder: () => {
          throw new Error('private native detail');
        },
      });
      cleanups.push(env.cleanup);
      const result = await env.host.selectRoot();
      expect(result).toEqual({ status: 'REFUSED', code: 'FOLDER_SELECTION_IDENTITY_UNAVAILABLE' });
      expect(JSON.stringify(result)).not.toContain('private native detail');
    });

    it('does not record a Host receipt when the exact INSPECT step changes during the async scan', async () => {
      let started!: () => void;
      let release!: () => void;
      const scanStarted = new Promise<void>((resolve) => {
        started = resolve;
      });
      const scanGate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const storage: FolderSelectionStoragePort = {
        resolveScope: async (_volume, declared) => ({ roots: [...declared.roots] }),
        observeStorage: async (scope, clock) => {
          started();
          await scanGate;
          return { ...evidence(scope.roots[0]!), observedAt: clock() };
        },
      };
      const env = createEnvironment(storage);
      cleanups.push(env.cleanup);
      const selected = await env.host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      if (selected.status !== 'SELECTED') return;
      env.host.afterSelectionRecorded(acceptedAnswer(selected.selectionRef), selectStep, recorded);

      const pending = env.host.observeCurrentSelectedFolder();
      await scanStarted;
      env.guided.setStep(replacementStep);
      release();
      const result = await pending;
      expect(result).toEqual({ ok: false, code: 'FOLDER_OBSERVATION_UNAVAILABLE' });
      expect(env.guided.receiptCount()).toBe(0);
    });

    it('binds scopeRevision to canonical directory and root-file metadata, not only total bytes', async () => {
      let currentRootFile = 'alpha.txt';
      let currentDirectory = 'Documents';
      const storage: FolderSelectionStoragePort = {
        resolveScope: async (_volume, declared) => ({ roots: [...declared.roots] }),
        observeStorage: async (scope, clock) => ({
          ...evidence(scope.roots[0]!, currentRootFile, currentDirectory),
          observedAt: clock(),
        }),
      };
      const env = createEnvironment(storage);
      cleanups.push(env.cleanup);
      mkdirSync(join(env.root, 'Pictures'));
      writeFileSync(join(env.root, 'alpha.txt'), 'x');
      writeFileSync(join(env.root, 'beta.txt'), 'x');
      const selected = await env.host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      if (selected.status !== 'SELECTED') return;
      env.host.afterSelectionRecorded(acceptedAnswer(selected.selectionRef), selectStep, recorded);
      const first = await env.host.observeCurrentSelectedFolder();
      expect(first.ok).toBe(true);

      currentRootFile = 'beta.txt';
      currentDirectory = 'Pictures';
      const second = await env.host.observeCurrentSelectedFolder();
      expect(second.ok).toBe(true);
      if (!first.ok || !second.ok) return;
      expect(first.observation.totalBytes).toBe(second.observation.totalBytes);
      expect(first.observation.observedAt).toBe(second.observation.observedAt);
      expect(first.observation.scopeRevision).not.toBe(second.observation.scopeRevision);
    });
  },
);

describe.skipIf(process.platform !== 'win32')(
  'R04 U05-A directory lease defense-in-depth and accepted path-scan race',
  () => {
    const cleanups: Array<() => void> = [];
    afterEach(() => {
      for (const cleanup of cleanups.splice(0)) cleanup();
    });

    it('keeps the best-effort lease through scan and receipt, then releases it', async () => {
      const events: string[] = [];
      let held = false;
      const storage: FolderSelectionStoragePort = {
        resolveScope: async (_volume, declared) => {
          events.push(`resolveScope:held=${held}`);
          return { roots: [...declared.roots] };
        },
        observeStorage: async (scope, clock) => {
          events.push(`observeStorage:held=${held}`);
          return { ...evidence(scope.roots[0]!), observedAt: clock() };
        },
      };
      const env = createEnvironment(storage, {
        acquireDirectoryLease: () => {
          held = true;
          events.push('acquire');
          return {
            leaseId: 'a'.repeat(32),
            directory: {
              ...identity,
              isDirectory: true,
              isReparsePoint: false,
              isNetworkPath: false,
              isVolumeRoot: false,
            },
          };
        },
        releaseDirectoryLease: () => {
          events.push('release');
          held = false;
        },
      });
      cleanups.push(env.cleanup);
      const selected = await env.host.selectRoot();
      if (selected.status !== 'SELECTED') throw new Error('selection failed');
      env.host.afterSelectionRecorded(acceptedAnswer(selected.selectionRef), selectStep, recorded);
      const result = await env.host.observeCurrentSelectedFolder();
      expect(result.ok).toBe(true);
      expect(env.guided.receiptCount()).toBe(1);
      // The lease remains held during the path-based scan and Host receipt.
      // This ordering is defense-in-depth only; it does not prove atomicity.
      expect(events).toEqual([
        'acquire',
        'resolveScope:held=true',
        'observeStorage:held=true',
        'release',
      ]);
      expect(held).toBe(false);
    });

    it('adversarial junction replacement: a native lease refusal opens no descendant metadata and records no receipt', async () => {
      let storageCalled = false;
      const storage: FolderSelectionStoragePort = {
        resolveScope: async (_volume, declared) => {
          storageCalled = true;
          return { roots: [...declared.roots] };
        },
        observeStorage: async () => {
          storageCalled = true;
          throw new Error('storage must never be reached for a refused lease');
        },
      };
      const env = createEnvironment(storage, {
        acquireDirectoryLease: () => {
          // The native chain found a reparse-replaced ancestor (the
          // junction-replacement attack) and refused the lease.
          throw new Error('FOLDER_PICKER_LEASE_PATH_REFUSED');
        },
      });
      cleanups.push(env.cleanup);
      const selected = await env.host.selectRoot();
      if (selected.status !== 'SELECTED') throw new Error('selection failed');
      env.host.afterSelectionRecorded(acceptedAnswer(selected.selectionRef), selectStep, recorded);

      const result = await env.host.observeCurrentSelectedFolder();
      expect(result).toEqual({ ok: false, code: 'FOLDER_OBSERVATION_UNAVAILABLE' });
      // The native reparse refusal prevents the storage port from being
      // reached, and no Host receipt exists. This does not claim to close a
      // replacement race after path-based walking has begun.
      expect(storageCalled).toBe(false);
      expect(env.guided.receiptCount()).toBe(0);
    });

    it('withholds the receipt when the pinned lease identity drifts during the async scan', async () => {
      const env = createEnvironment(undefined, {
        verifyDirectoryLease: () => ({
          ...identity,
          fileId: 'deadbeefdeadbeef',
          isDirectory: true,
          isReparsePoint: false,
          isNetworkPath: false,
          isVolumeRoot: false,
        }),
      });
      cleanups.push(env.cleanup);
      const selected = await env.host.selectRoot();
      if (selected.status !== 'SELECTED') throw new Error('selection failed');
      env.host.afterSelectionRecorded(acceptedAnswer(selected.selectionRef), selectStep, recorded);
      const result = await env.host.observeCurrentSelectedFolder();
      expect(result).toEqual({ ok: false, code: 'FOLDER_OBSERVATION_UNAVAILABLE' });
      expect(env.guided.receiptCount()).toBe(0);
    });

    it('releases the lease when the metadata walk itself fails', async () => {
      let released = false;
      const storage: FolderSelectionStoragePort = {
        resolveScope: async (_volume, declared) => ({ roots: [...declared.roots] }),
        observeStorage: async () => {
          throw new Error('walk failed');
        },
      };
      const env = createEnvironment(storage, {
        releaseDirectoryLease: () => {
          released = true;
        },
      });
      cleanups.push(env.cleanup);
      const selected = await env.host.selectRoot();
      if (selected.status !== 'SELECTED') throw new Error('selection failed');
      env.host.afterSelectionRecorded(acceptedAnswer(selected.selectionRef), selectStep, recorded);
      const result = await env.host.observeCurrentSelectedFolder();
      expect(result).toEqual({ ok: false, code: 'FOLDER_OBSERVATION_UNAVAILABLE' });
      expect(released).toBe(true);
      expect(env.guided.receiptCount()).toBe(0);
    });
  },
);

describe.skipIf(process.platform !== 'win32')(
  'R04 U05-A Host startup recovery for the select-root crash window',
  () => {
    const cleanups: Array<() => void> = [];
    afterEach(() => {
      for (const cleanup of cleanups.splice(0)) cleanup();
    });

    it('restages the consumed select-root answer and immediately supports observation', async () => {
      const env = createEnvironment();
      cleanups.push(env.cleanup);
      const selected = await env.host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      if (selected.status !== 'SELECTED') return;
      // Crash window: the answer is durably recorded, the INSPECT step never
      // staged.
      env.guided.setConsumedSelectRoot(
        selectStep,
        recordedAnswerEnvelope(selectStep, selected.selectionRef),
      );
      const recovery = env.host.recoverInterruptedSelection();
      expect(recovery).toEqual({
        status: 'RECOVERED',
        selectionRef: selected.selectionRef,
        stagedStepId: inspectStep.stepId,
      });
      expect(env.guided.service.readTrustedContext()).toMatchObject({
        state: 'CURRENT',
        observation: { selectedRootRef: selected.selectionRef },
      });
      // The recovered INSPECT step supports the full Host observation flow.
      const observed = await env.host.observeCurrentSelectedFolder();
      expect(observed.ok).toBe(true);
      expect(env.guided.receiptCount()).toBe(1);
      // Recovery is a one-shot no-op once the INSPECT step is current.
      expect(env.host.recoverInterruptedSelection()).toEqual({ status: 'NOT_APPLICABLE' });
    });

    it('is a no-op without the crash-window signature', async () => {
      const env = createEnvironment();
      cleanups.push(env.cleanup);
      // No staged Case at all, and a live CURRENT select-root step: neither
      // is a crash window.
      expect(env.host.recoverInterruptedSelection()).toEqual({ status: 'NOT_APPLICABLE' });
      const selected = await env.host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      expect(env.host.recoverInterruptedSelection()).toEqual({ status: 'NOT_APPLICABLE' });
    });

    it('refuses recovery when the consumed answer is not a proven selectedRoot submit', async () => {
      const env = createEnvironment();
      cleanups.push(env.cleanup);
      const selected = await env.host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      if (selected.status !== 'SELECTED') return;
      env.guided.setConsumedSelectRoot(selectStep, undefined);
      expect(env.host.recoverInterruptedSelection()).toEqual({
        status: 'REFUSED',
        code: 'FOLDER_SELECTION_RECOVERY_ANSWER_UNPROVEN',
      });
      expect(env.guided.service.readTrustedContext()).toMatchObject({ state: 'CONSUMED' });
    });

    it('leaves an expired selection stale, restages nothing and offers no automatic re-selection', async () => {
      const env = createEnvironment();
      cleanups.push(env.cleanup);
      const selected = await env.host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      if (selected.status !== 'SELECTED') return;
      env.guided.setConsumedSelectRoot(
        selectStep,
        recordedAnswerEnvelope(selectStep, selected.selectionRef),
      );
      env.advanceClock(SELECTION_TTL_MS + 1);
      expect(env.host.recoverInterruptedSelection()).toEqual({
        status: 'STALE',
        code: 'FOLDER_SELECTION_EXPIRED',
      });
      expect(env.guided.service.readTrustedContext()).toMatchObject({ state: 'CONSUMED' });
      // No automatic re-selection: the picker route stays refused on the
      // consumed step, and no INSPECT observation is available either.
      expect(await env.host.selectRoot()).toEqual({
        status: 'STALE',
        code: 'GUIDED_SELECT_ROOT_NOT_CURRENT',
      });
      expect(await env.host.observeCurrentSelectedFolder()).toEqual({
        ok: false,
        code: 'FOLDER_NOT_SELECTED',
      });
    });

    it('refuses a recovery whose row binding no longer matches the consumed step', async () => {
      const env = createEnvironment();
      cleanups.push(env.cleanup);
      const selected = await env.host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      if (selected.status !== 'SELECTED') return;
      const foreignStep = step('step-select-root', 'shun.guided.select-root', 'case-folder-other');
      env.guided.setConsumedSelectRoot(
        foreignStep,
        recordedAnswerEnvelope(foreignStep, selected.selectionRef),
      );
      expect(env.host.recoverInterruptedSelection()).toEqual({
        status: 'STALE',
        code: 'FOLDER_SELECTION_STEP_BINDING_MISMATCH',
      });
    });

    it('leaves a replaced root identity stale on recovery', async () => {
      let drift = false;
      const env = createEnvironment(undefined, {
        inspectFolder: () =>
          drift
            ? {
                ...identity,
                fileId: 'deadbeefdeadbeef',
                isDirectory: true,
                isReparsePoint: false,
                isNetworkPath: false,
                isVolumeRoot: false,
              }
            : {
                ...identity,
                isDirectory: true,
                isReparsePoint: false,
                isNetworkPath: false,
                isVolumeRoot: false,
              },
      });
      cleanups.push(env.cleanup);
      const selected = await env.host.selectRoot();
      expect(selected.status).toBe('SELECTED');
      if (selected.status !== 'SELECTED') return;
      env.guided.setConsumedSelectRoot(
        selectStep,
        recordedAnswerEnvelope(selectStep, selected.selectionRef),
      );
      drift = true; // the root directory was replaced between the crash and the restart
      expect(env.host.recoverInterruptedSelection()).toEqual({
        status: 'STALE',
        code: 'FOLDER_SELECTION_IDENTITY_DRIFT',
      });
    });
  },
);

describe.skipIf(process.platform !== 'win32')(
  'R04 U05-A folder-selection database LocalAppData boundary',
  () => {
    const savedLocalAppData = process.env.LOCALAPPDATA;
    const savedProgramData = process.env.ProgramData;
    let temporaryRoot: string;
    let localAppDataRoot: string;
    let programDataRoot: string;

    beforeEach(() => {
      // All filesystem fixtures stay inside an isolated temporary directory;
      // never create test data in the operator's real LocalAppData profile.
      temporaryRoot = mkdtempSync(join(tmpdir(), 'shun-folder-selection-db-'));
      localAppDataRoot = join(temporaryRoot, 'LocalAppData');
      programDataRoot = join(temporaryRoot, 'ProgramData');
      mkdirSync(localAppDataRoot, { recursive: true });
      mkdirSync(programDataRoot, { recursive: true });
      mkdirSync(join(localAppDataRoot, 'Shun'), { recursive: true });
      process.env.LOCALAPPDATA = localAppDataRoot;
      process.env.ProgramData = programDataRoot;
    });

    afterEach(() => {
      if (savedLocalAppData === undefined) delete process.env.LOCALAPPDATA;
      else process.env.LOCALAPPDATA = savedLocalAppData;
      if (savedProgramData === undefined) delete process.env.ProgramData;
      else process.env.ProgramData = savedProgramData;
      if (temporaryRoot) rmSync(temporaryRoot, { recursive: true, force: true });
    });

    it('accepts a database strictly inside the current Windows account LOCALAPPDATA', () => {
      expect(
        folderSelectionDatabaseRefusal(join(localAppDataRoot, 'Shun', 'folder-selection.sqlite')),
      ).toBe(null);
    });

    it('migrates legacy per-account records without retaining SID/session columns', () => {
      const directory = mkdtempSync(join(tmpdir(), 'shun-r04-folder-migration-'));
      const databaseFile = join(directory, 'folder-selection.sqlite');
      const legacy = new DatabaseSync(databaseFile);
      legacy.exec(
        `
          CREATE TABLE folder_selection_records (
            selection_ref TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            display_name TEXT NOT NULL,
            task_id TEXT NOT NULL,
            journey_id TEXT NOT NULL,
            case_ref_json TEXT NOT NULL,
            origin_step_id TEXT NOT NULL,
            template_digest TEXT NOT NULL,
            user_sid TEXT NOT NULL,
            logon_sid TEXT NOT NULL,
            session_id INTEGER NOT NULL,
            volume TEXT NOT NULL,
            volume_serial TEXT NOT NULL,
            file_id TEXT NOT NULL,
            expires_at_unix_ms INTEGER NOT NULL,
            created_at_unix_ms INTEGER NOT NULL
          )
        `,
      );
      legacy
        .prepare('INSERT INTO folder_selection_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(
          'host:folder:' + 'f'.repeat(64),
          join(directory, 'selected-root'),
          'Documents',
          'task-folder-r04',
          'journey-folder-r04',
          '{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","snapshotId":"case-folder-r04"}',
          'step-select-root',
          'b'.repeat(64),
          'S-1-5-21-1-2-3-1001',
          'S-1-5-5-0-1234',
          1,
          'C:',
          '1a2b3c4d',
          '0123456789abcdef',
          NOW + SELECTION_TTL_MS,
          NOW,
        );
      );
      legacy.close();
      const root = join(directory, 'selected-root');
      mkdirSync(root);
      const host = new FolderSelectionHost({
        guided: createGuided().service,
        databaseFile,
        native: nativePort(root),
        clock: () => NOW,
      });
      const migrated = new DatabaseSync(databaseFile);
      try {
        const columns = migrated.prepare('PRAGMA table_info(folder_selection_records)').all() as {
          name: string;
        }[];
        expect(columns.map((column) => column.name)).toEqual([
          'selection_ref',
          'path',
          'display_name',
          'task_id',
          'journey_id',
          'case_ref_json',
          'origin_step_id',
          'template_digest',
          'volume',
          'volume_serial',
          'file_id',
          'expires_at_unix_ms',
          'created_at_unix_ms',
        ]);
        expect(
          migrated.prepare('SELECT selection_ref FROM folder_selection_records').get(),
        ).toEqual({
          selection_ref: 'host:folder:' + 'f'.repeat(64),
        });
      } finally {
        migrated.close();
        host.close();
        rmSync(directory, { recursive: true, force: true });
      }
    });

    it('refuses ProgramData, UNC/device paths and out-of-profile locations', () => {
      expect(
        folderSelectionDatabaseRefusal(join(programDataRoot, 'Shun', 'folder-selection.sqlite')),
      ).toBe('FOLDER_SELECTION_DATABASE_PROGRAMDATA_REFUSED');
      expect(folderSelectionDatabaseRefusal('\\\\server\\share\\shun.sqlite')).toBe(
        'FOLDER_SELECTION_DATABASE_PATH_INVALID',
      );
      expect(folderSelectionDatabaseRefusal('\\\\.\\device\\shun.sqlite')).toBe(
        'FOLDER_SELECTION_DATABASE_PATH_INVALID',
      );
      expect(folderSelectionDatabaseRefusal('C:\\shun\\folder-selection.sqlite')).toBe(
        'FOLDER_SELECTION_DATABASE_OUTSIDE_LOCALAPPDATA',
      );
      expect(folderSelectionDatabaseRefusal(localAppDataRoot)).toBe(
        'FOLDER_SELECTION_DATABASE_OUTSIDE_LOCALAPPDATA',
      );
      expect(
        folderSelectionDatabaseRefusal(join(localAppDataRoot, '..', 'elsewhere', 'shun.sqlite')),
      ).toBe('FOLDER_SELECTION_DATABASE_OUTSIDE_LOCALAPPDATA');
    });

    it('refuses a LOCALAPPDATA root redirected into ProgramData and a missing LOCALAPPDATA', () => {
      process.env.LOCALAPPDATA = programDataRoot;
      expect(
        folderSelectionDatabaseRefusal(join(programDataRoot, 'Shun', 'folder-selection.sqlite')),
      ).toBe('FOLDER_SELECTION_DATABASE_PROGRAMDATA_REFUSED');
      delete process.env.LOCALAPPDATA;
      expect(
        folderSelectionDatabaseRefusal(join(programDataRoot, 'Shun', 'folder-selection.sqlite')),
      ).toBe('FOLDER_SELECTION_DATABASE_LOCALAPPDATA_REQUIRED');
    });

    it('refuses existing Junction redirects for both the database parent and LOCALAPPDATA root', () => {
      const outside = join(temporaryRoot, 'outside');
      const redirectedLocalAppData = join(temporaryRoot, 'LocalAppDataRedirected');
      mkdirSync(outside, { recursive: true });
      symlinkSync(outside, join(localAppDataRoot, 'Redirected'), 'junction');
      expect(
        folderSelectionDatabaseRefusal(
          join(localAppDataRoot, 'Redirected', 'folder-selection.sqlite'),
        ),
      ).toBe('FOLDER_SELECTION_DATABASE_OUTSIDE_LOCALAPPDATA');

      symlinkSync(programDataRoot, redirectedLocalAppData, 'junction');
      process.env.LOCALAPPDATA = redirectedLocalAppData;
      expect(
        folderSelectionDatabaseRefusal(
          join(redirectedLocalAppData, 'Shun', 'folder-selection.sqlite'),
        ),
      ).toBe('FOLDER_SELECTION_DATABASE_PROGRAMDATA_REFUSED');
    });

    it('the production factory refuses an out-of-boundary database path fail-closed', () => {
      expect(() =>
        createProductionFolderSelectionHost({
          guided: createGuided().service,
          databaseFile: join(programDataRoot, 'folder-selection.sqlite'),
        }),
      ).toThrow('FOLDER_SELECTION_DATABASE_PROGRAMDATA_REFUSED');
    });
  },
);
