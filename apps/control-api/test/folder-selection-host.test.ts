import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { FolderSelectionHost, type FolderSelectionStoragePort } from '../src/v03/folder-selection-host.ts';
import type { HostGuidedService, GuidedDecisionReceipt } from '../../../packages/domain-host/src/guided/host-guided-service.ts';

const NOW = 1_800_000_000_000;
const identity = {
  userSid: 'S-1-5-21-1-2-3-1001',
  logonSid: 'S-1-5-5-0-1234',
  sessionId: 1,
  volumeSerial: '1a2b3c4d',
  fileId: '0123456789abcdef',
};
const recorded: GuidedDecisionReceipt = {
  status: 'RECORDED', humanGrantIssued: false, effectSent: false, history: [],
};

function step(stepId: string, artifactId: string) {
  return {
    stepId,
    taskId: 'task-folder-r04',
    journeyId: 'journey-folder-r04',
    caseRef: { snapshotId: 'case-folder-r04', digest: 'a'.repeat(64) },
    templateRef: { digest: 'b'.repeat(64), artifactId },
  };
}
const selectStep = step('step-select-root', 'shun.guided.select-root');
const inspectStep = step('step-inspect-scope', 'shun.guided.inspect-scope');
const replacementStep = step('step-replacement-inspect', 'shun.guided.inspect-scope');

function createGuided() {
  let context: any = { state: 'CURRENT', step: selectStep, observation: {} };
  let currentStep: any = selectStep;
  let receipts = 0;
  const guided = {
    state: () => ({ currentStep }),
    readTrustedContext: () => context,
    stageTrustedSelectedRoot: ({ selectionRef }: { selectionRef: string }) => {
      currentStep = inspectStep;
      context = {
        state: 'CURRENT', step: inspectStep,
        observation: { selectedRootRef: selectionRef },
      };
      return { status: 'CURRENT', step: inspectStep };
    },
    recordHostObservationReceipt: () => {
      receipts += 1;
      return recorded;
    },
  };
  return {
    service: guided as unknown as HostGuidedService,
    setStep(next: any, observation: unknown = { selectedRootRef: 'host:folder:' + 'f'.repeat(64) }) {
      currentStep = next;
      context = { state: 'CURRENT', step: next, observation };
    },
    receiptCount: () => receipts,
  };
}

function nativePort(root: string, overrides: Record<string, unknown> = {}) {
  return {
    selectFolder: () => ({
      status: 'SELECTED' as const, path: root, displayName: 'Documents', identity,
    }),
    currentIdentity: () => ({
      userSid: identity.userSid, logonSid: identity.logonSid, sessionId: identity.sessionId,
    }),
    inspectDirectory: () => ({
      ...identity, isDirectory: true, isReparsePoint: false,
      isNetworkPath: false, isVolumeRoot: false,
    }),
    ...overrides,
  };
}

function evidence(root: string, rootFileName = 'root.txt', directoryName = 'Documents') {
  return {
    observedAt: '2026-11-06T12:00:00.000Z',
    roots: [root],
    directories: [{
      path: join(root, directoryName), bytes: 10, files: 1,
      lastModifiedMs: 1_700_000_000_000, inaccessibleEntries: [],
    }],
    rootFiles: [{ path: join(root, rootFileName), bytes: 5 }],
    totalBytes: 15,
  };
}

function createEnvironment(storage?: FolderSelectionStoragePort, nativeOverrides: Record<string, unknown> = {}) {
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
  const host = new FolderSelectionHost({
    guided: guided.service,
    databaseFile: join(directory, 'folder-selection.sqlite'),
    native: nativePort(root, nativeOverrides),
    clock: () => NOW,
    storage: storage ?? defaultStorage,
  });
  return {
    directory, root, guided, host,
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
      event: 'USER_SUBMIT', source: 'USER',
      answers: [{ fieldId: 'selectedRoot', value: selectionRef }],
    },
  };
}

describe.skipIf(process.platform !== 'win32')('R04 U05-A Host folder selection and observation', () => {
  const cleanups: Array<() => void> = [];
  afterEach(() => {
    for (const cleanup of cleanups.splice(0)) cleanup();
  });

  it('turns native identity exceptions into redacted typed refusal', async () => {
    const env = createEnvironment(undefined, {
      currentIdentity: () => { throw new Error('raw token detail must not escape'); },
    });
    cleanups.push(env.cleanup);
    const result = await env.host.selectRoot();
    expect(result).toEqual({ status: 'REFUSED', code: 'FOLDER_SELECTION_IDENTITY_UNAVAILABLE' });
    expect(JSON.stringify(result)).not.toContain('raw token detail');
  });

  it('refuses an inspectDirectory exception without leaking its OS detail', async () => {
    const env = createEnvironment(undefined, {
      inspectDirectory: () => { throw new Error('private native detail'); },
    });
    cleanups.push(env.cleanup);
    const result = await env.host.selectRoot();
    expect(result).toEqual({ status: 'REFUSED', code: 'FOLDER_SELECTION_IDENTITY_UNAVAILABLE' });
    expect(JSON.stringify(result)).not.toContain('private native detail');
  });

  it('does not record a Host receipt when the exact INSPECT step changes during the async scan', async () => {
    let started!: () => void;
    let release!: () => void;
    const scanStarted = new Promise<void>((resolve) => { started = resolve; });
    const scanGate = new Promise<void>((resolve) => { release = resolve; });
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
    env.host.afterSelectionRecorded(
      acceptedAnswer(selected.selectionRef), selectStep, recorded,
    );

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
    env.host.afterSelectionRecorded(
      acceptedAnswer(selected.selectionRef), selectStep, recorded,
    );
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
});
