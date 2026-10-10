// Winget adapter: official-source gating, exact provenance parsing, typed
// argv shape, and elevation-refusal mapping to the UAC_DECLINED terminal.
import { homedir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  WINGET_SOURCE_NAME,
  WingetAcquisition,
  WingetPrivilegedBackend,
} from '../src/adapters/winget.ts';
import { MemoryJournal } from '../src/journal.ts';
import { LocalAuthority } from '../src/local-authority.ts';
import { MemoryFilesystem, ScriptedProcessPort } from '../src/mocks.ts';
import { buildActionPlan, installAction } from '../src/plans.ts';
import type { ProcessResult } from '../src/ports.ts';

const SOURCE_LIST_OK = [
  '> winget source list',
  '',
  'Name    URL',
  '----    ---',
  'winget  https://cdn.winget.microsoft.com/cache',
  '',
].join('\r\n');

const SHOW_JSON = [
  'ExampleSoft.PdfTool 2.4.1',
  '',
  '  Found ExampleSoft.PdfTool [ExampleSoft.PdfTool]',
  '  Version: 2.4.1',
  '  Publisher: ExampleSoftware',
  '  Author: ExampleSoftware Ltd.',
  '  Installer SHA256: b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1',
  '  License: MIT',
].join('\r\n');

function ok(stdout = ''): ProcessResult {
  return { exitCode: 0, stdout, stderr: '', timedOut: false };
}

function scripted(responses: ProcessResult[]): ScriptedProcessPort {
  return new ScriptedProcessPort(responses.map((result) => () => result));
}

describe('WingetAcquisition — official source gate', () => {
  it('accepts the official winget endpoint', async () => {
    const acquisition = new WingetAcquisition(
      scripted([ok(SOURCE_LIST_OK)]),
      new MemoryFilesystem(),
    );
    const sources = await acquisition.officialSources();
    expect(sources).toEqual([
      { name: WINGET_SOURCE_NAME, url: 'https://cdn.winget.microsoft.com/cache' },
    ]);
  });

  it('refuses a mirror whose endpoint is not on the official allowlist', async () => {
    const redirected = SOURCE_LIST_OK.replace(
      'cdn.winget.microsoft.com',
      'winget.mirror.example.net',
    );
    const acquisition = new WingetAcquisition(scripted([ok(redirected)]), new MemoryFilesystem());
    await expect(acquisition.officialSources()).rejects.toMatchObject({
      kind: 'OFFICIAL_SOURCE_UNAVAILABLE',
    });
  });
});

describe('WingetAcquisition — exact provenance resolution', () => {
  it('records exact version, publisher, hash and license from the official source', async () => {
    const acquisition = new WingetAcquisition(
      scripted([ok(SOURCE_LIST_OK), ok(SHOW_JSON)]),
      new MemoryFilesystem(),
    );
    const candidate = await acquisition.resolveExact({ packageId: 'ExampleSoft.PdfTool' });
    expect(candidate).toMatchObject({
      packageId: 'ExampleSoft.PdfTool',
      source: 'winget',
      official: true,
      version: '2.4.1',
      publisher: 'ExampleSoftware',
      license: 'MIT',
      signature: 'authenticode:ExampleSoftware',
    });
    expect(candidate.installerSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('maps an unknown package to a typed PACKAGE_UNKNOWN acquisition error', async () => {
    const missing: ProcessResult = {
      exitCode: -1978335135,
      stdout: '',
      stderr: 'No package found matching input criteria.',
      timedOut: false,
    };
    const acquisition = new WingetAcquisition(
      scripted([ok(SOURCE_LIST_OK), missing]),
      new MemoryFilesystem(),
    );
    await expect(acquisition.resolveExact({ packageId: 'Ghost.Package' })).rejects.toMatchObject({
      kind: 'PACKAGE_UNKNOWN',
    });
  });

  it('launches winget with typed argv, pinned source and no interactivity', async () => {
    const process = scripted([ok(SOURCE_LIST_OK), ok(SHOW_JSON)]);
    const acquisition = new WingetAcquisition(process, new MemoryFilesystem());
    await acquisition.resolveExact({ packageId: 'ExampleSoft.PdfTool', version: '2.4.1' });
    const showCall = process.calls[1];
    expect(showCall?.argv).toEqual([
      'winget',
      'show',
      '--id',
      'ExampleSoft.PdfTool',
      '--exact',
      '--source',
      'winget',
      '--version',
      '2.4.1',
      '--disable-interactivity',
    ]);
  });
});

describe('WingetAcquisition — observed layout', () => {
  it('discovers portable package dirs and link shims under the WinGet roots', async () => {
    const packagesDir = join(homedir(), 'AppData', 'Local', 'Microsoft', 'WinGet', 'Packages');
    const linksDir = join(homedir(), 'AppData', 'Local', 'Microsoft', 'WinGet', 'Links');
    const packageDir = join(packagesDir, 'ExampleSoft.PdfTool_2.4.1');
    const fs = new MemoryFilesystem();
    fs.putTree([packageDir, linksDir], {
      [join(packageDir, 'pdftool.exe')]: 'pdftool-2.4.1',
      [join(linksDir, 'pdftool.exe')]: '<shim>',
    });
    const acquisition = new WingetAcquisition(scripted([]), fs);
    const layout = await acquisition.layoutOf({
      providerId: 'tool.pdftool',
      packageId: 'ExampleSoft.PdfTool',
      source: 'winget',
      official: true,
      version: '2.4.1',
    });
    expect(layout.installDirs).toEqual([packageDir]);
    expect(layout.executables).toHaveLength(2);
  });

  it('finds executables nested in version subdirectories (portable zip layout)', async () => {
    const packagesDir = join(homedir(), 'AppData', 'Local', 'Microsoft', 'WinGet', 'Packages');
    const packageDir = join(
      packagesDir,
      'BurntSushi.ripgrep.MSVC_Microsoft.Winget.Source_8wekyb3d8bbwe',
    );
    const nested = join(packageDir, 'ripgrep-15.2.0-x86_64-pc-windows-msvc');
    const fs = new MemoryFilesystem();
    fs.putTree([packageDir, nested], {
      [join(packageDir, 'manifest.db')]: 'db',
      [join(nested, 'rg.exe')]: 'rg',
    });
    const acquisition = new WingetAcquisition(scripted([]), fs);
    const layout = await acquisition.layoutOf({
      providerId: 'tool.ripgrep',
      packageId: 'BurntSushi.ripgrep.MSVC',
      source: 'winget',
      official: true,
      version: '15.2.0',
    });
    expect(layout.executables).toEqual([join(nested, 'rg.exe')]);
  });
});

describe('WingetPrivilegedBackend — elevation refusal', () => {
  it('maps a declined elevation to terminal UAC_DECLINED with NOT_STARTED recovery', async () => {
    const authority = new LocalAuthority({ now: () => '2026-10-10T08:00:00.000Z' });
    const journals = new Map<string, MemoryJournal>();
    const journalsFor = (actionId: string) => {
      const existing = journals.get(actionId);
      if (existing) return existing;
      const journal = new MemoryJournal();
      journals.set(actionId, journal);
      return journal;
    };
    const process = scripted([
      {
        exitCode: -1978335189,
        stdout: '',
        stderr: 'Administrator privileges are required to install this package.',
        timedOut: false,
      },
    ]);
    const backend = new WingetPrivilegedBackend({
      authority,
      clock: () => '2026-10-10T08:00:01.000Z',
      journals: journalsFor,
      process,
      machineScope: true,
    });

    const action = installAction({
      actionId: 'a1-install',
      bindingId: 'b1',
      packageId: 'ExampleSoft.PdfTool',
      version: '2.4.1',
      installRoots: ['C:\\Program Files\\ExampleSoftware'],
      networkDomains: ['cdn.winget.microsoft.com'],
      elevated: true,
      timeoutMs: 60_000,
    });
    const plan = buildActionPlan({
      taskId: 't1',
      capabilityId: 'pdf.convert',
      bindingId: 'b1',
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
      taskId: 't1',
      planHash: plan.planHash,
      policySnapshotRevision: 'pol-snap-r1',
      actionScope: {
        actionIds: [action.actionId],
        privilegeLevel: 'ELEVATED',
        filesystem: { read: [], write: ['C:\\Program Files\\ExampleSoftware'] },
        network: { allowed: true, domains: ['cdn.winget.microsoft.com'] },
      },
      authorizationKind: 'AUTOMATIC',
    });
    const receipt = await backend.execute(
      {
        taskId: 't1',
        actionId: action.actionId,
        planHash: plan.planHash,
        policySnapshotRevision: 'pol-snap-r1',
        authorizationKind: 'AUTOMATIC',
        authorizationRef: grant.grantId,
        expiresAt: grant.expiresAt,
        action,
      },
      grant,
    );

    expect(receipt.terminal).toBe('UAC_DECLINED');
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('NOT_STARTED');
    const entries = await journalsFor('a1-install').replay();
    expect(entries.some((entry) => entry.detail?.startsWith('NO_EFFECT:'))).toBe(true);
  });
});
