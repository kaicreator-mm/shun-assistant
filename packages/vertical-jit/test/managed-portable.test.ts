import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import {
  type ExtractedEntry,
  ManagedPortableAcquisition,
  type ZipExtractorPort,
} from '../src/adapters/managed-portable.ts';
import type {
  NativeDeletionPort,
  NativeObjectIdentity,
  NativeRemovalResult,
} from '../src/adapters/native-win.ts';
import { SafePowerShellZipExtractor } from '../src/adapters/native-win.ts';
import { NodeFilesystem } from '../src/adapters/node.ts';
import { uninstallAction } from '../src/plans.ts';
import type { ProcessPort, ProcessResult, ProcessRunSpec } from '../src/ports.ts';

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

class DownloadingProcess implements ProcessPort {
  readonly calls: ProcessRunSpec[] = [];
  readonly #archive: Buffer;
  readonly #catalogHash: string;

  constructor(archive: Buffer, catalogHash = sha256(archive)) {
    this.#archive = archive;
    this.#catalogHash = catalogHash;
  }

  async run(spec: ProcessRunSpec): Promise<ProcessResult> {
    this.calls.push(spec);
    if (spec.argv.includes('source') && spec.argv.includes('list')) {
      return {
        exitCode: 0,
        stdout: 'Name URL\r\nwinget https://cdn.winget.microsoft.com/cache\r\n',
        stderr: '',
        timedOut: false,
      };
    }
    if (spec.argv.includes('show')) {
      return {
        exitCode: 0,
        stdout: [
          'Version: 24.13.1',
          'Publisher: OpenJS Foundation',
          'Installer Type: portable (zip)',
          'Installer Url: https://nodejs.org/dist/v24.13.1/node-v24.13.1-win-x64.zip',
          `Installer SHA256: ${this.#catalogHash}`,
          'License: MIT',
        ].join('\r\n'),
        stderr: '',
        timedOut: false,
      };
    }
    if (spec.argv.includes('download')) {
      const index = spec.argv.indexOf('--download-directory');
      const dir = spec.argv[index + 1];
      if (!dir) throw new Error('test download call missing --download-directory');
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, 'Node.js (LTS)_24.13.1_X64_portable.zip'), this.#archive);
      await writeFile(
        join(dir, 'Node.js (LTS)_24.13.1_X64_portable_en-US.yaml'),
        'PackageIdentifier: OpenJS.NodeJS.LTS\nPackageVersion: 24.13.1\n',
      );
      return { exitCode: 0, stdout: 'downloaded', stderr: '', timedOut: false };
    }
    throw new Error(`unexpected process call: ${spec.argv.join(' ')}`);
  }
}

class FakeExtractor implements ZipExtractorPort {
  calls = 0;

  async extractZip(
    _archivePath: string,
    destination: string,
    _expectedSha256: string,
  ): Promise<readonly ExtractedEntry[]> {
    this.calls += 1;
    const bin = join(destination, 'node-v24.13.1-win-x64');
    const executable = join(bin, 'node.exe');
    const license = join(bin, 'LICENSE');
    await mkdir(bin, { recursive: true });
    await writeFile(executable, 'trusted portable executable');
    await writeFile(license, 'MIT');
    return [
      { path: bin, kind: 'dir', bytes: 0 },
      {
        path: executable,
        kind: 'file',
        sha256: sha256(Buffer.from('trusted portable executable')),
        bytes: 'trusted portable executable'.length,
      },
      { path: license, kind: 'file', sha256: sha256(Buffer.from('MIT')), bytes: 3 },
    ];
  }
}

/** Scripted stand-in for the native identity-pinned deleter (transport logic only). */
class ScriptedDeleter implements NativeDeletionPort {
  readonly calls: {
    root: string;
    manifest: readonly string[];
    identities?: ReadonlyMap<string, NativeObjectIdentity>;
  }[] = [];
  #outcome: (root: string) => NativeRemovalResult = () => ({ ok: true, removed: [], retained: [] });

  outcome(fn: (root: string) => NativeRemovalResult): void {
    this.#outcome = fn;
  }

  async snapshotTreePinned(
    _root: string,
    manifest: readonly string[],
  ): Promise<readonly NativeObjectIdentity[]> {
    const identities: NativeObjectIdentity[] = [];
    for (const path of manifest) {
      const stat = await lstat(path);
      const fileId = sha256(Buffer.from(`test-file-id:${resolve(path)}`)).slice(0, 48);
      if (stat.isDirectory()) {
        identities.push({ path: resolve(path), kind: 'dir', fileId });
      } else {
        identities.push({
          path: resolve(path),
          kind: 'file',
          fileId,
          sha256: sha256(await readFile(path)),
        });
      }
    }
    return identities;
  }

  async removeTreePinned(
    root: string,
    manifest: readonly string[],
    identities?: ReadonlyMap<string, NativeObjectIdentity>,
  ): Promise<NativeRemovalResult> {
    const call = { root, manifest: [...manifest], identities };
    this.calls.push(call);
    const result = this.#outcome(root);
    return call.manifest.length > 0 && result.ok
      ? { ...result, removed: [...call.manifest] }
      : result;
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

// The command-shape assertions are source-only transport controls. Real ZIP
// bomb, junction-swap and native handle behavior run in native-safety.win.test
// on genuine Windows hosts (no skip) against the same committed C# primitive.
describe('T10 safe portable ZIP extraction command', () => {
  class CapturingProcess implements ProcessPort {
    readonly calls: ProcessRunSpec[] = [];

    async run(spec: ProcessRunSpec): Promise<ProcessResult> {
      this.calls.push(spec);
      return { exitCode: 1, stdout: '', stderr: 'stopped-after-capture', timedOut: false };
    }
  }

  it('requires an absolute PowerShell path and keeps archive/destination out of argv entirely', async () => {
    const process = new CapturingProcess();
    expect(() => new SafePowerShellZipExtractor(process, 'powershell.exe')).toThrow(
      /absolute PowerShell path/,
    );

    const powershell = resolve(tmpdir(), 'WindowsPowerShell', 'powershell.exe');
    const extractor = new SafePowerShellZipExtractor(process, powershell);
    await extractor
      .extractZip('C:\\downloads\\artifact.zip', 'C:\\managed\\payload', 'a'.repeat(64))
      .catch(() => undefined);
    await extractor
      .extractZip(
        'C:\\other\\some dir (x64)\\ar(t).zip',
        'C:\\managed\\other payload',
        'b'.repeat(64),
      )
      .catch(() => undefined);
    expect(process.calls).toHaveLength(2);
    for (const call of process.calls) {
      expect(call.argv[0]).toBe(powershell);
      expect(call.argv).toHaveLength(5);
      expect(call.argv).not.toContain('C:\\downloads\\artifact.zip');
      expect(call.argv).not.toContain('C:\\managed\\payload');
      expect(call.argv[4]).toContain('Add-Type');
      expect(call.argv[4]).toContain('[Shun.Native]::Extract');
      expect(call.argv[4]).not.toContain('Expand-Archive');
    }
    // The bootstrap command is FIXED: only base64 stdin payloads vary.
    expect(process.calls[0]?.argv[4]).toBe(process.calls[1]?.argv[4]);

    const input = process.calls[0]?.input ?? '';
    const lines = input.split('\n');
    expect(lines[0]?.trim()).toBe('extract');
    expect(lines[1]?.trim()).toBe(
      Buffer.from(
        await readFile(
          fileURLToPath(new URL('../src/adapters/ShunNative.cs', import.meta.url)),
          'utf8',
        ),
        'utf8',
      ).toString('base64'),
    );
    expect(lines[2]?.trim()).toBe(
      Buffer.from('C:\\downloads\\artifact.zip', 'utf8').toString('base64'),
    );
    expect(lines[3]?.trim()).toBe(Buffer.from('C:\\managed\\payload', 'utf8').toString('base64'));
    expect(lines[4]?.trim()).toBe(Buffer.from('a'.repeat(64), 'utf8').toString('base64'));
    expect(input).not.toContain('C:\\downloads\\artifact.zip');
  });

  it('commits the native no-follow/identity-pinned primitive source with the required markers', async () => {
    const source = await readFile(
      fileURLToPath(new URL('../src/adapters/ShunNative.cs', import.meta.url)),
      'utf8',
    );
    // handle-relative no-follow primitives (not pathname re-checks)
    expect(source).toContain('NtCreateFile');
    expect(source).toContain('FILE_OPEN_REPARSE_POINT');
    expect(source).toContain('NtQueryDirectoryFile');
    expect(source).toContain('FileDispositionInformationEx');
    expect(source).toContain('FILE_DISPOSITION_FLAG_POSIX_SEMANTICS');
    expect(source).toContain('FileIdInformation');
    expect(source).toContain('MaxEntries = 4096');
    expect(source).toContain('MaxArchiveBytes = 536870912L');
    expect(source).toContain('MaxEntryBytes = 268435456L');
    expect(source).toContain('MaxExpandedBytes = 1073741824L');
    expect(source).toContain('MaxRatio = 400.0');
    // fail-closed refusals
    for (const marker of [
      'ZIP_SHA_MISMATCH',
      'ZIP_PATH_ESCAPE',
      'ZIP_ALTERNATE_STREAM',
      'ZIP_ENTRY_COLLISION',
      'ZIP_ENTRY_LIMIT',
      'ZIP_EXPANDED_LIMIT',
      'ZIP_COMPRESSION_RATIO_LIMIT',
      'ZIP_RUNTIME_EXPANDED_LIMIT',
      'ZIP_REPARSE_POINT',
      'ZIP_LENGTH_MISMATCH',
      'FOREIGN_CONTENT',
      'FOREIGN_REPARSE',
    ]) {
      expect(source).toContain(marker);
    }
    // pathname deletion primitives are structurally absent
    expect(source).not.toMatch(/DeleteFileW|RemoveDirectoryW/);
  });
});

describe('T10 managed portable acquisition', () => {
  it('refuses PATH-resolved winget composition', () => {
    expect(
      () =>
        new ManagedPortableAcquisition(
          new DownloadingProcess(Buffer.from('archive')),
          new NodeFilesystem(),
          {
            root: resolve(tmpdir(), 'shun-managed'),
            wingetExe: 'winget',
            executableName: 'node.exe',
            extractor: new FakeExtractor(),
          },
        ),
    ).toThrow(/absolute winget\.exe path/);
  });

  it('uses official ZIP catalog metadata, verifies the downloaded SHA and removes only through the native pinned deleter', async () => {
    const root = await mkdtemp(join(tmpdir(), 'shun-portable-'));
    roots.push(root);
    const archive = Buffer.from('catalog-pinned-portable-archive');
    const process = new DownloadingProcess(archive);
    const extractor = new FakeExtractor();
    const fs = new NodeFilesystem();
    const deleter = new ScriptedDeleter();
    const acquisition = new ManagedPortableAcquisition(process, fs, {
      root: join(root, 'managed'),
      wingetExe: resolve(root, 'winget.exe'),
      executableName: 'node.exe',
      extractor,
      nativeDeleter: deleter,
    });

    const candidate = await acquisition.resolveExact({ packageId: 'OpenJS.NodeJS.LTS' });
    expect(candidate).toMatchObject({
      packageId: 'OpenJS.NodeJS.LTS',
      version: '24.13.1',
      official: true,
      installerType: 'portable (zip)',
      installerSha256: sha256(archive),
    });
    expect(candidate.source).toContain('https://nodejs.org/');
    const show = process.calls.find((call) => call.argv.includes('show'));
    expect(show?.argv).toContain('--installer-type');
    expect(show?.argv).toContain('zip');

    const scope = await acquisition.predictScope(candidate, false);
    const packageRoot = scope[0];
    const downloadRoot = scope[1];
    expect(packageRoot).toBeDefined();
    expect(downloadRoot).toBeDefined();
    if (!packageRoot || !downloadRoot) throw new Error('managed roots missing');
    expect(packageRoot).not.toBe(downloadRoot);
    const installed = await acquisition.install(candidate.packageId, candidate.version);
    expect(installed.ok).toBe(true);
    expect(extractor.calls).toBe(1);

    const layout = await acquisition.layoutOf(candidate);
    expect(layout.installDirs).toEqual([packageRoot]);
    expect(layout.cacheDirs).toEqual([downloadRoot]);
    expect(layout.executables).toHaveLength(1);
    const executable = layout.executables[0];
    expect(executable).toBeDefined();
    if (!executable) throw new Error('managed portable executable missing');
    expect(basename(executable)).toBe('node.exe');

    const manifest = layout.ownedPaths;
    expect(manifest).toBeDefined();
    if (!manifest) throw new Error('trusted portable ownership manifest missing');
    expect(manifest).toContain(packageRoot);
    expect(manifest).toContain(downloadRoot);
    expect(manifest.some((path) => path.startsWith(downloadRoot))).toBe(true);
    expect(layout.ownedObjectIdentities?.some((entry) => basename(entry.path) === 'node.exe')).toBe(
      true,
    );
    expect(
      layout.ownedObjectIdentities?.some((entry) => entry.path.toLowerCase().endsWith('.yaml')),
    ).toBe(true);
    const foreign = join(packageRoot, 'user-created.txt');
    const foreignDownload = join(downloadRoot, 'user-created-download.txt');
    await writeFile(foreign, 'must survive/refuse');
    await writeFile(foreignDownload, 'must survive/refuse');

    const action = uninstallAction({
      actionId: 'b038-remove',
      bindingId: 'binding-portable-node',
      packageId: candidate.packageId,
      version: candidate.version,
      deleteRoots: [packageRoot, downloadRoot],
      deletionManifest: manifest,
      deletionIdentities: layout.ownedObjectIdentities,
      elevated: false,
      timeoutMs: 30_000,
    });
    const refusal = await acquisition.removalPreflight(action);
    expect(refusal).toMatchObject({ ok: false, noEffect: true, refusalTerminal: 'REFUSED' });
    expect(await exists(executable)).toBe(true);
    expect(await exists(foreign)).toBe(true);
    expect(await exists(foreignDownload)).toBe(true);

    await unlink(foreign);
    await unlink(foreignDownload);
    // Fresh process composition: resolve the catalog again but carry no in-memory
    // install ownership state. The authorized ActionPlan must be sufficient.
    const restarted = new ManagedPortableAcquisition(process, fs, {
      root: join(root, 'managed'),
      wingetExe: resolve(root, 'winget.exe'),
      executableName: 'node.exe',
      extractor,
      nativeDeleter: deleter,
    });
    await restarted.resolveExact({ packageId: candidate.packageId, version: candidate.version });
    expect(await restarted.removalPreflight(action)).toBeUndefined();
    const removed = await restarted.remove(action);
    expect(removed.ok).toBe(true);
    // Exactly one native pinned-removal call per managed root, each scoped to
    // that root's manifest subset and carrying install-time content identities.
    expect(deleter.calls).toHaveLength(2);
    const rootsCalled = deleter.calls.map((call) => resolve(call.root));
    expect(rootsCalled).toContain(resolve(packageRoot));
    expect(rootsCalled).toContain(resolve(downloadRoot));
    for (const call of deleter.calls) {
      expect(call.manifest.length).toBeGreaterThan(0);
      for (const path of call.manifest) {
        expect(
          resolve(path) === resolve(call.root) ||
            resolve(path).startsWith(`${resolve(call.root)}${sep}`),
        ).toBe(true);
      }
    }
    const identities = deleter.calls.flatMap((call) => [...(call.identities ?? new Map()).keys()]);
    expect(identities.some((path) => basename(path) === 'node.exe')).toBe(true);
    expect(identities.some((path) => path.toLowerCase().endsWith('.yaml'))).toBe(true);
  });

  it('fails removal closed when no native identity-pinned deleter is wired', async () => {
    const root = await mkdtemp(join(tmpdir(), 'shun-portable-nodeleter-'));
    roots.push(root);
    const archive = Buffer.from('catalog-pinned-portable-archive');
    const acquisition = new ManagedPortableAcquisition(
      new DownloadingProcess(archive),
      new NodeFilesystem(),
      {
        root: join(root, 'managed'),
        wingetExe: resolve(root, 'winget.exe'),
        executableName: 'node.exe',
        extractor: new FakeExtractor(),
      },
    );
    const candidate = await acquisition.resolveExact({ packageId: 'OpenJS.NodeJS.LTS' });
    expect((await acquisition.install(candidate.packageId, candidate.version)).ok).toBe(true);
    const layout = await acquisition.layoutOf(candidate);
    const packageRoot = layout.installDirs[0];
    const downloadRoot = layout.cacheDirs[0];
    const manifest = layout.ownedPaths;
    if (!packageRoot || !downloadRoot || !manifest) throw new Error('managed layout incomplete');
    const action = uninstallAction({
      actionId: 'b038-remove-nodeleter',
      bindingId: 'binding-portable-node',
      packageId: candidate.packageId,
      version: candidate.version,
      deleteRoots: [packageRoot, downloadRoot],
      deletionManifest: manifest,
      deletionIdentities: layout.ownedObjectIdentities,
      elevated: false,
      timeoutMs: 30_000,
    });
    const outcome = await acquisition.remove(action);
    expect(outcome).toMatchObject({ ok: false, noEffect: true, refusalTerminal: 'REFUSED' });
    expect(outcome.note).toMatch(/native identity-pinned deletion primitive/i);
    expect(await exists(packageRoot)).toBe(true);
    expect(await exists(downloadRoot)).toBe(true);
  });

  it('surfaces a native pinned-removal refusal with zero deletion as REFUSED/noEffect', async () => {
    const root = await mkdtemp(join(tmpdir(), 'shun-portable-refuse-'));
    roots.push(root);
    const archive = Buffer.from('catalog-pinned-portable-archive');
    const deleter = new ScriptedDeleter();
    deleter.outcome((root) => ({
      ok: false,
      removed: [],
      retained: [join(root, 'payload')],
      refusal: 'FOREIGN_CONTENT',
      detail: 'same-path replacement detected',
    }));
    const acquisition = new ManagedPortableAcquisition(
      new DownloadingProcess(archive),
      new NodeFilesystem(),
      {
        root: join(root, 'managed'),
        wingetExe: resolve(root, 'winget.exe'),
        executableName: 'node.exe',
        extractor: new FakeExtractor(),
        nativeDeleter: deleter,
      },
    );
    const candidate = await acquisition.resolveExact({ packageId: 'OpenJS.NodeJS.LTS' });
    expect((await acquisition.install(candidate.packageId, candidate.version)).ok).toBe(true);
    const layout = await acquisition.layoutOf(candidate);
    const packageRoot = layout.installDirs[0];
    const downloadRoot = layout.cacheDirs[0];
    const manifest = layout.ownedPaths;
    if (!packageRoot || !downloadRoot || !manifest) throw new Error('managed layout incomplete');
    const action = uninstallAction({
      actionId: 'b038-remove-refuse',
      bindingId: 'binding-portable-node',
      packageId: candidate.packageId,
      version: candidate.version,
      deleteRoots: [packageRoot, downloadRoot],
      deletionManifest: manifest,
      deletionIdentities: layout.ownedObjectIdentities,
      elevated: false,
      timeoutMs: 30_000,
    });
    const outcome = await acquisition.remove(action);
    expect(outcome).toMatchObject({ ok: false, noEffect: true, refusalTerminal: 'REFUSED' });
    expect(outcome.note).toContain('FOREIGN_CONTENT');
    expect(await exists(packageRoot)).toBe(true);
  });

  const itSymlink = process.platform === 'win32' ? it.skip : it;
  itSymlink(
    'refuses a manifest path whose parent is swapped to a symlink before deletion',
    async () => {
      const root = await mkdtemp(join(tmpdir(), 'shun-portable-symlink-'));
      roots.push(root);
      const archive = Buffer.from('catalog-pinned-portable-archive');
      const deleter = new ScriptedDeleter();
      const acquisition = new ManagedPortableAcquisition(
        new DownloadingProcess(archive),
        new NodeFilesystem(),
        {
          root: join(root, 'managed'),
          wingetExe: resolve(root, 'winget.exe'),
          executableName: 'node.exe',
          extractor: new FakeExtractor(),
          nativeDeleter: deleter,
        },
      );

      const candidate = await acquisition.resolveExact({ packageId: 'OpenJS.NodeJS.LTS' });
      expect((await acquisition.install(candidate.packageId, candidate.version)).ok).toBe(true);
      const layout = await acquisition.layoutOf(candidate);
      const packageRoot = layout.installDirs[0];
      const downloadRoot = layout.cacheDirs[0];
      const executable = layout.executables[0];
      const manifest = layout.ownedPaths;
      if (!packageRoot || !downloadRoot || !executable || !manifest) {
        throw new Error('managed layout incomplete');
      }

      const bin = dirname(executable);
      const outside = join(root, 'outside-provider');
      await rm(bin, { recursive: true, force: true });
      await mkdir(outside, { recursive: true });
      await writeFile(join(outside, 'node.exe'), 'outside must never be deleted');
      await symlink(outside, bin, 'dir');

      const action = uninstallAction({
        actionId: 'b038-junction-remove',
        bindingId: 'binding-portable-node',
        packageId: candidate.packageId,
        version: candidate.version,
        deleteRoots: [packageRoot, downloadRoot],
        deletionManifest: manifest,
        deletionIdentities: layout.ownedObjectIdentities,
        elevated: false,
        timeoutMs: 30_000,
      });
      const refusal = await acquisition.removalPreflight(action);
      expect(refusal).toMatchObject({ ok: false, noEffect: true, refusalTerminal: 'REFUSED' });
      expect(refusal?.note).toMatch(/reparse|symbolic-link/i);
      expect(await exists(join(outside, 'node.exe'))).toBe(true);
    },
  );

  it('accepts only the catalog-pinned ZIP plus one bounded winget YAML sidecar', async () => {
    const root = await mkdtemp(join(tmpdir(), 'shun-portable-sidecar-'));
    roots.push(root);
    const archive = Buffer.from('catalog-pinned-portable-archive');
    const process = new DownloadingProcess(archive);
    const acquisition = new ManagedPortableAcquisition(process, new NodeFilesystem(), {
      root: join(root, 'managed'),
      wingetExe: resolve(root, 'winget.exe'),
      executableName: 'node.exe',
      extractor: new FakeExtractor(),
    });
    const candidate = await acquisition.resolveExact({ packageId: 'OpenJS.NodeJS.LTS' });
    expect((await acquisition.install(candidate.packageId, candidate.version)).ok).toBe(true);
    const layout = await acquisition.layoutOf(candidate);
    const owned = layout.ownedPaths ?? [];
    expect(owned.some((path) => path.toLowerCase().endsWith('.yaml'))).toBe(true);
  });

  it('refuses any unrecognized extra download file instead of silently adopting it', async () => {
    const root = await mkdtemp(join(tmpdir(), 'shun-portable-extra-'));
    roots.push(root);
    const archive = Buffer.from('catalog-pinned-portable-archive');
    class ExtraDownloadingProcess extends DownloadingProcess {
      override async run(spec: ProcessRunSpec): Promise<ProcessResult> {
        const result = await super.run(spec);
        if (spec.argv.includes('download')) {
          const index = spec.argv.indexOf('--download-directory');
          const dir = spec.argv[index + 1];
          if (!dir) throw new Error('missing download dir');
          await writeFile(join(dir, 'attacker.txt'), 'must not be adopted');
        }
        return result;
      }
    }
    const process = new ExtraDownloadingProcess(archive);
    const extractor = new FakeExtractor();
    const acquisition = new ManagedPortableAcquisition(process, new NodeFilesystem(), {
      root: join(root, 'managed'),
      wingetExe: resolve(root, 'winget.exe'),
      executableName: 'node.exe',
      extractor,
    });
    const candidate = await acquisition.resolveExact({ packageId: 'OpenJS.NodeJS.LTS' });
    const result = await acquisition.install(candidate.packageId, candidate.version);
    expect(result.ok).toBe(false);
    expect(result.note).toMatch(/unexpected download byproduct/i);
    expect(extractor.calls).toBe(0);
  });

  it('refuses extraction when the downloaded artifact does not match the official SHA', async () => {
    const root = await mkdtemp(join(tmpdir(), 'shun-portable-hash-'));
    roots.push(root);
    const downloaded = Buffer.from('tampered-download');
    const official = sha256(Buffer.from('official-download'));
    const process = new DownloadingProcess(downloaded, official);
    const extractor = new FakeExtractor();
    const acquisition = new ManagedPortableAcquisition(process, new NodeFilesystem(), {
      root: join(root, 'managed'),
      wingetExe: resolve(root, 'winget.exe'),
      executableName: 'node.exe',
      extractor,
    });

    const candidate = await acquisition.resolveExact({ packageId: 'OpenJS.NodeJS.LTS' });
    const result = await acquisition.install(candidate.packageId, candidate.version);
    expect(result.ok).toBe(false);
    expect(result.note).toContain('SHA mismatch');
    expect(extractor.calls).toBe(0);
  });
});
