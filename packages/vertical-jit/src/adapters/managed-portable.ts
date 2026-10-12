import { createHash } from 'node:crypto';
import { lstat, mkdir, readdir, readFile, realpath, rmdir, unlink } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { PlanAction } from '@shun/contracts';
import type { JournalPort } from '../journal.ts';
import type { LocalAuthority } from '../local-authority.ts';
import { LocalPrivilegedBackend, type PerformOutcome } from '../local-backend.ts';
import {
  effectTimeScopeRefusal,
  manifestDeletionSpec,
  removeManifestEntries,
} from '../manifest-removal.ts';
import type {
  AcquisitionCandidate,
  AcquisitionPort,
  FilesystemPort,
  ProcessPort,
  ProviderInstallLayout,
} from '../ports.ts';
import { AcquisitionError } from '../ports.ts';
import { WINGET_SOURCE_NAME, WingetAcquisition } from './winget.ts';

export interface ZipExtractorPort {
  /** Exact archive entry targets accepted and extracted under destination. */
  extractZip(
    archivePath: string,
    destination: string,
    expectedSha256: string,
  ): Promise<readonly string[]>;
}

// Fixed-script PowerShell ZIP extractor. The executable path is injected by
// trusted host composition and must be absolute; no PATH lookup is performed.
export class SafePowerShellZipExtractor implements ZipExtractorPort {
  readonly #process: ProcessPort;
  readonly #powershellExe: string;
  readonly #timeoutMs: number;

  constructor(process: ProcessPort, powershellExe: string, options: { timeoutMs?: number } = {}) {
    if (!isAbsolute(powershellExe)) {
      throw new Error('portable ZIP extractor requires an absolute PowerShell path');
    }
    this.#process = process;
    this.#powershellExe = powershellExe;
    this.#timeoutMs = options.timeoutMs ?? 120_000;
  }

  async extractZip(
    archivePath: string,
    destination: string,
    expectedSha256: string,
  ): Promise<readonly string[]> {
    if (!/^[0-9a-f]{64}$/i.test(expectedSha256)) {
      throw new AcquisitionError('INSTALL_FAILED', 'portable ZIP expected SHA256 is malformed');
    }
    // PowerShell 5.1 may dequote/join tokens following -Command. Embed only
    // base64 data literals in the single command argument so spaces and
    // parentheses in real winget filenames can never become PowerShell syntax.
    const archiveB64 = Buffer.from(archivePath, 'utf8').toString('base64');
    const destinationB64 = Buffer.from(destination, 'utf8').toString('base64');
    const script = [
      `$archive=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${archiveB64}'))`,
      `$dest=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${destinationB64}'))`,
      `$expectedSha256='${expectedSha256.toLowerCase()}'`,
      '$ErrorActionPreference = "Stop"',
      '[void][Reflection.Assembly]::LoadWithPartialName("System.IO.Compression")',
      '$destFull = [IO.Path]::GetFullPath($dest).TrimEnd([IO.Path]::DirectorySeparatorChar)',
      '$destPrefix = $destFull + [IO.Path]::DirectorySeparatorChar',
      '$stream = [IO.File]::Open($archive,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)',
      '$sha = [Security.Cryptography.SHA256]::Create()',
      'try { $actualSha256 = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-","").ToLowerInvariant() } finally { $sha.Dispose() }',
      'if ($actualSha256 -ne $expectedSha256.ToLowerInvariant()) { $stream.Dispose(); throw "ZIP_SHA_MISMATCH" }',
      '$stream.Position = 0',
      '$zip = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read,$false)',
      '$targets = [Collections.Generic.List[string]]::new()',
      '$maxEntries = 4096',
      '$maxArchiveBytes = [long]536870912',
      '$maxEntryBytes = [long]268435456',
      '$maxExpandedBytes = [long]1073741824',
      '$maxRatio = 400.0',
      '$declaredTotal = [long]0',
      '$writtenTotal = [long]0',
      'try {',
      '  if ($stream.Length -gt $maxArchiveBytes) { throw "ZIP_ARCHIVE_LIMIT" }',
      '  if ($zip.Entries.Count -gt $maxEntries) { throw "ZIP_ENTRY_LIMIT" }',
      '  foreach ($entry in $zip.Entries) {',
      '    if ($entry.Length -gt $maxEntryBytes) { throw "ZIP_EXPANDED_LIMIT" }',
      '    $declaredTotal += $entry.Length',
      '    if ($declaredTotal -gt $maxExpandedBytes) { throw "ZIP_EXPANDED_LIMIT" }',
      '    if ($entry.Length -gt 0 -and (($entry.CompressedLength -eq 0) -or (([double]$entry.Length / [Math]::Max(1.0,[double]$entry.CompressedLength)) -gt $maxRatio))) { throw "ZIP_COMPRESSION_RATIO_LIMIT" }',
      '    if ($entry.FullName.Contains(":")) { throw "ZIP_ALTERNATE_STREAM" }',
      '    $target = [IO.Path]::GetFullPath([IO.Path]::Combine($destFull, $entry.FullName))',
      '    if (-not $target.StartsWith($destPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "ZIP_PATH_ESCAPE" }',
      '  }',
      '  foreach ($entry in $zip.Entries) {',
      '    if ($entry.FullName.Contains(":")) { throw "ZIP_ALTERNATE_STREAM" }',
      '    $target = [IO.Path]::GetFullPath([IO.Path]::Combine($destFull, $entry.FullName))',
      '    if (-not $target.StartsWith($destPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "ZIP_PATH_ESCAPE" }',
      '    if ([string]::IsNullOrEmpty($entry.Name)) {',
      '      [void][IO.Directory]::CreateDirectory($target)',
      '    } else {',
      '      $parent = [IO.Path]::GetDirectoryName($target)',
      '      [void][IO.Directory]::CreateDirectory($parent)',
      '      $input = $entry.Open()',
      '      try {',
      '        $output = [IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)',
      '        try {',
      '          $buffer = New-Object byte[] 65536',
      '          $entryWritten = [long]0',
      '          while (($n = $input.Read($buffer,0,$buffer.Length)) -gt 0) {',
      '            $entryWritten += $n',
      '            $writtenTotal += $n',
      '            if ($entryWritten -gt $maxEntryBytes -or $writtenTotal -gt $maxExpandedBytes) { throw "ZIP_RUNTIME_EXPANDED_LIMIT" }',
      '            $output.Write($buffer,0,$n)',
      '          }',
      '          if ($entryWritten -ne $entry.Length) { throw "ZIP_LENGTH_MISMATCH" }',
      '        } finally { $output.Dispose() }',
      '      } finally { $input.Dispose() }',
      '    }',
      '    $cursor = $target',
      '    while ($cursor.StartsWith($destPrefix,[StringComparison]::OrdinalIgnoreCase)) {',
      '      $attrs = [IO.File]::GetAttributes($cursor)',
      '      if (($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "ZIP_REPARSE_POINT" }',
      '      $cursor = [IO.Path]::GetDirectoryName($cursor)',
      '    }',
      '    $targets.Add($target)',
      '  }',
      '  foreach ($target in $targets) {',
      '    [Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($target)))',
      '  }',
      '} finally { $zip.Dispose(); $stream.Dispose() }',
    ].join('; ');
    const result = await this.#process.run({
      argv: [this.#powershellExe, '-NoProfile', '-NonInteractive', '-Command', `& { ${script} }`],
      timeoutMs: this.#timeoutMs,
    });
    if (result.exitCode !== 0 || result.timedOut) {
      throw new AcquisitionError(
        'INSTALL_FAILED',
        `portable ZIP extraction failed (${result.exitCode}${result.timedOut ? ', timed out' : ''})`,
        result.exitCode,
      );
    }

    const encodedTargets = result.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (encodedTargets.length === 0) {
      throw new AcquisitionError(
        'INSTALL_FAILED',
        'portable ZIP extractor returned no exact-entry manifest',
      );
    }
    const targets: string[] = [];
    for (const encoded of encodedTargets) {
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0) {
        throw new AcquisitionError(
          'INSTALL_FAILED',
          'portable ZIP extractor manifest is malformed',
        );
      }
      const decoded = Buffer.from(encoded, 'base64').toString('utf8');
      if (Buffer.from(decoded, 'utf8').toString('base64') !== encoded || decoded.length === 0) {
        throw new AcquisitionError(
          'INSTALL_FAILED',
          'portable ZIP extractor manifest is malformed',
        );
      }
      targets.push(decoded);
    }
    return targets;
  }
}

export interface ManagedPortableOptions {
  root: string;
  wingetExe: string;
  executableName: string;
  extractor: ZipExtractorPort;
  timeoutMs?: number;
}

interface ManagedRecord {
  candidate: AcquisitionCandidate;
  packageRoot: string;
  downloadRoot: string;
  executable?: string;
  ownedPaths?: readonly string[];
}

function recordKey(packageId: string, version: string): string {
  return `${packageId.toLowerCase()}@${version}`;
}

function stableDirectoryName(packageId: string, version: string): string {
  return createHash('sha256').update(`${packageId}\n${version}`, 'utf8').digest('hex').slice(0, 32);
}

async function sha256File(path: string): Promise<string> {
  return createHash('sha256')
    .update(await readFile(path))
    .digest('hex');
}

async function walkFiles(root: string): Promise<string[]> {
  const files: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        throw new AcquisitionError(
          'INSTALL_FAILED',
          `managed portable root contains a reparse/symbolic-link entry: ${path}`,
        );
      }
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile()) files.push(path);
    }
  };
  await walk(root);
  return files;
}

function within(child: string, root: string): boolean {
  const r = resolve(root);
  const c = resolve(child);
  return c === r || c.toLowerCase().startsWith(`${r.toLowerCase()}${sep}`);
}

async function reparseRefusal(root: string, target: string): Promise<string | undefined> {
  const resolvedRoot = resolve(root);
  const resolvedTarget = resolve(target);
  if (!within(resolvedTarget, resolvedRoot)) {
    return `managed path escapes provider root: ${target}`;
  }

  const rel = relative(resolvedRoot, resolvedTarget);
  const segments = rel.length === 0 ? [] : rel.split(/[\\/]+/).filter(Boolean);
  let current = resolvedRoot;
  for (let index = -1; index < segments.length; index += 1) {
    if (index >= 0) current = join(current, segments[index] ?? '');
    try {
      const stat = await lstat(current);
      if (stat.isSymbolicLink()) {
        return `managed deletion path crosses a reparse/symbolic-link entry: ${current}`;
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        // Missing manifest entries are harmless: removeManifestEntries skips
        // them. Any other observation failure cannot authorize deletion.
        return undefined;
      }
      return `managed deletion path identity cannot be verified: ${current}: ${String(error)}`;
    }
  }
  return undefined;
}

export class ManagedPortableAcquisition implements AcquisitionPort {
  readonly #process: ProcessPort;
  readonly #fs: FilesystemPort;
  readonly #options: ManagedPortableOptions;
  readonly #catalog: WingetAcquisition;
  readonly #records = new Map<string, ManagedRecord>();

  constructor(process: ProcessPort, fs: FilesystemPort, options: ManagedPortableOptions) {
    if (!isAbsolute(options.wingetExe)) {
      throw new Error('managed portable acquisition requires an absolute winget.exe path');
    }
    this.#process = process;
    this.#fs = fs;
    this.#options = options;
    this.#catalog = new WingetAcquisition(process, fs, {
      timeoutMs: options.timeoutMs,
      program: options.wingetExe,
      installerType: 'zip',
    });
  }

  async officialSources(): Promise<ReadonlyArray<{ name: string; url: string }>> {
    const sources = [...(await this.#catalog.officialSources())];
    for (const record of this.#records.values()) {
      const url = record.candidate.installerUrl;
      if (url && !sources.some((source) => source.url === url)) {
        sources.push({ name: `${WINGET_SOURCE_NAME}:installer`, url });
      }
    }
    return sources;
  }

  async resolveExact(request: {
    packageId: string;
    version?: string;
  }): Promise<AcquisitionCandidate> {
    const raw = await this.#catalog.resolveExact(request);
    const installerType = raw.installerType?.trim().toLowerCase();
    if (installerType !== 'zip' && installerType !== 'portable (zip)') {
      throw new AcquisitionError(
        'PACKAGE_UNKNOWN',
        `${raw.packageId}@${raw.version} did not resolve to a ZIP installer`,
      );
    }
    if (!raw.installerSha256 || !/^[0-9a-f]{64}$/.test(raw.installerSha256)) {
      throw new AcquisitionError(
        'PACKAGE_UNKNOWN',
        `${raw.packageId}@${raw.version} has no exact installer SHA256 in the official catalog`,
      );
    }
    if (!raw.installerUrl) {
      throw new AcquisitionError(
        'PACKAGE_UNKNOWN',
        `${raw.packageId}@${raw.version} has no installer URL in the official catalog`,
      );
    }
    let url: URL;
    try {
      url = new URL(raw.installerUrl);
    } catch {
      throw new AcquisitionError('PACKAGE_UNKNOWN', 'catalog installer URL is not parseable');
    }
    if (url.protocol !== 'https:') {
      throw new AcquisitionError('PACKAGE_UNKNOWN', 'catalog installer URL is not HTTPS');
    }
    const root = resolve(this.#options.root);
    const key = stableDirectoryName(raw.packageId, raw.version);
    const packageRoot = join(root, 'providers', key);
    const downloadRoot = join(root, 'downloads', key);
    const candidate: AcquisitionCandidate = {
      ...raw,
      source: `${WINGET_SOURCE_NAME}:${raw.installerUrl}`,
    };
    this.#records.set(recordKey(candidate.packageId, candidate.version), {
      candidate,
      packageRoot,
      downloadRoot,
    });
    return candidate;
  }

  async predictScope(
    candidate: AcquisitionCandidate,
    _machineScope: boolean,
  ): Promise<readonly string[]> {
    const record = this.#record(candidate.packageId, candidate.version);
    return [record.packageRoot, record.downloadRoot];
  }

  async layoutOf(candidate: AcquisitionCandidate): Promise<ProviderInstallLayout> {
    const record = this.#record(candidate.packageId, candidate.version);
    const executable = record.executable ?? (await this.#findExecutable(record.packageRoot));
    record.executable = executable;
    return {
      providerId: candidate.providerId,
      version: candidate.version,
      installDirs: [record.packageRoot],
      cacheDirs: [record.downloadRoot],
      configDirs: [],
      executables: executable ? [executable] : [],
      ...(record.ownedPaths ? { ownedPaths: record.ownedPaths } : {}),
    };
  }

  async install(packageId: string, version: string): Promise<PerformOutcome> {
    const record = this.#record(packageId, version);
    try {
      await lstat(record.packageRoot);
      return {
        ok: false,
        note: `managed portable root already exists; refusing reuse: ${record.packageRoot}`,
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        return {
          ok: false,
          note: `managed portable root cannot be proven absent: ${String(error)}`,
        };
      }
      // ENOENT is the only accepted fresh-root state.
    }
    try {
      await lstat(record.downloadRoot);
      return {
        ok: false,
        note: `managed download root already exists; refusing reuse: ${record.downloadRoot}`,
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        return {
          ok: false,
          note: `managed download root cannot be proven absent: ${String(error)}`,
        };
      }
    }
    const downloadDir = record.downloadRoot;
    const payloadDir = join(record.packageRoot, 'payload');

    // Parents are shared Shun-managed containers; the per-provider leaves are
    // created non-recursively so a same-user race that pre-creates either leaf
    // becomes EEXIST/failure instead of silently transferring ownership.
    await mkdir(dirname(record.packageRoot), { recursive: true });
    await mkdir(dirname(downloadDir), { recursive: true });
    try {
      await mkdir(record.packageRoot);
      await mkdir(payloadDir);
      await mkdir(downloadDir);
    } catch (error) {
      return {
        ok: false,
        note: `managed portable exclusive root creation failed: ${String(error)}`,
      };
    }

    const result = await this.#process.run({
      argv: [
        this.#options.wingetExe,
        'download',
        '--id',
        packageId,
        '--exact',
        '--source',
        WINGET_SOURCE_NAME,
        '--version',
        version,
        '--installer-type',
        'zip',
        '--download-directory',
        downloadDir,
        '--accept-package-agreements',
        '--accept-source-agreements',
        '--disable-interactivity',
      ],
      timeoutMs: this.#options.timeoutMs ?? 5 * 60_000,
    });
    if (result.exitCode !== 0 || result.timedOut) {
      return {
        ok: false,
        exitCode: result.exitCode,
        note: `winget download failed${result.timedOut ? ' (timed out)' : ''}: ${result.stderr.slice(0, 240)}`,
      };
    }

    const files = await walkFiles(downloadDir);
    const expected = record.candidate.installerSha256;
    if (!expected) {
      return { ok: false, note: 'resolved portable candidate lost its required installer SHA256' };
    }
    const matches: string[] = [];
    for (const file of files) {
      if ((await sha256File(file)) === expected) matches.push(file);
    }
    if (matches.length !== 1) {
      return {
        ok: false,
        note: `downloaded artifact SHA mismatch/ambiguity: expected one exclusive ${expected}, found ${matches.length} matching of ${files.length} file(s)`,
      };
    }

    // winget 1.29 writes one locale manifest sidecar beside the downloaded
    // artifact. It is never trusted as provenance/input; it is merely a
    // bounded disposable byproduct inside the fresh Shun-owned staging root.
    const byproducts = files.filter((file) => !matches.includes(file));
    if (byproducts.length > 1) {
      return {
        ok: false,
        note: `unexpected download byproduct count: ${byproducts.length}`,
      };
    }
    const sidecar = byproducts[0];
    if (sidecar) {
      const sidecarStat = await lstat(sidecar);
      if (
        dirname(resolve(sidecar)) !== resolve(downloadDir) ||
        !basename(sidecar).toLowerCase().endsWith('.yaml') ||
        !sidecarStat.isFile() ||
        sidecarStat.size > 2 * 1024 * 1024
      ) {
        return {
          ok: false,
          note: `unexpected download byproduct: ${basename(sidecar)}`,
        };
      }
    }
    const archive = matches[0];
    if (!archive) return { ok: false, note: 'verified archive vanished before extraction' };

    const extracted = await this.#options.extractor.extractZip(archive, payloadDir, expected);
    const owned = this.#ownedHierarchy(
      record.packageRoot,
      payloadDir,
      extracted,
      record.downloadRoot,
      files,
    );
    record.ownedPaths = owned;
    const executable = await this.#findExecutable(payloadDir);
    if (!executable) {
      return {
        ok: false,
        note: `verified ZIP contains no unique ${this.#options.executableName}`,
      };
    }
    if (!within(executable, record.packageRoot)) {
      return { ok: false, note: 'portable executable escaped managed root after extraction' };
    }
    if (!owned.some((path) => resolve(path) === resolve(executable))) {
      return {
        ok: false,
        note: 'portable executable was not one of the catalog-verified archive entries',
      };
    }
    record.executable = executable;
    return {
      ok: true,
      exitCode: 0,
      note: `verified portable ZIP installed under managed root; artifact sha256=${expected}`,
    };
  }

  async removalPreflight(
    action: PlanAction,
  ): Promise<(PerformOutcome & { noEffect: true }) | undefined> {
    const spec = manifestDeletionSpec(action);
    if (!spec) {
      return {
        ok: false,
        note: 'managed portable removal requires an exact deletion manifest',
        noEffect: true,
        refusalTerminal: 'REFUSED',
      };
    }
    const parameters = action.parameters as Record<string, unknown>;
    const record = this.#record(
      String(parameters.packageId ?? ''),
      String(parameters.version ?? ''),
    );
    const managedRoots = [record.packageRoot, record.downloadRoot];
    const expectedRoots = managedRoots.map((root) => resolve(root).toLowerCase()).sort();
    const actualRoots = spec.scopeRoots.map((root) => resolve(root).toLowerCase()).sort();
    if (
      actualRoots.length !== expectedRoots.length ||
      actualRoots.some((root, index) => root !== expectedRoots[index]) ||
      spec.manifest.some((path) => !managedRoots.some((root) => within(path, root)))
    ) {
      return {
        ok: false,
        note: 'managed portable deletion scope is not exactly the Shun-owned provider + download roots',
        noEffect: true,
        refusalTerminal: 'REFUSED',
      };
    }
    for (const path of spec.manifest) {
      const managedRoot = managedRoots.find((root) => within(path, root));
      if (!managedRoot) {
        return {
          ok: false,
          note: `managed manifest path escaped all owned roots: ${path}`,
          noEffect: true,
          refusalTerminal: 'REFUSED',
        };
      }
      const identityRefusal = await reparseRefusal(managedRoot, path);
      if (identityRefusal) {
        return {
          ok: false,
          note: identityRefusal,
          noEffect: true,
          refusalTerminal: 'REFUSED',
        };
      }
    }
    const refusal = await effectTimeScopeRefusal(this.#fs, spec);
    return refusal
      ? { ok: false, note: refusal, noEffect: true, refusalTerminal: 'REFUSED' }
      : undefined;
  }

  async remove(action: PlanAction): Promise<PerformOutcome> {
    const spec = manifestDeletionSpec(action);
    if (!spec) return { ok: false, note: 'missing managed deletion manifest' };
    const parameters = action.parameters as Record<string, unknown>;
    const record = this.#record(
      String(parameters.packageId ?? ''),
      String(parameters.version ?? ''),
    );
    const managedRoots = [record.packageRoot, record.downloadRoot];
    for (const path of spec.manifest) {
      const managedRoot = managedRoots.find((root) => within(path, root));
      if (!managedRoot) {
        return {
          ok: false,
          note: `managed manifest path escaped all owned roots: ${path}`,
          noEffect: true,
          refusalTerminal: 'REFUSED',
        };
      }
      const identityRefusal = await reparseRefusal(managedRoot, path);
      if (identityRefusal) {
        return {
          ok: false,
          note: identityRefusal,
          noEffect: true,
          refusalTerminal: 'REFUSED',
        };
      }
    }
    const refusal = await effectTimeScopeRefusal(this.#fs, spec);
    if (refusal) {
      return { ok: false, note: refusal, noEffect: true, refusalTerminal: 'REFUSED' };
    }
    const result = await removeManifestEntries(
      {
        removeEntry: async (path) => {
          // Re-check immediately before EACH destructive primitive. A
          // same-user race that swaps any manifest ancestor to a junction
          // must turn into retention/refusal, never an outside-root unlink.
          const managedRoot = managedRoots.find((root) => within(path, root));
          if (!managedRoot) return false;
          const identityRefusal = await reparseRefusal(managedRoot, path);
          if (identityRefusal) return false;
          const stat = await lstat(path);
          if (stat.isSymbolicLink()) return false;
          if (stat.isDirectory()) {
            const children = await readdir(path);
            if (children.length > 0) return false;
            await rmdir(path);
            return true;
          }
          await unlink(path);
          return true;
        },
      },
      this.#fs,
      spec,
    );
    if (result.retained.length > 0) {
      return {
        ok: false,
        note: `managed removal retained ${result.retained.length} path(s); provider state requires reconciliation`,
      };
    }
    return {
      ok: true,
      exitCode: 0,
      note: `manifest-owned portable provider removed (${result.removed.length} exact entries)`,
    };
  }

  #ownedHierarchy(
    packageRoot: string,
    payloadRoot: string,
    extractedTargets: readonly string[],
    downloadRoot: string,
    downloadedFiles: readonly string[],
  ): readonly string[] {
    const owned = new Set<string>([
      resolve(packageRoot),
      resolve(payloadRoot),
      resolve(downloadRoot),
    ]);

    const addHierarchy = (root: string, rawPaths: readonly string[], label: string): void => {
      for (const raw of rawPaths) {
        const target = resolve(raw);
        if (!within(target, root)) {
          throw new AcquisitionError(
            'INSTALL_FAILED',
            `${label} ownership target escaped managed root: ${target}`,
          );
        }
        owned.add(target);
        let parent = dirname(target);
        while (within(parent, root)) {
          owned.add(resolve(parent));
          if (resolve(parent) === resolve(root)) break;
          parent = dirname(parent);
        }
      }
    };

    addHierarchy(payloadRoot, extractedTargets, 'extractor');
    addHierarchy(downloadRoot, downloadedFiles, 'download');
    return [...owned];
  }

  #record(packageId: string, version: string): ManagedRecord {
    const record = this.#records.get(recordKey(packageId, version));
    if (!record) {
      throw new AcquisitionError(
        'PACKAGE_UNKNOWN',
        `${packageId}@${version} was not resolved through the managed portable catalog`,
      );
    }
    return record;
  }

  async #findExecutable(root: string): Promise<string | undefined> {
    let rootReal: string;
    try {
      rootReal = await realpath(root);
    } catch {
      return undefined;
    }
    const matches = (await walkFiles(root)).filter(
      (path) => basename(path).toLowerCase() === this.#options.executableName.toLowerCase(),
    );
    if (matches.length !== 1) return undefined;
    const match = matches[0];
    if (!match) return undefined;
    const actual = await realpath(match);
    return within(actual, rootReal) ? actual : undefined;
  }
}

export interface ManagedPortableBackendDeps {
  authority: LocalAuthority;
  clock: () => string;
  journals: (actionId: string) => JournalPort;
  acquisition: ManagedPortableAcquisition;
}

export class ManagedPortablePrivilegedBackend extends LocalPrivilegedBackend {
  constructor(deps: ManagedPortableBackendDeps) {
    super({
      authority: deps.authority,
      clock: deps.clock,
      journals: deps.journals,
      environmentId: 'local-windows-managed-portable',
      providerId: (action) =>
        `tool.${
          String((action.action.parameters as Record<string, unknown>).packageId ?? 'portable')
            .split('.')
            .at(-1)
            ?.toLowerCase() ?? 'portable'
        }`,
      providerVersion: (action) =>
        String((action.action.parameters as Record<string, unknown>).version ?? 'unknown'),
      preflight: async (action) =>
        action.op === 'software.uninstall' ? deps.acquisition.removalPreflight(action) : undefined,
      perform: async (action) => {
        const parameters = action.parameters as Record<string, unknown>;
        const packageId = String(parameters.packageId ?? '');
        const version = String(parameters.version ?? '');
        if (!packageId || !version) return { ok: false, note: 'missing packageId/version' };
        if (action.op === 'software.install') return deps.acquisition.install(packageId, version);
        if (action.op === 'software.uninstall') return deps.acquisition.remove(action);
        return { ok: false, note: `unsupported managed portable op ${action.op}` };
      },
    });
  }
}
