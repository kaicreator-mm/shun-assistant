import { createHash } from 'node:crypto';
import { lstat, mkdir, readdir, readFile, realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { PlanAction } from '@shun/contracts';
import type { JournalPort } from '../journal.ts';
import type { LocalAuthority } from '../local-authority.ts';
import { LocalPrivilegedBackend, type PerformOutcome } from '../local-backend.ts';
import { effectTimeScopeRefusal, manifestDeletionSpec } from '../manifest-removal.ts';
import type {
  AcquisitionCandidate,
  AcquisitionPort,
  FilesystemPort,
  ProcessPort,
  ProviderInstallLayout,
  ProviderOwnedObjectIdentity,
} from '../ports.ts';
import { AcquisitionError } from '../ports.ts';
import type { ExtractedEntry, NativeDeletionPort } from './native-win.ts';
import { WINGET_SOURCE_NAME, WingetAcquisition } from './winget.ts';

export type { ExtractedEntry, NativeRemovalResult } from './native-win.ts';
export { SafePowerShellZipExtractor } from './native-win.ts';

export interface ZipExtractorPort {
  /**
   * Extract exact archive entries under destination through the native
   * handle-relative primitive, reporting per-entry content identity so the
   * removal gate can pin deletion to install-time content.
   */
  extractZip(
    archivePath: string,
    destination: string,
    expectedSha256: string,
  ): Promise<readonly ExtractedEntry[]>;
}

export interface ManagedPortableOptions {
  root: string;
  wingetExe: string;
  executableName: string;
  extractor: ZipExtractorPort;
  /**
   * Native identity-pinned deletion primitive. Removal fails closed when it
   * is not wired: pathname-based lstat→unlink/rmdir is never a fallback.
   */
  nativeDeleter?: NativeDeletionPort;
  timeoutMs?: number;
}

interface ManagedRecord {
  candidate: AcquisitionCandidate;
  packageRoot: string;
  downloadRoot: string;
  executable?: string;
  ownedPaths?: readonly string[];
  /** Complete install-time NT object identities for restart-safe deletion. */
  ownedObjectIdentities?: ReadonlyMap<string, ProviderOwnedObjectIdentity>;
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

function actionDeletionIdentities(
  parameters: Record<string, unknown>,
  manifest: readonly string[],
  managedRoots: readonly string[],
  localIdentities?: ReadonlyMap<string, ProviderOwnedObjectIdentity>,
): {
  identities?: Map<string, ProviderOwnedObjectIdentity>;
  refusal?: string;
} {
  const raw = parameters.deletionIdentities;
  if (!Array.isArray(raw) || raw.length === 0)
    return {
      refusal:
        'managed portable removal requires install-time NT object identities bound into the authorized ActionPlan',
    };
  const manifestKeys = new Set(manifest.map((path) => resolve(path).toLowerCase()));
  const identities = new Map<string, ProviderOwnedObjectIdentity>();
  for (const value of raw) {
    if (!value || typeof value !== 'object')
      return { refusal: 'managed portable deletion identity is malformed' };
    const entry = value as {
      path?: unknown;
      kind?: unknown;
      fileId?: unknown;
      sha256?: unknown;
    };
    if (
      typeof entry.path !== 'string' ||
      !isAbsolute(entry.path) ||
      (entry.kind !== 'file' && entry.kind !== 'dir') ||
      typeof entry.fileId !== 'string' ||
      !/^[0-9a-f]{48}$/.test(entry.fileId) ||
      (entry.kind === 'file' &&
        (typeof entry.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(entry.sha256))) ||
      (entry.kind === 'dir' && entry.sha256 !== undefined)
    ) {
      return { refusal: 'managed portable deletion identity is malformed' };
    }
    const canonical = resolve(entry.path);
    const key = canonical.toLowerCase();
    if (!manifestKeys.has(key) || !managedRoots.some((root) => within(canonical, root))) {
      return {
        refusal: `managed portable deletion identity escaped the authorized manifest: ${entry.path}`,
      };
    }
    if (identities.has(key))
      return { refusal: `managed portable deletion identity is duplicated: ${entry.path}` };
    const identity: ProviderOwnedObjectIdentity = {
      path: canonical,
      kind: entry.kind,
      fileId: entry.fileId,
      ...(entry.kind === 'file' ? { sha256: entry.sha256 as string } : {}),
    };
    const local = localIdentities?.get(key);
    if (
      local !== undefined &&
      (local.kind !== identity.kind ||
        local.fileId !== identity.fileId ||
        local.sha256 !== identity.sha256)
    ) {
      return {
        refusal: `authorized deletion identity disagrees with install-time process evidence: ${entry.path}`,
      };
    }
    identities.set(key, identity);
  }
  return { identities };
}

function identityEntries(
  record: ManagedRecord,
): readonly ProviderOwnedObjectIdentity[] | undefined {
  if (!record.ownedObjectIdentities || record.ownedObjectIdentities.size === 0) return undefined;
  return [...record.ownedObjectIdentities.values()];
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
    // Re-resolving the same provider must not forget what a previous install
    // recorded (executable, ownership manifest, content identities): the
    // identity-pinned removal effect depends on them surviving later
    // resolveExact calls in the same process composition.
    const keyString = recordKey(candidate.packageId, candidate.version);
    const existing = this.#records.get(keyString);
    if (existing) {
      existing.candidate = candidate;
      return candidate;
    }
    this.#records.set(keyString, {
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
      ...(identityEntries(record) ? { ownedObjectIdentities: identityEntries(record) } : {}),
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
      extracted.map((entry) => entry.path),
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

    const snapshotter = this.#options.nativeDeleter;
    if (snapshotter) {
      const objectIdentities = new Map<string, ProviderOwnedObjectIdentity>();
      for (const root of [record.packageRoot, record.downloadRoot]) {
        const rootResolved = resolve(root);
        const rootManifest = owned.filter(
          (path) => resolve(path) === rootResolved || within(path, root),
        );
        const snapshot = await snapshotter.snapshotTreePinned(root, rootManifest);
        for (const identity of snapshot) {
          const key = resolve(identity.path).toLowerCase();
          if (objectIdentities.has(key)) {
            return { ok: false, note: `native identity snapshot duplicated ${identity.path}` };
          }
          objectIdentities.set(key, {
            path: resolve(identity.path),
            kind: identity.kind,
            fileId: identity.fileId,
            ...(identity.sha256 ? { sha256: identity.sha256 } : {}),
          });
        }
      }
      if (objectIdentities.size !== owned.length) {
        return {
          ok: false,
          note: `native identity snapshot covered ${objectIdentities.size}/${owned.length} owned paths`,
        };
      }
      record.ownedObjectIdentities = objectIdentities;
    }

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
    const identityCheck = actionDeletionIdentities(
      parameters,
      spec.manifest,
      managedRoots,
      record.ownedObjectIdentities,
    );
    if (!identityCheck.identities) {
      return {
        ok: false,
        note: identityCheck.refusal ?? 'managed portable deletion identities are unavailable',
        noEffect: true,
        refusalTerminal: 'REFUSED',
      };
    }
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
    const deleter = this.#options.nativeDeleter;
    if (!deleter) {
      return {
        ok: false,
        note: 'managed removal requires the native identity-pinned deletion primitive; none is wired (fail closed)',
        noEffect: true,
        refusalTerminal: 'REFUSED',
      };
    }
    const managedRoots = [record.packageRoot, record.downloadRoot];
    const identityCheck = actionDeletionIdentities(
      parameters,
      spec.manifest,
      managedRoots,
      record.ownedObjectIdentities,
    );
    if (!identityCheck.identities) {
      return {
        ok: false,
        note: identityCheck.refusal ?? 'managed portable deletion identities are unavailable',
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
    if (refusal) {
      return { ok: false, note: refusal, noEffect: true, refusalTerminal: 'REFUSED' };
    }

    // Destructive effect: per-root native identity-pinned deletion. The
    // primitive pins the root chain and every census object BY HANDLE
    // (no-follow opens, NT FileId + content identity re-verification, POSIX
    // delete-by-handle), so a same-path replacement or parent-junction swap
    // between census and delete retains/refuses instead of deleting foreign
    // content. There is no pathname unlink/rmdir path here at all.
    let removedTotal = 0;
    for (const root of managedRoots) {
      const rootResolved = resolve(root);
      const entries = spec.manifest.filter(
        (path) => resolve(path) === rootResolved || within(path, root),
      );
      if (entries.length === 0) continue;
      const identities = new Map<string, ProviderOwnedObjectIdentity>();
      for (const [key, identity] of identityCheck.identities) {
        const original = spec.manifest.find((path) => resolve(path).toLowerCase() === key);
        if (original && (resolve(original) === rootResolved || within(original, root))) {
          identities.set(resolve(original), { ...identity, path: resolve(original) });
        }
      }
      const result = await deleter.removeTreePinned(root, entries, identities);
      if (result.absentRoot) continue;
      if (!result.ok) {
        const refusalNote = result.refusal
          ? `native pinned removal refused (${result.refusal}${result.detail ? `: ${result.detail}` : ''})`
          : `native pinned removal retained ${result.retained.length} path(s)`;
        return {
          ok: false,
          note: `${refusalNote}; root=${root}; removedBeforeRefusal=${removedTotal}; reconciliation required`,
          ...(removedTotal === 0
            ? { noEffect: true as const, refusalTerminal: 'REFUSED' as const }
            : {}),
        };
      }
      removedTotal += result.removed.length;
    }
    return {
      ok: true,
      exitCode: 0,
      note: `identity-pinned native removal completed (${removedTotal} exact entries)`,
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
