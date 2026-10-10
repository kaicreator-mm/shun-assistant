// Winget acquisition adapter (real Windows host, LOCAL_WINDOWS_BUILD_HOST).
//
// Trust model: only the official winget community source endpoints are
// eligible; the adapter refuses to resolve, install or remove anything from
// any other source, and records exact provenance (publisher, exact version,
// Installer SHA256) from `winget show`. All process launches use typed argv
// with `--disable-interactivity` so no hidden elevation prompt can occur.
//
// This module performs NO I/O itself: effects flow exclusively through
// `WingetPrivilegedBackend` (AuthorizedAction boundary); the acquisition side
// is read-only resolution/observation.
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { JournalPort } from '../journal.ts';
import type { LocalAuthority } from '../local-authority.ts';
import { LocalPrivilegedBackend, type PrivilegedFault } from '../local-backend.ts';
import type {
  AcquisitionCandidate,
  AcquisitionPort,
  FilesystemPort,
  ProcessPort,
  ProviderInstallLayout,
} from '../ports.ts';
import { AcquisitionError } from '../ports.ts';

/** Official winget endpoints (community source + store source). */
const OFFICIAL_ENDPOINT_HOSTS = new Set([
  'cdn.winget.microsoft.com',
  'storeedgefd.dsx.mp.microsoft.com',
]);

export const WINGET_SOURCE_NAME = 'winget';

function wingetArgv(...args: string[]): string[] {
  return ['winget', ...args];
}

interface LabeledFields {
  readonly [label: string]: string;
}

/** Parse `Label: value` lines from winget's human output. */
function parseLabeled(output: string): LabeledFields {
  const fields: Record<string, string> = {};
  for (const line of output.split(/\r?\n/)) {
    const match = /^\s{0,8}([A-Za-z][A-Za-z0-9 /()-]{1,40}):\s*(.+?)\s*$/.exec(line);
    const label = match?.[1];
    const value = match?.[2];
    if (label && value) {
      fields[label.toLowerCase()] = value;
    }
  }
  return fields;
}

export class WingetAcquisition implements AcquisitionPort {
  readonly #process: ProcessPort;
  readonly #fs: FilesystemPort;
  readonly #timeoutMs: number;

  constructor(process: ProcessPort, fs: FilesystemPort, options: { timeoutMs?: number } = {}) {
    this.#process = process;
    this.#fs = fs;
    this.#timeoutMs = options.timeoutMs ?? 120_000;
  }

  async officialSources(): Promise<ReadonlyArray<{ name: string; url: string }>> {
    const result = await this.#process.run({
      argv: wingetArgv('source', 'list', '--name', WINGET_SOURCE_NAME),
      timeoutMs: this.#timeoutMs,
    });
    if (result.exitCode !== 0) {
      throw new AcquisitionError(
        'OFFICIAL_SOURCE_UNAVAILABLE',
        `winget source list failed (${result.exitCode})`,
        result.exitCode,
        result.stderr,
      );
    }
    const url = /https?:\/\/[^\s]+/.exec(result.stdout)?.[0] ?? '';
    let host = '';
    try {
      host = new URL(url).hostname;
    } catch {
      host = '';
    }
    if (!OFFICIAL_ENDPOINT_HOSTS.has(host)) {
      throw new AcquisitionError(
        'OFFICIAL_SOURCE_UNAVAILABLE',
        `configured "winget" source endpoint "${url}" is not an official endpoint — refusing acquisition`,
      );
    }
    return [{ name: WINGET_SOURCE_NAME, url }];
  }

  async resolveExact(request: {
    packageId: string;
    version?: string;
  }): Promise<AcquisitionCandidate> {
    // Pre-flight: the official source must be the one this adapter resolves from.
    await this.officialSources();
    const argv = wingetArgv(
      'show',
      '--id',
      request.packageId,
      '--exact',
      '--source',
      WINGET_SOURCE_NAME,
      ...(request.version ? ['--version', request.version] : []),
      '--disable-interactivity',
    );
    const result = await this.#process.run({ argv, timeoutMs: this.#timeoutMs });
    const combined = `${result.stdout}\n${result.stderr}`;
    if (result.exitCode !== 0) {
      if (/no package found matching/i.test(combined)) {
        throw new AcquisitionError(
          'PACKAGE_UNKNOWN',
          `${request.packageId} is not in the official winget source`,
          result.exitCode,
          combined,
        );
      }
      if (/no version found matching/i.test(combined)) {
        throw new AcquisitionError(
          'VERSION_UNAVAILABLE',
          `${request.packageId} has no version ${request.version ?? '(latest)'}`,
          result.exitCode,
          combined,
        );
      }
      throw new AcquisitionError(
        'PACKAGE_UNKNOWN',
        `winget show failed for ${request.packageId} (${result.exitCode})`,
        result.exitCode,
        combined,
      );
    }
    const fields = parseLabeled(result.stdout);
    const version = fields.version;
    if (!version) {
      throw new AcquisitionError(
        'PACKAGE_UNKNOWN',
        `winget show returned no version for ${request.packageId}`,
        result.exitCode,
        result.stdout,
      );
    }
    const publisher = fields.publisher;
    return {
      providerId: `tool.${request.packageId.split('.').slice(-1)[0]?.toLowerCase() ?? 'unknown'}`,
      packageId: request.packageId,
      source: WINGET_SOURCE_NAME,
      official: true,
      version,
      ...(fields['installer sha256']
        ? { installerSha256: fields['installer sha256'].toLowerCase() }
        : {}),
      ...(publisher ? { publisher } : {}),
      ...(fields.license ? { license: fields.license } : {}),
      ...(publisher ? { signature: `authenticode:${publisher}` } : {}),
    };
  }

  /**
   * Filesystem roots the winget mechanism is authorized to touch. User-scope
   * portable installs land under the per-user WinGet package/link roots;
   * machine-scope installs additionally cover the Program Files /
   * ProgramData roots. These are the ONLY roots an install plan may declare.
   */
  async predictScope(
    candidate: AcquisitionCandidate,
    machineScope: boolean,
  ): Promise<readonly string[]> {
    void candidate;
    const userRoots = [
      join(homedir(), 'AppData', 'Local', 'Microsoft', 'WinGet', 'Packages'),
      join(homedir(), 'AppData', 'Local', 'Microsoft', 'WinGet', 'Links'),
    ];
    if (!machineScope) return userRoots;
    return [
      ...userRoots,
      join(process.env.ProgramFiles ?? 'C:\\Program Files', 'WinGet', 'Packages'),
      join(process.env.ProgramData ?? 'C:\\ProgramData', 'Microsoft', 'WinGet', 'Packages'),
    ];
  }

  /**
   * Observed layout after install: the package directory under the WinGet
   * Packages root (name starts with the package id) plus link shims.
   * Portable zip packages may nest their payload in version directories, so
   * executable discovery walks the package tree (depth-bounded).
   */
  async layoutOf(candidate: AcquisitionCandidate): Promise<ProviderInstallLayout> {
    const packagesRoot = join(homedir(), 'AppData', 'Local', 'Microsoft', 'WinGet', 'Packages');
    const linksRoot = join(homedir(), 'AppData', 'Local', 'Microsoft', 'WinGet', 'Links');
    const installDirs: string[] = [];
    const executables: string[] = [];
    const stem = candidate.packageId.toLowerCase();
    if (await this.#fs.isDirectory(packagesRoot)) {
      for (const child of await this.#fs.listChildren(packagesRoot)) {
        if (!child.toLowerCase().startsWith(stem)) continue;
        const dir = join(packagesRoot, child);
        installDirs.push(dir);
        executables.push(...(await this.#findExecutables(dir, 3)));
      }
    }
    if (await this.#fs.isDirectory(linksRoot)) {
      for (const child of await this.#fs.listChildren(linksRoot)) {
        if (child.toLowerCase().endsWith('.exe')) {
          executables.push(join(linksRoot, child));
        }
      }
    }
    return {
      providerId: candidate.providerId,
      version: candidate.version,
      installDirs,
      cacheDirs: [],
      configDirs: [],
      executables,
    };
  }

  async #findExecutables(dir: string, depth: number): Promise<string[]> {
    const found: string[] = [];
    for (const entry of await this.#fs.listChildren(dir)) {
      const path = join(dir, entry);
      if (entry.toLowerCase().endsWith('.exe')) {
        found.push(path);
      } else if (depth > 0 && (await this.#fs.isDirectory(path))) {
        found.push(...(await this.#findExecutables(path, depth - 1)));
      }
    }
    return found;
  }
}

export interface WingetBackendDeps {
  readonly authority: LocalAuthority;
  readonly clock: () => string;
  readonly journals: (actionId: string) => JournalPort;
  readonly process: ProcessPort;
  readonly timeoutMs?: number;
  readonly machineScope: boolean;
  /** Fault injection for negative evidence scenarios (never in production). */
  readonly faults?: readonly PrivilegedFault[];
}

export class WingetPrivilegedBackend extends LocalPrivilegedBackend {
  constructor(deps: WingetBackendDeps) {
    super({
      authority: deps.authority,
      clock: deps.clock,
      journals: deps.journals,
      environmentId: 'local-windows-1',
      providerId: (action) =>
        `tool.${
          String((action.action.parameters as Record<string, unknown>).packageId ?? 'unknown')
            .split('.')
            .slice(-1)[0]
            ?.toLowerCase() ?? 'unknown'
        }`,
      providerVersion: (action) =>
        String((action.action.parameters as Record<string, unknown>).version ?? 'unknown'),
      perform: (action) => this.#perform(action),
      ...(deps.faults ? { faults: deps.faults } : {}),
    });
    this.#deps = deps;
  }

  readonly #deps: WingetBackendDeps;

  async #perform(action: {
    op: string;
    parameters: Record<string, unknown>;
  }): Promise<{ ok: boolean; exitCode?: number; note?: string; noEffect?: true }> {
    const packageId = String(action.parameters.packageId ?? '');
    const version = String(action.parameters.version ?? '');
    if (!packageId || !version) {
      return { ok: false, note: 'plan parameters lack packageId/version' };
    }
    const argv =
      action.op === 'software.install'
        ? wingetArgv(
            'install',
            '--id',
            packageId,
            '--exact',
            '--source',
            WINGET_SOURCE_NAME,
            '--version',
            version,
            '--silent',
            '--accept-package-agreements',
            '--accept-source-agreements',
            '--disable-interactivity',
            ...(this.#deps.machineScope ? ['--scope', 'machine'] : []),
          )
        : action.op === 'software.uninstall'
          ? wingetArgv(
              'uninstall',
              '--id',
              packageId,
              '--exact',
              '--version',
              version,
              '--silent',
              '--disable-interactivity',
            )
          : null;
    if (!argv) {
      return { ok: false, note: `unsupported op ${action.op}` };
    }
    const result = await this.#deps.process.run({
      argv,
      timeoutMs: this.#deps.timeoutMs ?? 15 * 60_000,
    });
    const combined = `${result.stdout}\n${result.stderr}`;
    const excerpt = combined.replace(/\s+/g, ' ').trim().slice(0, 240);
    const note = `winget exit ${result.exitCode}${result.timedOut ? ' (timed out)' : ''}${excerpt ? ` :: ${excerpt}` : ''}`;
    if (result.exitCode === 0) return { ok: true, exitCode: result.exitCode, note };
    if (result.timedOut) return { ok: false, exitCode: result.exitCode, note: `${note} timed-out` };
    if (
      /elevat|administrator|admin privileges|admin right|uac|requires admin|run as admin|access is denied/i.test(
        combined,
      )
    ) {
      return {
        ok: false,
        exitCode: result.exitCode,
        note: `${note} elevation-required`,
        noEffect: true,
      };
    }
    if (
      action.op === 'software.uninstall' &&
      /no installed package found matching/i.test(combined)
    ) {
      // Uninstall of an already-absent package: the removal effect is already true.
      return {
        ok: true,
        exitCode: result.exitCode,
        note: `${note} already-absent treated as removed`,
      };
    }
    if (action.op === 'software.install' && /already installed/i.test(combined)) {
      // Idempotent install: the pinned version is already present, so the
      // expected post-state (providerPresent@version) is already true — the
      // lifecycle's own post-state check confirms it on disk.
      return {
        ok: true,
        exitCode: result.exitCode,
        note: `${note} already-installed treated as present`,
      };
    }
    return { ok: false, exitCode: result.exitCode, note };
  }
}
