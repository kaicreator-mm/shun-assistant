// EnvironmentFacts observation for the local Windows backend (L2 §4.4, §8.1).
// Pragmatic and stdlib-first: node:os + fs.statfs; a single typed
// `whoami /groups` spawn for token state; PATH probes for optional runtime
// capabilities. Every probe degrades honestly (never fabricates capability).
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, statfsSync } from 'node:fs';
import { cpus, hostname, version as osVersion, platform, release, totalmem } from 'node:os';
import { canonicalJson, type EnvironmentFacts, type PrivilegeMode } from '@shun/contracts';

export interface ObserveOptions {
  /** Disk free is reported for this root (the executor workspace). */
  workspaceRoot: string;
  networkPolicy?: EnvironmentFacts['networkPolicy'];
}

export async function observeEnvironment(options: ObserveOptions): Promise<EnvironmentFacts> {
  const groupsCsv = await whoamiGroups();
  const privilegeMode = privilegeModeOf(groupsCsv);
  let freeDiskMb = 0;
  try {
    const st = statfsSync(options.workspaceRoot);
    freeDiskMb = Math.floor((Number(st.bsize) * Number(st.bavail)) / (1024 * 1024));
  } catch {
    freeDiskMb = 0;
  }
  const facts: EnvironmentFacts = {
    environmentId: `local-windows/${hostname()}`,
    backendKind: 'LOCAL_WINDOWS',
    os: `${platform()} ${release()} (${osVersion()})`,
    arch: process.arch,
    observationRevision: '',
    runtimeCapabilities: runtimeCapabilities(),
    privilegeMode,
    guiSession: hasGuiSession(),
    filesystemCapabilities: ['ntfs', 'long-path'],
    networkPolicy: options.networkPolicy ?? 'POLICY_CONTROLLED',
    resources: {
      cpuCores: cpus().length || 1,
      memoryMb: Math.floor(totalmem() / (1024 * 1024)),
      freeDiskMb,
    },
  };
  // Durable observation identity (L2 §11.2): digest of the fact snapshot itself.
  facts.observationRevision = `obs-${createHash('sha256')
    .update(canonicalJson({ ...facts, observationRevision: '' }), 'utf8')
    .digest('hex')
    .slice(0, 16)}`;
  return facts;
}

function privilegeModeOf(groupsCsv: string): PrivilegeMode {
  if (groupsCsv.includes('S-1-16-12288') || groupsCsv.includes('S-1-16-16384'))
    return 'ELEVATED_ADMIN';
  if (groupsCsv.includes('S-1-5-32-544')) return 'FILTERED_ADMIN';
  // Unparseable capture is reported as STANDARD_USER — capability reporting
  // degrades honestly; privileged work is refused elsewhere, fail-closed.
  return 'STANDARD_USER';
}

function hasGuiSession(): boolean {
  const session = process.env.SESSIONNAME?.toLowerCase() ?? '';
  return session.startsWith('console') || session.startsWith('rdp');
}

function runtimeCapabilities(): string[] {
  const caps = ['node'];
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  if (existsSync(`${systemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`))
    caps.push('powershell');
  if (findOnPath('winget.exe')) caps.push('winget');
  return caps;
}

function findOnPath(exe: string): boolean {
  const pathDirs = (process.env.Path ?? process.env.PATH ?? '').split(';');
  return pathDirs.some((d) => d && existsSync(`${d.trim()}\\${exe}`));
}

export async function whoamiGroups(): Promise<string> {
  if (process.platform !== 'win32') return '';
  return new Promise((resolvePromise) => {
    execFile(
      'whoami.exe',
      ['/groups', '/fo', 'csv'],
      { windowsHide: true, timeout: 10000 },
      (err, stdout) => {
        resolvePromise(err ? '' : String(stdout));
      },
    );
  });
}
