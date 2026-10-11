// EnvironmentFacts observation for the local Windows backend (L2 §4.4, §8.1).
// Pragmatic and stdlib-first: node:os + fs.statfs; a single typed
// `whoami /groups` spawn for token state; PATH probes for optional runtime
// capabilities. Every probe degrades honestly (never fabricates capability).
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, statfsSync } from 'node:fs';
import { cpus, hostname, version as osVersion, platform, release, totalmem } from 'node:os';
import { canonicalJson, type EnvironmentFacts, type PrivilegeMode } from '@shun/contracts';
import { resolveWithinScope } from './fs-safety.ts';
import { systemPowershellExe, systemRoot, systemWhoamiExe } from './system-exe.ts';

export interface ObserveOptions {
  /** Disk free is reported for this root (the executor workspace). */
  workspaceRoot: string;
  networkPolicy?: EnvironmentFacts['networkPolicy'];
  /**
   * N-1: trusted authority store holding the system-tools identity pin. The
   * whoami/powershell probes verify candidates against it; without the
   * anchor the token probe degrades honestly to STANDARD_USER and the
   * powershell capability is not reported (fail-closed, never fabricated).
   */
  authorityDir?: string;
}

export async function observeEnvironment(options: ObserveOptions): Promise<EnvironmentFacts> {
  const groupsCsv = await whoamiGroups(options.authorityDir);
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
    runtimeCapabilities: runtimeCapabilities(options.authorityDir),
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

function runtimeCapabilities(authorityDir: string | undefined): string[] {
  const caps = ['node'];
  // C13: anchored to the machine-evidenced system root, never the inherited
  // SystemRoot variable — a planted root would fabricate a 'powershell'
  // capability for the planner out of a fake binary. N-1: the candidate is
  // additionally verified against the system-tools identity pin; without the
  // anchor the capability degrades honestly (not reported).
  const ps = systemPowershellExe(authorityDir);
  if (ps && existsSync(ps)) caps.push('powershell');
  // N-R2-3 (P2 honesty): winget is reported ONLY through machine-owned
  // evidence. The inherited PATH is attacker-settable — a same-user attacker
  // planting 'winget.exe' anywhere on it (or pointing a PATH entry at their
  // own directory) must not fabricate a capability the planner would trust.
  // The probe therefore accepts a PATH hit only when the containing
  // directory natively resolves INSIDE a machine-owned root (the
  // machine-evidenced system root or the well-known Program Files
  // locations); everything else — user-profile alias dirs, TEMP, any
  // attacker dir — degrades honestly to "not reported". Machine roots are
  // admin-owned, so planting there is out of the same-user threat model.
  // Residual (documented): non-default Program Files installs on other
  // drives are simply not reported — capability reporting stays honest.
  if (wingetFromMachineOwnedPath()) caps.push('winget');
  return caps;
}

const WINGET_EXE = 'winget.exe';

/** Machine-owned roots a same-user (non-elevated) attacker cannot write. */
function machineOwnedRoots(): string[] {
  const roots: string[] = [];
  const root = systemRoot();
  if (root) roots.push(root);
  roots.push('C:\\Program Files', 'C:\\Program Files (x86)');
  return roots;
}

/**
 * N-R2-3 winget honesty probe. Accepts a PATH hit only when the containing
 * directory natively resolves INSIDE a machine-owned root; everything else
 * (user-profile alias dirs, TEMP, any attacker-planted directory) reports
 * nothing. `pathValue` and `fileExists` are injectable so the negative
 * controls run on any host without touching the real machine roots.
 */
export function wingetFromMachineOwnedPath(
  pathValue: string = process.env.Path ?? process.env.PATH ?? '',
  fileExists: (candidate: string) => boolean = (candidate) => existsSync(candidate),
): boolean {
  const pathDirs = pathValue.split(';');
  for (const entry of pathDirs) {
    const dir = entry.trim();
    if (!dir) continue;
    if (!fileExists(`${dir}\\${WINGET_EXE}`)) continue;
    for (const root of machineOwnedRoots()) {
      // Native realpath containment (C07 surface): a junction planted inside
      // a machine-rooted PATH entry that redirects OUTSIDE the root is
      // refused, and sibling-name prefixes ('C:\Program Files-Evil') do not
      // pass pathWithin's boundary check.
      if (resolveWithinScope(dir, [root]).ok) return true;
    }
  }
  return false;
}

export async function whoamiGroups(authorityDir?: string): Promise<string> {
  if (process.platform !== 'win32') return '';
  // C13: machine-evidenced resolution, never PATH and never the inherited
  // SystemRoot alone: whoever calls observeEnvironment can control PATH and
  // the environment, and a planted fake whoami could get a filtered token
  // judged ELEVATED_ADMIN. N-1: the candidate is additionally verified
  // against the system-tools identity pin — without the anchor (or on any
  // mismatch) the capture degrades to '' ⇒ fail-closed STANDARD_USER.
  const exe = systemWhoamiExe(authorityDir);
  if (!exe) return '';
  return new Promise((resolvePromise) => {
    execFile(
      exe,
      ['/groups', '/fo', 'csv'],
      { windowsHide: true, timeout: 10000 },
      (err, stdout) => {
        resolvePromise(err ? '' : String(stdout));
      },
    );
  });
}
