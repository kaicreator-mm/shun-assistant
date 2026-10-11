// SystemRoot-anchored system executables (C13). Anything the executor or the
// privileged helper spawns MUST be resolved against the real Windows system
// directory, never against PATH and never against the inherited SystemRoot
// variable alone: the launcher that spawned us is UNTRUSTED and fully
// controls our inherited environment — a planted SystemRoot would let it ship
// fake whoami/reg/powershell/taskkill binaries and forge every token /
// elevation observation, or replace the very binary the UAC relay elevates.
//
// Windows semantics: the system directory is machine state recorded in
// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion (SystemRoot value), which
// requires elevation to modify — a same-user attacker at the caller's IL can
// rewrite their own environment variables but NOT that registry key. We read
// the machine record with reg.exe found from independent evidence (env hints
// cross-checked against the pinned well-known root), validate it as a
// fixed point (the reported root's own reg.exe re-reports the same value and
// the directory genuinely exists), and fail CLOSED when machine evidence is
// unavailable or contradictory. A planted fake reg.exe cannot forge the
// fixed point: a copy of the real reg.exe reports the real root, and the
// elevated helper path (the real System32 is admin-writable only) is outside
// the same-user threat model.
//
// Residual (documented, not hidden): if the registry is entirely unreadable,
// resolution falls back to inherited env ONLY on unanimous SystemRoot/windir
// agreement plus existence — a degraded, honest mode, never a silent guess
// from a single attacker-set variable.
import { execFileSync } from 'node:child_process';
import { statSync } from 'node:fs';
import { join } from 'node:path';

export type SystemRootResolution = { ok: true; systemRoot: string } | { ok: false; reason: string };

/** Shape of the injected registry probe (kept a pure function for tests). */
export type RegQuery = (regExe: string, args: readonly string[]) => string | undefined;

const REG_QUERY_SYSTEMROOT_ARGS = [
  'query',
  'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion',
  '/v',
  'SystemRoot',
] as const;

const HARD_CODED_FALLBACK_ROOT = 'C:\\Windows';

/**
 * Resolve the Windows system directory per machine evidence, not caller
 * say-so. `env` and `query` are injectable so the resolution logic is
 * testable on any host without real elevation.
 */
export function resolveSystemRoot(
  env: NodeJS.ProcessEnv = process.env,
  query: RegQuery = queryRegistryValue,
  platform: NodeJS.Platform = process.platform,
): SystemRootResolution {
  if (platform !== 'win32') {
    // Best-effort constant for non-Windows hosts; every spawn site degrades
    // honestly (missing exe ⇒ empty observation / refused step).
    return { ok: true, systemRoot: HARD_CODED_FALLBACK_ROOT };
  }

  // 1. Machine evidence: the HKLM SystemRoot value, read with reg.exe from
  //    every candidate root that actually has one. The first report that
  //    validates as a fixed point wins.
  for (const hint of uniqueRoots([env.SystemRoot, env.windir, HARD_CODED_FALLBACK_ROOT])) {
    const hintReg = join(hint, 'System32', 'reg.exe');
    if (!isFile(hintReg)) continue;
    const reported = query(hintReg, REG_QUERY_SYSTEMROOT_ARGS)?.trim();
    if (!reported || !isAbsoluteWindowsPath(reported)) continue;
    // Fixed point: the machine record must reference a real directory whose
    // own reg.exe re-reports the same value. This is what a planted fake
    // root cannot satisfy with the REAL reg.exe (it reports the real root).
    const reportedReg = join(reported, 'System32', 'reg.exe');
    if (!isDirectory(reported) || !isFile(reportedReg)) continue;
    const confirmed = query(reportedReg, REG_QUERY_SYSTEMROOT_ARGS)?.trim();
    if (confirmed !== reported) continue;
    return { ok: true, systemRoot: reported };
  }

  // 2. Degraded fallback: inherited env on unanimous agreement + existence.
  const agreed = uniqueRoots([env.SystemRoot, env.windir]);
  if (agreed.length === 1 && isDirectory(join(agreed[0] as string, 'System32'))) {
    return { ok: true, systemRoot: agreed[0] as string };
  }
  return {
    ok: false,
    reason:
      'system directory unresolvable: HKLM SystemRoot machine evidence unavailable and inherited SystemRoot/windir absent, contradictory or nonexistent — refusing to resolve system executables (fail closed)',
  };
}

let cached: SystemRootResolution | undefined;

/** Cached process-wide resolution; undefined result means fail closed. */
export function systemRoot(): string | undefined {
  cached ??= resolveSystemRoot();
  return cached.ok ? cached.systemRoot : undefined;
}

/** <SystemRoot>\System32\whoami.exe — the token-state probe. */
export function systemWhoamiExe(): string | undefined {
  const root = systemRoot();
  return root ? join(root, 'System32', 'whoami.exe') : undefined;
}

/** <SystemRoot>\System32\reg.exe — the registry op binary. */
export function systemRegExe(): string | undefined {
  const root = systemRoot();
  return root ? join(root, 'System32', 'reg.exe') : undefined;
}

/** <SystemRoot>\System32\WindowsPowerShell\v1.0\powershell.exe — the UAC relay host. */
export function systemPowershellExe(): string | undefined {
  const root = systemRoot();
  return root ? join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe') : undefined;
}

/** <SystemRoot>\System32\taskkill.exe — the non-elevated relay tree kill. */
export function systemTaskkillExe(): string | undefined {
  const root = systemRoot();
  return root ? join(root, 'System32', 'taskkill.exe') : undefined;
}

// ---- internals. ----

function queryRegistryValue(regExe: string, args: readonly string[]): string | undefined {
  try {
    const stdout = execFileSync(regExe, [...args], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 15000,
    });
    return parseSystemRootQuery(stdout);
  } catch {
    return undefined;
  }
}

/** `    SystemRoot    REG_SZ    C:\Windows` — tolerant line parse, fail closed. */
function parseSystemRootQuery(stdout: string): string | undefined {
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^ {4}\S+ {4}REG_SZ {4}(\S.*)$/.exec(line.trimEnd());
    if (m?.[1]) return m[1].trim();
  }
  return undefined;
}

function uniqueRoots(candidates: Array<string | undefined>): string[] {
  const seen = new Set<string>();
  const roots: string[] = [];
  for (const candidate of candidates) {
    const trimmed = candidate?.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    roots.push(trimmed);
  }
  return roots;
}

function isFile(path: string): boolean {
  try {
    return statSync(path, { throwIfNoEntry: false })?.isFile() ?? false;
  } catch {
    return false;
  }
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path, { throwIfNoEntry: false })?.isDirectory() ?? false;
  } catch {
    return false;
  }
}

function isAbsoluteWindowsPath(path: string): boolean {
  return /^[A-Za-z]:[\\/]/.test(path) || path.startsWith('\\\\');
}
