// SystemRoot-anchored system executables (C13) with pinned BINARY IDENTITY
// (N-1). Anything the executor or the privileged helper spawns MUST be
// resolved against the real Windows system directory, never against PATH and
// never against the inherited SystemRoot variable alone: the launcher that
// spawned us is UNTRUSTED and fully controls our inherited environment — a
// planted SystemRoot would let it ship fake whoami/reg/powershell/taskkill
// binaries and forge every token / elevation observation, or replace the very
// binary the UAC relay elevates.
//
// Windows semantics: the system directory is machine state recorded in
// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion (SystemRoot value), which
// requires elevation to modify — a same-user attacker at the caller's IL can
// rewrite their own environment variables but NOT that registry key. We read
// the machine record with reg.exe found from independent evidence (env hints
// cross-checked against the pinned well-known root) and validate it as a
// fixed point (the reported root's own reg.exe re-reports the same value and
// the directory genuinely exists).
//
// N-1 honest boundary of that fixed point: it constrains the REPORT, not the
// REPORTER's bytes. A self-written reg.exe in a planted root can re-report
// the planted root and satisfy the loop — so every resolved candidate binary
// is additionally verified against the authority store's system-tools identity
// pin (SystemToolsPinSchema, provisioned at the same trusted moment as the
// helper pin): a FORGED binary is refused (sha mismatch) and a missing record
// or digest fails closed. What identity CANNOT do is distinguish a real
// binary COPIED into a planted root (equal bytes = equal sha256); the
// machine-evidence path defeats copies by construction — a real reg.exe copy
// reports the real root — and the pin store itself sits inside the C06
// same-user boundary (an attacker who can rewrite the store can re-pin their
// own tools; the complete fix stays escalated).
//
// Residual (documented, not hidden): if the registry is entirely unreadable,
// resolution falls back to inherited env ONLY on unanimous SystemRoot/windir
// agreement plus existence — a degraded, honest mode, never a silent guess
// from a single attacker-set variable; even there the binary identity gate
// still applies to whatever this module hands out.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { readSystemToolsPin } from './trusted-store.ts';

export type SystemRootResolution = { ok: true; systemRoot: string } | { ok: false; reason: string };

/** Shape of the injected registry probe (kept a pure function for tests). */
export type RegQuery = (regExe: string, args: readonly string[]) => string | undefined;

/**
 * Injectable filesystem gates so candidate probing runs against a virtual
 * filesystem on any host (the negative controls never touch the real disk).
 */
export type SystemRootFsSeam = {
  isFile?: (path: string) => boolean;
  isDirectory?: (path: string) => boolean;
};

/** The security-relevant system tools whose bytes are pinned (N-1). */
export type SystemToolKey = 'whoami' | 'reg' | 'powershell' | 'taskkill';

const SYSTEM_TOOL_RELATIVE: Record<SystemToolKey, readonly string[]> = {
  whoami: ['System32', 'whoami.exe'],
  reg: ['System32', 'reg.exe'],
  powershell: ['System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'],
  taskkill: ['System32', 'taskkill.exe'],
};

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
  seam: SystemRootFsSeam = {},
): SystemRootResolution {
  if (platform !== 'win32') {
    // Best-effort constant for non-Windows hosts; every spawn site degrades
    // honestly (missing exe ⇒ empty observation / refused step).
    return { ok: true, systemRoot: HARD_CODED_FALLBACK_ROOT };
  }
  const statFile = seam.isFile ?? isFile;
  const statDirectory = seam.isDirectory ?? isDirectory;

  // 1. Machine evidence: the HKLM SystemRoot value, read with reg.exe from
  //    every candidate root that actually has one. The first report that
  //    validates as a fixed point wins. (N-1: the fixed point constrains the
  //    REPORTED ROOT; the identity gate below constrains the BYTES.)
  for (const hint of uniqueRoots([env.SystemRoot, env.windir, HARD_CODED_FALLBACK_ROOT])) {
    const hintReg = join(hint, 'System32', 'reg.exe');
    if (!statFile(hintReg)) continue;
    const reported = query(hintReg, REG_QUERY_SYSTEMROOT_ARGS)?.trim();
    if (!reported || !isAbsoluteWindowsPath(reported)) continue;
    // Fixed point: the machine record must reference a real directory whose
    // own reg.exe re-reports the same value. A self-written reg.exe CAN
    // satisfy this loop with self-referential answers — which is exactly why
    // the candidate binaries are identity-checked against the pin afterwards.
    const reportedReg = join(reported, 'System32', 'reg.exe');
    if (!statDirectory(reported) || !statFile(reportedReg)) continue;
    const confirmed = query(reportedReg, REG_QUERY_SYSTEMROOT_ARGS)?.trim();
    if (confirmed !== reported) continue;
    return { ok: true, systemRoot: reported };
  }

  // 2. Degraded fallback: inherited env on unanimous agreement + existence.
  const agreed = uniqueRoots([env.SystemRoot, env.windir]);
  if (agreed.length === 1 && statDirectory(join(agreed[0] as string, 'System32'))) {
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

/**
 * N-1 core identity gate: `root` + tool → binary path, verified against the
 * pinned digest. Only fs observation (no process spawns), injectable
 * expected value so planted-root negative tests run on any host.
 * `expectedSha256` undefined (pin record or digest missing) fails closed.
 */
export function verifySystemToolExe(
  root: string,
  tool: SystemToolKey,
  expectedSha256: string | undefined,
): { ok: true; exe: string } | { ok: false; reason: string } {
  if (!expectedSha256) {
    return {
      ok: false,
      reason: `system tool identity pin missing for '${tool}' — refusing to resolve an unpinned system executable (fail closed)`,
    };
  }
  const exe = join(root, ...SYSTEM_TOOL_RELATIVE[tool]);
  if (!isFile(exe)) {
    return { ok: false, reason: `system tool '${tool}' candidate is not a file: ${exe}` };
  }
  let measured: string;
  try {
    measured = createHash('sha256').update(readFileSync(exe)).digest('hex');
  } catch {
    return { ok: false, reason: `system tool '${tool}' candidate unreadable: ${exe}` };
  }
  if (measured !== expectedSha256) {
    return {
      ok: false,
      reason: `system tool identity mismatch for '${tool}': measured sha256 ${measured} != pinned ${expectedSha256} — forged/substituted binary refused (fail closed)`,
    };
  }
  return { ok: true, exe };
}

/** <SystemRoot>\System32\whoami.exe — the token-state probe. */
export function systemWhoamiExe(authorityDir?: string): string | undefined {
  return resolvePinnedSystemExe('whoami', authorityDir);
}

/** <SystemRoot>\System32\reg.exe — the registry op binary. */
export function systemRegExe(authorityDir?: string): string | undefined {
  return resolvePinnedSystemExe('reg', authorityDir);
}

/** <SystemRoot>\System32\WindowsPowerShell\v1.0\powershell.exe — the UAC relay host. */
export function systemPowershellExe(authorityDir?: string): string | undefined {
  return resolvePinnedSystemExe('powershell', authorityDir);
}

/** <SystemRoot>\System32\taskkill.exe — the non-elevated relay tree kill. */
export function systemTaskkillExe(authorityDir?: string): string | undefined {
  return resolvePinnedSystemExe('taskkill', authorityDir);
}

/**
 * Root resolution + identity pin verification for one tool. `authorityDir`
 * is the trusted store whose system-tools pin provisions the expected
 * digests; WITHOUT it there is no trust anchor to verify against and the
 * resolution fails closed — callers degrade honestly (empty token
 * observation, refused step, refused relay spawn).
 */
function resolvePinnedSystemExe(
  tool: SystemToolKey,
  authorityDir: string | undefined,
): string | undefined {
  if (!authorityDir) return undefined;
  const pin = readSystemToolsPin(authorityDir);
  if (!pin) return undefined;
  const root = systemRoot();
  if (!root) return undefined;
  const expected =
    tool === 'whoami'
      ? pin.whoamiSha256
      : tool === 'reg'
        ? pin.regSha256
        : tool === 'powershell'
          ? pin.powershellSha256
          : pin.taskkillSha256;
  const verdict = verifySystemToolExe(root, tool, expected);
  return verdict.ok ? verdict.exe : undefined;
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
