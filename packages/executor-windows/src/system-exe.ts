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
// the machine record with reg.exe RANKED BY TRUST, never by attacker say-so:
// the pinned well-known root's own reg.exe (C:\Windows\System32\reg.exe, the
// MACHINE FIXED POINT) is consulted FIRST. When it exists and its HKLM report
// validates as a fixed point, its answer IS the resolution — an inherited
// SystemRoot/windir hint can never outrank it, so a planted real directory
// whose self-written reg.exe re-reports the planted root (a forgery the old
// hint-first ordering accepted) is rejected by construction. If the fixed
// point SPEAKS but its report contradicts itself (fixed-point re-query
// mismatch, reported directory absent), resolution FAILS CLOSED rather than
// letting a validating attacker hint override readable machine evidence.
// (This corrects the earlier header's overstatement that a planted fake
// reg.exe could not forge the fixed point: it could, whenever attacker
// hints were probed before machine evidence.)
//
// N-1 honest boundary of the fixed point: it constrains the REPORT, not the
// REPORTER's bytes. In the DEGRADED tier — machine fixed point absent or
// entirely unreadable — a self-written reg.exe in a planted root can still
// satisfy the fixed-point loop with self-referential answers, so every
// resolved candidate binary is additionally verified against the authority
// store's system-tools identity pin (SystemToolsPinSchema, provisioned at
// the same trusted moment as the helper pin): a FORGED binary is refused
// (sha mismatch) and a missing record or digest fails closed. What identity
// CANNOT do is distinguish a real binary COPIED into a planted root (equal
// bytes = equal sha256) — but a copied real reg.exe still reports the real
// HKLM root, so its report is honest by construction. The pin store itself
// sits inside the C06 same-user boundary (an attacker who can rewrite the
// store can re-pin their own tools; the complete fix stays escalated).
//
// Residual (documented, not hidden): if the registry is entirely unreadable,
// resolution falls back to inherited env ONLY on unanimous SystemRoot/windir
// agreement plus existence — a degraded, honest mode, never a silent guess
// from a single attacker-set variable; even there the binary identity gate
// still applies to whatever this module hands out.
//
// PROBE BOUNDARY (F-1): resolution itself SPAWNS reg.exe candidates, so the
// module's own spawn surface is gated by the same pin. Every security caller
// enters through resolvePinnedSystemExe, which loads the system-tools pin
// FIRST and threads regSha256 into the resolution; with a digest supplied,
// EVERY candidate is identity-checked BEFORE execFileSync — the machine
// anchor must match the pinned digest (a mismatch means this host is not the
// pinned machine: fail closed, never a fallback to executing hints), and
// hint/reported candidates failing the gate are never executed at all. Only
// the bare, pin-less entry (tests, non-Windows constants) skips the gate,
// and then only the machine anchor at its admin-owned well-known path is
// involved; hint candidates in that mode are a documented degraded-tier
// residual whose outputs are still identity-gated downstream (N-1).

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
 * `shaFile` feeds the F-1 execution gate the same bytes view.
 */
export type SystemRootFsSeam = {
  isFile?: (path: string) => boolean;
  isDirectory?: (path: string) => boolean;
  shaFile?: (path: string) => string | undefined;
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
 * Windows path construction that is HOST-INDEPENDENT (P1-2 root cause): the
 * resolver runs its Windows logic on ANY platform (injected platform/fs seam
 * in the negative controls), so candidate paths must always be
 * backslash-joined. node:path's `join` splices the HOST separator — on a
 * POSIX test host `join('C:\\Windows', 'System32', 'reg.exe')` yields the
 * mixed-separator `C:\Windows/System32/reg.exe`, which silently misses every
 * seam-registered (and every real Windows) candidate: the machine anchor
 * "vanishes" and the resolver degrades for the wrong reason. Collapses
 * duplicated separators except a leading UNC double-backslash.
 */
function winPathJoin(...parts: readonly string[]): string {
  const merged = parts.filter((part) => part.length > 0).join('\\');
  if (merged.startsWith('\\\\')) return `\\\\${merged.slice(2).replace(/\\{2,}/g, '\\')}`;
  return merged.replace(/\\{2,}/g, '\\');
}

/**
 * Resolve the Windows system directory per machine evidence, not caller
 * say-so. `env`, `query`, `platform` and the fs `seam` are injectable so the
 * resolution logic is testable on any host without real elevation.
 *
 * F-1: `expectedRegSha256` (the pinned reg.exe digest, threaded by
 * resolvePinnedSystemExe from the pin it loads FIRST) turns on the probe
 * execution gate — no candidate is spawned unless its bytes hash to the
 * pinned digest; the machine anchor failing the gate is a fail-closed
 * "not the pinned machine" verdict, never a fallback to hints.
 */
export function resolveSystemRoot(
  env: NodeJS.ProcessEnv = process.env,
  query: RegQuery = queryRegistryValue,
  platform: NodeJS.Platform = process.platform,
  seam: SystemRootFsSeam = {},
  expectedRegSha256?: string,
): SystemRootResolution {
  if (platform !== 'win32') {
    // Best-effort constant for non-Windows hosts; every spawn site degrades
    // honestly (missing exe ⇒ empty observation / refused step).
    return { ok: true, systemRoot: HARD_CODED_FALLBACK_ROOT };
  }
  const statFile = seam.isFile ?? isFile;
  const statDirectory = seam.isDirectory ?? isDirectory;
  const shaOf = seam.shaFile ?? shaFileOf;
  // F-1 execution gate: with a pinned digest, a candidate is executed ONLY
  // when its bytes hash to the pin. Without a pin (bare/test path) the gate
  // is open — documented residual; security callers never use that path.
  const executeAllowed = (candidate: string): boolean =>
    expectedRegSha256 === undefined || shaOf(candidate) === expectedRegSha256;

  // 1. Machine fixed point FIRST (P1): the pinned well-known root's own
  //    reg.exe outranks every inherited hint. If it exists and its HKLM
  //    report validates as a fixed point, its answer IS the resolution — a
  //    planted root + self-written lying reg.exe can then never win by
  //    candidate ordering, because attacker-controlled SystemRoot/windir
  //    hints are only consulted when the machine evidence is absent or
  //    entirely unreadable. (N-1: the fixed point constrains the REPORTED
  //    ROOT; the identity gate below constrains the BYTES.)
  const machineReg = winPathJoin(HARD_CODED_FALLBACK_ROOT, 'System32', 'reg.exe');
  if (statFile(machineReg)) {
    // F-1: verify the anchor's bytes BEFORE executing it. A readable anchor
    // that fails the pinned identity is readable contradicting evidence —
    // "this host is not the pinned machine" — and must fail closed rather
    // than degrade into executing attacker-gated hints.
    if (!executeAllowed(machineReg)) {
      return {
        ok: false,
        reason:
          'system directory unresolvable: the machine reg.exe bytes do not match the pinned system-tool identity — this host is not the pinned machine, refusing to resolve and refusing to fall back to inherited hints (fail closed)',
      };
    }
    const machineReport = query(machineReg, REG_QUERY_SYSTEMROOT_ARGS)?.trim();
    if (machineReport) {
      // The machine anchor SPOKE. Its report must be the answer: accept it
      // only as a validated fixed point; if readable machine evidence
      // contradicts itself (re-query mismatch / reported directory absent),
      // fail closed instead of letting a self-consistent attacker hint
      // override it.
      const root = validatedFixedPoint(
        machineReport,
        query,
        statFile,
        statDirectory,
        executeAllowed,
      );
      if (root) return { ok: true, systemRoot: root };
      return {
        ok: false,
        reason:
          'system directory unresolvable: the machine reg.exe reported a SystemRoot that failed the fixed-point consistency check — readable machine evidence is contradictory, refusing to fall back to inherited hints (fail closed)',
      };
    }
    // Anchor entirely unreadable (query failed / no parseable value): honest
    // degradation — fall through to the hint tier and the env fallback.
  }

  // 2. Inherited hints (attacker-controllable, so strictly behind the
  //    machine fixed point): the first report that validates as a fixed
  //    point wins. A self-written reg.exe CAN satisfy this loop with
  //    self-referential answers — which is why (F-1) a candidate is executed
  //    only after its bytes pass the pin gate, and why the binaries handed
  //    out are identity-checked against the pin afterwards.
  for (const hint of uniqueRoots([env.SystemRoot, env.windir])) {
    const hintReg = winPathJoin(hint, 'System32', 'reg.exe');
    if (!statFile(hintReg)) continue;
    if (!executeAllowed(hintReg)) continue; // never EXECUTE an unpinned candidate
    const reported = query(hintReg, REG_QUERY_SYSTEMROOT_ARGS)?.trim();
    if (!reported || !isAbsoluteWindowsPath(reported)) continue;
    const root = validatedFixedPoint(reported, query, statFile, statDirectory, executeAllowed);
    if (root) return { ok: true, systemRoot: root };
  }

  // 3. Degraded fallback: inherited env on unanimous agreement + existence.
  const agreed = uniqueRoots([env.SystemRoot, env.windir]);
  if (agreed.length === 1 && statDirectory(winPathJoin(agreed[0] as string, 'System32'))) {
    return { ok: true, systemRoot: agreed[0] as string };
  }
  return {
    ok: false,
    reason:
      'system directory unresolvable: HKLM SystemRoot machine evidence unavailable and inherited SystemRoot/windir absent, contradictory or nonexistent — refusing to resolve system executables (fail closed)',
  };
}

const rootCache = new Map<string | undefined, SystemRootResolution>();

/** Cached process-wide resolution (keyed by the pinned digest, F-1); undefined result means fail closed. */
export function systemRoot(expectedRegSha256?: string): string | undefined {
  if (!rootCache.has(expectedRegSha256)) {
    rootCache.set(
      expectedRegSha256,
      resolveSystemRoot(undefined, undefined, undefined, {}, expectedRegSha256),
    );
  }
  const cached = rootCache.get(expectedRegSha256);
  return cached?.ok ? cached.systemRoot : undefined;
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
 *
 * F-1: the pin is loaded BEFORE the resolution and its regSha256 is threaded
 * into it, so the probe itself never spawns a candidate that fails the
 * pinned identity (see the module header's PROBE BOUNDARY).
 */
function resolvePinnedSystemExe(
  tool: SystemToolKey,
  authorityDir: string | undefined,
): string | undefined {
  if (!authorityDir) return undefined;
  const pin = readSystemToolsPin(authorityDir);
  if (!pin) return undefined;
  const root = systemRoot(pin.regSha256);
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

/**
 * A reported root is believed only when it is an absolute Windows path, the
 * directory genuinely exists, and its own reg.exe re-reports the same value
 * (fixed point). `executeAllowed` is the F-1 gate: the re-probe binary is
 * executed only when the gate accepts its bytes. Returns the validated root,
 * or undefined.
 */
function validatedFixedPoint(
  reported: string,
  query: RegQuery,
  statFile: (path: string) => boolean,
  statDirectory: (path: string) => boolean,
  executeAllowed: (candidate: string) => boolean,
): string | undefined {
  if (!isAbsoluteWindowsPath(reported)) return undefined;
  if (!statDirectory(reported)) return undefined;
  const reportedReg = winPathJoin(reported, 'System32', 'reg.exe');
  if (!statFile(reportedReg)) return undefined;
  if (!executeAllowed(reportedReg)) return undefined;
  const confirmed = query(reportedReg, REG_QUERY_SYSTEMROOT_ARGS)?.trim();
  return confirmed === reported ? reported : undefined;
}

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

function shaFileOf(path: string): string | undefined {
  try {
    return createHash('sha256').update(readFileSync(path)).digest('hex');
  } catch {
    return undefined;
  }
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
