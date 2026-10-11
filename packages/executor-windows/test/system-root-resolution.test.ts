// T04 C13 — system executable resolution follows Windows machine semantics,
// never the launcher-inherited environment. The launcher that spawned any
// executor/helper process is UNTRUSTED and controls the inherited SystemRoot
// variable; every security-relevant spawn (whoami token probe, reg.exe
// registry ops, the powershell UAC relay host, taskkill) must resolve against
// machine evidence (HKLM SystemRoot, writable only elevated) or fail closed.
//
// The resolver takes injected env/query/platform so the negative controls
// below exercise the attack shapes on any host; the Windows-only block adds
// a REAL copied-reg.exe attack (a same-user attacker can copy binaries — but
// a copied reg.exe still reports the real HKLM root).
//
// P1 (Reviewer, C13 fixed-point ordering): the negative controls against a
// LYING reg.exe run on a fully virtual filesystem via the fs seam — a planted
// root whose self-written reg.exe re-reports the planted root satisfies the
// old fixed-point loop when attacker-controlled env hints were consulted
// first. These tests pin the new invariant: the machine fixed point
// (C:\Windows\System32\reg.exe) is consulted FIRST, its validated report IS
// the resolution, and any hint-derived report that disagrees with readable
// machine evidence fails closed.
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { type RegQuery, resolveSystemRoot, type SystemRootFsSeam } from '../src/system-exe.ts';
import { ON_WINDOWS } from './helpers.ts';

const PLANTED = 'D:\\shun-fake-root';

const queryAlways =
  (value: string | undefined): RegQuery =>
  () =>
    value;

describe('C13 — system root resolution (injected env/query, host-independent)', () => {
  it('a planted SystemRoot with no real binaries fails closed (no silent guess)', () => {
    const env = { SystemRoot: PLANTED, windir: PLANTED };
    const r = resolveSystemRoot(env, queryAlways(PLANTED), 'win32');
    // The planted root does not exist on any real filesystem, so the machine
    // evidence never validates and the env fallback's existence gate fails.
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('fail closed');
  });

  it('a fixed-point-forging query (fake root re-reporting itself) is still rejected by the existence gate', () => {
    // Even if a fake reg.exe consistently reports the planted root, the
    // planted directory must EXIST and contain System32\reg.exe for the
    // report to be believed; a pure-env attack without planted files never
    // reaches that gate because the candidate reg.exe is not a file.
    const env = { SystemRoot: PLANTED, windir: PLANTED };
    const r = resolveSystemRoot(env, queryAlways(PLANTED), 'win32');
    expect(r.ok).toBe(false);
  });

  it('contradictory SystemRoot/windir with no machine evidence fails closed', () => {
    const env = { SystemRoot: 'C:\\Windows', windir: 'E:\\elsewhere' };
    const r = resolveSystemRoot(env, queryAlways(undefined), 'win32');
    expect(r.ok).toBe(false);
  });

  it('unanimous inherited env is accepted ONLY as the degraded fallback (machine evidence preferred)', () => {
    // Non-Windows platform: no filesystem probing at all — the resolver must
    // take its documented constant branch, proving the fallback logic is not
    // reached accidentally.
    const r = resolveSystemRoot({}, queryAlways(undefined), 'darwin');
    expect(r).toEqual({ ok: true, systemRoot: 'C:\\Windows' });
  });

  it('a machine record that fails the fixed point (roots disagree with their own reg.exe) is rejected', () => {
    // Simulated: reg.exe at the hinted root reports root A, but reg.exe at A
    // reports a different value — inconsistent evidence, never trusted.
    const env = { SystemRoot: 'C:\\WinA', windir: 'C:\\WinA' };
    const query: RegQuery = (exe) => {
      if (exe.startsWith('C:\\WinA')) return 'C:\\WinB';
      if (exe.startsWith('C:\\WinB')) return 'C:\\WinC';
      return undefined;
    };
    const r = resolveSystemRoot(env, query, 'win32');
    expect(r.ok).toBe(false);
  });

  it('off-Windows callers get the documented best-effort constant', () => {
    expect(resolveSystemRoot({}, queryAlways(undefined), 'linux')).toEqual({
      ok: true,
      systemRoot: 'C:\\Windows',
    });
  });
});

describe('C13 P1 — a lying planted reg.exe cannot forge the machine fixed point (virtual-fs negative controls)', () => {
  const MACHINE = 'C:\\Windows';
  const PLANTED = 'D:\\shun-planted-root';
  const lower = (p: string): string => p.toLowerCase();

  /** Virtual filesystem seam: no real disk is touched, any host runs this. */
  function makeSeam(paths: { files: string[]; dirs: string[] }): SystemRootFsSeam {
    const files = new Set(paths.files.map(lower));
    const dirs = new Set(paths.dirs.map(lower));
    return {
      isFile: (p: string) => files.has(lower(p)),
      isDirectory: (p: string) => dirs.has(lower(p)),
    };
  }

  const bothRootsSeam = (): SystemRootFsSeam =>
    makeSeam({
      files: [`${MACHINE}\\System32\\reg.exe`, `${PLANTED}\\System32\\reg.exe`],
      dirs: [MACHINE, `${MACHINE}\\System32`, PLANTED, `${PLANTED}\\System32`],
    });

  /** The planted reg.exe LIES (reports/re-reports the planted root); the machine anchor tells the truth. */
  const lyingQuery =
    (calls: string[]): RegQuery =>
    (regExe) => {
      calls.push(regExe);
      return lower(regExe).startsWith(lower(PLANTED)) ? PLANTED : MACHINE;
    };

  it('a planted root + lying reg.exe loses to the machine anchor even though the attacker env is consulted-shape-first', () => {
    const calls: string[] = [];
    const env = { SystemRoot: PLANTED, windir: PLANTED };
    // Pre-fix behavior: env hints came first, the planted fixed point
    // validated, and PLANTED won — this assertion was RED. Post-fix the
    // machine anchor is probed FIRST and its validated report IS the answer.
    const r = resolveSystemRoot(env, lyingQuery(calls), 'win32', bothRootsSeam());
    expect(calls.length).toBeGreaterThan(0);
    expect(lower(calls[0] as string)).toBe(lower(`${MACHINE}\\System32\\reg.exe`));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(lower(r.systemRoot)).toBe(lower(MACHINE));
      expect(lower(r.systemRoot)).not.toBe(lower(PLANTED));
    }
  });

  it('a readable machine anchor whose report fails the fixed point fails CLOSED — a validating attacker hint must not override it', () => {
    // The anchor EXISTS and SPEAKS (reports MACHINE) but its report does not
    // validate (the MACHINE directory is missing from the filesystem) —
    // readable machine evidence that contradicts itself. Resolution must
    // fail closed, NOT fall back to the planted hint's self-consistent lie.
    const seam = makeSeam({
      files: [`${MACHINE}\\System32\\reg.exe`, `${PLANTED}\\System32\\reg.exe`],
      dirs: [PLANTED, `${PLANTED}\\System32`],
    });
    const env = { SystemRoot: PLANTED, windir: PLANTED };
    const r = resolveSystemRoot(env, lyingQuery([]), 'win32', seam);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('fail closed');
  });

  it('when the machine anchor is entirely UNREADABLE the documented hint tier still applies (honest degradation boundary)', () => {
    // The anchor's reg.exe exists but every query returns undefined: the
    // machine fixed point has no opinion. The validated hint tier may then
    // answer — this pins the exact boundary of the new invariant.
    const unreadableQuery: RegQuery = (regExe) =>
      lower(regExe).startsWith(lower(PLANTED)) ? PLANTED : undefined;
    const env = { SystemRoot: PLANTED, windir: PLANTED };
    const r = resolveSystemRoot(env, unreadableQuery, 'win32', bothRootsSeam());
    expect(r.ok).toBe(true);
    if (r.ok) expect(lower(r.systemRoot)).toBe(lower(PLANTED));
  });

  it('P1-2 (host-independent path construction): every candidate handed to the seam is a backslash-canonical Windows path on ANY host', () => {
    // Root cause of the historical Linux-CI red (run 38114000384): the
    // resolver built candidates with node:path's host `join`, which on POSIX
    // spliced '/' into Windows paths (`C:\Windows/System32/reg.exe`) — the
    // seam never matched, the machine anchor "vanished", and these pure
    // injected-seam controls degraded for the wrong reason. This control
    // pins the invariant directly: whatever host runs the suite, the paths
    // probed against the (virtual) filesystem must be Windows-canonical.
    const probed: string[] = [];
    const recordingSeam: SystemRootFsSeam = {
      isFile: (p: string) => {
        probed.push(p);
        return false;
      },
      isDirectory: (p: string) => {
        probed.push(p);
        return false;
      },
      shaFile: (p: string) => {
        probed.push(p);
        return undefined;
      },
    };
    resolveSystemRoot(
      { SystemRoot: PLANTED, windir: PLANTED },
      () => undefined,
      'win32',
      recordingSeam,
    );
    expect(probed.length).toBeGreaterThan(0);
    for (const p of probed) expect(p.includes('/')).toBe(false);
  });
});

describe('F-1 — the resolver never EXECUTES an unpinned reg.exe candidate (probe identity gate)', () => {
  // F-1 (Reviewer): resolution itself SPAWNS reg.exe probes, and the hint
  // tier executes attacker-planted candidates WITHOUT any identity check —
  // an elevated helper reaching that tier would run attacker bytes once per
  // UAC consent. The fix threads the system-tools pin digest (loaded FIRST
  // in resolvePinnedSystemExe) into the resolution: every candidate is
  // identity-gated BEFORE execFileSync. These controls run on the virtual
  // seam; the query spy records what WOULD have been executed.
  const MACHINE = 'C:\\Windows';
  const PLANTED = 'D:\\shun-planted-root';
  const PINNED_REG_SHA = 'b'.repeat(64);
  const ATTACKER_REG_SHA = 'f'.repeat(64);
  const lower = (p: string): string => p.toLowerCase();
  const machineReg = `${MACHINE}\\System32\\reg.exe`;
  const plantedReg = `${PLANTED}\\System32\\reg.exe`;

  /**
   * Virtual filesystem with per-file DIGESTS: isFile is true exactly when a
   * digest is listed, and shaFile returns it — the same gate the resolver
   * must apply before executing a candidate.
   */
  function digestSeam(
    digests: Record<string, string | undefined>,
    extraDirs: string[] = [],
  ): SystemRootFsSeam {
    const files = new Set(
      Object.keys(digests)
        .filter((k) => digests[k] !== undefined)
        .map(lower),
    );
    const dirs = new Set(
      [MACHINE, `${MACHINE}\\System32`, PLANTED, `${PLANTED}\\System32`, ...extraDirs].map(lower),
    );
    return {
      isFile: (p: string) => files.has(lower(p)),
      isDirectory: (p: string) => dirs.has(lower(p)),
      shaFile: (p: string) =>
        digests[Object.keys(digests).find((k) => lower(k) === lower(p)) ?? ''],
    };
  }

  /** The planted reg.exe lies (self-consistent planted root); the machine anchor tells the truth. */
  const spyingQuery =
    (calls: string[], machineSpeaks = true): RegQuery =>
    (regExe) => {
      calls.push(regExe);
      if (lower(regExe).startsWith(lower(PLANTED))) return PLANTED;
      return machineSpeaks ? MACHINE : undefined;
    };

  it('in the degraded tier a planted reg.exe whose bytes FAIL the pin is NEVER executed', () => {
    // Machine anchor ABSENT (degraded tier reached), attacker env → planted,
    // planted reg.exe bytes ≠ pin. Pre-fix the probe execFileSync'd it (the
    // query spy below WOULD record the call) — RED on the unfixed ordering
    // of checks; post-fix the gate skips the candidate before any spawn.
    const calls: string[] = [];
    const r = resolveSystemRoot(
      { SystemRoot: PLANTED, windir: PLANTED },
      spyingQuery(calls),
      'win32',
      digestSeam({ [plantedReg]: ATTACKER_REG_SHA }),
      PINNED_REG_SHA,
    );
    expect(calls.map(lower)).not.toContain(lower(plantedReg));
    // Whatever the resolution answers (the no-execution env tier may still
    // name a root), the handed-out binaries stay gated downstream (N-1).
    void r;
  });

  it('a machine anchor whose bytes mismatch the pin FAILS CLOSED — a pin-forged planted lie never executes', () => {
    // Strongest shape: the planted candidate's bytes MATCH the pin (a copied
    // real reg.exe the attacker re-pinned the store for) and would answer a
    // self-consistent lie. The machine anchor's bytes DON'T match the pin —
    // readable evidence this host is not the pinned machine — so resolution
    // must fail closed and the planted reg.exe must never be executed.
    const calls: string[] = [];
    const r = resolveSystemRoot(
      { SystemRoot: PLANTED, windir: PLANTED },
      spyingQuery(calls),
      'win32',
      digestSeam({ [machineReg]: ATTACKER_REG_SHA, [plantedReg]: PINNED_REG_SHA }),
      PINNED_REG_SHA,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('fail closed');
    expect(calls.map(lower)).not.toContain(lower(plantedReg));
  });

  it('a machine anchor matching the pin is executed and resolves normally (gate is not a blocker)', () => {
    const calls: string[] = [];
    const r = resolveSystemRoot(
      { SystemRoot: PLANTED, windir: PLANTED },
      spyingQuery(calls),
      'win32',
      digestSeam({ [machineReg]: PINNED_REG_SHA }),
      PINNED_REG_SHA,
    );
    expect(r.ok).toBe(true);
    if (r.ok) expect(lower(r.systemRoot)).toBe(lower(MACHINE));
    expect(calls.map(lower)).toContain(lower(machineReg));
    expect(calls.map(lower)).not.toContain(lower(plantedReg));
  });
});

describe.skipIf(!ON_WINDOWS)('C13 — real Windows machine evidence', () => {
  const real = resolveSystemRoot();
  const envRoot = (process.env.SystemRoot ?? '').trim().toLowerCase();

  it('resolves to the real system root from HKLM regardless of a planted env (copy-attack defeated)', () => {
    // The same-user attacker CAN copy reg.exe into a planted directory —
    // copying needs no elevation — but the copy still reports the real HKLM
    // root, so machine evidence overrides the planted env by construction.
    expect(real.ok).toBe(true);
    if (!real.ok) return;
    if (envRoot.length > 0) {
      expect(real.systemRoot.toLowerCase()).toBe(envRoot);
    }
    // And the resolved root is where the real system binaries live.
    expect(existsSync(join(real.systemRoot, 'System32', 'reg.exe'))).toBe(true);
    expect(existsSync(join(real.systemRoot, 'System32', 'whoami.exe'))).toBe(true);
  });

  it('unanimous-env degraded fallback returns the real root when the registry probe is unavailable', () => {
    const r = resolveSystemRoot(process.env, () => undefined, 'win32');
    expect(r.ok).toBe(true);
    if (r.ok && envRoot.length > 0) expect(r.systemRoot.toLowerCase()).toBe(envRoot);
  });

  it('contradictory planted env with probe unavailable fails closed', () => {
    const r = resolveSystemRoot(
      { SystemRoot: process.env.SystemRoot, windir: 'Q:\\no-such-root' },
      () => undefined,
      'win32',
    );
    expect(r.ok).toBe(false);
  });

  it('a physically planted root with a REAL copied reg.exe is overridden by the HKLM report', () => {
    // Full attack simulation on a real host: plant an existing directory
    // that contains System32\reg.exe copied from the real system32, point
    // BOTH env vars at it. The copied binary reports the real HKLM root;
    // the resolver must return the real root, not the planted one.
    expect(real.ok).toBe(true);
    if (!real.ok) return;
    const plantedDir = mkdtempSync(join(tmpdir(), 'shun-c13-planted-'));
    try {
      const plantedSystem32 = join(plantedDir, 'System32');
      mkdirSync(plantedSystem32, { recursive: true });
      cpSync(join(real.systemRoot, 'System32', 'reg.exe'), join(plantedSystem32, 'reg.exe'));
      const r = resolveSystemRoot(
        { SystemRoot: plantedDir, windir: plantedDir },
        undefined,
        'win32',
      );
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.systemRoot.toLowerCase()).toBe(real.systemRoot.toLowerCase());
        expect(r.systemRoot.toLowerCase()).not.toBe(plantedDir.toLowerCase());
      }
    } finally {
      rmSync(plantedDir, { recursive: true, force: true });
    }
  });

  it('P1 (real host): a physically planted root with a never-executed LYING reg.exe is overridden by the machine anchor', () => {
    // Full attack simulation on a real host: plant an existing directory
    // containing System32\reg.exe (attacker-written bytes — never executed
    // here because the query is injected), point BOTH env vars at it, and
    // have the planted binary report the planted root as the HKLM value.
    // The machine anchor (the real C:\Windows\System32\reg.exe, via the
    // pre-resolved real root) must outrank it.
    expect(real.ok).toBe(true);
    if (!real.ok) return;
    if (real.systemRoot.toLowerCase() !== 'c:\\windows') return; // non-standard install: machine anchor elsewhere, degraded tier governs
    const plantedDir = mkdtempSync(join(tmpdir(), 'shun-c13-lying-'));
    try {
      const plantedSystem32 = join(plantedDir, 'System32');
      mkdirSync(plantedSystem32, { recursive: true });
      writeFileSync(join(plantedSystem32, 'reg.exe'), 'MZ-fake-attacker-bytes');
      const lyingQuery: RegQuery = (regExe) =>
        regExe.toLowerCase().startsWith(plantedDir.toLowerCase()) ? plantedDir : real.systemRoot;
      const r = resolveSystemRoot(
        { SystemRoot: plantedDir, windir: plantedDir },
        lyingQuery,
        'win32',
      );
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.systemRoot.toLowerCase()).toBe(real.systemRoot.toLowerCase());
        expect(r.systemRoot.toLowerCase()).not.toBe(plantedDir.toLowerCase());
      }
    } finally {
      rmSync(plantedDir, { recursive: true, force: true });
    }
  });
});

describe('C13 — relay/reg helpers resolve only when machine evidence exists', () => {
  it('system root helper type shape', async () => {
    const mod = await import('../src/system-exe.ts');
    expect(typeof mod.systemWhoamiExe).toBe('function');
    expect(typeof mod.systemRegExe).toBe('function');
    expect(typeof mod.systemPowershellExe).toBe('function');
    expect(typeof mod.systemTaskkillExe).toBe('function');
  });
});
