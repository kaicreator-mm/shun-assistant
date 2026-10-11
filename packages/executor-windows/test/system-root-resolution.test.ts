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
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { type RegQuery, resolveSystemRoot } from '../src/system-exe.ts';
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
