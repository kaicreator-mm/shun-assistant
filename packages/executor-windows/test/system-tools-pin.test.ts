// T04 N-1 — system tool BINARY IDENTITY pins. The C13 fixed point
// (env hint → reg.exe report → re-report) proves nothing about WHICH BYTES
// answered the query: an attacker who plants a root with a SELF-WRITTEN
// System32\reg.exe that re-reports the planted root passes the old fixed
// point, and the resolver would then hand out the planted root's fake
// powershell.exe as the UAC relay host. The authority store therefore pins
// the real sha256 of every security-relevant system tool at provisioning
// time (the same trusted moment as the helper pin); resolution must verify
// the candidate binary against that pin and fail CLOSED on mismatch or
// missing pin.
//
// Honest boundary (documented, not hidden): a real binary COPIED into a
// planted root still passes identity (same bytes = same sha256); the
// machine-evidence path defeats it by construction (a real reg.exe copy
// reports the real root — covered in system-root-resolution.test.ts). The
// pin store itself lives inside the C06 same-user boundary — an attacker who
// can rewrite the store can re-pin their own tools; closing THAT requires
// the escalated independent trust principal.
import { cpSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { verifySystemToolExe } from '../src/system-exe.ts';
import { sha256File, writeSystemToolsPin } from '../src/trusted-store.ts';
import { createTestAuthority, ON_WINDOWS, writeHostSystemToolsPin } from './helpers.ts';

const created: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  created.push(dir);
  return dir;
}

const realRoot = process.env.SystemRoot ?? 'C:\\Windows';

describe('N-1 — verifySystemToolExe identity gate (planted-root core, host-independent)', () => {
  it('a self-written (forged) reg.exe in a planted root is refused — sha mismatch vs pin', () => {
    const planted = tempDir('shun-n1-planted-');
    const plantedSystem32 = join(planted, 'System32');
    mkdirSync(plantedSystem32, { recursive: true });
    writeFileSync(join(plantedSystem32, 'reg.exe'), 'FAKE REGINARY — not a windows binary', 'utf8');
    // The pin names the REAL reg.exe bytes (as authority provisioning would).
    let pinnedSha = 'a'.repeat(64);
    try {
      pinnedSha = sha256File(join(realRoot, 'System32', 'reg.exe'));
    } catch {
      // off-Windows: the fake-vs-pinned comparison below does not need the
      // real file — the forged bytes simply do not hash to 'a'.repeat(64).
    }
    const verdict = verifySystemToolExe(planted, 'reg', pinnedSha);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toContain('identity');
  });

  it('a REAL binary copied into a planted root passes identity (documented residual)', () => {
    // Copies are byte-identical: the identity pin cannot and must not claim
    // to distinguish a copy from the original — the copied reg.exe also
    // REPORTS the real root, which is what the machine-evidence path relies on.
    if (!ON_WINDOWS) return;
    const planted = tempDir('shun-n1-copy-');
    const plantedSystem32 = join(planted, 'System32');
    mkdirSync(plantedSystem32, { recursive: true });
    const real = join(realRoot, 'System32', 'reg.exe');
    cpSync(real, join(plantedSystem32, 'reg.exe'));
    const verdict = verifySystemToolExe(planted, 'reg', sha256File(real));
    expect(verdict.ok).toBe(true);
  });

  it('a missing pin value (record present or not, tool unlisted) fails closed', () => {
    const verdict = verifySystemToolExe(realRoot, 'whoami', undefined);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toContain('pin');
  });

  it('a nonexistent candidate binary fails closed even with a pin value present', () => {
    const planted = tempDir('shun-n1-empty-');
    mkdirSync(planted, { recursive: true });
    const verdict = verifySystemToolExe(planted, 'taskkill', 'a'.repeat(64));
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toContain('not a file');
  });
});

describe.skipIf(!ON_WINDOWS)('N-1 — resolver wrappers verify against the authority store', () => {
  it('with a pinned store, every security-relevant tool resolves to the real binary', async () => {
    const authority = await createTestAuthority('shun-n1-auth-');
    created.push(authority.root);
    const { systemWhoamiExe, systemRegExe, systemPowershellExe, systemTaskkillExe } = await import(
      '../src/system-exe.ts'
    );
    for (const [exe, suffix] of [
      [systemWhoamiExe, 'whoami.exe'],
      [systemRegExe, 'reg.exe'],
      [systemPowershellExe, 'powershell.exe'],
      [systemTaskkillExe, 'taskkill.exe'],
    ] as const) {
      const resolved = exe(authority.authorityDir);
      expect(resolved, suffix).toBeDefined();
      expect(resolved?.toLowerCase()).toContain('system32');
    }
  });

  it('with a store whose pin record is MISSING, resolution fails closed (undefined)', async () => {
    const dir = tempDir('shun-n1-nopin-');
    mkdirSync(dir, { recursive: true });
    const { systemRegExe } = await import('../src/system-exe.ts');
    expect(systemRegExe(dir)).toBeUndefined();
  });

  it('with a pin that names DIFFERENT bytes (forged/re-pinned tool), resolution refuses', async () => {
    const dir = tempDir('shun-n1-evil-');
    writeSystemToolsPin(dir, {
      schemaVersion: 'shun.executor-windows.system-tools-pin/1',
      whoamiSha256: 'a'.repeat(64),
      regSha256: 'b'.repeat(64),
      powershellSha256: 'c'.repeat(64),
      taskkillSha256: 'd'.repeat(64),
      pinnedAt: new Date().toISOString(),
    });
    const { systemRegExe } = await import('../src/system-exe.ts');
    expect(systemRegExe(dir)).toBeUndefined();
  });

  it('without any authority anchor, resolution fails closed (undefined)', async () => {
    const { systemRegExe } = await import('../src/system-exe.ts');
    expect(systemRegExe(undefined)).toBeUndefined();
  });

  it('the host pin writer records the REAL host tool digests', async () => {
    const dir = tempDir('shun-n1-host-');
    writeHostSystemToolsPin(dir);
    const { readSystemToolsPin } = await import('../src/trusted-store.ts');
    const pin = readSystemToolsPin(dir);
    expect(pin).toBeDefined();
    if (!pin) return;
    expect(pin.regSha256).toBe(sha256File(join(realRoot, 'System32', 'reg.exe')));
    expect(pin.whoamiSha256).toBe(sha256File(join(realRoot, 'System32', 'whoami.exe')));
  });

  it('F-4: the package index exports the pin provisioning API (compile-level check)', async () => {
    const index = await import('../src/index.ts');
    // Deploy tooling provisions pins through the package root, never a
    // deep import into src/.
    expect(typeof index.writeSystemToolsPin).toBe('function');
    expect(typeof index.readSystemToolsPin).toBe('function');
    expect(index.SYSTEM_TOOLS_PIN_SCHEMA_VERSION).toBe('shun.executor-windows.system-tools-pin/1');
    expect(
      index.SystemToolsPinSchema.safeParse({
        schemaVersion: 'shun.executor-windows.system-tools-pin/1',
        whoamiSha256: 'a'.repeat(64),
        regSha256: 'b'.repeat(64),
        powershellSha256: 'c'.repeat(64),
        taskkillSha256: 'd'.repeat(64),
        pinnedAt: new Date().toISOString(),
      }).success,
    ).toBe(true);
    // Same provisioning class: program byte-identity pins (N-2).
    expect(typeof index.writeProgramPin).toBe('function');
    expect(typeof index.readProgramPin).toBe('function');
    expect(index.PROGRAM_PIN_SCHEMA_VERSION).toBe('shun.executor-windows.program-pin/1');
  });
});
