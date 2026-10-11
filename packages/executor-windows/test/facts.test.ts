// EnvironmentFacts probe hygiene: the token-state probe must be anchored to
// the machine-evidenced SystemRoot (never PATH) AND, since N-1, verified
// against the authority store's system-tools identity pin — an unpinned or
// mismatched whoami degrades the observation honestly instead of reporting.
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { observeEnvironment, whoamiGroups, wingetFromMachineOwnedPath } from '../src/facts.ts';
import { systemWhoamiExe } from '../src/system-exe.ts';
import { ON_WINDOWS, writeHostSystemToolsPin } from './helpers.ts';

const pinnedDirs: string[] = [];

function pinnedAuthorityDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'shun-facts-pin-'));
  mkdirSync(dir, { recursive: true });
  writeHostSystemToolsPin(dir);
  pinnedDirs.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of pinnedDirs) rmSync(dir, { recursive: true, force: true });
});

describe('whoami token probe anchoring + identity pin (N-1)', () => {
  it('resolves whoami.exe under SystemRoot only through a pinned authority store', () => {
    // Without an authority anchor the probe refuses to resolve (fail closed).
    expect(systemWhoamiExe(undefined)).toBeUndefined();
    const exe = systemWhoamiExe(pinnedAuthorityDir());
    // Off-Windows the resolution is a harmless best-effort constant.
    if (exe === undefined) return;
    expect(exe.toLowerCase()).toContain('system32');
    expect(exe.toLowerCase().endsWith('whoami.exe')).toBe(true);
    // On a Windows host the anchored location is the real binary — proving
    // resolution never depends on the (attacker-controlled) PATH.
    if (process.platform === 'win32') expect(existsSync(exe)).toBe(true);
  });

  describe.skipIf(!ON_WINDOWS)('real probe (win32)', () => {
    const pathKeys = ['Path', 'PATH'];
    const saved: Record<string, string | undefined> = {};

    it('still observes the real token with PATH wiped (PATH-injection immune)', async () => {
      for (const key of pathKeys) {
        saved[key] = process.env[key];
        process.env[key] = '';
      }
      try {
        const csv = await whoamiGroups(pinnedAuthorityDir());
        // The real `whoami /groups` CSV always carries at least the mandatory
        // S-1-16 integrity SID; a PATH-dependent or unpinned probe would have
        // failed to spawn and degraded to ''.
        expect(csv).toContain('S-1-');
      } finally {
        for (const key of pathKeys) {
          if (saved[key] === undefined) delete process.env[key];
          else process.env[key] = saved[key];
        }
      }
    });

    it('degrades honestly without an authority anchor (empty capture, never fabricated)', async () => {
      expect(await whoamiGroups(undefined)).toBe('');
    });
  });

  it('degrades honestly off-Windows (empty capture, never fabricated)', async () => {
    if (process.platform === 'win32') return; // covered by the cases above
    expect(await whoamiGroups(pinnedAuthorityDir())).toBe('');
  });
});

describe('N-R2-3 — winget capability is reported only through machine-owned evidence', () => {
  const attackerDirs: string[] = [];
  function attackerDirWithWinget(): string {
    const dir = mkdtempSync(join(tmpdir(), 'shun-winget-attacker-'));
    writeFileSync(join(dir, 'winget.exe'), 'MZ-attacker-planted');
    attackerDirs.push(dir);
    return dir;
  }
  afterAll(() => {
    for (const dir of attackerDirs) rmSync(dir, { recursive: true, force: true });
  });

  it('a winget.exe planted on the attacker-controlled PATH is NOT reported as a capability', async () => {
    const dir = attackerDirWithWinget();
    const saved = process.env.Path;
    process.env.Path = dir;
    try {
      // The probe itself refuses the attacker-owned directory.
      expect(wingetFromMachineOwnedPath(`${dir};C:\\ nowhere`, (c) => existsSync(c))).toBe(false);
      // And the planner-facing capability list never contains the forgery.
      const facts = await observeEnvironment({ workspaceRoot: tmpdir() });
      expect(facts.runtimeCapabilities).not.toContain('winget');
    } finally {
      if (saved === undefined) delete process.env.Path;
      else process.env.Path = saved;
    }
  });

  it('empty/unset PATH never fabricates the capability (honest degrade)', () => {
    expect(wingetFromMachineOwnedPath('', () => true)).toBe(false);
    expect(wingetFromMachineOwnedPath('   ;  ', () => true)).toBe(false);
  });

  it.skipIf(!ON_WINDOWS)(
    'a PATH hit inside a machine-owned root IS accepted (positive control)',
    () => {
      // The acceptance path is proven with the REAL machine root: an injected
      // fileExists that answers only for the well-known Program Files location
      // (planting there needs admin — out of the same-user threat model — so
      // the file itself is simulated while the containment is real).
      const probe = 'C:\\Program Files\\Common Files';
      if (!existsSync(probe)) return; // exotic host: containment target missing
      expect(
        wingetFromMachineOwnedPath(
          probe,
          (candidate) => candidate.toLowerCase() === `${probe.toLowerCase()}\\winget.exe`,
        ),
      ).toBe(true);
    },
  );
});
