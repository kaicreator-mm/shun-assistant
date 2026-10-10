// EnvironmentFacts probe hygiene: the token-state probe must be anchored to
// SystemRoot, never resolved via PATH (review finding: a PATH-injected fake
// whoami.exe could get a filtered token judged ELEVATED_ADMIN).
import { existsSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { whoamiGroups } from '../src/facts.ts';
import { systemWhoamiExe } from '../src/system-exe.ts';
import { ON_WINDOWS } from './helpers.ts';

describe('whoami token probe anchoring', () => {
  it('resolves whoami.exe under SystemRoot (same convention as reg.exe/powershell.exe)', () => {
    const exe = systemWhoamiExe();
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
        const csv = await whoamiGroups();
        // The real `whoami /groups` CSV always carries at least the mandatory
        // S-1-16 integrity SID; a PATH-dependent probe would have failed to
        // spawn and degraded to ''.
        expect(csv).toContain('S-1-');
      } finally {
        for (const key of pathKeys) {
          if (saved[key] === undefined) delete process.env[key];
          else process.env[key] = saved[key];
        }
      }
    });
  });

  it('degrades honestly off-Windows (empty capture, never fabricated)', async () => {
    if (process.platform === 'win32') return; // covered by the case above
    expect(await whoamiGroups()).toBe('');
  });
});
