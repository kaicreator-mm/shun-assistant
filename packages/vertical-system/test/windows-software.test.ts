import { describe, expect, it } from 'vitest';
import { observeInstalledSoftwareWithHost, SOFTWARE_COMMAND } from '../src/internal/windows-software.ts';
import { collectWindowsInstalledSoftware } from '../src/windows-runtime.ts';

describe('T06 fixed read-only HKLM software sample', () => {
  it('returns only bounded names/versions, no commands or cloud authority', () => {
    const value = observeInstalledSoftwareWithHost((script) => {
      expect(script).toBe(SOFTWARE_COMMAND);
      expect(script).not.toContain('HKCU');
      expect(script).not.toContain('Uninstall-Package');
      return JSON.stringify([{ DisplayName: 'Example App', DisplayVersion: '2.4' }]);
    }, 'win32');
    expect(value).toMatchObject({
      ok: true,
      report: {
        status: 'OBSERVED_ONLY',
        localOnly: true,
        automaticCloudDisclosure: false,
        entries: [{ name: 'Example App', version: '2.4' }],
      },
    });
    expect(JSON.stringify(value)).not.toContain('InstallLocation');
  });

  it('rejects path and secret-bearing extra keys without reflecting them', () => {
    const poison = [
      { DisplayName: 'C:/Users/private', DisplayVersion: '1' },
      { DisplayName: 'OK', DisplayVersion: '1', InstallLocation: 'Bearer-secret' },
      { DisplayName: 'OK', DisplayVersion: 'https://remote.invalid' },
    ];
    for (const row of poison) {
      expect(observeInstalledSoftwareWithHost(() => JSON.stringify(row), 'win32')).toEqual({
        ok: false,
        code: 'SOFTWARE_FACTS_INVALID',
      });
    }
  });

  it('fails closed on unavailable Windows command and non-Windows host', () => {
    let called = false;
    expect(observeInstalledSoftwareWithHost(() => {
      called = true;
      return '{}';
    }, 'linux')).toEqual({ ok: false, code: 'WINDOWS_REQUIRED' });
    expect(called).toBe(false);
    expect(observeInstalledSoftwareWithHost(() => {
      throw new Error('Bearer secret');
    }, 'win32')).toEqual({ ok: false, code: 'SOFTWARE_FACTS_UNAVAILABLE' });
  });

  it('public collector takes no untrusted options and declines off Windows', () => {
    expect(collectWindowsInstalledSoftware.length).toBe(0);
    if (process.platform !== 'win32') {
      expect(collectWindowsInstalledSoftware()).toEqual({
        ok: false,
        code: 'WINDOWS_REQUIRED',
      });
    }
  });
});
