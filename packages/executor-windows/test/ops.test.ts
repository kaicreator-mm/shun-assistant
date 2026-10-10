// Typed op surface tests: the allowlist is structural — unknown ops and
// unknown parameter keys are refusals; shell metacharacters are DATA and pass
// byte-exact; NTFS-illegal path characters fail closed.
import { describe, expect, it } from 'vitest';
import {
  checkRegistryKey,
  checkStepSurface,
  checkWindowsPath,
  EXECUTOR_OPS,
  ExecutorStepSchema,
} from '../src/ops.ts';

describe('op allowlist', () => {
  it('exposes exactly the frozen executor ops', () => {
    expect(EXECUTOR_OPS).toEqual([
      'windows.proc.contextCheck',
      'windows.fs.write',
      'windows.fs.delete',
      'windows.fs.verify',
      'windows.registry.createKey',
      'windows.registry.setValue',
      'windows.registry.deleteKey',
      'windows.registry.verify',
      'windows.proc.exec',
    ]);
  });

  it('refuses unknown ops structurally (no shell endpoint)', () => {
    for (const op of [
      'shell.exec',
      'proc.exec',
      'windows.shell',
      'cmd.run',
      'windows.fs.glob-delete',
    ]) {
      const r = ExecutorStepSchema.safeParse({ op, args: {} });
      expect(r.success, op).toBe(false);
    }
  });

  it('refuses unknown parameter keys (no helper-path / fault smuggling)', () => {
    expect(
      ExecutorStepSchema.safeParse({
        op: 'windows.fs.write',
        args: { path: 'C:\\x\\f.txt', content: 'x', helperPath: 'C:\\evil\\helper.mjs' },
      }).success,
    ).toBe(false);
    expect(
      ExecutorStepSchema.safeParse({
        op: 'windows.proc.exec',
        args: { program: 'C:\\x\\p.exe', args: [], shell: 'cmd.exe /c' },
      }).success,
    ).toBe(false);
  });
});

describe('checkWindowsPath', () => {
  it('accepts absolute NTFS paths', () => {
    expect(checkWindowsPath('C:\\work\\file.txt').ok).toBe(true);
    expect(checkWindowsPath('\\\\server\\share\\dir\\f').ok).toBe(true);
  });

  it('refuses relative paths and bogus drive forms', () => {
    expect(checkWindowsPath('relative\\file.txt').ok).toBe(false);
    expect(checkWindowsPath('C:file.txt').ok).toBe(false);
  });

  it('fails closed on traversal segments on either side', () => {
    expect(checkWindowsPath('C:\\work\\..\\protected').ok).toBe(false);
    expect(checkWindowsPath('C:\\work\\sub\\..\\..\\x').ok).toBe(false);
  });

  it('fails closed on NTFS-illegal characters', () => {
    for (const ch of ['<', '>', '"', '|', '?', '*', '\u0007', '\u0000']) {
      expect(checkWindowsPath(`C:\\work\\bad${ch}name`).ok, ch).toBe(false);
    }
    // `:` beyond the drive position (ADS / NtObject paths)
    expect(checkWindowsPath('C:\\work\\file.txt:stream').ok).toBe(false);
  });

  it('allows shell metacharacters — they are data, not syntax', () => {
    // `|` is absent here on purpose: it is ALSO Win32-illegal in filenames
    // and fails closed with the other reserved characters.
    for (const name of ['a&b', 'a;b', 'a%PATH%b', "a'b", 'a`b', 'a$(whoami)b', 'a & b.txt']) {
      expect(checkWindowsPath(`C:\\work\\${name}`).ok, name).toBe(true);
    }
  });

  it('fails closed on trailing dots/spaces Win32 would strip', () => {
    expect(checkWindowsPath('C:\\work\\file.').ok).toBe(false);
    expect(checkWindowsPath('C:\\work\\file ').ok).toBe(false);
  });

  it('fails closed on reserved device names', () => {
    for (const name of ['CON', 'nul.txt', 'COM1.txt', 'LPT9.bak']) {
      expect(checkWindowsPath(`C:\\work\\${name}`).ok, name).toBe(false);
    }
  });
});

describe('checkRegistryKey', () => {
  it('accepts real-hive keys', () => {
    expect(checkRegistryKey('HKLM\\SOFTWARE\\Shun').ok).toBe(true);
    expect(checkRegistryKey('HKEY_CURRENT_USER\\Software\\Shun').ok).toBe(true);
  });

  it('refuses non-hive roots, wildcards and illegal segments', () => {
    expect(checkRegistryKey('SOFTWARE\\Shun').ok).toBe(false);
    expect(checkRegistryKey('HKLM\\SOFTWARE\\*').ok).toBe(false);
    expect(checkRegistryKey('HKLM\\SOFTWARE\\Shun\\..\\Evil').ok).toBe(false);
    expect(checkRegistryKey('HKLM\\SOFTWARE\\Shun"').ok).toBe(false);
  });
});

describe('checkStepSurface', () => {
  it('validates each op family against its path rules', () => {
    expect(
      checkStepSurface({
        op: 'windows.fs.write',
        args: { path: 'C:\\a\\..\\b', content: 'x', encoding: 'utf8' },
      }).ok,
    ).toBe(false);
    expect(
      checkStepSurface({
        op: 'windows.proc.exec',
        args: { program: 'not-absolute', args: [], expectExitCode: 0, captureCapBytes: 1 },
      }).ok,
    ).toBe(false);
    expect(
      checkStepSurface({ op: 'windows.proc.contextCheck', args: { expectElevated: true } }).ok,
    ).toBe(true);
  });
});
