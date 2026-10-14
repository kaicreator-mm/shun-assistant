import { describe, expect, it } from 'vitest';
import {
  observeRuntimeCountsWithHost,
  PROCESS_COUNT_COMMAND,
  STARTUP_COUNT_COMMAND,
} from '../src/internal/windows-counts.ts';
import { collectWindowsRuntimeCounts } from '../src/windows-runtime.ts';

describe('T06 fixed, readonly Windows process/startup observations', () => {
  it('reports counts only with fixed schema/provenance and no private names', () => {
    const scripts: string[] = [];
    const result = observeRuntimeCountsWithHost((s) => {
      scripts.push(s);
      return s === PROCESS_COUNT_COMMAND ? '93\r\n' : '8\r\n';
    }, 'win32');
    expect(result).toEqual({
      ok: true,
      facts: {
        schema: 'shun.windows-runtime-counts.v02',
        localOnly: true,
        externalDisclosures: [],
        processCount: 93,
        startupEntryCount: 8,
        provenance: 'fixed-readonly-powershell',
      },
    });
    expect(scripts).toEqual([PROCESS_COUNT_COMMAND, STARTUP_COUNT_COMMAND]);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain('C:/Users');
    expect(serialized).not.toContain('Bearer');
    expect(serialized).not.toContain('taskId');
    expect(serialized).not.toContain('powershell.exe');
  });

  it('rejects non-Windows without invoking even a fake trusted runner', () => {
    let called = false;
    expect(observeRuntimeCountsWithHost(() => {
      called = true;
      return '42';
    }, 'linux')).toEqual({ ok: false, code: 'WINDOWS_REQUIRED' });
    expect(called).toBe(false);
  });

  it('rejects leaked process names, misleading counters and out of range counts', () => {
    for (const invalid of ['12\nC:/Users/secret', '-1', '1.5', 'Infinity', '', '999999']) {
      expect(observeRuntimeCountsWithHost(() => invalid, 'win32')).toEqual({
        ok: false,
        code: 'SYSTEM_OBSERVATION_INVALID',
      });
    }
  });

  it('returns fixed errors for host failures and never reflects poisoned diagnostics', () => {
    const a = observeRuntimeCountsWithHost(() => {
      throw new Error('private path C:/Users/Alice/secrets.txt');
    }, 'win32');
    expect(a).toEqual({ ok: false, code: 'PROCESS_FACTS_UNAVAILABLE' });
    const b = observeRuntimeCountsWithHost((s) => {
      if (s === STARTUP_COUNT_COMMAND) throw new Error('Authorization Bearer SECRET');
      return '1';
    }, 'win32');
    expect(b).toEqual({ ok: false, code: 'STARTUP_FACTS_UNAVAILABLE' });
    expect(JSON.stringify(a) + JSON.stringify(b)).not.toContain('SECRET');
  });

  it('public entrypoint remains non-injectable and refuses other operating systems', () => {
    expect(collectWindowsRuntimeCounts.length).toBe(0);
    if (process.platform !== 'win32') {
      expect((collectWindowsRuntimeCounts as unknown as (arg: unknown) => unknown)({
        script: 'Remove-Item', platform: 'win32',
      })).toEqual({ ok: false, code: 'WINDOWS_REQUIRED' });
    }
  });
});
