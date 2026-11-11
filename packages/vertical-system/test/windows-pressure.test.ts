import { describe, expect, it } from 'vitest';
import {
  observeTopMemoryProcessesWithHost,
  TOP_MEMORY_PROCESS_COMMAND,
} from '../src/internal/windows-pressure.ts';
import { collectWindowsTopMemoryProcesses } from '../src/windows-runtime.ts';

const valid = JSON.stringify([
  { Name: 'MemoryApp', WorkingSet64: 9000000 },
  { Name: 'explorer', WorkingSet64: 5000000 },
]);

describe('T06 Windows bounded top-memory process evidence', () => {
  it('accepts sorted memory facts and makes no CPU/root-cause/speedup claim', () => {
    let calls = 0;
    const result = observeTopMemoryProcessesWithHost((script) => {
      calls += 1;
      expect(script).toBe(TOP_MEMORY_PROCESS_COMMAND);
      expect(script).not.toContain('Stop-Process');
      expect(script).not.toContain('Set-ItemProperty');
      expect(script).not.toContain('Invoke-Expression');
      return valid;
    }, 'win32');
    expect(calls).toBe(1);
    expect(result).toMatchObject({
      ok: true,
      facts: {
        localOnly: true,
        externalDisclosures: [],
        status: 'OBSERVED_ONLY',
        metric: 'RESIDENT_MEMORY_BYTES_AT_SNAPSHOT',
        interpretation: 'MEMORY_ONLY_NO_CPU_OR_ROOT_CAUSE_INFERENCE',
        top: [
          { name: 'MemoryApp', residentBytes: 9000000 },
          { name: 'explorer', residentBytes: 5000000 },
        ],
      },
    });
    expect(JSON.stringify(result)).not.toContain('CommandLine');
    expect(JSON.stringify(result)).not.toContain('ProcessId');
  });

  it('refuses paths, additional fields, invalid memory values and inconsistent ordering', () => {
    const adversarial = [
      [{ Name: 'C:/Users/private', WorkingSet64: 300 }],
      [{ Name: 'pwsh', WorkingSet64: -1 }],
      [{ Name: 'safe', WorkingSet64: 3, CommandLine: 'Bearer token' }],
      [
        { Name: 'low', WorkingSet64: 10 },
        { Name: 'high', WorkingSet64: 20 },
      ],
      [],
      Array.from({ length: 9 }, (_, i) => ({ Name: `p${i}`, WorkingSet64: 100 - i })),
    ];
    for (const rows of adversarial) {
      const result = observeTopMemoryProcessesWithHost(() => JSON.stringify(rows), 'win32');
      expect(result).toEqual({ ok: false, code: 'PROCESS_FACTS_INVALID' });
      expect(JSON.stringify(result)).not.toContain('private');
      expect(JSON.stringify(result)).not.toContain('token');
    }
  });

  it('fails closed for unavailable runner and non-Windows without invoking runner', () => {
    let calls = 0;
    const denied = observeTopMemoryProcessesWithHost(() => {
      calls += 1;
      return valid;
    }, 'linux');
    expect(denied).toEqual({ ok: false, code: 'WINDOWS_REQUIRED' });
    expect(calls).toBe(0);
    expect(
      observeTopMemoryProcessesWithHost(() => {
        throw new Error('C:/Users/secret');
      }, 'win32'),
    ).toEqual({ ok: false, code: 'PROCESS_FACTS_UNAVAILABLE' });
  });

  it('native public API has zero injectable parameters and refuses non-Windows', () => {
    expect(collectWindowsTopMemoryProcesses.length).toBe(0);
    if (process.platform !== 'win32') {
      expect(collectWindowsTopMemoryProcesses()).toEqual({
        ok: false,
        code: 'WINDOWS_REQUIRED',
      });
    }
  });
});
