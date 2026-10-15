import { describe, expect, it } from 'vitest';
import { projectReadonlyDiagnosis, collectWindowsReadonlyDiagnosis } from '../src/diagnostics.ts';
import type { SystemInventoryResult } from '../src/index.ts';
import type { RuntimeCountResult } from '../src/internal/windows-counts.ts';

const inventory: SystemInventoryResult = {
  ok: true,
  snapshot: {
    schema: 'shun.system-inventory.v02',
    platform: 'win32',
    localOnly: true,
    externalDisclosures: [],
    provenance: 'node:os+node:fs:statfs',
    cpuLogicalCount: 8,
    memoryTotalBytes: 1000,
    memoryFreeBytes: 40,
    diskTotalBytes: 10000,
    diskFreeBytes: 500,
    uptimeSeconds: 42,
  },
};
const runtime: RuntimeCountResult = {
  ok: true,
  facts: {
    schema: 'shun.windows-runtime-counts.v02',
    localOnly: true,
    externalDisclosures: [],
    processCount: 123,
    startupEntryCount: 9,
    provenance: 'fixed-readonly-powershell',
  },
};

describe('T06 deterministic readonly system diagnosis', () => {
  it('reports measured counts plus only conservative advisory suggestions', () => {
    const result = projectReadonlyDiagnosis(inventory, runtime);
    expect(result).toMatchObject({
      ok: true,
      report: {
        status: 'OBSERVED_ONLY',
        localOnly: true,
        externalDisclosures: [],
        signals: ['LOW_DISK_SPACE', 'LOW_FREE_MEMORY'],
        advice: [
          { action: 'REVIEW_STORAGE', effect: 'NONE' },
          { action: 'REVIEW_APPLICATIONS', effect: 'NONE' },
        ],
        limitation: 'SINGLE_SNAPSHOT_NO_ROOT_CAUSE_OR_SPEEDUP_CLAIM',
      },
    });
    const raw = JSON.stringify(result);
    expect(raw).not.toContain('C:/Users/');
    expect(raw).not.toContain('Bearer');
    expect(raw).not.toContain('processName');
    expect(raw).not.toContain('DISK_CLEANUP_EXECUTED');
  });

  it('refuses malformed measurements rather than emitting an invented optimization', () => {
    if (!inventory.ok) throw new Error('fixture unavailable');
    const wrong: SystemInventoryResult = {
      ok: true,
      snapshot: { ...inventory.snapshot, diskFreeBytes: inventory.snapshot.diskTotalBytes + 1 },
    };
    expect(projectReadonlyDiagnosis(wrong, runtime)).toEqual({
      ok: false,
      code: 'OBSERVATION_INVALID',
    });
  });

  it('does not infer performance improvements from normal counts', () => {
    if (!inventory.ok) throw new Error('fixture unavailable');
    const normal: SystemInventoryResult = {
      ok: true,
      snapshot: { ...inventory.snapshot, diskFreeBytes: 5000, memoryFreeBytes: 500 },
    };
    const result = projectReadonlyDiagnosis(normal, runtime);
    expect(result).toMatchObject({
      ok: true,
      report: { signals: [], advice: [], status: 'OBSERVED_ONLY' },
    });
  });

  it('does not hide a denied or unavailable native observation', () => {
    expect(projectReadonlyDiagnosis(inventory, { ok: false, code: 'PROCESS_FACTS_UNAVAILABLE' }))
      .toEqual({ ok: false, code: 'OBSERVATION_UNAVAILABLE' });
    expect(projectReadonlyDiagnosis({ ok: false, code: 'WINDOWS_REQUIRED' }, runtime))
      .toEqual({ ok: false, code: 'WINDOWS_REQUIRED' });
  });

  it('public entrypoint has zero injectable parameters and fails closed on non-Windows', () => {
    expect(collectWindowsReadonlyDiagnosis.length).toBe(0);
    if (process.platform !== 'win32') {
      expect(collectWindowsReadonlyDiagnosis()).toEqual({
        ok: false,
        code: 'WINDOWS_REQUIRED',
      });
    }
  });
});
