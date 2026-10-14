import { describe, expect, it } from 'vitest';
import {
  collectSystemInventoryWithTrustedHost,
  collectWindowsSystemInventory,
  suggestReadonlyOptimizations,
  type SystemInventoryHost,
} from '../src/index.ts';

function trustedHost(): SystemInventoryHost {
  return {
    availableParallelism: () => 8,
    cpuCount: () => 8,
    totalMemory: () => 16_000,
    freeMemory: () => 8_000,
    uptime: () => 3600,
    diskTotals: () => ({ total: 100_000, free: 60_000 }),
  };
}

describe('v0.2 readonly Windows system inventory', () => {
  it('returns bounded local-only facts without paths, user names or env values', () => {
    const result = collectSystemInventoryWithTrustedHost(trustedHost(), 'win32');
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot).toMatchObject({
      localOnly: true,
      externalDisclosures: [],
      platform: 'win32',
      cpuLogicalCount: 8,
      memoryTotalBytes: 16000,
      diskFreeBytes: 60000,
    });
    const exported = JSON.stringify(result);
    expect(exported).not.toContain('username');
    expect(exported).not.toContain('PATH');
    expect(exported).not.toContain('SHUN_CANARY_PRIVATE_KEY');
    expect(suggestReadonlyOptimizations(result)).toEqual([]);
  });

  it('refuses non-Windows before touching the host', () => {
    let called = false;
    const fake: SystemInventoryHost = {
      ...trustedHost(),
      cpuCount: () => {
        called = true;
        return 2;
      },
    };
    expect(collectSystemInventoryWithTrustedHost(fake, 'linux')).toEqual({
      ok: false,
      code: 'WINDOWS_REQUIRED',
    });
    expect(called).toBe(false);
  });

  it('replaces exception details with fixed code, never leaking private canaries', () => {
    const fake: SystemInventoryHost = {
      ...trustedHost(),
      diskTotals: () => {
        throw new Error('SHUN_CANARY_PRIVATE_KEY C:/Users/Secret/notes.txt');
      },
    };
    const result = collectSystemInventoryWithTrustedHost(fake, 'win32');
    expect(result).toEqual({ ok: false, code: 'SYSTEM_OBSERVATION_UNAVAILABLE' });
    expect(JSON.stringify(result)).not.toContain('SHUN_CANARY_PRIVATE_KEY');
  });

  it('rejects NaN, negative, inconsistent, astronomical or noninteger telemetry', () => {
    for (const value of [-1, Number.NaN, Number.POSITIVE_INFINITY, 1.2]) {
      const fake: SystemInventoryHost = { ...trustedHost(), freeMemory: () => value };
      expect(collectSystemInventoryWithTrustedHost(fake, 'win32')).toEqual({
        ok: false,
        code: 'SYSTEM_OBSERVATION_INVALID',
      });
    }
    const inflated: SystemInventoryHost = {
      ...trustedHost(),
      diskTotals: () => ({ total: 100, free: 101 }),
    };
    expect(collectSystemInventoryWithTrustedHost(inflated, 'win32').ok).toBe(false);
  });

  it('suggestions remain explicitly nonmutating even when thresholds breached', () => {
    const fake: SystemInventoryHost = {
      ...trustedHost(),
      freeMemory: () => 100,
      diskTotals: () => ({ total: 100_000, free: 100 }),
    };
    const result = collectSystemInventoryWithTrustedHost(fake, 'win32');
    expect(suggestReadonlyOptimizations(result)).toEqual([
      { kind: 'LOW_DISK_SPACE', effect: 'NONE', action: 'REVIEW_STORAGE' },
      { kind: 'LOW_FREE_MEMORY', effect: 'NONE', action: 'REVIEW_APPLICATIONS' },
    ]);
  });

  it('the public entrypoint cannot be spoofed by a JavaScript extra runner argument', () => {
    expect(collectWindowsSystemInventory.length).toBe(0);
    if (process.platform !== 'win32') {
      const injected = collectWindowsSystemInventory as unknown as (x: unknown) => unknown;
      expect(injected({ platform: 'win32', diskTotals: () => ({ total: 1, free: 1 }) })).toEqual({
        ok: false,
        code: 'WINDOWS_REQUIRED',
      });
    }
  });
});
