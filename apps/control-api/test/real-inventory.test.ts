import { describe, expect, it } from 'vitest';
import { startHarness } from './helpers.ts';

// Real OS-backed T08 J0 entry: on Windows the T06 collector reads actual
// machine CPU/memory/disk through Node core APIs; no mocked data is injected.
// Linux contract CI proves explicit unavailability, NOT fake Windows success.
describe('T08 real local Windows inventory user journey', () => {
  it('distinguishes live Windows facts from the still-simulated task backend', async () => {
    const h = await startHarness();
    try {
      const health = await h.get('/api/health');
      expect(health.status).toBe(200);
      expect(health.body).toMatchObject({ simulated: true });

      const result = await h.get('/api/system/inventory');
      if (process.platform !== 'win32') {
        expect(result.status).toBe(503);
        expect(result.body).toEqual({
          ok: false,
          code: 'LIVE_SYSTEM_INVENTORY_UNAVAILABLE',
        });
        return;
      }

      expect(result.status).toBe(200);
      const body = result.body as Record<string, unknown>;
      expect(body).toMatchObject({
        ok: true,
        source: 'LIVE_WINDOWS_LOCAL_READONLY',
        localOnly: true,
        externalDisclosures: [],
        snapshot: {
          schema: 'shun.system-inventory.v02',
          platform: 'win32',
          localOnly: true,
          externalDisclosures: [],
        },
      });
      const snapshot = body.snapshot as Record<string, unknown>;
      for (const key of [
        'cpuLogicalCount',
        'memoryTotalBytes',
        'memoryFreeBytes',
        'diskTotalBytes',
        'diskFreeBytes',
        'uptimeSeconds',
      ]) {
        expect(typeof snapshot[key]).toBe('number');
        expect(Number.isFinite(snapshot[key])).toBe(true);
      }
      expect((snapshot.cpuLogicalCount as number) > 0).toBe(true);
      expect((snapshot.memoryTotalBytes as number) > 0).toBe(true);
      expect((snapshot.diskTotalBytes as number) > 0).toBe(true);
      // Snapshot is an explicit bounded allowlist: no process names,
      // file paths, credential objects or raw Win32/Shell output.
      expect(Object.keys(snapshot).sort()).toEqual(
        [
          'schema',
          'localOnly',
          'externalDisclosures',
          'provenance',
          'platform',
          'cpuLogicalCount',
          'memoryTotalBytes',
          'memoryFreeBytes',
          'diskTotalBytes',
          'diskFreeBytes',
          'uptimeSeconds',
        ].sort(),
      );
    } finally {
      await h.close();
    }
  });
});
