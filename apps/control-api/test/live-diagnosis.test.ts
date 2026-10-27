import { describe, expect, it } from 'vitest';
import { startHarness } from './helpers.ts';

describe('T08 C07 real local read-only diagnosis route', () => {
  it('never substitutes Demo tasks or a model for a Windows observation', async () => {
    const h = await startHarness();
    try {
      const outcome = await h.get('/api/system/diagnosis');
      if (outcome.status === 200) {
        expect(outcome.body).toMatchObject({
          ok: true,
          source: 'LIVE_WINDOWS_LOCAL_READONLY',
          recipeExecuted: false,
          cloudCalls: 0,
          report: {
            schema: 'shun.windows-diagnostic-report.v02',
            status: 'OBSERVED_ONLY',
            localOnly: true,
            externalDisclosures: [],
            limitation: 'SINGLE_SNAPSHOT_NO_ROOT_CAUSE_OR_SPEEDUP_CLAIM',
          },
        });
        const report = (outcome.body as { report: {
          evidence: { processCount: number; startupEntryCount: number };
          advice: Array<{ action: string; effect: string }>;
        } }).report;
        expect(report.evidence.processCount).toBeGreaterThanOrEqual(0);
        expect(report.evidence.startupEntryCount).toBeGreaterThanOrEqual(0);
        expect(report.advice.every((advice) => advice.effect === 'NONE')).toBe(true);
      } else {
        expect(outcome).toEqual({
          status: 503,
          body: { ok: false, code: 'LIVE_DIAGNOSIS_UNAVAILABLE' },
        });
      }
      if (process.platform !== 'win32') {
        expect(outcome.status).toBe(503);
      }
      expect((await h.get('/api/tasks')).body).toEqual({ tasks: [] });
    } finally {
      await h.close();
    }
  });

  it('refuses caller options and does not turn a requested command into system input', async () => {
    const h = await startHarness();
    try {
      for (const query of [
        '?processName=secret.exe',
        '?path=C%3A%5CUsers',
        '?script=Get-Process',
        '?cloud=true',
      ]) {
        expect(await h.get(`/api/system/diagnosis${query}`)).toEqual({
          status: 400,
          body: { ok: false, code: 'DIAGNOSIS_INPUT_REFUSED' },
        });
      }
      expect((await h.get('/api/tasks')).body).toEqual({ tasks: [] });
    } finally {
      await h.close();
    }
  });
});
