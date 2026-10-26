import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  cloudInterpreterFromEnvironment,
  TrustedCloudInterpreter,
} from '../src/cloud-interpret.ts';
import { startHarness } from './helpers.ts';

// These are safety/interface checks, NOT a claim to have paid for a real
// DeepSeek call or clicked a physical Windows consent dialog in CI.
describe('T08 C03 real DeepSeek composition pre-send boundary', () => {
  it('keeps real sending disabled when the trusted host has not opted in', async () => {
    const h = await startHarness();
    try {
      expect((await h.get('/api/cloud/status')).body).toEqual({
        enabled: false,
        provider: 'deepseek',
        model: 'deepseek-flash',
        osConsentRequired: true,
        tasksSimulated: true,
      });
      const r = await h.post('/api/cloud/interpret', { goalText: '检查磁盘空间' });
      expect(r.status).toBe(503);
      expect(r.body).toEqual({ error: { code: 'CLOUD_UNAVAILABLE' } });
      expect((await h.get('/api/tasks')).body).toEqual({ tasks: [] });
    } finally {
      await h.close();
    }
  });

  it('rejects invented provider, credentials and forged approval in route body', async () => {
    const h = await startHarness();
    try {
      for (const body of [
        { goalText: '' },
        { goalText: 'x'.repeat(8193) },
        { goalText: 'hello', provider: 'evil' },
        { goalText: 'hello', approval: { issuer: { proof: 'fake' } } },
        { goalText: 'hello', apiKey: 'forged' },
        { goalText: 'hello', maxCostMicros: 0 },
      ]) {
        const r = await h.post('/api/cloud/interpret', body);
        expect(r.status).toBe(400);
        expect(r.body).toEqual({ error: { code: 'CLOUD_GOAL_INVALID' } });
      }
    } finally {
      await h.close();
    }
  });

  it('refuses a trusted-host offline mode before loading broker or reaching HTTPS', async () => {
    const cloud = new TrustedCloudInterpreter({
      ledgerFile: resolve('test-cloud-no-connect.sqlite'),
      registryRevision: 'registry-test',
      policyRevision: 'policy-test',
      scopeRevision: 'scope-test',
      pricingRevision: 'pricing-test',
      revocationEpoch: 0,
      inputMicrosPerToken: 1,
      outputMicrosPerToken: 1,
      maxInputTokens: 2048,
      maxOutputTokens: 128,
      maxCostMicros: 10000,
      isCurrent: () => true,
      isOffline: () => true,
      readApiKey: () => 'never-sent-key',
    });
    expect(cloud.status().enabled).toBe(false);
    expect(await cloud.interpretGoal('Diagnose disk')).toEqual({
      ok: false,
      code: 'CLOUD_UNAVAILABLE',
    });
  });

  it('does not enable cloud mode by default or with a caller request', () => {
    const prior = process.env.SHUN_CLOUD_ENABLED;
    try {
      delete process.env.SHUN_CLOUD_ENABLED;
      expect(cloudInterpreterFromEnvironment()).toBeUndefined();
    } finally {
      if (prior === undefined) delete process.env.SHUN_CLOUD_ENABLED;
      else process.env.SHUN_CLOUD_ENABLED = prior;
    }
  });
});
