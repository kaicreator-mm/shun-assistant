import { buildDeepSeekGoalDisclosure } from '@shun/llm-remote';
import { describe, expect, it } from 'vitest';
import { startHarness } from './helpers.ts';

// T08's browser-facing preview must reuse T01's exact projection, not a
// separately hand-written approximation of the cloud request. It is still
// NOT a signed consent; the only real T01 transport remains inaccessible.
describe('T08 exact DeepSeek Flash disclosure preview (NO SEND)', () => {
  it('shows exact T01 canonical JSON/digest but cannot issue an approval or cloud call', async () => {
    const h = await startHarness();
    try {
      const goalText = '诊断本机内存和磁盘空间，不修改任何文件';
      const expected = buildDeepSeekGoalDisclosure(goalText);
      expect(expected).not.toBeNull();

      const response = await h.post('/api/cloud/disclosure-preview', { goalText });
      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        ok: true,
        status: 'LOCAL_PREVIEW_ONLY',
        projectionJson: expected?.projectionJson,
        sha256: expected?.sha256,
        consentIssued: false,
        cloudSendAllowed: false,
        privateBrokerReady: false,
      });
      const disclosure = JSON.parse(expected?.projectionJson ?? '{}') as Record<string, unknown>;
      expect(disclosure).toMatchObject({
        destination: 'https://api.deepseek.com/chat/completions',
        modelId: 'deepseek-flash',
        disclosureCategories: ['GOAL_TEXT'],
        goalText,
      });
      expect(response.body).not.toHaveProperty('approval');
      expect(response.body).not.toHaveProperty('brokerProof');
      expect(response.body).not.toHaveProperty('apiKey');
      expect((await h.get('/api/health')).body).toMatchObject({ simulated: true });
      expect((await h.get('/api/tasks')).body).toEqual({ tasks: [] });
    } finally {
      await h.close();
    }
  });

  it('refuses extra provider fields, invalid goals and markup without authorizing sends', async () => {
    const h = await startHarness();
    try {
      const rejected = [
        { goalText: '' },
        { goalText: '  ' },
        { goalText: 'a'.repeat(8193) },
        { goalText: 'diagnose', authorization: 'USER_APPROVED' },
        { goalText: 'diagnose', endpoint: 'https://other-provider.invalid' },
        { goalText: 'diagnose', consentId: 'spoofed' },
        { goalText: 'hello\\u0000world' },
      ];
      for (const body of rejected) {
        const response = await h.post('/api/cloud/disclosure-preview', body);
        expect(response.status).toBe(400);
        expect(response.body).toEqual({ error: { code: 'DISCLOSURE_PREVIEW_INVALID' } });
      }
      expect((await h.get('/api/tasks')).body).toEqual({ tasks: [] });
    } finally {
      await h.close();
    }
  });
});
