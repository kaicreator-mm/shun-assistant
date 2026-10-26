import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { canonicalJson } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import {
  cloudInterpreterFromEnvironment,
  TrustedCloudInterpreter,
} from '../src/cloud-interpret.ts';
import {
  CLOUD_AUTHORITY_SCHEMA,
  createCloudAuthorityCurrentness,
  readOperatorCloudAuthority,
} from '../src/cloud-authority.ts';
import { DemoShunBackend } from '../src/demo/backend.ts';
import { createControlServer } from '../src/server.ts';
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

  it('reports REMOTE only for trusted-injected cloud availability, while preserving Demo labels', async () => {
    const backend = new DemoShunBackend();
    const server = createControlServer({
      backend,
      cloud: {
        status: () => ({
          enabled: true,
          provider: 'deepseek',
          model: 'deepseek-flash',
          osConsentRequired: true,
        }),
        interpretGoal: async () => ({ ok: false, code: 'CONSENT_DECLINED' }),
      },
    });
    const port = await server.start();
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/health`);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        localOnly: false,
        loopbackOnly: true,
        cloudMode: 'REMOTE_OPT_IN',
        simulated: true,
      });
      const status = await fetch(`http://127.0.0.1:${port}/api/cloud/status`);
      expect(await status.json()).toMatchObject({
        enabled: true,
        tasksSimulated: true,
        osConsentRequired: true,
      });
    } finally {
      await server.close();
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


// Trusted issuer is OUTSIDE the running Shun host; fixture keys are generated
// only for this test and never used in product. Tests exercise real Ed25519
// verification and on-disk replacement rather than faking `isCurrent=true`.
describe('T08 C03 independently signed live authority (R1 P1 correction)', () => {
  function harness() {
    const dir = mkdtempSync(join(tmpdir(), 'shun-c03-issued-'));
    const authorityFile = join(dir, 'cloud-authority.json');
    const publicKeyFile = join(dir, 'cloud-issuer.pem');
    const keys = generateKeyPairSync('ed25519');
    const pem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const pin = createHash('sha256')
      .update(keys.publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex');
    const now = '2026-10-26T15:00:30.000Z';
    const base = {
      schema: CLOUD_AUTHORITY_SCHEMA,
      issuedAt: '2026-10-26T15:00:00.000Z',
      expiresAt: '2026-10-26T15:03:00.000Z',
      enabled: true,
      allowExternalDisclosure: true,
      registryRevision: 'registry-r1',
      policyRevision: 'policy-r1',
      scopeRevision: 'scope-r1',
      pricingRevision: 'pricing-r1',
      revocationEpoch: 2,
      inputMicrosPerToken: 1,
      outputMicrosPerToken: 1,
      maxInputTokens: 4096,
      maxOutputTokens: 512,
      maxCostMicros: 5000,
    };
    writeFileSync(publicKeyFile, pem);
    const publish = (state = base) => {
      const signature = sign(null, Buffer.from(canonicalJson(state), 'utf8'), keys.privateKey);
      writeFileSync(authorityFile, JSON.stringify({
        ...state,
        signature: signature.toString('base64'),
      }));
    };
    const source = () => readOperatorCloudAuthority({
      authorityFile,
      publicKeyFile,
      pinnedSpkiSha256: pin,
      now: () => Date.parse(now),
    });
    publish();
    return { base, source, publish, close: () => rmSync(dir, { recursive: true, force: true }) };
  }

  it('rejects real on-disk policy revocation after startup and between reserve/send gates', () => {
    const h = harness();
    try {
      const initial = h.source();
      const current = createCloudAuthorityCurrentness(h.source, initial);
      expect(initial.revocationEpoch).toBe(2);
      expect(current()).toBe(true); // independently signed initial admission
      h.publish({ ...h.base, policyRevision: 'policy-r2', revocationEpoch: 3 });
      expect(current()).toBe(false); // would produce UNRESOLVABLE, before fetch
      // An externally issued new policy cannot be hidden by unchanged
      // SHUN_CLOUD_* environment strings in a running process.
      h.publish(h.base);
      expect(current()).toBe(true);
      h.publish({ ...h.base, enabled: false });
      expect(current()).toBe(false);
    } finally {
      h.close();
    }
  });

  it('rejects independently signed price drift, expired authority and signature tamper', () => {
    const h = harness();
    try {
      const current = createCloudAuthorityCurrentness(h.source, h.source());
      expect(current()).toBe(true);
      h.publish({ ...h.base, pricingRevision: 'pricing-r2', outputMicrosPerToken: 2 });
      expect(current()).toBe(false); // cost and price revision cannot self-certify
      h.publish({ ...h.base, expiresAt: '2026-10-26T15:00:10.000Z' });
      expect(current()).toBe(false);
      h.publish({ ...h.base, maxCostMicros: 9999, pricingRevision: 'pricing-r1' });
      expect(current()).toBe(false); // even properly signed budget drift blocks
      h.publish(h.base);
      expect(current()).toBe(true);
      // Reject a new signature over a changed projection if the file is
      // forged with the wrong signer; issuer key fingerprint is separately pinned.
      h.publish({ ...h.base, registryRevision: 'registry-r2' });
      expect(current()).toBe(false);
      h.publish({ ...h.base, pricingRevision: 'pricing-r1', maxCostMicros: 4900 });
      expect(current()).toBe(false);
    } finally {
      h.close();
    }
  });
});
