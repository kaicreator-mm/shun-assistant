// T10 I02: short-lived TEST-ONLY operator signing + live native DeepSeek run.
// This is NOT a production publisher identity, silent user consent or a
// substitute for the Windows Home/Authenticode T11 release gate.
// Invoke only on an actual Windows desktop with a locally provided API key,
// explicit two-paid-call opt-in and two independent human Allow clicks.
// The private Ed25519 key never leaves process memory or enters any file/env.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { canonicalJson } from '../../../packages/contracts/src/plan.ts';

const EXPLICIT = process.env.SHUN_T10_LIVE === '1'
  && process.env.SHUN_T10_APPROVE_TWO_PAID_REQUESTS === 'YES';

if (!EXPLICIT) {
  console.error('T10_LIVE_REFUSED: explicit two-paid-request operator opt-in required');
  process.exitCode = 2;
} else if (process.platform !== 'win32' || !process.env.LOCALAPPDATA) {
  console.error('T10_LIVE_REFUSED: real Windows desktop LOCALAPPDATA required');
  process.exitCode = 2;
} else if (!process.env.DEEPSEEK_API_KEY?.trim()) {
  console.error('T10_LIVE_REFUSED: DEEPSEEK_API_KEY must exist in operator environment');
  process.exitCode = 2;
} else {
  const scratch = mkdtempSync(join(process.env.LOCALAPPDATA, 'shun-t10-live-'));
  try {
    const keys = generateKeyPairSync('ed25519');
    const publicDer = keys.publicKey.export({ type: 'spki', format: 'der' });
    const publicPem = keys.publicKey.export({ type: 'spki', format: 'pem' });
    const pin = createHash('sha256').update(publicDer).digest('hex');
    const issuedAt = new Date(Date.now() - 1000).toISOString();
    const expiresAt = new Date(Date.now() + 4 * 60_000).toISOString();
    const signed = {
      schema: 'shun.cloud-authority/1',
      issuedAt,
      expiresAt,
      enabled: true,
      allowExternalDisclosure: true,
      providerId: 'deepseek',
      modelId: 'deepseek-flash',
      destination: 'https://api.deepseek.com/chat/completions',
      registryRevision: 't10-test-registry-r1',
      policyRevision: 't10-test-policy-r1',
      scopeRevision: 't10-test-scope-r1',
      pricingRevision: 't10-test-pricing-r1',
      revocationEpoch: 0,
      inputMicrosPerToken: 1,
      outputMicrosPerToken: 2,
      maxInputTokens: 4096,
      maxOutputTokens: 256,
      maxCostMicros: 4608,
    };
    const authorityPath = join(scratch, 'cloud-authority.json');
    const publicKeyPath = join(scratch, 'operator-public.pem');
    const ledgerPath = join(scratch, 'cloud-budget.sqlite');
    writeFileSync(publicKeyPath, publicPem, { mode: 0o600 });
    writeFileSync(authorityPath, JSON.stringify({
      ...signed,
      signature: sign(
        null, Buffer.from(canonicalJson(signed), 'utf8'), keys.privateKey,
      ).toString('base64'),
    }), { mode: 0o600 });

    // No private key is stored or passed to the child. The independent
    // public-key fingerprint is pinned by the trusted launch environment.
    assert.match(pin, /^[a-f0-9]{64}$/);
    const childEnv = {
      ...process.env,
      // A real human must click each native OS dialog. Do not inherit
      // any prior unit-test-only dialog automation override.
      SHUN_CONSENT_TEST_INSTRUMENTS: '0',
      SHUN_CLOUD_ENABLED: '1',
      SHUN_CLOUD_LEDGER_FILE: ledgerPath,
      SHUN_CLOUD_AUTHORITY_FILE: authorityPath,
      SHUN_CLOUD_PUBLIC_KEY_FILE: publicKeyPath,
      SHUN_CLOUD_PUBLIC_KEY_SPKI_SHA256: pin,
    };
    console.info('T10_LIVE_TEST_ISSUER=EPHEMERAL_OPERATOR_TEST_ONLY');
    console.info('T10_LIVE_MODEL_REQUESTS_MAX=2_USER_APPROVAL_REQUIRED_FOR_EACH');
    const child = spawnSync(process.execPath, [
      '--experimental-transform-types',
      '--test',
      resolve('tests/integration/v02/live-cloud-http.test.mjs'),
    ], {
      cwd: process.cwd(),
      stdio: 'inherit',
      env: childEnv,
      timeout: 240_000,
      windowsHide: false,
    });
    // Never print child environment or errors that might embed the key.
    if (child.error || child.signal || child.status !== 0) {
      console.error('T10_LIVE_RESULT=BLOCK_OR_FAIL');
      process.exitCode = 1;
    } else {
      console.info('T10_LIVE_RESULT=TEST_EXIT_0_VERIFY_CHILD_TEST_COUNTS');
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}
