// T10 I01: actual T01 transport + durable SQLite budget composed together.
// These deterministic tests use a TEST-ONLY broker verifier and intercepted
// HTTP; they are not evidence of a real Win32 consent dialog or live DeepSeek.
// Run on Node 24 after a frozen pnpm workspace install:
// node --experimental-transform-types --test tests/integration/v02/cloud-gates.test.mjs
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { DurableCloudBudgetLedger } from '../../../packages/llm-remote/src/atomic-budget.ts';
import {
  buildDeepSeekGoalDisclosure,
  DEEPSEEK_FLASH_DESTINATION,
  TrustedDeepSeekTransport,
} from '../../../packages/llm-remote/src/deepseek-transport.ts';

const NOW = '2026-10-15T00:00:00.000Z';
const EN = 'Summarize disk usage under my selected folder';
const CN = '请汇总所选文件夹的磁盘占用';
const TRUSTED_FIXTURE_PROOF = 'test-only-broker-approval-not-a-real-OS-proof';

function approval(goal, consentId = 'consent-A') {
  const display = buildDeepSeekGoalDisclosure(goal);
  assert.ok(display);
  return {
    consentId,
    confirmationNonce: `nonce-${consentId}`,
    displayedProjectionSha256: display.sha256,
    displayedDisclosureCategories: ['GOAL_TEXT'],
    issuer: {
      brokerId: 'integration-fixture-only',
      brokerRevision: 'test-r1',
      assertionId: `assertion-${consentId}`,
      channel: 'AUTHENTICATED_PRIVATE_IPC',
      proof: TRUSTED_FIXTURE_PROOF,
    },
    scope: {
      taskId: 'integration-task',
      principalId: 'synthetic-principal',
      sessionId: 'synthetic-session',
      providerId: 'deepseek',
      modelId: 'deepseek-flash',
      destination: DEEPSEEK_FLASH_DESTINATION,
      approvedProjectionSha256: display.sha256,
      scopeRevision: 'scope-r1',
      disclosureCategories: ['GOAL_TEXT'],
      registryRevision: 'registry-r1',
      policyRevision: 'policy-r1',
      pricingRevision: 'price-r1',
      revocationEpoch: 0,
      maxCalls: 1,
      maxInputTokens: 4096,
      maxOutputTokens: 256,
      maxCostMicros: 10000,
      issuedAt: '2026-10-14T23:00:00.000Z',
      expiresAt: '2026-10-15T01:00:00.000Z',
    },
  };
}

function currentness(record) {
  return {
    kind: 'CURRENT',
    taskId: record.scope.taskId,
    principalId: record.scope.principalId,
    sessionId: record.scope.sessionId,
    registryRevision: record.scope.registryRevision,
    policyRevision: record.scope.policyRevision,
    pricingRevision: record.scope.pricingRevision,
    scopeRevision: record.scope.scopeRevision,
    revocationEpoch: record.scope.revocationEpoch,
    nonceIsUnused: true,
  };
}

function harness(t, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'shun-t10-integration-'));
  const sent = [];
  let keyReads = 0;
  const ledger = new DurableCloudBudgetLedger({
    file: join(dir, 'attempts.sqlite'),
    // Deterministic test seam only: a real Shun private broker must verify
    // its own cryptographic assertion in the separate Windows host journey.
    verifyBroker: options.verifyBroker ?? ((value) =>
      value.issuer.proof === TRUSTED_FIXTURE_PROOF),
    pricing: { revision: 'price-r1', inputMicrosPerToken: 1, outputMicrosPerToken: 2 },
  });
  t.after(() => {
    ledger.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const transport = new TrustedDeepSeekTransport({
    ledger,
    isOffline: options.isOffline ?? (() => false),
    isLocalOnly: options.isLocalOnly ?? (() => false),
    currentnessFor: options.currentnessFor ?? currentness,
    now: () => NOW,
    readApiKey: () => {
      keyReads++;
      return 'fixture-placeholder-never-live-secret';
    },
    fetchTransport: async (url, init) => {
      sent.push({ url: String(url), body: Buffer.from(init.body).toString('utf8') });
      if (options.networkFails) throw Error('sensitive://internal/secret-token');
      return new Response(JSON.stringify({
        choices: [{
          finish_reason: 'stop',
          message: { role: 'assistant', content: '{"proposal":"untrusted-only"}' },
        }],
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  return { transport, sent, ledger, keyReads: () => keyReads };
}

function invoke(transport, goal, consent, attemptId) {
  return transport.invoke({
    goalText: goal, approval: consent, attemptId, maxOutputTokens: 128,
  });
}

test('CN and EN disclosed goal bytes reach one fixed endpoint; receipts remain UNKNOWN_COST', async (t) => {
  const { transport, sent, ledger } = harness(t);
  const results = await Promise.all([
    invoke(transport, CN, approval(CN, 'consent-CN'), 'attempt-CN'),
    invoke(transport, EN, approval(EN, 'consent-EN'), 'attempt-EN'),
  ]);
  assert.deepEqual(results.map((r) => r.ok), [true, true]);
  assert.equal(sent.length, 2);
  for (const [index, goal] of [CN, EN].entries()) {
    const actual = sent[index];
    assert.equal(actual.url, DEEPSEEK_FLASH_DESTINATION);
    assert.deepEqual(JSON.parse(actual.body), {
      model: 'deepseek-flash',
      messages: [{ role: 'user', content: goal }],
      max_tokens: 128,
      thinking: { type: 'disabled' },
      stream: false,
    });
  }
  assert.equal(ledger.inspect('attempt-CN')?.status, 'UNKNOWN_COST');
  assert.equal(ledger.inspect('attempt-EN')?.status, 'UNKNOWN_COST');
});

test('schema-shaped forged private approval is rejected by the trusted verifier before HTTP', async (t) => {
  const { transport, sent, ledger } = harness(t);
  const forged = approval(EN);
  forged.issuer.proof = 'forged-localhost-cannot-authorize';
  assert.deepEqual(await invoke(transport, EN, forged, 'forged-attempt'),
    { ok: false, code: 'BUDGET_REFUSED' });
  assert.equal(sent.length, 0);
  assert.equal(ledger.inspect('forged-attempt'), null);
});

test('two concurrent attempts under maxCalls=1 produce at most one HTTP send', async (t) => {
  const { transport, sent, ledger } = harness(t);
  const consent = approval(EN);
  const results = await Promise.all([
    invoke(transport, EN, consent, 'race-a'),
    invoke(transport, EN, consent, 'race-b'),
  ]);
  assert.equal(results.filter((r) => r.ok).length, 1);
  assert.equal(results.filter((r) => !r.ok && r.code === 'BUDGET_REFUSED').length, 1);
  assert.equal(sent.length, 1);
  assert.equal(['UNKNOWN_COST', null].filter((v) =>
    v === ledger.inspect('race-a')?.status || v === ledger.inspect('race-b')?.status).length >= 1, true);
});

test('changed display projection and revoked source-currentness both cause zero HTTP sends', async (t) => {
  const { transport: drift, sent: driftSent, ledger: driftLedger } = harness(t);
  assert.deepEqual(
    await invoke(drift, `${EN} /private/credential.txt`, approval(EN), 'drift'),
    { ok: false, code: 'DISCLOSURE_SCOPE_DRIFT' },
  );
  assert.equal(driftSent.length, 0);
  assert.equal(driftLedger.inspect('drift'), null);

  let reads = 0;
  const { transport, sent, ledger } = harness(t, {
    currentnessFor: (record) => (++reads === 2 ? { kind: 'UNRESOLVABLE' } : currentness(record)),
  });
  assert.deepEqual(await invoke(transport, EN, approval(EN), 'revoked-before-send'),
    { ok: false, code: 'CONSENT_STALE' });
  assert.equal(sent.length, 0);
  assert.equal(ledger.inspect('revoked-before-send')?.status, 'RESERVED');
});

test('ambiguous HTTP failure holds UNKNOWN_COST; no retry, no private error leakage', async (t) => {
  const { transport, sent, ledger } = harness(t, { networkFails: true });
  assert.deepEqual(await invoke(transport, EN, approval(EN), 'ambiguous'),
    { ok: false, code: 'REMOTE_UNAVAILABLE' });
  assert.equal(ledger.inspect('ambiguous')?.status, 'UNKNOWN_COST');
  assert.deepEqual(await invoke(transport, EN, approval(EN), 'retry-refused'),
    { ok: false, code: 'BUDGET_REFUSED' });
  assert.equal(sent.length, 1);
});

test('offline policy refuses before credential read, budget reservation and network', async (t) => {
  const { transport, sent, ledger, keyReads } = harness(t, { isOffline: () => true });
  assert.deepEqual(await invoke(transport, EN, approval(EN), 'offline'),
    { ok: false, code: 'REMOTE_POLICY_REFUSED' });
  assert.equal(keyReads(), 0);
  assert.equal(sent.length, 0);
  assert.equal(ledger.inspect('offline'), null);
});
