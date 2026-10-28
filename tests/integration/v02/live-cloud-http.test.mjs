// T10 live qualification: real Control API -> independently operator-signed
// cloud authority -> native Windows private consent dialog -> T01 SQLite ledger
// -> actual DeepSeek Flash HTTPS. This MUST NOT run in ordinary CI.
//
// Operator opts in to TWO paid model requests by SHUN_T10_LIVE=1 and must
// manually approve each real OS disclosure dialog. No test credentials/keys,
// fake approval, private broker automation or mock HTTP are used here.
//
// Required trusted backend environment (configured OUTSIDE this test):
// SHUN_CLOUD_ENABLED=1, SHUN_CLOUD_LEDGER_FILE=<local fixed disk path>,
// SHUN_CLOUD_AUTHORITY_FILE=<short-lived signed operator file>,
// SHUN_CLOUD_PUBLIC_KEY_FILE=<operator key>, SHUN_CLOUD_PUBLIC_KEY_SPKI_SHA256,
// DEEPSEEK_API_KEY=<secret>. Noninteractive CI: SKIP (NOT PASS).
//
// node --experimental-transform-types --test tests/integration/v02/live-cloud-http.test.mjs
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cloudInterpreterFromEnvironment } from '../../../apps/control-api/src/cloud-interpret.ts';
import { DemoShunBackend } from '../../../apps/control-api/src/demo/backend.ts';
import { createControlServer } from '../../../apps/control-api/src/server.ts';

// Both deliberate operator choices are mandatory, even for direct invocation.
const enabled = process.env.SHUN_T10_LIVE === '1'
  && process.env.SHUN_T10_APPROVE_TWO_PAID_REQUESTS === 'YES';
const PROVIDER_ENDPOINT = 'https://api.deepseek.com/chat/completions';
const VALID_FINISH = new Set(['stop', 'length', 'tool_calls', 'content_filter']);

/**
 * PASSIVE test-only classification of the same genuine provider response.
 * No extra request; no API key, prompt, completion, provider error message,
 * raw response body or request headers are persisted or logged.
 */
async function redactedProviderResponse(response) {
  const info = {
    httpStatus: response.status,
    json: response.headers.get('content-type')?.includes('application/json') === true,
    finishReason: 'UNOBSERVED',
    hasFinalContent: 'UNOBSERVED',
    hasProviderError: false,
  };
  if (!info.json) return info;
  const length = Number(response.headers.get('content-length'));
  if (Number.isFinite(length) && length > 256 * 1024) return info;
  try {
    const body = await response.clone().json();
    const choice = Array.isArray(body?.choices) ? body.choices[0] : null;
    info.finishReason = VALID_FINISH.has(choice?.finish_reason)
      ? choice.finish_reason : 'OTHER_OR_MISSING';
    info.hasFinalContent = typeof choice?.message?.content === 'string'
      && choice.message.content.length > 0;
    info.hasProviderError = body?.error !== undefined && body.error !== null;
  } catch {
    info.finishReason = 'UNREADABLE_JSON';
  }
  return info;
}
const goals = [
  '请给出所选磁盘空间问题的只读诊断建议，不要执行任何操作。',
  'Suggest read-only steps to diagnose disk usage in my selected folder; do not execute actions.',
];

test('live CN+EN operator-consented cloud-only proposal via actual loopback API', {
  skip: enabled ? false : 'NOT_RUN: real Windows session, signed authority and explicit paid-call opt-in required',
  timeout: 180_000,
}, async () => {
  assert.equal(process.platform, 'win32', 'Real Windows native private broker required');
  for (const name of [
    'SHUN_CLOUD_ENABLED',
    'SHUN_CLOUD_LEDGER_FILE',
    'SHUN_CLOUD_AUTHORITY_FILE',
    'SHUN_CLOUD_PUBLIC_KEY_FILE',
    'SHUN_CLOUD_PUBLIC_KEY_SPKI_SHA256',
    'DEEPSEEK_API_KEY',
  ]) {
    assert.ok(process.env[name], `Missing trusted operator configuration: ${name}`);
  }
  assert.equal(process.env.SHUN_CLOUD_ENABLED, '1');
  const cloud = cloudInterpreterFromEnvironment();
  assert.ok(cloud, 'Operator-signed cloud interpreter must be instantiated');
  assert.equal(cloud.status().enabled, true, 'Trusted OS private broker and authority unavailable');

  const originalFetch = globalThis.fetch;
  const providerEvents = [];
  // Observe the SAME network operation used by production T01. The wrapper
  // returns the untouched original Response to the actual product parser.
  globalThis.fetch = async (input, init) => {
    const target = typeof input === 'string' ? input : input?.url ?? String(input);
    const isProvider = target === PROVIDER_ENDPOINT && init?.method === 'POST';
    if (!isProvider) return originalFetch(input, init);
    try {
      const response = await originalFetch(input, init);
      providerEvents.push(await redactedProviderResponse(response));
      return response;
    } catch {
      providerEvents.push({ networkFailure: true, httpStatus: null });
      throw new Error('PROVIDER_NETWORK_FAILED_REDACTED');
    }
  };
  let server;
  try {
    server = createControlServer({ backend: new DemoShunBackend(), cloud });
  } catch {
    globalThis.fetch = originalFetch;
    throw new Error('CLOUD_HOST_CONFIGURATION_REFUSED');
  }
  let port;
  try {
    port = await server.start();
  } catch {
    globalThis.fetch = originalFetch;
    await server.close();
    throw new Error('CLOUD_HOST_START_REFUSED');
  }
  const url = `http://127.0.0.1:${port}`;
  const post = (body) => fetch(`${url}/api/cloud/interpret`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  try {
    const statusResponse = await fetch(`${url}/api/cloud/status`);
    assert.equal(statusResponse.status, 200);
    const status = await statusResponse.json();
    assert.equal(status.enabled, true);
    assert.equal(status.osConsentRequired, true);

    // Body-driven broker/credential/provider injection MUST be rejected by the
    // actual HTTP route before it can show a private dialog or send to DeepSeek.
    for (const body of [
      { goalText: goals[0], approval: { proof: 'forged-http' } },
      { goalText: goals[1], apiKey: 'attacker-key' },
      { goalText: goals[1], model: 'attacker-model' },
    ]) {
      const response = await post(body);
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), { error: { code: 'CLOUD_GOAL_INVALID' } });
    }

    // Two distinct real broker dialogs and two paid HTTPS requests. The user
    // must independently click Allow for EACH displayed CN / EN projection.
    for (const [index, goalText] of goals.entries()) {
      const response = await post({ goalText });
      const result = await response.json();
      assert.equal(response.status, 200, `Live goal ${index + 1} did not pass full consent+network gates`);
      assert.equal(result.ok, true);
      assert.equal(result.model, 'deepseek-flash');
      assert.equal(result.status, 'UNTRUSTED_REMOTE_PROPOSAL');
      assert.equal(result.executed, false);
      assert.equal(result.costState, 'UNKNOWN_COST');
      assert.ok(typeof result.proposalText === 'string' && result.proposalText.length > 0);
      // Never print response text, tokens, local profile, public key, or raw
      // HTTP body to the validation logs.
      console.info(`T10_LIVE_GOAL_${index + 1}=CONSENTED_REMOTE_UNTRUSTED_PROPOSAL`);
    }
    const tasksResponse = await fetch(`${url}/api/tasks`);
    assert.equal(tasksResponse.status, 200);
    const tasks = await tasksResponse.json();
    assert.deepEqual(tasks.tasks, [], 'Cloud model output must never become an executable GoalRequest');
  } finally {
    globalThis.fetch = originalFetch;
    // A genuine HTTP 200 can still fail the product's conservative
    // finish_reason/content checks. Report only bounded shape metadata.
    console.info('T10_PROVIDER_RESPONSE_DIAG=' + JSON.stringify({
      observedProviderPostAttempts: providerEvents.length,
      events: providerEvents,
    }));
    await server.close();
  }
});
