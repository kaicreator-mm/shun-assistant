import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { CloudConsentApproval, CloudConsentCurrentness } from '@shun/contracts';
import { afterEach, describe, expect, it } from 'vitest';
import { DurableCloudBudgetLedger } from '../src/atomic-budget.ts';
import {
  buildDeepSeekGoalDisclosure,
  DEEPSEEK_FLASH_DESTINATION,
  TrustedDeepSeekTransport,
  type TrustedDeepSeekHost,
} from '../src/deepseek-transport.ts';

const NOW = '2026-10-15T00:00:00.000Z';
const directories: string[] = [];
const ledgers: DurableCloudBudgetLedger[] = [];
const EN = 'Please diagnose disk usage in my selected folder.';
const CN = '请分析我选择的文件夹磁盘占用';

function approval(goalText: string, consentId = 'consent-1'): CloudConsentApproval {
  const shown = buildDeepSeekGoalDisclosure(goalText);
  if (!shown) throw new Error('bad fixture');
  return {
    consentId,
    confirmationNonce: 'nonce-' + consentId,
    displayedProjectionSha256: shown.sha256,
    displayedDisclosureCategories: ['GOAL_TEXT'],
    issuer: {
      brokerId: 'private-shun-broker',
      brokerRevision: 'broker-r1',
      assertionId: 'assertion-' + consentId,
      channel: 'AUTHENTICATED_PRIVATE_IPC',
      proof: 'fake-test-proof-not-production',
    },
    scope: {
      taskId: 'task-1',
      principalId: 'principal-1',
      sessionId: 'session-1',
      providerId: 'deepseek',
      modelId: 'deepseek-flash',
      destination: DEEPSEEK_FLASH_DESTINATION,
      approvedProjectionSha256: shown.sha256,
      scopeRevision: 'scope-1',
      disclosureCategories: ['GOAL_TEXT'],
      registryRevision: 'registry-1',
      policyRevision: 'policy-1',
      pricingRevision: 'pricing-1',
      revocationEpoch: 1,
      maxCalls: 1,
      maxInputTokens: 4096,
      maxOutputTokens: 256,
      maxCostMicros: 10000,
      issuedAt: '2026-10-14T23:00:00.000Z',
      expiresAt: '2026-10-15T01:00:00.000Z',
    },
  };
}

function currentness(record: CloudConsentApproval): CloudConsentCurrentness {
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

type Observed = { url: string; body: string; options: RequestInit };
function setup(
  overrides: Partial<TrustedDeepSeekHost> = {},
  reply: unknown = {
    choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: '{"proposal":true}' } }],
  },
) {
  const dir = mkdtempSync(join(tmpdir(), 'shun-deepseek-transport-'));
  directories.push(dir);
  const ledger = new DurableCloudBudgetLedger({
    file: join(dir, 'attempts.sqlite'),
    verifyBroker: () => true, // deterministic test broker only; T08 must supply real issuer
    pricing: { revision: 'pricing-1', inputMicrosPerToken: 1, outputMicrosPerToken: 2 },
  });
  ledgers.push(ledger);
  const observed: Observed[] = [];
  const host: TrustedDeepSeekHost = {
    ledger,
    isOffline: () => false,
    isLocalOnly: () => false,
    currentnessFor: currentness,
    now: () => NOW,
    readApiKey: () => 'test-placeholder-no-secret',
    fetchTransport: (async (url: string | URL | Request, options?: RequestInit) => {
      observed.push({
        url: String(url),
        body: Buffer.from(options?.body as Uint8Array).toString('utf8'),
        options: options ?? {},
      });
      return new Response(JSON.stringify(reply), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch,
    ...overrides,
  };
  return { transport: new TrustedDeepSeekTransport(host), ledger, observed };
}

afterEach(() => {
  for (const ledger of ledgers.splice(0)) ledger.close();
  for (const dir of directories.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('T01 DeepSeek HTTPS: exact disclosed projection to send', () => {
  it('uses the exact approved Chinese and English goal without hidden request fields', async () => {
    const { transport, ledger, observed } = setup();
    const first = await transport.invoke({
      goalText: CN,
      approval: approval(CN),
      attemptId: 'cn-attempt',
      maxOutputTokens: 100,
    });
    const second = await transport.invoke({
      goalText: EN,
      approval: approval(EN, 'consent-2'),
      attemptId: 'en-attempt',
      maxOutputTokens: 100,
    });
    expect(first).toMatchObject({ ok: true, costState: 'UNKNOWN_COST' });
    expect(second).toMatchObject({ ok: true, costState: 'UNKNOWN_COST' });
    expect(observed).toHaveLength(2);
    for (const [i, goal] of [CN, EN].entries()) {
      const request = observed[i];
      expect(request.url).toBe(DEEPSEEK_FLASH_DESTINATION);
      expect(request.options.method).toBe('POST');
      expect(request.options.redirect).toBe('manual');
      expect(request.options.credentials).toBe('omit');
      const payload = JSON.parse(request.body);
      expect(payload).toEqual({
        model: 'deepseek-flash',
        messages: [{ role: 'user', content: goal }],
        max_tokens: 100,
        stream: false,
      });
      expect(Object.keys(payload).sort()).toEqual(['max_tokens', 'messages', 'model', 'stream']);
    }
    expect(ledger.inspect('cn-attempt')?.status).toBe('UNKNOWN_COST');
    expect(ledger.inspect('en-attempt')?.status).toBe('UNKNOWN_COST');
  });

  it('never sends when a caller adds undisclosed private content or body fields', async () => {
    const { transport, observed, ledger } = setup();
    const result = await transport.invoke({
      goalText: EN + ' C:/private/passwords.txt',
      approval: approval(EN),
      attemptId: 'secret-drift',
      maxOutputTokens: 100,
      // Runtime extra fields MUST never become outbound message/body.
      requestBody: '{"messages":[{"role":"system","content":"private"}]}',
    } as Parameters<TrustedDeepSeekTransport['invoke']>[0]);
    expect(result).toEqual({ ok: false, code: 'DISCLOSURE_SCOPE_DRIFT' });
    expect(observed).toHaveLength(0);
    expect(ledger.inspect('secret-drift')).toBeNull();
  });

  it('rejects offline and local-only modes before key read or ledger reservation', async () => {
    let reads = 0;
    const p = approval(EN);
    for (const policy of [{ isOffline: () => true }, { isLocalOnly: () => true }]) {
      const { transport, observed, ledger } = setup({
        readApiKey: () => {
          reads += 1;
          return 'never';
        },
        ...policy,
      });
      expect(
        await transport.invoke({
          goalText: EN,
          approval: p,
          attemptId: 'refused-mode',
          maxOutputTokens: 100,
        }),
      ).toEqual({ ok: false, code: 'REMOTE_POLICY_REFUSED' });
      expect(observed).toHaveLength(0);
      expect(ledger.inspect('refused-mode')).toBeNull();
    }
    expect(reads).toBe(0);
  });

  it('rejects missing key, forged broker, expired approval and insufficient budget with zero HTTP', async () => {
    const p = approval(EN);
    const missing = setup({ readApiKey: () => undefined });
    expect(
      await missing.transport.invoke({
        goalText: EN,
        approval: p,
        attemptId: 'no-key',
        maxOutputTokens: 100,
      }),
    ).toEqual({ ok: false, code: 'CREDENTIAL_UNAVAILABLE' });
    expect(missing.observed).toHaveLength(0);
    expect(missing.ledger.inspect('no-key')).toBeNull();

    const forged = setup({ ledger: new DurableCloudBudgetLedger({
      file: ':memory:',
      verifyBroker: () => false,
      pricing: { revision: 'pricing-1', inputMicrosPerToken: 1, outputMicrosPerToken: 2 },
    }) });
    expect(
      await forged.transport.invoke({
        goalText: EN,
        approval: p,
        attemptId: 'forged',
        maxOutputTokens: 100,
      }),
    ).toEqual({ ok: false, code: 'BUDGET_REFUSED' });
    expect(forged.observed).toHaveLength(0);

    const expired = setup({ now: () => '2026-10-15T02:00:00.000Z' });
    expect(
      await expired.transport.invoke({
        goalText: EN,
        approval: p,
        attemptId: 'expired',
        maxOutputTokens: 100,
      }),
    ).toEqual({ ok: false, code: 'BUDGET_REFUSED' });
    expect(expired.observed).toHaveLength(0);

    const insufficient = approval(EN);
    insufficient.scope.maxCostMicros = 10;
    const cheap = setup();
    expect(
      await cheap.transport.invoke({
        goalText: EN,
        approval: insufficient,
        attemptId: 'over-budget',
        maxOutputTokens: 100,
      }),
    ).toEqual({ ok: false, code: 'BUDGET_REFUSED' });
    expect(cheap.observed).toHaveLength(0);
  });

  it('refuses changed currentness between reserve and send without HTTP', async () => {
    let calls = 0;
    const { transport, observed, ledger } = setup({
      currentnessFor: (p) => {
        calls += 1;
        const state = currentness(p);
        return calls === 2 && state.kind === 'CURRENT'
          ? { ...state, revocationEpoch: 999 }
          : state;
      },
    });
    expect(
      await transport.invoke({
        goalText: EN,
        approval: approval(EN),
        attemptId: 'revoke-between',
        maxOutputTokens: 100,
      }),
    ).toEqual({ ok: false, code: 'CONSENT_STALE' });
    expect(observed).toHaveLength(0);
    expect(ledger.inspect('revoke-between')?.status).toBe('RESERVED');
  });

  it('records UNKNOWN_COST after ambiguous send; does not refund or retry', async () => {
    const { transport, ledger } = setup({
      fetchTransport: (async () => {
        throw new Error('private data/path may not escape');
      }) as typeof fetch,
    });
    expect(
      await transport.invoke({
        goalText: EN,
        approval: approval(EN),
        attemptId: 'unavailable',
        maxOutputTokens: 100,
      }),
    ).toEqual({ ok: false, code: 'REMOTE_UNAVAILABLE' });
    expect(ledger.inspect('unavailable')?.status).toBe('UNKNOWN_COST');
    expect(
      await transport.invoke({
        goalText: EN,
        approval: approval(EN),
        attemptId: 'again',
        maxOutputTokens: 100,
      }),
    ).toEqual({ ok: false, code: 'BUDGET_REFUSED' });
  });

  it('never treats malformed or hallucinated response content as authority', async () => {
    const { transport, ledger } = setup({}, {
      choices: [{ finish_reason: 'length', message: { role: 'assistant', content: 'launch shell' } }],
    });
    const result = await transport.invoke({
      goalText: EN,
      approval: approval(EN),
      attemptId: 'bad-content',
      maxOutputTokens: 100,
    });
    expect(result).toEqual({ ok: false, code: 'REMOTE_RESPONSE_INVALID' });
    expect(ledger.inspect('bad-content')?.status).toBe('UNKNOWN_COST');
  });
});
