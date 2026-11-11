// T11 Commit A (Owner Amendment R1 acceptance item 4) — the PRODUCTION
// `TrustedCloudInterpreter` (apps/control-api/src/cloud-interpret.ts)
// realizes the frozen T04 `TrustedCloudInterpreterPort`:
//
//   - DEADLINE_EXPIRED on entry: zero broker dialog, zero ledger reserve,
//     zero MAY_HAVE_SENT, zero fetch (documented zero-send);
//   - DEADLINE_EXPIRED at the FINAL pre-send / MAY_HAVE_SENT boundary (the
//     consent dialog consumed the budget): zero reserve / MAY_HAVE_SENT /
//     fetch — the single existing sender is provably never entered;
//   - a just-sufficient budget sends exactly once with the exact L2
//     one-closed-immutable-Buffer request bytes at the configured
//     maxOutputTokens ceiling;
//   - UNKNOWN stays conservative: one remote call, no blind retry, no refund
//     path, no second sender.
//
// ZERO-PAID constraint: every surface is a fake (broker session, ledger,
// HTTP). Nothing in this file can reach DeepSeek, the Windows consent broker
// or a real SQLite ledger file.
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  type CloudBudgetLedgerPort,
  type ConsentBrokerSessionPort,
  type TrustedCloudConfig,
  TrustedCloudInterpreter,
} from '../../../../apps/control-api/src/cloud-interpret.ts';
import {
  type CloudConsentApproval,
  canonicalJson,
} from '../../../../packages/contracts/src/index.ts';
import { MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS } from '../../../../packages/domain-host/src/cloud/openai-host.ts';
import { DEEPSEEK_FLASH_DESTINATION } from '../../../../packages/llm-remote/src/deepseek-transport.ts';

const HOST_NOW = Date.parse('2026-10-31T00:00:00.000Z');
const GOAL = 'Please inspect the selected folder and summarize its contents.';
const PRINCIPAL = 'principal-t11';
const SESSION = 'session-t11';
const MODEL_ID = 'deepseek-flash';

/** Mutable trusted clock for the two deadline paths. */
function clock(start: number) {
  let current = start;
  return {
    now: (): number => current,
    setTo: (value: number): void => {
      current = value;
    },
  };
}

/** The exact closed request bytes the single existing sender serializes. */
function expectedRequestBytes(goalText: string, maxOutputTokens: number): Buffer {
  return Buffer.from(
    canonicalJson({
      model: MODEL_ID,
      messages: [{ role: 'user', content: goalText }],
      max_tokens: maxOutputTokens,
      thinking: { type: 'disabled' },
      stream: false,
    }),
    'utf8',
  );
}

interface Harness {
  interpreter: TrustedCloudInterpreter;
  opened: () => number;
  consentCalls: () => number;
  reserveCalls: () => number;
  mayHaveSentCalls: () => number;
  unknownCostCalls: () => number;
  fetchCalls: () => number;
  lastFetchBody: () => Buffer | undefined;
  lastFetchUrl: () => string | undefined;
}

/**
 * Zero-paid composition: fake broker session (mints a real-schema approval
 * from the trusted request), fake ledger (call counters only) and fake
 * fetch (never leaves the process).
 */
function harness(options: {
  deadlineUnixMs: number;
  fetchResponse?: () => Response;
  expireAfterConsent?: boolean;
}): Harness {
  let opened = 0;
  let consentCalls = 0;
  let reserveCalls = 0;
  let mayHaveSentCalls = 0;
  let unknownCostCalls = 0;
  let fetchCalls = 0;
  let lastBody: Buffer | undefined;
  let lastUrl: string | undefined;
  const time = clock(HOST_NOW);
  const deadline = options.deadlineUnixMs;

  const expireAfterConsent = (): void => {
    // The OS consent dialog consumed the budget: leave less than the
    // MINIMUM_PRE_SEND floor when the boundary recheck runs.
    time.setTo(deadline - MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS + 1);
  };

  const broker: ConsentBrokerSessionPort = {
    facts: { principalUserSid: PRINCIPAL, logonSid: SESSION },
    requestConsent(request) {
      consentCalls += 1;
      const approval: CloudConsentApproval = {
        consentId: 'consent-t11',
        confirmationNonce: 'nonce-t11',
        displayedProjectionSha256: request.approvedProjectionSha256,
        displayedDisclosureCategories: ['GOAL_TEXT'],
        issuer: {
          brokerId: 'fake-shun-broker',
          brokerRevision: 'broker-t11',
          assertionId: 'assertion-t11',
          channel: 'AUTHENTICATED_PRIVATE_IPC',
          proof: 'fake-session-zero-paid-only',
        },
        scope: {
          taskId: request.taskId,
          principalId: request.principalId,
          sessionId: request.sessionId,
          providerId: 'deepseek',
          modelId: MODEL_ID,
          destination: DEEPSEEK_FLASH_DESTINATION,
          approvedProjectionSha256: request.approvedProjectionSha256,
          scopeRevision: request.scopeRevision,
          disclosureCategories: ['GOAL_TEXT'],
          registryRevision: request.registryRevision,
          policyRevision: request.policyRevision,
          pricingRevision: request.pricingRevision,
          revocationEpoch: request.revocationEpoch,
          maxCalls: request.maxCalls,
          maxInputTokens: request.maxInputTokens,
          maxOutputTokens: request.maxOutputTokens,
          maxCostMicros: request.maxCostMicros,
          issuedAt: request.issuedAt,
          expiresAt: request.expiresAt,
        },
      };
      if (options.expireAfterConsent === true) expireAfterConsent();
      return { outcome: 'APPROVED', approval };
    },
    checkNonce: () => true,
    verifyApproval: () => ({ valid: true, reason: 'fake-session' }),
    shutdown: () => ({ exitCode: 0, timedOut: false }),
  };

  const ledger: CloudBudgetLedgerPort = {
    reserve: () => {
      reserveCalls += 1;
      return {
        ok: true as const,
        attemptId: 'attempt-t11',
        requestBytesSha256: 'b'.repeat(64),
        reservedCostMicros: 1,
      };
    },
    markMayHaveSent: () => {
      mayHaveSentCalls += 1;
      return true;
    },
    markUnknownCost: () => {
      unknownCostCalls += 1;
      return true;
    },
  };

  const fetchTransport = (async (
    input: Parameters<typeof fetch>[0],
    init?: RequestInit,
  ): Promise<Response> => {
    fetchCalls += 1;
    lastUrl = typeof input === 'string' ? input : String(input);
    const body = init?.body;
    lastBody = Buffer.isBuffer(body) ? body : Buffer.from(String(body ?? ''), 'utf8');
    return options.fetchResponse
      ? options.fetchResponse()
      : new Response(
          JSON.stringify({
            choices: [
              {
                finish_reason: 'stop',
                message: { role: 'assistant', content: 'untrusted proposal text' },
              },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
  }) as typeof fetch;

  const openedBroker = (): ConsentBrokerSessionPort => {
    opened += 1;
    return broker;
  };

  const config: TrustedCloudConfig = {
    ledgerFile: join(tmpdir(), 't11-zero-paid-unused.sqlite'),
    registryRevision: 'registry-t11',
    policyRevision: 'policy-t11',
    scopeRevision: 'scope-t11',
    pricingRevision: 'pricing-t11',
    revocationEpoch: 1,
    inputMicrosPerToken: 1,
    outputMicrosPerToken: 2,
    maxInputTokens: 4096,
    maxOutputTokens: 256,
    maxCostMicros: 100_000,
    isCurrent: () => true,
    isOffline: () => false,
    readApiKey: () => 't11-local-test-key-never-a-real-credential',
    consentHostAvailable: () => true,
    openConsentSession: openedBroker,
    createLedger: () => ledger,
    fetchTransport,
    now: () => {
      const value = time.now();
      return value;
    },
  };

  return {
    interpreter: new TrustedCloudInterpreter(config),
    opened: () => opened,
    consentCalls: () => consentCalls,
    reserveCalls: () => reserveCalls,
    mayHaveSentCalls: () => mayHaveSentCalls,
    unknownCostCalls: () => unknownCostCalls,
    fetchCalls: () => fetchCalls,
    lastFetchBody: () => lastBody,
    lastFetchUrl: () => lastUrl,
  };
}

describe('T11 production interpreter realizes the frozen T04 port (zero paid)', () => {
  it('DEADLINE_EXPIRED on entry: zero broker, zero ledger, zero fetch', async () => {
    const h = harness({ deadlineUnixMs: HOST_NOW + 1_000 });
    const result = await h.interpreter.interpretGoal({
      goalText: GOAL,
      deadlineUnixMs: HOST_NOW + 1_000,
    });
    expect(result).toEqual({ ok: false, code: 'DEADLINE_EXPIRED' });
    expect(h.opened()).toBe(0);
    expect(h.consentCalls()).toBe(0);
    expect(h.reserveCalls()).toBe(0);
    expect(h.mayHaveSentCalls()).toBe(0);
    expect(h.unknownCostCalls()).toBe(0);
    expect(h.fetchCalls()).toBe(0);
  });

  it('DEADLINE_EXPIRED at the final pre-send boundary: consent ran, sender never entered', async () => {
    const deadline = HOST_NOW + MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS;
    const h = harness({ deadlineUnixMs: deadline, expireAfterConsent: true });
    const result = await h.interpreter.interpretGoal({
      goalText: GOAL,
      deadlineUnixMs: deadline,
    });
    // The private consent dialog itself ran (its outcome was APPROVED), but
    // the expiry hit the boundary BEFORE the sender: documented zero-send.
    expect(result).toEqual({ ok: false, code: 'DEADLINE_EXPIRED' });
    expect(h.opened()).toBe(1);
    expect(h.consentCalls()).toBe(1);
    expect(h.reserveCalls()).toBe(0);
    expect(h.mayHaveSentCalls()).toBe(0);
    expect(h.unknownCostCalls()).toBe(0);
    expect(h.fetchCalls()).toBe(0);
  });

  it('just-sufficient budget sends once with the exact closed request bytes', async () => {
    const deadline = HOST_NOW + MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS;
    const h = harness({ deadlineUnixMs: deadline });
    const result = await h.interpreter.interpretGoal({
      goalText: GOAL,
      deadlineUnixMs: deadline,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.status).toBe('UNTRUSTED_REMOTE_PROPOSAL');
      expect(result.proposalText).toBe('untrusted proposal text');
      expect(result.model).toBe('deepseek-flash');
      expect(result.costState).toBe('UNKNOWN_COST');
      expect(result.executed).toBe(false);
    }
    expect(h.fetchCalls()).toBe(1);
    expect(h.lastFetchUrl()).toBe(DEEPSEEK_FLASH_DESTINATION);
    expect(h.lastFetchBody()?.equals(expectedRequestBytes(GOAL, 256))).toBe(true);
    expect(h.reserveCalls()).toBe(1);
    expect(h.mayHaveSentCalls()).toBe(1);
    expect(h.unknownCostCalls()).toBe(1);
  });

  it('UNKNOWN stays conservative: one remote call, no retry, no refund path', async () => {
    const deadline = HOST_NOW + MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS;
    const h = harness({
      deadlineUnixMs: deadline,
      fetchResponse: () =>
        new Response(JSON.stringify({ error: 'remote refusal body' }), {
          status: 500,
          headers: { 'content-type': 'application/json' },
        }),
    });
    const result = await h.interpreter.interpretGoal({
      goalText: GOAL,
      deadlineUnixMs: deadline,
    });
    // REMOTE_REFUSED cannot prove zero-send (the fetch happened), so it must
    // stay conservative: the K Host maps it to UNKNOWN — no retry pass here.
    expect(result).toEqual({ ok: false, code: 'REMOTE_REFUSED' });
    expect(h.fetchCalls()).toBe(1);
    // The cost state stays UNKNOWN_COST — the budget is never silently refunded.
    expect(h.unknownCostCalls()).toBe(1);
    expect(h.reserveCalls()).toBe(1);
    expect(h.mayHaveSentCalls()).toBe(1);
  });
});
