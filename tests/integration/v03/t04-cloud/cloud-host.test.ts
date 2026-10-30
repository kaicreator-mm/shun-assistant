import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  CloudConsentApproval,
  CloudConsentCurrentness,
} from '../../../../packages/contracts/src/index.ts';
import type {
  ShunLlmGenerateRequestV1,
  ShunLlmGenerateResultV1,
} from '../../../../packages/domain-computer/src/contracts/llm-generate-v1.ts';
import {
  buildDeepSeekGoalDisclosure,
  DEEPSEEK_FLASH_DESTINATION,
  TrustedDeepSeekTransport,
  type TrustedDeepSeekHost,
} from '../../../../packages/llm-remote/src/deepseek-transport.ts';
import {
  MINIMUM_SENDER_DEADLINE_BUDGET_MS,
  type CloudRequestJournalDecision,
  type DurableCloudRequestJournal,
  type TrustedCloudHostBindingConfig,
  type TrustedCloudInterpretResult,
} from '../../../../packages/domain-host/src/cloud/openai-host.ts';
import { buildNeutralGoalRequest } from '../../../../packages/domain-computer/src/cloud/goal-request.ts';
import { generate as selectedCapabilityGenerate } from './capability-llm-openai-compatible.mjs';
import { generate as hostGenerate } from './host-binding-fixture.ts';
import { configureFakeHost, resetFakeHost } from './host-binding-fixture.ts';

type CapabilityTerminalResult = Readonly<{
  phase: 'terminal';
  externalRef: string;
  outcome: Readonly<{ ok: true; output: ShunLlmGenerateResultV1 }>;
}>;

async function invokeSelectedCapability(
  value: ShunLlmGenerateRequestV1,
): Promise<ShunLlmGenerateResultV1> {
  const result = await selectedCapabilityGenerate(value) as CapabilityTerminalResult;
  if (result.phase !== 'terminal' || result.outcome?.ok !== true) {
    throw new Error('SELECTED_C_TERMINAL_CONTRACT_INVALID');
  }
  return result.outcome.output;
}

const HOST_NOW = Date.parse('2026-10-30T00:00:00.000Z');
const GOAL = 'Please inspect the selected folder and summarize its contents.';

type JournalRow = { requestSha256: string; result?: ShunLlmGenerateResultV1 };

function memoryJournal() {
  const rows = new Map<string, JournalRow>();
  let reserveCalls = 0;
  let completeCalls = 0;
  const journal: DurableCloudRequestJournal = {
    durability: 'DURABLE_SHUN_STORE',
    reserve: async (input) => {
      reserveCalls++;
      const prior = rows.get(input.requestId);
      if (!prior) {
        rows.set(input.requestId, { requestSha256: input.requestSha256 });
        return { status: 'RESERVED' };
      }
      if (prior.requestSha256 !== input.requestSha256) return { status: 'CONFLICT' };
      return prior.result
        ? { status: 'REPLAY', result: prior.result }
        : { status: 'IN_FLIGHT' };
    },
    complete: async (input) => {
      completeCalls++;
      const prior = rows.get(input.requestId);
      if (!prior || prior.requestSha256 !== input.requestSha256 || prior.result) return false;
      prior.result = input.result;
      return true;
    },
  };
  return {
    journal,
    reserveCalls: () => reserveCalls,
    completeCalls: () => completeCalls,
    rows,
  };
}

function interpreter(
  handler: (goalText: string) => Promise<TrustedCloudInterpretResult> = async () => ({
    ok: true,
    taskId: 'cloud-task-01',
    status: 'UNTRUSTED_REMOTE_PROPOSAL',
    proposalText: '{"proposalId":"untrusted-proposal"}',
    model: 'deepseek-flash',
    costState: 'UNKNOWN_COST',
    executed: false,
  }),
  enabled = true,
) {
  let calls = 0;
  const port = {
    status: () => ({
      enabled,
      provider: 'deepseek' as const,
      model: 'deepseek-flash' as const,
      osConsentRequired: true as const,
    }),
    interpretGoal: async (goalText: string) => {
      calls++;
      return handler(goalText);
    },
  };
  return { port, calls: () => calls };
}

function config(
  port: ReturnType<typeof interpreter>['port'],
  journal: DurableCloudRequestJournal = memoryJournal().journal,
  overrides: Partial<TrustedCloudHostBindingConfig> = {},
): TrustedCloudHostBindingConfig {
  return {
    interpreter: port,
    journal,
    configuredMaxOutputTokens: 256,
    now: () => HOST_NOW,
    ...overrides,
  };
}

function request(
  overrides: Partial<{
    requestId: string;
    goalText: string;
    deadlineUnixMs: number;
    maxOutputTokens: number;
  }> = {},
): ShunLlmGenerateRequestV1 {
  const result = buildNeutralGoalRequest({
    requestId: 'request-01',
    goalText: GOAL,
    deadlineUnixMs: HOST_NOW + MINIMUM_SENDER_DEADLINE_BUDGET_MS,
    maxOutputTokens: 256,
    ...overrides,
  });
  if (!result) throw new Error('BAD_TEST_REQUEST');
  return result;
}

function approval(goalText: string, consentId = 'consent-t04'): CloudConsentApproval {
  const disclosure = buildDeepSeekGoalDisclosure(goalText);
  if (!disclosure) throw new Error('BAD_DISCLOSURE_FIXTURE');
  return {
    consentId,
    confirmationNonce: `nonce-${consentId}`,
    displayedProjectionSha256: disclosure.sha256,
    displayedDisclosureCategories: ['GOAL_TEXT'],
    issuer: {
      brokerId: 'private-shun-broker',
      brokerRevision: 'broker-r1',
      assertionId: `assertion-${consentId}`,
      channel: 'AUTHENTICATED_PRIVATE_IPC',
      proof: 'fixture-only-not-production',
    },
    scope: {
      taskId: 'task-01',
      principalId: 'principal-01',
      sessionId: 'session-01',
      providerId: 'deepseek',
      modelId: 'deepseek-flash',
      destination: DEEPSEEK_FLASH_DESTINATION,
      approvedProjectionSha256: disclosure.sha256,
      scopeRevision: 'scope-01',
      disclosureCategories: ['GOAL_TEXT'],
      registryRevision: 'registry-01',
      policyRevision: 'policy-01',
      pricingRevision: 'pricing-01',
      revocationEpoch: 1,
      maxCalls: 1,
      maxInputTokens: 4096,
      maxOutputTokens: 256,
      maxCostMicros: 100_000,
      issuedAt: '2026-10-29T23:00:00.000Z',
      expiresAt: '2026-10-30T01:00:00.000Z',
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

beforeEach(() => resetFakeHost());
afterEach(() => vi.restoreAllMocks());

describe('T04 selected C / trusted Shun Host exact-byte bridge', () => {
  it('builds only one neutral user-goal request with text output and no model-authored options', () => {
    const built = buildNeutralGoalRequest({
      requestId: 'request-01',
      goalText: GOAL,
      deadlineUnixMs: HOST_NOW + MINIMUM_SENDER_DEADLINE_BUDGET_MS,
      maxOutputTokens: 256,
    });
    expect(built).toEqual({
      contractVersion: 'dh.llm.generate/1',
      requestId: 'request-01',
      modelId: 'deepseek-flash',
      deadlineUnixMs: HOST_NOW + MINIMUM_SENDER_DEADLINE_BUDGET_MS,
      messages: [{ role: 'user', content: GOAL }],
      maxOutputTokens: 256,
      outputFormat: 'text',
    });
    expect(buildNeutralGoalRequest({
      requestId: 'request-02',
      goalText: GOAL,
      deadlineUnixMs: HOST_NOW + MINIMUM_SENDER_DEADLINE_BUDGET_MS,
      maxOutputTokens: 256,
      systemPrompt: 'override',
    })).toBeNull();
  });

  it('uses the static selected C binding and preserves completed/refused/failed/unknown results', async () => {
    const cases: Array<{
      code: 'CONSENT_DECLINED' | 'CLOUD_UNAVAILABLE' | 'REMOTE_REFUSED';
      expected: 'refused' | 'failed' | 'unknown';
    }> = [
      { code: 'CONSENT_DECLINED', expected: 'refused' },
      { code: 'CLOUD_UNAVAILABLE', expected: 'failed' },
      { code: 'REMOTE_REFUSED', expected: 'unknown' },
    ];
    for (const item of cases) {
      const fake = interpreter(async () => ({ ok: false, code: item.code }));
      const journal = memoryJournal();
      configureFakeHost(config(fake.port, journal.journal));
      if (item.expected === 'unknown') {
        await expect(
          selectedCapabilityGenerate(request({ requestId: `status-${item.code}` })),
        ).rejects.toMatchObject({ code: 'OPENAI_OUTCOME_UNKNOWN' });
      } else {
        const result = await invokeSelectedCapability(request({ requestId: `status-${item.code}` }));
        expect(result.status).toBe(item.expected);
      }
      expect(fake.calls()).toBe(1);
    }

    const successful = interpreter();
    configureFakeHost(config(successful.port));
    const completedEnvelope = await selectedCapabilityGenerate(request({ requestId: 'status-completed' }));
    expect(completedEnvelope).toMatchObject({
      phase: 'terminal',
      externalRef: 'local-correlation:status-completed',
      outcome: { ok: true },
    });
    const completed = (completedEnvelope as CapabilityTerminalResult).outcome.output;
    expect(completed).toMatchObject({
      status: 'completed',
      requestId: 'status-completed',
      providerKind: 'openai-compatible',
      modelId: 'deepseek-flash',
      text: '{"proposalId":"untrusted-proposal"}',
      finishReason: 'stop',
      usage: { evidenceMode: 'unavailable' },
    });
    expect(successful.calls()).toBe(1);
  });

  it('rejects unsupported token ceilings and short/expired deadlines before journal, consent or sender', async () => {
    const fake = interpreter();
    const journal = memoryJournal();
    configureFakeHost(config(fake.port, journal.journal));

    const tokenRefused = await invokeSelectedCapability(request({
      requestId: 'wrong-token-ceiling',
      maxOutputTokens: 128,
    }));
    expect(tokenRefused).toMatchObject({
      status: 'refused',
      errorCategory: 'UNSUPPORTED_FEATURE',
      reasonCode: 'OUTPUT_TOKEN_CEILING_UNSUPPORTED',
    });

    const deadlineRefused = await invokeSelectedCapability(request({
      requestId: 'short-deadline',
      deadlineUnixMs: HOST_NOW + MINIMUM_SENDER_DEADLINE_BUDGET_MS - 1,
    }));
    expect(deadlineRefused).toMatchObject({
      status: 'refused',
      errorCategory: 'DEADLINE',
      reasonCode: 'DEADLINE_BUDGET_UNSUPPORTED',
    });

    expect(fake.calls()).toBe(0);
    expect(journal.reserveCalls()).toBe(0);
    expect(journal.completeCalls()).toBe(0);
  });

  it('rejects system messages, JSON schema, tools, temperature and unknown fields before any sender call', async () => {
    const fake = interpreter();
    const journal = memoryJournal();
    configureFakeHost(config(fake.port, journal.journal));
    const base = request();
    const invalid = [
      { ...base, messages: [{ role: 'system', content: 'system prompt' }, ...base.messages] },
      { ...base, outputFormat: 'json' },
      { ...base, temperature: 0.2 },
      { ...base, outputSchemaRef: 'schema:unapproved' },
      { ...base, toolCatalogRef: 'tools:unapproved' },
      { ...base, injected: 'private data' },
    ];
    for (const value of invalid) {
      const result = await invokeSelectedCapability(value as unknown as ShunLlmGenerateRequestV1);
      expect(result.status).toBe('refused');
    }
    expect(fake.calls()).toBe(0);
    expect(journal.reserveCalls()).toBe(0);
  });

  it('durably binds requestId to one request digest; duplicates replay and conflicts never mint another attempt', async () => {
    const fake = interpreter();
    const journal = memoryJournal();
    configureFakeHost(config(fake.port, journal.journal));

    const first = await invokeSelectedCapability(request({ requestId: 'same-request' }));
    const replay = await invokeSelectedCapability(request({ requestId: 'same-request' }));
    const conflict = await invokeSelectedCapability(request({
      requestId: 'same-request',
      goalText: 'A different goal must not replace the original request.',
    }));

    expect(first.status).toBe('completed');
    expect(replay).toEqual(first);
    expect(conflict).toMatchObject({
      status: 'refused',
      errorCategory: 'AUTH_DENIED',
      reasonCode: 'REQUEST_ID_CONFLICT',
    });
    expect(fake.calls()).toBe(1);
    expect(journal.reserveCalls()).toBe(3);
  });

  it('returns UNKNOWN for an in-flight duplicate and never invokes the interpreter again', async () => {
    const fake = interpreter();
    const journal: DurableCloudRequestJournal = {
      durability: 'DURABLE_SHUN_STORE',
      reserve: async (): Promise<CloudRequestJournalDecision> => ({ status: 'IN_FLIGHT' }),
      complete: async () => false,
    };
    configureFakeHost(config(fake.port, journal));
    await expect(selectedCapabilityGenerate(request())).rejects.toMatchObject({
      code: 'OPENAI_OUTCOME_UNKNOWN',
    });
    expect(fake.calls()).toBe(0);
  });

  it('uses the existing TrustedDeepSeekTransport with fake HTTP and the identical Buffer at reserve, MAY_HAVE_SENT and fetch', async () => {
    const goalText = GOAL;
    const approved = approval(goalText);
    let reservedBytes: Uint8Array | undefined;
    let mayHaveSentBytes: Uint8Array | undefined;
    let sentBody: BodyInit | null | undefined;
    let fetchCalls = 0;
    let keyReads = 0;
    let unknownCostCalls = 0;
    const ledger = {
      reserve: (input: { requestBytes: Uint8Array }) => {
        reservedBytes = input.requestBytes;
        return {
          ok: true as const,
          attemptId: 'transport-attempt-01',
          requestBytesSha256: 'a'.repeat(64),
          reservedCostMicros: 1000,
        };
      },
      markMayHaveSent: (input: { actualRequestBytes: Uint8Array }) => {
        mayHaveSentBytes = input.actualRequestBytes;
        return true;
      },
      markUnknownCost: () => {
        unknownCostCalls++;
        return true;
      },
    };
    const senderHost: TrustedDeepSeekHost = {
      ledger: ledger as unknown as TrustedDeepSeekHost['ledger'],
      currentnessFor: currentness,
      isOffline: () => false,
      isLocalOnly: () => false,
      readApiKey: () => {
        keyReads++;
        return 'test-placeholder-no-real-credential';
      },
      now: () => '2026-10-30T00:00:00.000Z',
      fetchTransport: (async (_url: string | URL | Request, options?: RequestInit) => {
        fetchCalls++;
        sentBody = options?.body;
        return new Response(JSON.stringify({
          choices: [{
            finish_reason: 'stop',
            message: { role: 'assistant', content: '{"proposalId":"fake-http-proposal"}' },
          }],
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }) as typeof fetch,
    };
    const transport = new TrustedDeepSeekTransport(senderHost);
    const fakeInterpreter = interpreter(async (receivedGoal) => {
      const sent = await transport.invoke({
        goalText: receivedGoal,
        attemptId: 'transport-attempt-01',
        approval: approved,
        maxOutputTokens: 256,
      });
      return sent.ok
        ? {
            ok: true,
            taskId: 'cloud-task-transport',
            status: 'UNTRUSTED_REMOTE_PROPOSAL',
            proposalText: sent.proposalText,
            model: 'deepseek-flash',
            costState: 'UNKNOWN_COST',
            executed: false,
          }
        : { ok: false, code: 'REMOTE_REFUSED' };
    });
    configureFakeHost(config(fakeInterpreter.port, memoryJournal().journal));
    const globalFetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
      throw new Error('global fetch is forbidden; only the injected fake transport is allowed');
    });

    const result = await invokeSelectedCapability(request({ requestId: 'fake-http-request' }));
    const payload = JSON.parse(Buffer.from(sentBody as Uint8Array).toString('utf8'));
    expect(result).toMatchObject({
      status: 'completed',
      text: '{"proposalId":"fake-http-proposal"}',
    });
    expect(fetchCalls).toBe(1);
    expect(reservedBytes).toBeDefined();
    expect(reservedBytes).toBe(mayHaveSentBytes);
    expect(mayHaveSentBytes).toBe(sentBody);
    expect(payload).toEqual({
      model: 'deepseek-flash',
      messages: [{ role: 'user', content: GOAL }],
      max_tokens: 256,
      thinking: { type: 'disabled' },
      stream: false,
    });
    expect(Object.keys(payload).sort()).toEqual([
      'max_tokens', 'messages', 'model', 'stream', 'thinking',
    ]);
    expect(unknownCostCalls).toBe(1);
    expect(keyReads).toBe(1);
    expect(globalFetch).not.toHaveBeenCalled();
  });

  it('maps an exception after the send boundary to UNKNOWN rather than a false success', async () => {
    const fake = interpreter(async () => {
      throw new Error('private transport detail must not escape');
    });
    const journal = memoryJournal();
    configureFakeHost(config(fake.port, journal.journal));
    expect(await hostGenerate(request())).toMatchObject({
      status: 'unknown',
      errorCategory: 'OUTCOME_UNKNOWN',
      reasonCode: 'REMOTE_OUTCOME_UNRESOLVED',
    });
    await expect(selectedCapabilityGenerate(request())).rejects.toMatchObject({
      code: 'OPENAI_OUTCOME_UNKNOWN',
    });
  });

  it('refuses stale consent and an unapproved disclosure with zero HTTP and no budget reservation', async () => {
    const approved = approval(GOAL);
    let fetchCalls = 0;
    let reserveCalls = 0;
    let keyReads = 0;
    const ledger = {
      reserve: (input: { currentness: CloudConsentCurrentness }) => {
        reserveCalls++;
        if (input.currentness.kind !== 'CURRENT') return { ok: false as const, code: 'STALE' };
        return {
          ok: true as const,
          attemptId: 'must-not-reserve',
          requestBytesSha256: 'a'.repeat(64),
          reservedCostMicros: 1,
        };
      },
      markMayHaveSent: () => true,
      markUnknownCost: () => true,
    };
    const baseHost: TrustedDeepSeekHost = {
      ledger: ledger as unknown as TrustedDeepSeekHost['ledger'],
      currentnessFor: () => ({ kind: 'UNRESOLVABLE' }),
      isOffline: () => false,
      isLocalOnly: () => false,
      readApiKey: () => { keyReads++; return 'test-placeholder-no-secret'; },
      now: () => '2026-10-30T00:00:00.000Z',
      fetchTransport: (async () => {
        fetchCalls++;
        return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      }) as typeof fetch,
    };
    const stale = new TrustedDeepSeekTransport(baseHost);
    expect(await stale.invoke({
      goalText: GOAL,
      approval: approved,
      attemptId: 'stale-consent',
      maxOutputTokens: 128,
    })).toEqual({ ok: false, code: 'CONSENT_STALE' });
    expect(fetchCalls).toBe(0);
    expect(reserveCalls).toBe(1);

    const unapproved = new TrustedDeepSeekTransport({
      ...baseHost,
      currentnessFor: currentness,
    });
    expect(await unapproved.invoke({
      goalText: GOAL,
      approval: approval('A different goal not shown to the user.'),
      attemptId: 'unapproved-disclosure',
      maxOutputTokens: 128,
    })).toEqual({ ok: false, code: 'DISCLOSURE_SCOPE_DRIFT' });
    expect(fetchCalls).toBe(0);
    expect(reserveCalls).toBe(0);
    expect(keyReads).toBe(1);
  });

  it('does not send a duplicate underlying DeepSeek attempt or silently retry it', async () => {
    const approved = approval(GOAL);
    const attempts = new Set<string>();
    let fetchCalls = 0;
    const ledger = {
      reserve: (input: { attemptId: string }) => {
        if (attempts.has(input.attemptId)) return { ok: false as const, code: 'DUPLICATE' };
        attempts.add(input.attemptId);
        return {
          ok: true as const,
          attemptId: input.attemptId,
          requestBytesSha256: 'b'.repeat(64),
          reservedCostMicros: 1,
        };
      },
      markMayHaveSent: () => true,
      markUnknownCost: () => true,
    };
    const transport = new TrustedDeepSeekTransport({
      ledger: ledger as unknown as TrustedDeepSeekHost['ledger'],
      currentnessFor: currentness,
      isOffline: () => false,
      isLocalOnly: () => false,
      readApiKey: () => 'test-placeholder-no-secret',
      now: () => '2026-10-30T00:00:00.000Z',
      fetchTransport: (async () => {
        fetchCalls++;
        return new Response(JSON.stringify({
          choices: [{
            finish_reason: 'stop',
            message: { role: 'assistant', content: '{"proposalId":"one-attempt"}' },
          }],
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }) as typeof fetch,
    });
    expect(await transport.invoke({
      goalText: GOAL,
      approval: approved,
      attemptId: 'same-underlying-attempt',
      maxOutputTokens: 128,
    })).toMatchObject({ ok: true, costState: 'UNKNOWN_COST' });
    expect(await transport.invoke({
      goalText: GOAL,
      approval: approved,
      attemptId: 'same-underlying-attempt',
      maxOutputTokens: 128,
    })).toEqual({ ok: false, code: 'BUDGET_REFUSED' });
    expect(fetchCalls).toBe(1);
  });

  it('refuses missing broker and a deadline consumed during preflight before entering consent', async () => {
    const unavailable = interpreter(async () => ({
      ok: false,
      code: 'CLOUD_UNAVAILABLE',
    }), false);
    const unavailableJournal = memoryJournal();
    configureFakeHost(config(unavailable.port, unavailableJournal.journal));
    expect(await invokeSelectedCapability(request({ requestId: 'missing-broker' }))).toMatchObject({
      status: 'failed',
      errorCategory: 'UNAVAILABLE',
      reasonCode: 'CLOUD_UNAVAILABLE',
    });
    expect(unavailable.calls()).toBe(0);
    expect(unavailableJournal.reserveCalls()).toBe(1);

    const expiring = interpreter();
    const expiringJournal = memoryJournal();
    let clockReads = 0;
    configureFakeHost(config(expiring.port, expiringJournal.journal, {
      now: () => {
        clockReads++;
        return HOST_NOW + (clockReads >= 3 ? 1 : 0);
      },
    }));
    expect(await invokeSelectedCapability(request({ requestId: 'deadline-preflight' }))).toMatchObject({
      status: 'refused',
      errorCategory: 'DEADLINE',
      reasonCode: 'DEADLINE_BUDGET_UNSUPPORTED',
    });
    expect(clockReads).toBe(3);
    expect(expiring.calls()).toBe(0);
    expect(expiringJournal.reserveCalls()).toBe(1);
  });

  it('maps a result that arrives after the approved deadline to UNKNOWN at the selected C boundary', async () => {
    const fake = interpreter();
    const journal = memoryJournal();
    let clockReads = 0;
    configureFakeHost(config(fake.port, journal.journal, {
      now: () => {
        clockReads++;
        return clockReads >= 4
          ? HOST_NOW + MINIMUM_SENDER_DEADLINE_BUDGET_MS + 1
          : HOST_NOW;
      },
    }));
    await expect(selectedCapabilityGenerate(request({ requestId: 'late-result' }))).rejects.toMatchObject({
      code: 'OPENAI_OUTCOME_UNKNOWN',
    });
    expect(clockReads).toBe(4);
    expect(fake.calls()).toBe(1);
    expect(journal.completeCalls()).toBe(1);
  });

  it('refuses an unconfigured or non-durable Host journal', () => {
    expect(() => configureFakeHost({
      interpreter: interpreter().port,
      journal: { durability: 'MEMORY_ONLY' } as unknown as DurableCloudRequestJournal,
      configuredMaxOutputTokens: 256,
      now: () => HOST_NOW,
    })).toThrow('CLOUD_HOST_CONFIGURATION_REFUSED');
  });
});
