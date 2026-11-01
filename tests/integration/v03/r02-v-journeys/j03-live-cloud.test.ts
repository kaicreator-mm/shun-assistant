/**
 * R02-V J03 — REAL paid DeepSeek CN/EN journey over the production v0.3
 * gateway, executed under Owner authorization
 * OWNER_SHUN_V030_R02_J02030509_DISPOSITION_APPROVE (#259).
 *
 * MUST NOT run in ordinary CI: requires SHUN_R02V_LIVE_CLOUD=1 on a real
 * Windows desktop with DEEPSEEK_API_KEY in the operator environment and
 * SHUN_CONSENT_TEST_INSTRUMENTS=1. Target: exactly TWO paid completions
 * (one CN goal, one EN goal), each up to 1024 output tokens; hard ceiling 8
 * per OWNER_SHUN_V030_R02_J03_PAID_CEILING_AMEND_R1 (7/8 consumed by the
 * recorded runs; do NOT re-run — the budget is exhausted).
 *
 * What is REAL here (no doubles on the paid path):
 *   - the production v0.3 gateway over real loopback HTTP with the REAL
 *     TrustedCloudInterpreter and the ONE existing TrustedDeepSeekTransport;
 *   - a short-lived Ed25519 operator authority (private key lives only in
 *     this process memory, exactly the run-live-cloud.mjs pattern);
 *   - the REAL native C02 consent broker dialog per request with single-use
 *     nonce consumption and signature verification. The Allow/Deny click is
 *     delivered by the gated brokerTestInstruments automation — DISCLOSED in
 *     the Owner authorization and in the validation receipt;
 *   - the durable SQLite budget ledger and the production cloud request
 *     journal (request CAS + committed result).
 *
 * Negatives are zero-paid by construction: a denied consent dialog and a
 * forged reference pair both refuse BEFORE the sender with provider events
 * unchanged.
 */
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  createCloudAuthorityCurrentness,
  readOperatorCloudAuthority,
} from '../../../../apps/control-api/src/cloud-authority.ts';
import { TrustedCloudInterpreter } from '../../../../apps/control-api/src/cloud-interpret.ts';
import type { ConsentBrokerSessionPort } from '../../../../apps/control-api/src/cloud-interpret.ts';
import { PrivateConsentBrokerSession, brokerTestInstruments } from '../../../../apps/control-api/native/index.ts';
import { canonicalJson } from '../../../../packages/contracts/src/plan.ts';
import { bootLiveStack, json, submission, type LiveStack } from './stack-harness.ts';

const RUN_LIVE =
  process.env.SHUN_R02V_LIVE_CLOUD === '1' &&
  process.platform === 'win32' &&
  !!(process.env.DEEPSEEK_API_KEY ?? '').trim();

const PROVIDER_ENDPOINT = 'https://api.deepseek.com/chat/completions';
const VALID_FINISH = new Set(['stop', 'length', 'tool_calls', 'content_filter']);
/** Only completed provider POSTs are paid sends; anomaly objects (network
 * failures, probe artifacts) are recorded separately and never counted. */
const paidSends = (events: Record<string, unknown>[]): Record<string, unknown>[] =>
  events.filter((event) => event.networkFailure !== true && typeof event.httpStatus === 'number');

const GOALS = {
  cn: '请用不超过80字给出所选磁盘空间问题的只读诊断建议，不要执行任何操作。',
  en: 'In under 60 words, suggest read-only steps to diagnose disk usage in my folder; do not execute actions.',
};

/** Passive redacted classification of the genuine provider response. */
async function redactedProviderResponse(
  response: Response,
): Promise<Record<string, unknown>> {
  const info: Record<string, unknown> = {
    httpStatus: response.status,
    expectedResponseUrl: response.url === PROVIDER_ENDPOINT,
    json: response.headers.get('content-type')?.includes('application/json') === true,
    finishReason: 'UNOBSERVED',
    hasFinalContent: 'UNOBSERVED',
    hasProviderError: false,
  };
  if (info.json !== true) return info;
  try {
    const body = (await response.clone().json()) as {
      choices?: { finish_reason?: string; message?: { content?: unknown } }[];
      error?: unknown;
    };
    const choice = Array.isArray(body?.choices) ? body.choices[0] : null;
    info.finishReason = VALID_FINISH.has(choice?.finish_reason ?? '')
      ? choice?.finish_reason
      : 'OTHER_OR_MISSING';
    info.hasFinalContent = typeof choice?.message?.content === 'string' && choice.message.content.length > 0;
    info.hasProviderError = body?.error !== undefined && body.error !== null;
  } catch {
    info.finishReason = 'UNREADABLE_JSON';
  }
  return info;
}

describe.skipIf(!RUN_LIVE)(
  'R02-V J03: real paid DeepSeek CN/EN journey through the production gateway',
  () => {
    let scratch: string;
    let stack: LiveStack;
    let providerEvents: Record<string, unknown>[] = [];
    let dialogArms: { pid: number; armId: number | null; action: string }[] = [];
    let nextDialogAction: 'allow' | 'deny' = 'allow';
    let dialogSessions = 0;
    let manuallyClosed = false;
    const originalFetch = globalThis.fetch;

    beforeAll(() => {
      if (process.env.SHUN_CONSENT_TEST_INSTRUMENTS !== '1') {
        throw new Error('J03_LIVE_REFUSED: SHUN_CONSENT_TEST_INSTRUMENTS=1 required (disclosed automation)');
      }
      // ---- short-lived operator signing identity (in-memory private key) ----
      const keys = generateKeyPairSync('ed25519');
      const publicDer = keys.publicKey.export({ type: 'spki', format: 'der' });
      const publicPem = keys.publicKey.export({ type: 'spki', format: 'pem' }) as string;
      const pin = createHash('sha256').update(publicDer).digest('hex');
      scratch = mkdtempSync(join(tmpdir(), 'shun-r02v-j03-'));
      const signed = {
        schema: 'shun.cloud-authority/1',
        issuedAt: new Date(Date.now() - 1000).toISOString(),
        expiresAt: new Date(Date.now() + 4 * 60_000).toISOString(),
        enabled: true,
        allowExternalDisclosure: true,
        providerId: 'deepseek',
        modelId: 'deepseek-flash',
        destination: PROVIDER_ENDPOINT,
        registryRevision: 'r02v-live-registry-r1',
        policyRevision: 'r02v-live-policy-r1',
        scopeRevision: 'r02v-live-scope-r1',
        pricingRevision: 'r02v-live-pricing-r1',
        revocationEpoch: 0,
        inputMicrosPerToken: 1,
        outputMicrosPerToken: 2,
        maxInputTokens: 4096,
        maxOutputTokens: 1024,
        // Hard ceiling: 2x the per-request worst case (4096*1 + 1024*2 = 6144).
        maxCostMicros: 12288,
      };
      const authorityPath = join(scratch, 'cloud-authority.json');
      const publicKeyPath = join(scratch, 'operator-public.pem');
      writeFileSync(publicKeyPath, publicPem, { mode: 0o600 });
      writeFileSync(
        authorityPath,
        JSON.stringify({
          ...signed,
          signature: cryptoSign(
            null,
            Buffer.from(canonicalJson(signed), 'utf8'),
            keys.privateKey,
          ).toString('base64'),
        }),
        { mode: 0o600 },
      );
      const ledgerFile = join(scratch, 'cloud-budget.sqlite');

      // ---- the REAL interpreter; only the session factory wraps the real
      // broker to arm the disclosed dialog automation on the REAL surface. ----
      const source = () =>
        readOperatorCloudAuthority({
          authorityFile: authorityPath,
          publicKeyFile: publicKeyPath,
          pinnedSpkiSha256: pin,
        });
      const initial = source();
      const interpreter = new TrustedCloudInterpreter({
        ledgerFile,
        registryRevision: initial.registryRevision,
        policyRevision: initial.policyRevision,
        scopeRevision: initial.scopeRevision,
        pricingRevision: initial.pricingRevision,
        revocationEpoch: initial.revocationEpoch,
        inputMicrosPerToken: initial.inputMicrosPerToken,
        outputMicrosPerToken: initial.outputMicrosPerToken,
        maxInputTokens: initial.maxInputTokens,
        maxOutputTokens: initial.maxOutputTokens,
        maxCostMicros: initial.maxCostMicros,
        isCurrent: createCloudAuthorityCurrentness(source, initial),
        isOffline: () => false,
        readApiKey: () => process.env.DEEPSEEK_API_KEY,
        openConsentSession: (): ConsentBrokerSessionPort => {
          const session = PrivateConsentBrokerSession.open();
          const armId = brokerTestInstruments.armDialog(session.pid, nextDialogAction, 30_000);
          dialogSessions++;
          dialogArms.push({ pid: session.pid, armId, action: nextDialogAction });
          return session;
        },
      });

      // Observe the SAME network operation production uses; nothing is logged
      // beyond the redacted classification (no key, prompt or completion).
      globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const target = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
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
      }) as typeof fetch;

      return bootLiveStack({ interpreter, prefix: 'shun-r02v-j03-stack-' }).then((live) => {
        stack = live;
      });
    });

    afterAll(async () => {
      globalThis.fetch = originalFetch;
      if (stack && !manuallyClosed) await stack.close();
      if (scratch) rmSync(scratch, { recursive: true, force: true });
    });

    it('the trusted cloud interpreter is genuinely enabled on this host', async () => {
      expect(stack.caseId).toBeTruthy();
      const state = await json(stack.port, 'GET', '/api/v03/guided/state');
      expect(state.status).toBe(200);
      expect(providerEvents).toHaveLength(0);
      expect(dialogSessions).toBe(0);
    });

    it('CN goal: real consent dialog + one real paid completion → HTTP 200 COMPLETED', async () => {
      const result = await json(
        stack.port,
        'POST',
        '/api/v03/gateway/submit',
        submission(stack.caseId, GOALS.cn, stack.submitRefs()),
      );
      expect(result.status).toBe(200);
      expect((result.body as { status: string }).status).toBe('COMPLETED');
      const paid = paidSends(providerEvents);
      expect(paid).toHaveLength(1);
      expect(paid[0]).toMatchObject({
        httpStatus: 200,
        expectedResponseUrl: true,
        json: true,
        hasProviderError: false,
      });
      expect(['stop', 'length']).toContain(paid[0]?.finishReason);
      expect(paid[0]?.hasFinalContent).toBe(true);
      expect(dialogSessions).toBe(1);
    });

    it('EN goal: second real consent + second real paid completion → HTTP 200 COMPLETED', async () => {
      const result = await json(
        stack.port,
        'POST',
        '/api/v03/gateway/submit',
        submission(stack.caseId, GOALS.en, stack.submitRefs()),
      );
      expect(result.status).toBe(200);
      expect((result.body as { status: string }).status).toBe('COMPLETED');
      expect(paidSends(providerEvents)).toHaveLength(2);
      expect(dialogSessions).toBe(2);
    });

    it('NEGATIVE (zero paid): a DENIED consent dialog refuses the send', async () => {
      nextDialogAction = 'deny';
      try {
        const result = await json(
          stack.port,
          'POST',
          '/api/v03/gateway/submit',
          submission(stack.caseId, 'This goal must never reach the provider.', stack.submitRefs()),
        );
        expect(result.status).toBe(422);
        // Both vocabularies are truthful zero-send refusals: the denied T04
        // consent surfaces as REFUSED (interpreter-level) or KERNEL_REFUSED
        // (kernel turn vocabulary); the journal asserts the exact reason.
        expect(['REFUSED', 'KERNEL_REFUSED']).toContain(
          (result.body as { status: string }).status,
        );
        expect(paidSends(providerEvents)).toHaveLength(2); // unchanged: zero paid sends
        expect(dialogSessions).toBe(3); // a REAL dialog was shown and denied
      } finally {
        nextDialogAction = 'allow';
      }
    });

    it('NEGATIVE (zero paid): a forged reference pair refuses pre-send', async () => {
      const forged = {
        ...submission(stack.caseId, GOALS.en, {
          currentnessRef: `forged-${'a'.repeat(32)}`,
          approvalRef: `forged-${'b'.repeat(32)}`,
        }),
      };
      const result = await json(stack.port, 'POST', '/api/v03/gateway/submit', forged);
      expect(result.status).toBe(422);
      expect((result.body as { status: string }).status).toBe('REFUSED');
      expect(paidSends(providerEvents)).toHaveLength(2);
      expect(dialogSessions).toBe(3);
    });

    it('evidence: exactly two paid sends; journal carries both committed results', async () => {
      const paid = paidSends(providerEvents);
      expect(paid).toHaveLength(2);
      const journalFile = join(stack.dir, 'cloud-journal.sqlite');
      await stack.close();
      manuallyClosed = true;
      const db = new DatabaseSync(journalFile);
      try {
        const rows = db
          .prepare('SELECT request_id, request_sha256, result_json FROM cloud_request_journal')
          .all() as { request_id: string; request_sha256: string; result_json: string | null }[];
        // CN completed + EN completed + the denied-consent request refused
        // with zero send — the durable journal is the authoritative counter.
        expect(rows).toHaveLength(3);
        const statuses = rows.map((row) => {
          expect(row.result_json).not.toBeNull();
          return (JSON.parse(row.result_json ?? '{}') as { status?: string }).status;
        });
        expect(statuses.filter((status) => status === 'completed')).toHaveLength(2);
        expect(statuses.filter((status) => status === 'refused')).toHaveLength(1);
        for (const row of rows) {
          const result = JSON.parse(row.result_json ?? '{}') as {
            status?: string;
            text?: string;
            errorCategory?: string;
            reasonCode?: string;
            modelId?: string;
          };
          if (result.status === 'completed') {
            expect(result.modelId).toBe('deepseek-flash');
            expect(typeof result.text).toBe('string');
            expect((result.text ?? '').length).toBeGreaterThan(0);
          } else {
            expect(result.errorCategory).toBe('CANCELLED');
            expect(result.reasonCode).toBe('CONSENT_DECLINED');
          }
        }
        const digest = (value: string) =>
          createHash('sha256').update(value, 'utf8').digest('hex');
        console.log(
          '[J03] real paid journey receipt:',
          JSON.stringify({
            paidProviderEvents: paid.length,
            observerAnomalies: providerEvents.length - paid.length,
            rawObserverEvents: providerEvents,
            dialogSessions,
            dialogArms: dialogArms.map((arm) => ({ pid: arm.pid, action: arm.action, armed: arm.armId !== null })),
            journalRequests: rows.map((row) => ({
              requestId: row.request_id,
              requestSha256: row.request_sha256.slice(0, 16),
              resultDigest: digest(row.result_json ?? '').slice(0, 16),
            })),
            providerEvents,
          }),
        );
      } finally {
        db.close();
      }
    });
  },
);
