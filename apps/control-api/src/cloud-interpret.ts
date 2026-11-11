// v0.2 T08 C03 — actual user-confirmed DeepSeek goal interpretation.
// Reuses the reviewed T01 transport/SQLite budget and C02 Win32 broker.
// No browser can supply an approval, target, price, credential or token.
// The result is an UNTRUSTED suggestion for display, NOT an executable plan.
//
// v0.3 T11 (Owner Amendment R1): this interpreter now realizes the frozen
// T04 `TrustedCloudInterpreterPort` (packages/domain-host). The absolute
// request deadline travels WITH the goal text, is enforced on entry and is
// rechecked once more at the FINAL pre-send boundary — immediately before
// the existing single sender reserves the ledger, marks MAY_HAVE_SENT or
// reaches HTTP. `DEADLINE_EXPIRED` is a documented zero-send: the sender is
// provably never entered, so no ledger reservation, no MAY_HAVE_SENT and no
// HTTP can occur on that path. UNKNOWN remains conservative:模糊的远端结果
// (REMOTE_REFUSED 等) 永不盲目重试、不退款、无第二 sender — the one existing
// `TrustedDeepSeekTransport` fetch stays the only remote path.
import { randomUUID } from 'node:crypto';
import { isAbsolute } from 'node:path';
import {
  type CloudConsentApproval,
  type CloudConsentCurrentness,
  canonicalJson,
} from '@shun/contracts';
import {
  buildDeepSeekGoalDisclosure,
  DurableCloudBudgetLedger,
  TrustedDeepSeekTransport,
} from '@shun/llm-remote';
import {
  MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS,
  MINIMUM_SENDER_DEADLINE_BUDGET_MS,
  type TrustedCloudInterpreterPort,
  type TrustedCloudInterpretResult,
} from '../../../packages/domain-host/src/cloud/openai-host.ts';
import {
  type BrokerConsentRequest,
  PrivateConsentBrokerSession,
  privateConsentHostAvailability,
} from '../native/index.ts';
import { createCloudAuthorityCurrentness, readOperatorCloudAuthority } from './cloud-authority.ts';

/** The ledger seam the single existing sender consumes (T01 transport host). */
export type CloudBudgetLedgerPort = Pick<
  DurableCloudBudgetLedger,
  'reserve' | 'markMayHaveSent' | 'markUnknownCost'
> & {
  /** The real SQLite ledger closes its handle; fakes may omit it. */
  close?(): void;
};

/**
 * The structural consent-broker seam. The production instance is the real
 * C02 `PrivateConsentBrokerSession`; trusted host composition (and zero-paid
 * tests) may inject a substitute. Never populated from HTTP.
 */
export interface ConsentBrokerSessionPort {
  readonly facts: {
    principalUserSid: string;
    logonSid: string;
  };
  requestConsent(
    request: BrokerConsentRequest,
  ): { outcome: 'APPROVED'; approval: CloudConsentApproval } | { outcome: string };
  checkNonce(confirmationNonce: string): boolean;
  verifyApproval(approval: CloudConsentApproval): { valid: boolean; reason: string };
  shutdown(timeoutMs?: number): unknown;
}

export type CloudInterpretResult = TrustedCloudInterpretResult;

/**
 * The frozen T04 port realized by `TrustedCloudInterpreter`. The deprecated
 * bare-string form below is kept only so the reviewed v0.2 callers outside
 * the T11 write set keep compiling; a bare string receives the SAME
 * trusted-side absolute deadline as the HTTP route.
 */
export type CloudInterpretPort = TrustedCloudInterpreterPort;

export interface TrustedCloudConfig {
  ledgerFile: string;
  registryRevision: string;
  policyRevision: string;
  scopeRevision: string;
  pricingRevision: string;
  revocationEpoch: number;
  inputMicrosPerToken: number;
  outputMicrosPerToken: number;
  maxInputTokens: number;
  maxOutputTokens: number;
  maxCostMicros: number;
  /** Only trusted local host configuration, never HTTP body or browser. */
  isCurrent: () => boolean;
  isOffline: () => boolean;
  readApiKey: () => string | undefined;
  /**
   * Trusted-host-only composition seams below. Each defaults to the exact
   * production surface; nothing here is reachable from HTTP input.
   */
  /** Trusted wall clock (defaults Date.now). */
  now?: () => number;
  /**
   * Real broker availability: win32 AND verified pinned native artifacts.
   * Defaults to exactly that; trusted composition/tests may narrow it.
   */
  consentHostAvailable?: () => boolean;
  /** Broker session factory (defaults the real private IPC broker). */
  openConsentSession?: () => ConsentBrokerSessionPort;
  /** Durable budget ledger factory (defaults the real SQLite ledger). */
  createLedger?: (input: {
    verifyBroker: (record: CloudConsentApproval) => boolean;
    pricing: {
      revision: string;
      inputMicrosPerToken: number;
      outputMicrosPerToken: number;
    };
  }) => CloudBudgetLedgerPort;
  /** The ONE fetch seam of the ONE existing sender (defaults global fetch). */
  fetchTransport?: typeof fetch;
}

/** Enable actual egress only against the independent short-lived Ed25519
 * operator source. Startup environment strings do NOT certify registry or
 * pricing currentness; the signed source is fetched again at both send gates.
 */
export function cloudInterpreterFromEnvironment(): CloudInterpretPort | undefined {
  if (process.env.SHUN_CLOUD_ENABLED !== '1') return undefined;
  const ledgerFile = process.env.SHUN_CLOUD_LEDGER_FILE;
  const authorityFile = process.env.SHUN_CLOUD_AUTHORITY_FILE;
  const publicKeyFile = process.env.SHUN_CLOUD_PUBLIC_KEY_FILE;
  const pinnedSpkiSha256 = process.env.SHUN_CLOUD_PUBLIC_KEY_SPKI_SHA256;
  if (
    !ledgerFile ||
    !isAbsolute(ledgerFile) ||
    ledgerFile === ':memory:' ||
    !authorityFile ||
    !publicKeyFile ||
    !pinnedSpkiSha256
  ) {
    throw new Error('CLOUD_TRUSTED_CONFIG_MISSING');
  }
  const source = () =>
    readOperatorCloudAuthority({
      authorityFile,
      publicKeyFile,
      pinnedSpkiSha256,
    });
  // No signer, self-issued revision or silent fallback. If absent/expired,
  // production startup fails closed rather than advertising a remote planner.
  const initial = source();
  const config: TrustedCloudConfig = {
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
    isOffline: () => process.env.SHUN_CLOUD_OFFLINE === '1',
    isCurrent: () =>
      process.env.SHUN_CLOUD_ENABLED === '1' && createCloudAuthorityCurrentness(source, initial)(),
    readApiKey: () => process.env.DEEPSEEK_API_KEY,
  };
  return new TrustedCloudInterpreter(config);
}

/**
 * First verification is backed by the *private broker-returned* approval,
 * exact canonical identity and live single-use nonce. The SECOND and final
 * T01 verification (immediately before MAY_HAVE_SENT) cryptographically
 * verifies AND CONSUMES that nonce in C02. Never mint from HTTP, never
 * issue a second attempt, never treat this as transferable grant authority.
 */
function stagedBrokerVerifier(
  session: Pick<PrivateConsentBrokerSession, 'checkNonce' | 'verifyApproval'>,
  issued: CloudConsentApproval,
): (record: CloudConsentApproval) => boolean {
  const pinned = canonicalJson(issued);
  let phase = 0;
  return (record) => {
    if (phase >= 2 || canonicalJson(record) !== pinned) return false;
    if (phase === 0) {
      if (!session.checkNonce(issued.confirmationNonce)) return false;
      phase = 1;
      return true;
    }
    // T01 send-gate verification is the real OS-broker proof consumption.
    const verified = session.verifyApproval(record).valid === true;
    phase = 2;
    return verified;
  };
}

export class TrustedCloudInterpreter implements CloudInterpretPort {
  private readonly trusted: TrustedCloudConfig;
  private readonly now: () => number;
  private readonly consentHostAvailable: () => boolean;
  private readonly openConsentSession: () => ConsentBrokerSessionPort;
  private readonly createLedger: (input: {
    verifyBroker: (record: CloudConsentApproval) => boolean;
    pricing: { revision: string; inputMicrosPerToken: number; outputMicrosPerToken: number };
  }) => CloudBudgetLedgerPort;
  private readonly fetchTransport: typeof fetch | undefined;

  constructor(trusted: TrustedCloudConfig) {
    this.trusted = trusted;
    const t = trusted;
    this.now = typeof t.now === 'function' ? t.now : Date.now;
    this.consentHostAvailable =
      typeof t.consentHostAvailable === 'function'
        ? t.consentHostAvailable
        : (): boolean => process.platform === 'win32' && privateConsentHostAvailability().ok;
    this.openConsentSession =
      typeof t.openConsentSession === 'function'
        ? t.openConsentSession
        : (): ConsentBrokerSessionPort => PrivateConsentBrokerSession.open();
    this.createLedger =
      t.createLedger ??
      ((input: {
        verifyBroker: (record: CloudConsentApproval) => boolean;
        pricing: { revision: string; inputMicrosPerToken: number; outputMicrosPerToken: number };
      }): CloudBudgetLedgerPort =>
        new DurableCloudBudgetLedger({
          file: t.ledgerFile,
          verifyBroker: input.verifyBroker,
          pricing: input.pricing,
        }));
    this.fetchTransport = t.fetchTransport;
    if (
      !isAbsolute(t.ledgerFile) ||
      !t.registryRevision ||
      !t.policyRevision ||
      !t.scopeRevision ||
      !t.pricingRevision ||
      !Number.isSafeInteger(t.maxInputTokens) ||
      !Number.isSafeInteger(t.maxOutputTokens) ||
      !Number.isSafeInteger(t.maxCostMicros) ||
      !Number.isSafeInteger(t.inputMicrosPerToken) ||
      !Number.isSafeInteger(t.outputMicrosPerToken) ||
      t.maxInputTokens < 1 ||
      t.maxOutputTokens < 1 ||
      t.maxCostMicros < 1 ||
      t.inputMicrosPerToken < 1 ||
      t.outputMicrosPerToken < 1 ||
      !Number.isSafeInteger(t.revocationEpoch) ||
      t.revocationEpoch < 0
    ) {
      throw new Error('CLOUD_TRUSTED_CONFIG_INVALID');
    }
  }

  status() {
    return {
      enabled:
        this.consentHostAvailable() &&
        this.trusted.isCurrent() &&
        !this.trusted.isOffline() &&
        !!this.trusted.readApiKey()?.trim(),
      provider: 'deepseek' as const,
      model: 'deepseek-flash' as const,
      osConsentRequired: true as const,
    };
  }

  /**
   * The frozen T04 port form. The deprecated bare-string form receives the
   * same trusted-side absolute deadline as the HTTP route so reviewed v0.2
   * callers outside the T11 write set keep their exact semantics.
   */
  async interpretGoal(
    input: string | Readonly<{ goalText: string; deadlineUnixMs: number }>,
  ): Promise<CloudInterpretResult> {
    const t = this.trusted;
    let goalText: string;
    let deadlineUnixMs: number;
    let nowMs: number;
    // ---- Entry deadline gate (documented zero-send on refusal). ----
    try {
      nowMs = this.now();
    } catch {
      return { ok: false, code: 'CLOUD_UNAVAILABLE' };
    }
    if (typeof input === 'string') {
      // Deprecated string form: the deadline is computed on the trusted side,
      // never from HTTP input, using the same window the v0.3 route uses.
      goalText = input;
      deadlineUnixMs = nowMs + MINIMUM_SENDER_DEADLINE_BUDGET_MS;
    } else {
      goalText = input.goalText;
      deadlineUnixMs = input.deadlineUnixMs;
      if (
        typeof goalText !== 'string' ||
        !Number.isSafeInteger(deadlineUnixMs) ||
        deadlineUnixMs <= 0
      ) {
        return { ok: false, code: 'CLOUD_UNAVAILABLE' };
      }
    }
    if (deadlineUnixMs - nowMs < MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS) {
      // Zero-send proof: the sender (ledger reserve / MAY_HAVE_SENT / fetch)
      // is entered only inside the single transport below — never reached.
      return { ok: false, code: 'DEADLINE_EXPIRED' };
    }
    const disclosure = buildDeepSeekGoalDisclosure(goalText);
    if (!disclosure) return { ok: false, code: 'REMOTE_REFUSED' };
    // Only GOAL_TEXT is sent. Reject too-long goals before a real OS dialog,
    // and reserve enough trusted budget for full approved token ceilings.
    const cost =
      BigInt(t.maxInputTokens) * BigInt(t.inputMicrosPerToken) +
      BigInt(t.maxOutputTokens) * BigInt(t.outputMicrosPerToken);
    if (
      Buffer.byteLength(goalText, 'utf8') > t.maxInputTokens ||
      cost > BigInt(t.maxCostMicros) ||
      !this.status().enabled
    ) {
      return { ok: false, code: 'CLOUD_UNAVAILABLE' };
    }
    const taskId = `cloud-${randomUUID()}`;
    const attemptId = `attempt-${randomUUID()}`;
    let session: ConsentBrokerSessionPort;
    try {
      session = this.openConsentSession();
    } catch {
      return { ok: false, code: 'CLOUD_UNAVAILABLE' };
    }
    try {
      let consentNow: number;
      try {
        consentNow = this.now();
      } catch {
        // Sender provably not entered yet: honest non-UNKNOWN refusal.
        return { ok: false, code: 'CLOUD_UNAVAILABLE' };
      }
      const facts = session.facts;
      const request: BrokerConsentRequest = {
        taskId,
        principalId: facts.principalUserSid,
        sessionId: facts.logonSid,
        projectionJson: disclosure.projectionJson,
        approvedProjectionSha256: disclosure.sha256,
        scopeRevision: t.scopeRevision,
        disclosureCategories: ['GOAL_TEXT'],
        registryRevision: t.registryRevision,
        policyRevision: t.policyRevision,
        pricingRevision: t.pricingRevision,
        revocationEpoch: t.revocationEpoch,
        maxCalls: 1,
        maxInputTokens: t.maxInputTokens,
        maxOutputTokens: t.maxOutputTokens,
        maxCostMicros: t.maxCostMicros,
        issuedAt: new Date(consentNow).toISOString(),
        expiresAt: new Date(consentNow + 5 * 60_000).toISOString(),
      };
      const consent = session.requestConsent(request);
      if (consent.outcome !== 'APPROVED' || !('approval' in consent)) {
        return { ok: false, code: 'CONSENT_DECLINED' };
      }
      const approval = consent.approval;
      // Keep private broker proof in this stack frame only.
      const verifyBroker = stagedBrokerVerifier(session, approval);
      const ledger = this.createLedger({
        verifyBroker,
        pricing: {
          revision: t.pricingRevision,
          inputMicrosPerToken: t.inputMicrosPerToken,
          outputMicrosPerToken: t.outputMicrosPerToken,
        },
      });
      try {
        const currentnessFor = (record: CloudConsentApproval): CloudConsentCurrentness => {
          if (
            !t.isCurrent() ||
            t.isOffline() ||
            record.scope.taskId !== taskId ||
            record.scope.principalId !== facts.principalUserSid ||
            record.scope.sessionId !== facts.logonSid ||
            !session.checkNonce(approval.confirmationNonce)
          ) {
            return { kind: 'UNRESOLVABLE' };
          }
          return {
            kind: 'CURRENT',
            taskId,
            principalId: facts.principalUserSid,
            sessionId: facts.logonSid,
            registryRevision: t.registryRevision,
            policyRevision: t.policyRevision,
            pricingRevision: t.pricingRevision,
            scopeRevision: t.scopeRevision,
            revocationEpoch: t.revocationEpoch,
            nonceIsUnused: true,
          };
        };
        const transport = new TrustedDeepSeekTransport({
          ledger,
          currentnessFor,
          isOffline: t.isOffline,
          isLocalOnly: () => false, // only in explicitly enabled REMOTE lane
          readApiKey: t.readApiKey,
          ...(this.fetchTransport === undefined ? {} : { fetchTransport: this.fetchTransport }),
        });
        // ---- FINAL pre-send / MAY_HAVE_SENT boundary (T04 Port contract).
        // The single existing sender performs ledger reserve, markMayHaveSent
        // and fetch ONLY inside invoke() below; refusing here is therefore a
        // documented zero-send (no reservation, no MAY_HAVE_SENT, no HTTP).
        let boundaryMs: number;
        try {
          boundaryMs = this.now();
        } catch {
          return { ok: false, code: 'CLOUD_UNAVAILABLE' };
        }
        if (
          !Number.isSafeInteger(boundaryMs) ||
          deadlineUnixMs - boundaryMs < MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS
        ) {
          return { ok: false, code: 'DEADLINE_EXPIRED' };
        }
        const result = await transport.invoke({
          goalText,
          attemptId,
          approval,
          maxOutputTokens: t.maxOutputTokens,
        });
        if (!result.ok) return { ok: false, code: 'REMOTE_REFUSED' };
        return {
          ok: true,
          taskId,
          status: 'UNTRUSTED_REMOTE_PROPOSAL',
          proposalText: result.proposalText,
          model: 'deepseek-flash',
          costState: result.costState,
          executed: false,
        };
      } finally {
        if (typeof (ledger as { close?: unknown }).close === 'function') {
          (ledger as { close: () => void }).close();
        }
      }
    } catch {
      // Never reflect OS error, HTTP response, model text or token to browser.
      return { ok: false, code: 'REMOTE_REFUSED' };
    } finally {
      session.shutdown();
    }
  }
}
