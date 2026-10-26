// v0.2 T08 C03 — actual user-confirmed DeepSeek goal interpretation.
// Reuses the reviewed T01 transport/SQLite budget and C02 Win32 broker.
// No browser can supply an approval, target, price, credential or token.
// The result is an UNTRUSTED suggestion for display, NOT an executable plan.
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
  type BrokerConsentRequest,
  PrivateConsentBrokerSession,
  privateConsentHostAvailability,
} from '../native/index.ts';
import { createCloudAuthorityCurrentness, readOperatorCloudAuthority } from './cloud-authority.ts';

export type CloudInterpretResult =
  | {
      ok: true;
      taskId: string;
      status: 'UNTRUSTED_REMOTE_PROPOSAL';
      proposalText: string;
      model: 'deepseek-flash';
      costState: 'UNKNOWN_COST';
      executed: false;
    }
  | { ok: false; code: 'CLOUD_UNAVAILABLE' | 'CONSENT_DECLINED' | 'REMOTE_REFUSED' };

export interface CloudInterpretPort {
  status(): {
    enabled: boolean;
    provider: 'deepseek';
    model: 'deepseek-flash';
    osConsentRequired: true;
  };
  interpretGoal(goalText: string): Promise<CloudInterpretResult>;
}

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

  constructor(trusted: TrustedCloudConfig) {
    this.trusted = trusted;
    const t = trusted;
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
        process.platform === 'win32' &&
        this.trusted.isCurrent() &&
        !this.trusted.isOffline() &&
        !!this.trusted.readApiKey()?.trim() &&
        privateConsentHostAvailability().ok,
      provider: 'deepseek' as const,
      model: 'deepseek-flash' as const,
      osConsentRequired: true as const,
    };
  }

  async interpretGoal(goalText: string): Promise<CloudInterpretResult> {
    const t = this.trusted;
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
    let session: PrivateConsentBrokerSession;
    try {
      session = PrivateConsentBrokerSession.open();
    } catch {
      return { ok: false, code: 'CLOUD_UNAVAILABLE' };
    }
    try {
      const now = Date.now();
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
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + 5 * 60_000).toISOString(),
      };
      const consent = session.requestConsent(request);
      if (consent.outcome !== 'APPROVED') {
        return { ok: false, code: 'CONSENT_DECLINED' };
      }
      const approval = consent.approval;
      // Keep private broker proof in this stack frame only.
      const verifyBroker = stagedBrokerVerifier(session, approval);
      const ledger = new DurableCloudBudgetLedger({
        file: t.ledgerFile,
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
        });
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
        ledger.close();
      }
    } catch {
      // Never reflect OS error, HTTP response, model text or token to browser.
      return { ok: false, code: 'REMOTE_REFUSED' };
    } finally {
      session.shutdown();
    }
  }
}
