// v0.2 T01: trusted backend-only DeepSeek Flash HTTPS transport.
// This adapter never mints consent, authorizes an action or runs a model proposal.
// T08 owns genuine user gesture/private IPC; this module consumes its proof.
import { createHash } from 'node:crypto';
import {
  type CloudConsentApproval,
  CloudConsentApprovalSchema,
  type CloudConsentCurrentness,
  canonicalJson,
} from '@shun/contracts';
import type { DurableCloudBudgetLedger } from './atomic-budget.ts';

export const DEEPSEEK_FLASH_DESTINATION = 'https://api.deepseek.com/chat/completions';
const MODEL_ID = 'deepseek-flash';
const MAX_GOAL_CHARS = 8192;
const MAX_RESPONSE_BYTES = 256 * 1024;

export type DeepSeekTransportRefusal =
  | 'REMOTE_POLICY_REFUSED'
  | 'DISCLOSURE_INVALID'
  | 'DISCLOSURE_SCOPE_DRIFT'
  | 'CREDENTIAL_UNAVAILABLE'
  | 'BUDGET_REFUSED'
  | 'CONSENT_STALE'
  | 'REMOTE_UNAVAILABLE'
  | 'REMOTE_RESPONSE_INVALID'
  | 'COST_STATE_UNCERTAIN';

export type DeepSeekTransportResult =
  | { ok: true; attemptId: string; proposalText: string; costState: 'UNKNOWN_COST' }
  | { ok: false; code: DeepSeekTransportRefusal };

export type DeepSeekGoalInput = Readonly<{
  goalText: string;
  attemptId: string;
  approval: unknown;
  maxOutputTokens: number;
}>;

export type TrustedDeepSeekHost = Readonly<{
  ledger: Pick<DurableCloudBudgetLedger, 'reserve' | 'markMayHaveSent' | 'markUnknownCost'>;
  /** These ports are injected by Shun's trusted backend, NOT an API request. */
  currentnessFor: (approval: CloudConsentApproval) => CloudConsentCurrentness;
  isOffline: () => boolean;
  isLocalOnly: () => boolean;
  /** Defaults to Shun backend's environment; key never reaches the UI. */
  readApiKey?: () => string | undefined;
  now?: () => string;
  /** Only the host can install a test transport. Never expose to a request. */
  fetchTransport?: typeof fetch;
}>;

function eligibleGoal(goal: unknown): goal is string {
  return (
    typeof goal === 'string' &&
    goal.length > 0 &&
    goal.length <= MAX_GOAL_CHARS &&
    goal.trim().length > 0 &&
    !goal.includes('\0')
  );
}

/**
 * The UI must display this EXACT JSON and then have T08 issue its private
 * approval for the returned digest. No file, process, environment or secret
 * fields exist in this v0.2 T01 minimal-GOAL_TEXT disclosure shape.
 */
export function buildDeepSeekGoalDisclosure(
  goalText: unknown,
): { projectionJson: string; sha256: string } | null {
  if (!eligibleGoal(goalText)) return null;
  const projectionJson = canonicalJson({
    destination: DEEPSEEK_FLASH_DESTINATION,
    providerId: 'deepseek',
    modelId: MODEL_ID,
    disclosureCategories: ['GOAL_TEXT'],
    goalText,
  });
  const sha256 = createHash('sha256').update(projectionJson, 'utf8').digest('hex');
  return { projectionJson, sha256 };
}

function exactRequestBytes(goalText: string, maxOutputTokens: number): Buffer {
  // Closed field set. No caller-supplied raw body, messages, system prompt,
  // host facts, private paths, tool schema or arbitrary options are accepted.
  return Buffer.from(
    canonicalJson({
      model: MODEL_ID,
      messages: [{ role: 'user', content: goalText }],
      max_tokens: maxOutputTokens,
      stream: false,
    }),
    'utf8',
  );
}

async function boundedJsonResponse(response: Response): Promise<unknown | null> {
  if (
    response.status !== 200 ||
    response.redirected ||
    (response.url !== '' && response.url !== DEEPSEEK_FLASH_DESTINATION) ||
    !response.headers.get('content-type')?.toLowerCase().includes('application/json') ||
    !response.body
  ) {
    return null;
  }
  const reader = response.body.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      total += chunk.value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        return null;
      }
      parts.push(chunk.value);
    }
    const decoded = Buffer.concat(parts, total).toString('utf8');
    return JSON.parse(decoded) as unknown;
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}

function extractProposal(value: unknown): string | null {
  if (!value || typeof value !== 'object') return null;
  const choices = (value as { choices?: unknown }).choices;
  if (!Array.isArray(choices) || choices.length !== 1) return null;
  const first: unknown = choices[0];
  if (!first || typeof first !== 'object') return null;
  const { finish_reason, message } = first as {
    finish_reason?: unknown;
    message?: unknown;
  };
  if (finish_reason !== 'stop' || !message || typeof message !== 'object') return null;
  const { role, content } = message as { role?: unknown; content?: unknown };
  return role === 'assistant' && typeof content === 'string' && content.length > 0 ? content : null;
}

/**
 * Returned proposalText is UNTRUSTED. A later PlannerPort must parse and
 * independently normalize it against the registered GoalProposal schema.
 */
export class TrustedDeepSeekTransport {
  private readonly host: TrustedDeepSeekHost;

  constructor(host: TrustedDeepSeekHost) {
    if (
      !host?.ledger ||
      typeof host.ledger.reserve !== 'function' ||
      typeof host.ledger.markMayHaveSent !== 'function' ||
      typeof host.ledger.markUnknownCost !== 'function' ||
      typeof host.currentnessFor !== 'function' ||
      typeof host.isOffline !== 'function' ||
      typeof host.isLocalOnly !== 'function'
    ) {
      throw new Error('DEEPSEEK_HOST_CONFIGURATION_REFUSED');
    }
    this.host = host;
  }

  async invoke(input: DeepSeekGoalInput): Promise<DeepSeekTransportResult> {
    // Fail closed before ever reading a credential or reserving a call.
    try {
      if (this.host.isOffline() !== false || this.host.isLocalOnly() !== false) {
        return { ok: false, code: 'REMOTE_POLICY_REFUSED' };
      }
    } catch {
      return { ok: false, code: 'REMOTE_POLICY_REFUSED' };
    }

    const parsed = CloudConsentApprovalSchema.safeParse(input.approval);
    const disclosure = buildDeepSeekGoalDisclosure(input.goalText);
    if (!parsed.success || !disclosure) return { ok: false, code: 'DISCLOSURE_INVALID' };
    const approval = parsed.data;
    const scope = approval.scope;
    if (
      scope.destination !== DEEPSEEK_FLASH_DESTINATION ||
      scope.modelId !== MODEL_ID ||
      scope.providerId !== 'deepseek' ||
      scope.disclosureCategories.length !== 1 ||
      scope.disclosureCategories[0] !== 'GOAL_TEXT' ||
      scope.approvedProjectionSha256 !== disclosure.sha256 ||
      !Number.isSafeInteger(input.maxOutputTokens) ||
      input.maxOutputTokens < 1 ||
      input.maxOutputTokens > scope.maxOutputTokens
    ) {
      return { ok: false, code: 'DISCLOSURE_SCOPE_DRIFT' };
    }

    let key: string | undefined;
    let currentness: CloudConsentCurrentness;
    let now: string;
    try {
      key = (this.host.readApiKey ?? (() => process.env.DEEPSEEK_API_KEY))();
      currentness = this.host.currentnessFor(approval);
      now = (this.host.now ?? (() => new Date().toISOString()))();
    } catch {
      return { ok: false, code: 'CONSENT_STALE' };
    }
    if (!key?.trim() || key.trim() !== key || key.includes('\r') || key.includes('\n')) {
      return { ok: false, code: 'CREDENTIAL_UNAVAILABLE' };
    }

    const bytes = exactRequestBytes(input.goalText, input.maxOutputTokens);
    const reserved = this.host.ledger.reserve({
      attemptId: input.attemptId,
      approval,
      currentness,
      now,
      requestBytes: bytes,
      disclosureProjectionBytes: Buffer.from(disclosure.projectionJson, 'utf8'),
      outputTokenCeiling: input.maxOutputTokens,
    });
    if (!reserved.ok) return { ok: false, code: 'BUDGET_REFUSED' };

    // A second host currentness read is mandatory after durable reservation.
    // If revocation happened in between, do not reach fetch, even if the
    // reservation consumed budget; no blind refund is offered.
    let sendCurrentness: CloudConsentCurrentness;
    let sendTime: string;
    try {
      if (this.host.isOffline() !== false || this.host.isLocalOnly() !== false) {
        return { ok: false, code: 'REMOTE_POLICY_REFUSED' };
      }
      sendCurrentness = this.host.currentnessFor(approval);
      sendTime = (this.host.now ?? (() => new Date().toISOString()))();
    } catch {
      return { ok: false, code: 'CONSENT_STALE' };
    }
    if (
      !this.host.ledger.markMayHaveSent({
        attemptId: input.attemptId,
        actualRequestBytes: bytes,
        approval,
        currentness: sendCurrentness,
        now: sendTime,
      })
    ) {
      return { ok: false, code: 'CONSENT_STALE' };
    }

    let response: Response;
    try {
      response = await (this.host.fetchTransport ?? fetch)(DEEPSEEK_FLASH_DESTINATION, {
        method: 'POST',
        redirect: 'manual',
        credentials: 'omit',
        cache: 'no-store',
        headers: {
          Authorization: `Bearer ${key}`,
          'Content-Type': 'application/json',
        },
        body: bytes,
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      this.host.ledger.markUnknownCost(input.attemptId);
      return { ok: false, code: 'REMOTE_UNAVAILABLE' };
    }
    // Regardless of HTTP outcome or response parsing, the call may be billed.
    if (!this.host.ledger.markUnknownCost(input.attemptId)) {
      return { ok: false, code: 'COST_STATE_UNCERTAIN' };
    }
    const raw = await boundedJsonResponse(response);
    const proposalText = extractProposal(raw);
    if (proposalText === null) return { ok: false, code: 'REMOTE_RESPONSE_INVALID' };
    return {
      ok: true,
      attemptId: input.attemptId,
      proposalText,
      costState: 'UNKNOWN_COST',
    };
  }
}
