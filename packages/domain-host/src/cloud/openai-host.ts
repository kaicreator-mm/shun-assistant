/**
 * Trusted Shun Host binding for the selected DomainHarness OpenAI-compatible C.
 *
 * This module contains no HTTP sender. T11 installs the existing
 * TrustedCloudInterpreter.interpretGoal and a durable ShunStore-backed
 * request journal. The only remote path remains llm-remote's existing
 * TrustedDeepSeekTransport.
 */
import { createHash } from 'node:crypto';
import type { ShunLlmGenerateResultV1 } from '../../../domain-computer/src/contracts/llm-generate-v1.ts';

const CONTRACT = 'dh.llm.generate/1' as const;
const MODEL = 'deepseek-flash' as const;
const PROVIDER = 'openai-compatible' as const;
const REQUEST_ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_GOAL_CHARS = 8192;

/**
 * Existing sender has a five-minute private consent window and a fixed
 * 15-second AbortSignal.timeout. Keep a five-second scheduling guard. A
 * shorter request deadline is explicitly refused before consent/HTTP rather
 * than silently letting the sender exceed it.
 */
const CONSENT_WINDOW_MS = 300_000;
const SENDER_TIMEOUT_MS = 15_000;
const SENDER_SCHEDULING_GUARD_MS = 5_000;
/** Remaining-budget floor that must still hold when the sender is entered. */
export const MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS = SENDER_TIMEOUT_MS + SENDER_SCHEDULING_GUARD_MS;
export const MINIMUM_SENDER_DEADLINE_BUDGET_MS =
  CONSENT_WINDOW_MS + MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS;

export type TrustedCloudInterpretResult =
  | Readonly<{
      ok: true;
      taskId: string;
      status: 'UNTRUSTED_REMOTE_PROPOSAL';
      proposalText: string;
      model: 'deepseek-flash';
      costState: 'UNKNOWN_COST';
      executed: false;
    }>
  | Readonly<{
      ok: false;
      code: 'CLOUD_UNAVAILABLE' | 'CONSENT_DECLINED' | 'REMOTE_REFUSED' | 'DEADLINE_EXPIRED';
    }>;

export interface TrustedCloudInterpreterPort {
  status(): Readonly<{
    enabled: boolean;
    provider: 'deepseek';
    model: 'deepseek-flash';
    osConsentRequired: true;
  }>;
  /**
   * The absolute request deadline travels with the goal text. Implementations
   * MUST recheck it at the final pre-send / MAY_HAVE_SENT boundary — after
   * consent and broker resolution, immediately before the existing sender
   * reserves the ledger, marks MAY_HAVE_SENT or reaches HTTP — and refuse
   * with DEADLINE_EXPIRED without entering the sender when the remaining
   * budget no longer covers MINIMUM_PRE_SEND_DEADLINE_BUDGET_MS. Returning
   * DEADLINE_EXPIRED asserts a documented zero-send (no ledger reservation,
   * no MAY_HAVE_SENT, no HTTP); any refusal that cannot prove the sender was
   * never entered must stay REMOTE_REFUSED so K preserves UNKNOWN.
   */
  interpretGoal(
    input: Readonly<{ goalText: string; deadlineUnixMs: number }>,
  ): Promise<TrustedCloudInterpretResult>;
}

export type CloudRequestJournalDecision =
  | Readonly<{ status: 'RESERVED' }>
  | Readonly<{ status: 'REPLAY'; result: ShunLlmGenerateResultV1 }>
  | Readonly<{ status: 'IN_FLIGHT' }>
  | Readonly<{ status: 'CONFLICT' }>
  | Readonly<{ status: 'UNAVAILABLE' }>;

/**
 * T11 must provide an atomic, durable ShunStore-backed implementation.
 * requestSha256 binds the exact neutral request without persisting raw goal
 * text in the journal. A RESERVED record is never replaced or re-issued.
 */
export interface DurableCloudRequestJournal {
  readonly durability: 'DURABLE_SHUN_STORE';
  reserve(
    input: Readonly<{
      requestId: string;
      requestSha256: string;
      createdAtUnixMs: number;
    }>,
  ): Promise<CloudRequestJournalDecision>;
  complete(
    input: Readonly<{
      requestId: string;
      requestSha256: string;
      result: ShunLlmGenerateResultV1;
    }>,
  ): Promise<boolean>;
}

export interface TrustedCloudHostBindingConfig {
  readonly interpreter: TrustedCloudInterpreterPort;
  readonly journal: DurableCloudRequestJournal;
  /** Must be the same trusted ceiling used to configure TrustedCloudInterpreter. */
  readonly configuredMaxOutputTokens: number;
  readonly now?: () => number;
}

type ParsedRequest = Readonly<{
  requestId: string;
  goalText: string;
  deadlineUnixMs: number;
  maxOutputTokens: number;
}>;

function isRecord(value: unknown): value is Record<string, unknown> {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function requestIdFrom(value: unknown): string {
  try {
    if (isRecord(value)) {
      const requestId = value.requestId;
      if (typeof requestId === 'string' && REQUEST_ID.test(requestId)) return requestId;
    }
  } catch {
    /* return a fixed non-authoritative correlation */
  }
  return 'invalid-request';
}

function parseRequest(value: unknown): ParsedRequest | null {
  try {
    if (!isRecord(value)) return null;
    const keys = Object.keys(value).sort();
    if (
      keys.join(',') !==
      'contractVersion,deadlineUnixMs,maxOutputTokens,messages,modelId,outputFormat,requestId'
    )
      return null;
    const contractVersion = value.contractVersion;
    const modelId = value.modelId;
    const outputFormat = value.outputFormat;
    const requestId = value.requestId;
    const deadlineUnixMs = value.deadlineUnixMs;
    const maxOutputTokens = value.maxOutputTokens;
    const messages = value.messages;
    if (
      contractVersion !== CONTRACT ||
      modelId !== MODEL ||
      outputFormat !== 'text' ||
      typeof requestId !== 'string' ||
      !REQUEST_ID.test(requestId) ||
      !Number.isSafeInteger(deadlineUnixMs) ||
      (deadlineUnixMs as number) <= 0 ||
      !Number.isSafeInteger(maxOutputTokens) ||
      (maxOutputTokens as number) < 1 ||
      (maxOutputTokens as number) > 8192 ||
      !Array.isArray(messages) ||
      messages.length !== 1
    )
      return null;
    const message = messages[0];
    if (!isRecord(message) || Object.keys(message).sort().join(',') !== 'content,role') return null;
    const role = message.role;
    const content = message.content;
    if (
      role !== 'user' ||
      typeof content !== 'string' ||
      content.length < 1 ||
      content.length > MAX_GOAL_CHARS ||
      content.trim().length === 0 ||
      content.includes('\0')
    )
      return null;
    return Object.freeze({
      requestId,
      goalText: content,
      deadlineUnixMs: deadlineUnixMs as number,
      maxOutputTokens: maxOutputTokens as number,
    });
  } catch {
    return null;
  }
}

function requestDigest(request: ParsedRequest): string {
  return createHash('sha256')
    .update(
      JSON.stringify({
        contractVersion: CONTRACT,
        requestId: request.requestId,
        modelId: MODEL,
        deadlineUnixMs: request.deadlineUnixMs,
        messages: [{ role: 'user', content: request.goalText }],
        maxOutputTokens: request.maxOutputTokens,
        outputFormat: 'text',
      }),
      'utf8',
    )
    .digest('hex');
}

function resultBase(requestId: string) {
  return {
    contractVersion: CONTRACT,
    requestId,
    providerKind: PROVIDER,
    modelId: MODEL,
    usage: { evidenceMode: 'unavailable' as const },
  };
}

function refused(
  requestId: string,
  category: 'UNSUPPORTED_FEATURE' | 'AUTH_DENIED' | 'CANCELLED' | 'DEADLINE',
  reason: string,
): ShunLlmGenerateResultV1 {
  return {
    ...resultBase(requestId),
    status: 'refused',
    errorCategory: category,
    reasonCode: reason,
  };
}

function failed(requestId: string, reason: string): ShunLlmGenerateResultV1 {
  return {
    ...resultBase(requestId),
    status: 'failed',
    errorCategory: 'UNAVAILABLE',
    reasonCode: reason,
  };
}

function unknown(requestId: string, reason: string): ShunLlmGenerateResultV1 {
  return {
    ...resultBase(requestId),
    status: 'unknown',
    errorCategory: 'OUTCOME_UNKNOWN',
    reasonCode: reason,
  };
}

function completed(requestId: string, text: string): ShunLlmGenerateResultV1 {
  return {
    ...resultBase(requestId),
    status: 'completed',
    text,
    finishReason: 'stop',
  };
}

function validResult(value: unknown, requestId: string): value is ShunLlmGenerateResultV1 {
  try {
    if (
      !isRecord(value) ||
      value.contractVersion !== CONTRACT ||
      value.requestId !== requestId ||
      value.providerKind !== PROVIDER ||
      value.modelId !== MODEL ||
      !isRecord(value.usage) ||
      Object.keys(value.usage).join(',') !== 'evidenceMode' ||
      value.usage.evidenceMode !== 'unavailable'
    )
      return false;
    const base = ['contractVersion', 'modelId', 'providerKind', 'requestId', 'status', 'usage'];
    const keys = Object.keys(value).sort();
    if (value.status === 'completed') {
      const allowed = [...base, 'finishReason', 'providerRequestId', 'receiptRef', 'text'].sort();
      return (
        keys.every((key) => allowed.includes(key)) &&
        [
          'contractVersion',
          'modelId',
          'providerKind',
          'requestId',
          'status',
          'usage',
          'text',
          'finishReason',
        ].every((key) => keys.includes(key)) &&
        typeof value.text === 'string' &&
        value.text.length > 0 &&
        value.text.length <= 65_536 &&
        (value.finishReason === 'stop' ||
          value.finishReason === 'length' ||
          value.finishReason === 'tool_proposal' ||
          value.finishReason === 'content_filtered' ||
          value.finishReason === 'other') &&
        (value.providerRequestId === undefined ||
          (typeof value.providerRequestId === 'string' && value.providerRequestId.length <= 256)) &&
        (value.receiptRef === undefined ||
          (typeof value.receiptRef === 'string' && value.receiptRef.length <= 256))
      );
    }
    const allowed = [
      ...base,
      'errorCategory',
      'providerRequestId',
      'reasonCode',
      'receiptRef',
    ].sort();
    if (
      !keys.every((key) => allowed.includes(key)) ||
      ![
        'contractVersion',
        'modelId',
        'providerKind',
        'requestId',
        'status',
        'usage',
        'errorCategory',
        'reasonCode',
      ].every((key) => keys.includes(key)) ||
      typeof value.reasonCode !== 'string' ||
      !/^[A-Z0-9_]{1,64}$/.test(value.reasonCode) ||
      (value.providerRequestId !== undefined &&
        (typeof value.providerRequestId !== 'string' || value.providerRequestId.length > 256)) ||
      (value.receiptRef !== undefined &&
        (typeof value.receiptRef !== 'string' || value.receiptRef.length > 256))
    )
      return false;
    if (value.status === 'unknown') return value.errorCategory === 'OUTCOME_UNKNOWN';
    if (value.status === 'failed') return value.errorCategory === 'UNAVAILABLE';
    return (
      value.status === 'refused' &&
      (value.errorCategory === 'UNSUPPORTED_FEATURE' ||
        value.errorCategory === 'AUTH_DENIED' ||
        value.errorCategory === 'CANCELLED' ||
        value.errorCategory === 'DEADLINE') &&
      (value.providerRequestId === undefined ||
        (typeof value.providerRequestId === 'string' && value.providerRequestId.length <= 256)) &&
      (value.receiptRef === undefined ||
        (typeof value.receiptRef === 'string' && value.receiptRef.length <= 256))
    );
  } catch {
    return false;
  }
}

function mapInterpreterResult(requestId: string, value: unknown): ShunLlmGenerateResultV1 {
  try {
    if (!isRecord(value)) return unknown(requestId, 'REMOTE_OUTCOME_UNRESOLVED');
    if (value.ok === true) {
      if (
        value.status !== 'UNTRUSTED_REMOTE_PROPOSAL' ||
        value.model !== MODEL ||
        value.costState !== 'UNKNOWN_COST' ||
        value.executed !== false ||
        typeof value.proposalText !== 'string' ||
        value.proposalText.trim().length === 0 ||
        value.proposalText.length > 65_536 ||
        typeof value.taskId !== 'string' ||
        value.taskId.length === 0
      )
        return unknown(requestId, 'REMOTE_OUTCOME_UNRESOLVED');
      return completed(requestId, value.proposalText);
    }
    if (value.ok === false && value.code === 'CONSENT_DECLINED') {
      return refused(requestId, 'CANCELLED', 'CONSENT_DECLINED');
    }
    if (value.ok === false && value.code === 'CLOUD_UNAVAILABLE') {
      return failed(requestId, 'CLOUD_UNAVAILABLE');
    }
    // DEADLINE_EXPIRED is a trusted pre-send refusal: the sender was never
    // entered, so unlike REMOTE_REFUSED it needs no UNKNOWN fence.
    if (value.ok === false && value.code === 'DEADLINE_EXPIRED') {
      return refused(requestId, 'DEADLINE', 'DEADLINE_EXPIRED');
    }
    // REMOTE_REFUSED does not prove zero-send; preserve K UNKNOWN/UNKNOWN_COST.
    return unknown(requestId, 'REMOTE_OUTCOME_UNRESOLVED');
  } catch {
    return unknown(requestId, 'REMOTE_OUTCOME_UNRESOLVED');
  }
}

export function createTrustedCloudHostBinding(config: TrustedCloudHostBindingConfig): Readonly<{
  generate(input: unknown): Promise<ShunLlmGenerateResultV1>;
}> {
  let status: TrustedCloudInterpreterPort['status'];
  let interpretGoal: TrustedCloudInterpreterPort['interpretGoal'];
  let reserve: DurableCloudRequestJournal['reserve'];
  let complete: DurableCloudRequestJournal['complete'];
  let now: () => number;
  let configuredMaxOutputTokens: number;
  try {
    const interpreter = config?.interpreter;
    const journal = config?.journal;
    const rawConfiguredMaxOutputTokens = config?.configuredMaxOutputTokens;
    const rawNow = config?.now;
    const rawStatus = interpreter?.status;
    const rawInterpret = interpreter?.interpretGoal;
    const rawReserve = journal?.reserve;
    const rawComplete = journal?.complete;
    if (
      journal?.durability !== 'DURABLE_SHUN_STORE' ||
      typeof rawStatus !== 'function' ||
      typeof rawInterpret !== 'function' ||
      typeof rawReserve !== 'function' ||
      typeof rawComplete !== 'function' ||
      !Number.isSafeInteger(rawConfiguredMaxOutputTokens) ||
      (rawConfiguredMaxOutputTokens as number) < 1 ||
      (rawConfiguredMaxOutputTokens as number) > 8192
    )
      throw new Error('CLOUD_HOST_CONFIGURATION_REFUSED');
    status = rawStatus.bind(interpreter);
    interpretGoal = rawInterpret.bind(interpreter);
    reserve = rawReserve.bind(journal);
    complete = rawComplete.bind(journal);
    now = (rawNow ?? Date.now).bind(config);
    configuredMaxOutputTokens = rawConfiguredMaxOutputTokens as number;
  } catch {
    throw new Error('CLOUD_HOST_CONFIGURATION_REFUSED');
  }

  const generate = async (raw: unknown): Promise<ShunLlmGenerateResultV1> => {
    const request = parseRequest(raw);
    if (!request) return refused(requestIdFrom(raw), 'AUTH_DENIED', 'LLM_REQUEST_REFUSED');
    if (request.maxOutputTokens !== configuredMaxOutputTokens) {
      return refused(request.requestId, 'UNSUPPORTED_FEATURE', 'OUTPUT_TOKEN_CEILING_UNSUPPORTED');
    }

    let currentTime: number;
    try {
      currentTime = now();
    } catch {
      return failed(request.requestId, 'CLOCK_UNAVAILABLE');
    }
    if (
      !Number.isSafeInteger(currentTime) ||
      request.deadlineUnixMs - currentTime < MINIMUM_SENDER_DEADLINE_BUDGET_MS
    )
      return refused(request.requestId, 'DEADLINE', 'DEADLINE_BUDGET_UNSUPPORTED');

    const digest = requestDigest(request);
    let reservation: CloudRequestJournalDecision;
    try {
      reservation = await reserve({
        requestId: request.requestId,
        requestSha256: digest,
        createdAtUnixMs: currentTime,
      });
    } catch {
      return failed(request.requestId, 'REQUEST_JOURNAL_UNAVAILABLE');
    }
    let reservationStatus: unknown;
    let replayValue: unknown;
    try {
      if (!isRecord(reservation)) return failed(request.requestId, 'REQUEST_JOURNAL_UNAVAILABLE');
      reservationStatus = reservation.status;
      if (reservationStatus === 'REPLAY')
        replayValue = (reservation as { result?: unknown }).result;
    } catch {
      return failed(request.requestId, 'REQUEST_JOURNAL_UNAVAILABLE');
    }
    if (reservationStatus === 'REPLAY') {
      return validResult(replayValue, request.requestId)
        ? replayValue
        : unknown(request.requestId, 'REQUEST_JOURNAL_CORRUPT');
    }
    if (reservationStatus === 'IN_FLIGHT')
      return unknown(request.requestId, 'REQUEST_ALREADY_IN_FLIGHT');
    if (reservationStatus === 'CONFLICT')
      return refused(request.requestId, 'AUTH_DENIED', 'REQUEST_ID_CONFLICT');
    if (reservationStatus === 'UNAVAILABLE')
      return failed(request.requestId, 'REQUEST_JOURNAL_UNAVAILABLE');
    if (reservationStatus !== 'RESERVED')
      return failed(request.requestId, 'REQUEST_JOURNAL_UNAVAILABLE');

    const finish = async (result: ShunLlmGenerateResultV1): Promise<ShunLlmGenerateResultV1> => {
      try {
        return (await complete({ requestId: request.requestId, requestSha256: digest, result }))
          ? result
          : unknown(request.requestId, 'REQUEST_JOURNAL_COMPLETION_UNAVAILABLE');
      } catch {
        return unknown(request.requestId, 'REQUEST_JOURNAL_COMPLETION_UNAVAILABLE');
      }
    };

    try {
      currentTime = now();
      if (
        !Number.isSafeInteger(currentTime) ||
        request.deadlineUnixMs - currentTime < MINIMUM_SENDER_DEADLINE_BUDGET_MS
      )
        return await finish(refused(request.requestId, 'DEADLINE', 'DEADLINE_BUDGET_UNSUPPORTED'));

      let hostStatus: ReturnType<TrustedCloudInterpreterPort['status']>;
      try {
        hostStatus = status();
      } catch {
        return await finish(failed(request.requestId, 'CLOUD_UNAVAILABLE'));
      }
      if (
        hostStatus?.enabled !== true ||
        hostStatus.provider !== 'deepseek' ||
        hostStatus.model !== MODEL ||
        hostStatus.osConsentRequired !== true
      )
        return await finish(failed(request.requestId, 'CLOUD_UNAVAILABLE'));

      // Recheck after the Host status/currentness read and immediately before
      // entering the existing broker+sender path.
      currentTime = now();
      if (
        !Number.isSafeInteger(currentTime) ||
        request.deadlineUnixMs - currentTime < MINIMUM_SENDER_DEADLINE_BUDGET_MS
      )
        return await finish(refused(request.requestId, 'DEADLINE', 'DEADLINE_BUDGET_UNSUPPORTED'));

      // The absolute deadline is bound into the trusted interpreter so its
      // consent/broker/sender path can enforce it again at the final pre-send
      // / MAY_HAVE_SENT boundary (zero HTTP once the remaining budget cannot
      // cover the sender floor).
      const cloudResult = await interpretGoal({
        goalText: request.goalText,
        deadlineUnixMs: request.deadlineUnixMs,
      });
      const mapped = mapInterpreterResult(request.requestId, cloudResult);
      const resultTime = now();
      if (
        !Number.isSafeInteger(resultTime) ||
        (resultTime > request.deadlineUnixMs &&
          (mapped.status === 'completed' || mapped.status === 'unknown'))
      )
        return await finish(unknown(request.requestId, 'DEADLINE_OUTCOME_UNRESOLVED'));
      return await finish(mapped);
    } catch {
      return await finish(unknown(request.requestId, 'REMOTE_OUTCOME_UNRESOLVED'));
    }
  };

  return Object.freeze({ generate });
}

let installedBinding: ReturnType<typeof createTrustedCloudHostBinding> | undefined;

/** T11 calls once with the existing trusted interpreter and durable ShunStore journal. */
export function installTrustedCloudHostBinding(config: TrustedCloudHostBindingConfig): void {
  if (installedBinding) throw new Error('CLOUD_HOST_ALREADY_INSTALLED');
  installedBinding = createTrustedCloudHostBinding(config);
}

/** Static module entry consumed by domain-harness-openai-host.generate. */
export async function generate(input: unknown): Promise<ShunLlmGenerateResultV1> {
  if (!installedBinding) return failed(requestIdFrom(input), 'CLOUD_HOST_NOT_INSTALLED');
  return installedBinding.generate(input);
}
