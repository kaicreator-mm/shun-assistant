/**
 * T09 — the single trusted Control API Host gateway before `domainApp.send`.
 *
 * DomainHarness Git v0.10.3 does not fix upstream #1437: a malformed raw
 * public `DomainApp.send()` payload can be rejected only AFTER the selected K
 * reserved an Effect Journal entry, poisoning a stable Case identity (L2 §7).
 * This gateway is Shun's own Host-only admission boundary: every untrusted
 * submission is fully validated here — canonical plain-data projection, exact
 * shape, bounded GoalRequest-compatible source data, CaseId scope binding,
 * typed Goal/target, currentness reference and human approval reference —
 * BEFORE the facade is ever touched. A refused submission performs zero
 * `send` calls and therefore can never reserve a K journal entry or poison
 * its Case: a later valid submission for the same stable Case stays
 * admissible. The gateway only ever accepts approval/currentness REFERENCE
 * strings; it never accepts, reads or manufactures approval or grant object
 * content, and it never exposes the raw facade send.
 */
import { type GoalRequest, GoalRequestSchema } from '../../../contracts/src/goal.ts';

/** The injected real facade (T11 binds the selected K-gated DomainApp). */
export interface DomainAppSendFacade {
  send(payload: unknown): Promise<unknown>;
}

export interface ControlApiGatewayInput {
  readonly domainApp: DomainAppSendFacade;
  /** Trusted clock for refusal evidence stamping only; never for admission. */
  readonly now?: () => number;
}

export type GatewayRefusalCode =
  | 'GATEWAY_INPUT_INVALID'
  | 'CASE_ID_INVALID'
  | 'CASE_SCOPE_MISMATCH'
  | 'SOURCE_DATA_INVALID'
  | 'SOURCE_OVER_BUDGET'
  | 'CURRENTNESS_REF_INVALID'
  | 'APPROVAL_REF_INVALID';

/** Do not equate a resolved send() Promise with a Kernel permit or terminal effect. */
export type SendReceipt =
  | Readonly<{
      status: 'REFUSED';
      code: GatewayRefusalCode;
      detail: string;
      sendCalls: 0;
      journalEntries: 0;
      refusedAtUnixMs: number;
    }>
  | Readonly<{
      status: 'KERNEL_REFUSED';
      code: 'KERNEL_REFUSED';
      sendCalls: 1;
      result: unknown;
    }>
  | Readonly<{
      status: 'ADMITTED';
      sendCalls: 1;
      /** K accepted the turn, but a terminal effect is not proven. */
      result: unknown;
    }>
  | Readonly<{
      status: 'COMPLETED';
      sendCalls: 1;
      result: unknown;
    }>
  | Readonly<{
      status: 'UNKNOWN';
      code: 'KERNEL_RESULT_UNKNOWN' | 'EFFECT_RESULT_UNKNOWN' | 'SEND_OUTCOME_UNKNOWN';
      sendCalls: 1;
      /** A response may not exist after MAY_HAVE_SENT; never retry blindly. */
      result?: unknown;
    }>;

export interface ControlApiGateway {
  /** The ONLY surface: pre-validated admission in front of the facade. */
  submit(rawInput: unknown): Promise<SendReceipt>;
}

/**
 * The exact submission shape admitted before `domainApp.send`. References are
 * opaque strings minted by trusted Shun authority surfaces — never objects.
 */
interface Submission {
  readonly caseId: string;
  readonly request: GoalRequest;
  readonly currentnessRef: string;
  readonly approvalRef: string;
}

const SUBMISSION_KEYS = ['approvalRef', 'caseId', 'currentnessRef', 'request'] as const;
const CONFIG_REFUSED = 'CONTROL_API_GATEWAY_CONFIGURATION_REFUSED';
/**
 * Case identities use their own bounded namespace without ':' so a Case can
 * never be confused with a reference namespace ('shun.*.v1/...').
 */
const CASE_ID = /^[A-Za-z][A-Za-z0-9._-]{0,127}$/;
const CURRENTNESS_REF = /^shun\.currentness\.v1\/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const APPROVAL_REF = /^shun\.approval\.v1\/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/** Canonical source bound: malformed or oversized payloads refuse pre-send. */
const MAX_SOURCE_CHARS = 65_536;
const MAX_GOAL_CHARS = 8192;
const MAX_OBJECTS = 256;

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function refused(code: GatewayRefusalCode, detail: string, atUnixMs: number): SendReceipt {
  return {
    status: 'REFUSED',
    code,
    detail,
    sendCalls: 0,
    journalEntries: 0,
    refusedAtUnixMs: atUnixMs,
  };
}

/**
 * Project the raw submission onto canonical plain data before ANY validation.
 * Getters, hostile prototypes, cycles and non-JSON values cannot present one
 * value to validation and another to the facade: only the snapshot is
 * validated and only the snapshot is forwarded. Alias keys ('__proto__',
 * 'constructor') survive as ordinary own properties and are refused by the
 * exact-shape checks.
 */
function canonicalSnapshot(raw: unknown): { ok: true; value: unknown } | { ok: false } {
  try {
    const text = JSON.stringify(raw);
    if (text === undefined || text.length > MAX_SOURCE_CHARS) return { ok: false };
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

function exactSubmissionKeys(value: Record<string, unknown>): boolean {
  const keys = Object.keys(value).sort();
  return (
    keys.length === SUBMISSION_KEYS.length &&
    keys.every((key, index) => key === [...SUBMISSION_KEYS].sort()[index])
  );
}

/**
 * Pre-validate one canonical snapshot completely (send happens only on the
 * success path, after this function returned).
 */
function parseSubmission(
  snapshot: unknown,
): { ok: true; value: Submission } | { ok: false; code: GatewayRefusalCode; detail: string } {
  if (!isRecord(snapshot) || !exactSubmissionKeys(snapshot)) {
    return {
      ok: false,
      code: 'GATEWAY_INPUT_INVALID',
      detail:
        'submission must be a record with exactly: approvalRef, caseId, currentnessRef, request',
    };
  }
  const { caseId, currentnessRef, approvalRef } = snapshot;
  if (typeof caseId !== 'string' || !CASE_ID.test(caseId)) {
    return { ok: false, code: 'CASE_ID_INVALID', detail: 'caseId must be a bounded Case identity' };
  }
  const requestResult = GoalRequestSchema.safeParse(snapshot.request);
  if (!requestResult.success) {
    return {
      ok: false,
      code: 'SOURCE_DATA_INVALID',
      detail: 'request does not satisfy the frozen GoalRequest-compatible controlled subset',
    };
  }
  const request = requestResult.data;
  if (
    request.goal.trim().length === 0 ||
    request.goal.length > MAX_GOAL_CHARS ||
    request.objects.length > MAX_OBJECTS
  ) {
    return {
      ok: false,
      code: 'SOURCE_OVER_BUDGET',
      detail: 'goal text or object scope exceeds the bounded source budget',
    };
  }
  // The Case identity is bound to the exact request task scope: no mixed
  // Case/namespace submissions.
  if (caseId !== request.taskId) {
    return {
      ok: false,
      code: 'CASE_SCOPE_MISMATCH',
      detail: 'caseId must equal the request taskId; mixed Case scopes refuse',
    };
  }
  if (typeof currentnessRef !== 'string' || !CURRENTNESS_REF.test(currentnessRef)) {
    return {
      ok: false,
      code: 'CURRENTNESS_REF_INVALID',
      detail: 'currentnessRef must be a non-empty trusted currentness reference',
    };
  }
  // Only a reference string: an embedded approval object is hostile data and
  // never becomes authority. The gateway does not read or validate consent
  // content — the trusted approval surface owns that.
  if (typeof approvalRef !== 'string' || !APPROVAL_REF.test(approvalRef)) {
    return {
      ok: false,
      code: 'APPROVAL_REF_INVALID',
      detail: 'approvalRef must be an explicit trusted approval reference string',
    };
  }
  return {
    ok: true,
    value: { caseId, request, currentnessRef, approvalRef },
  };
}

/**
 * Build the single trusted gateway. Configuration is snapshotted exactly
 * once; the returned surface exposes only `submit` — never a raw send.
 */
export function createControlApiGateway(input: ControlApiGatewayInput): ControlApiGateway {
  try {
    const rawSend = input?.domainApp?.send;
    if (typeof rawSend !== 'function') throw new Error(CONFIG_REFUSED);
    const rawNow = input?.now;
    if (rawNow !== undefined && typeof rawNow !== 'function') throw new Error(CONFIG_REFUSED);
    const send = rawSend.bind(input.domainApp);
    const now = (rawNow ?? Date.now).bind(input.now === undefined ? Date : input.now);
    return Object.freeze({
      async submit(rawInput: unknown): Promise<SendReceipt> {
        let atUnixMs: number;
        try {
          atUnixMs = now();
        } catch {
          atUnixMs = 0;
        }
        // Whole submission is projected and validated BEFORE any send; the
        // refused path below is reached without the facade ever being called.
        const snapshot = canonicalSnapshot(rawInput);
        if (!snapshot.ok) {
          return refused(
            'GATEWAY_INPUT_INVALID',
            'submission is not bounded canonical JSON plain data (cycle, oversized or non-serializable)',
            atUnixMs,
          );
        }
        const parsed = parseSubmission(snapshot.value);
        if (!parsed.ok) return refused(parsed.code, parsed.detail, atUnixMs);
        // Forward exactly the validated canonical submission — no rewrite of
        // the payload, no second admission path.
        // Once send() starts, even a rejection may mean the Kernel recorded an
        // effect. Never retry or claim zero Journal entries after this point.
        let result: unknown;
        try {
          result = await send(deepFreeze(parsed.value));
        } catch {
          return { status: 'UNKNOWN', code: 'SEND_OUTCOME_UNKNOWN', sendCalls: 1 };
        }
        return classifyKernelResult(result);
      },
    }) satisfies ControlApiGateway;
  } catch {
    throw new TypeError(CONFIG_REFUSED);
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/**
 * DomainHarness public send() reports a top-level K decision. Its resolved
 * payload is NOT automatically terminal. Only the K-admitted envelope with
 * explicitly terminal, executed and successful effects can be COMPLETED.
 * Unknown/partial/rejected post-send outcomes retain the may-have-sent fact.
 */
function classifyKernelResult(result: unknown): SendReceipt {
  if (!isRecord(result)) {
    return { status: 'UNKNOWN', code: 'KERNEL_RESULT_UNKNOWN', sendCalls: 1, result };
  }
  if (result.status === 'refused' || result.status === 'rejected') {
    return { status: 'KERNEL_REFUSED', code: 'KERNEL_REFUSED', sendCalls: 1, result };
  }
  if (result.status !== 'admitted') {
    return { status: 'UNKNOWN', code: 'KERNEL_RESULT_UNKNOWN', sendCalls: 1, result };
  }
  const admitted = result.admitted;
  if (!isRecord(admitted) || !Array.isArray(admitted.effects)) {
    return { status: 'UNKNOWN', code: 'KERNEL_RESULT_UNKNOWN', sendCalls: 1, result };
  }
  // A K-admitted turn with no scheduled external effects may be admissible,
  // but it proves no terminal external effect. HTTP must not call it complete.
  if (admitted.effects.length === 0) {
    return { status: 'ADMITTED', sendCalls: 1, result };
  }
  const effects = admitted.effects;
  for (const effect of effects) {
    if (!isRecord(effect) || effect.disposition !== 'executed' ||
        !isRecord(effect.output) || effect.output.phase !== 'terminal' ||
        !isRecord(effect.output.outcome)) {
      return { status: 'UNKNOWN', code: 'EFFECT_RESULT_UNKNOWN', sendCalls: 1, result };
    }
    if (effect.output.outcome.ok !== true) {
      return effect.output.outcome.ok === false
        ? { status: 'KERNEL_REFUSED', code: 'KERNEL_REFUSED', sendCalls: 1, result }
        : { status: 'UNKNOWN', code: 'EFFECT_RESULT_UNKNOWN', sendCalls: 1, result };
    }
  }
  return { status: 'COMPLETED', sendCalls: 1, result };
}
