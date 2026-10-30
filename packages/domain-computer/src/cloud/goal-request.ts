import type { ShunLlmGenerateRequestV1 } from '../contracts/llm-generate-v1.ts';

const REQUEST_ID = /^[A-Za-z0-9_-]{1,128}$/;

export type NeutralGoalRequestInput = Readonly<{
  requestId: string;
  goalText: string;
  deadlineUnixMs: number;
  maxOutputTokens: number;
}>;

/**
 * Build the only disclosure shape supported by this selected C: exactly one
 * user goal and text output. No system prompt, history, files, B-040 context,
 * tools, schema, temperature or arbitrary options are copied.
 */
export function buildNeutralGoalRequest(input: unknown): ShunLlmGenerateRequestV1 | null {
  try {
    if (input === null || typeof input !== 'object' || Array.isArray(input)) return null;
    const value = input as Record<string, unknown>;
    const keys = Object.keys(value).sort();
    if (keys.join(',') !== 'deadlineUnixMs,goalText,maxOutputTokens,requestId') return null;
    const requestId = value.requestId;
    const goalText = value.goalText;
    const deadlineUnixMs = value.deadlineUnixMs;
    const maxOutputTokens = value.maxOutputTokens;
    if (typeof requestId !== 'string' || !REQUEST_ID.test(requestId)) return null;
    if (
      typeof goalText !== 'string' ||
      goalText.length < 1 ||
      goalText.length > 8192 ||
      goalText.trim().length === 0 ||
      goalText.includes('\0')
    )
      return null;
    if (!Number.isSafeInteger(deadlineUnixMs) || (deadlineUnixMs as number) <= 0) return null;
    if (
      !Number.isSafeInteger(maxOutputTokens) ||
      (maxOutputTokens as number) < 1 ||
      (maxOutputTokens as number) > 8192
    )
      return null;

    return Object.freeze({
      contractVersion: 'dh.llm.generate/1',
      requestId,
      modelId: 'deepseek-flash',
      deadlineUnixMs: deadlineUnixMs as number,
      messages: Object.freeze([Object.freeze({ role: 'user' as const, content: goalText })]),
      maxOutputTokens: maxOutputTokens as number,
      outputFormat: 'text' as const,
    });
  } catch {
    return null;
  }
}
