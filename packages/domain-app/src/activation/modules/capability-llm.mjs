/**
 * Shun v0.3 one trusted LLM Capability Domain Package.
 * No model transport is constructed here. The only static import binds the
 * selected public K Effect to Shun's pre-existing T04 trusted cloud interpreter
 * through operator-provisioned domain-harness-openai-host; no second sender.
 */
import { generate } from 'domain-harness-openai-host';

export const MODULE_ID = 'shun.capability.llm-openai-compatible@v0.3.0';
export const PACKAGE_KIND = 'capability';
export const ABI_VERSION = 'v08-capability-abi/1';
export const ENDPOINTS = [
  { endpointId: 'capability:shun-trusted-cloud', kind: 'capability-endpoint' },
];
export const CAPABILITY_ID = 'llm';
export const EXTERNAL_EFFECT = true;
export const HANDLERS = [{ operationId: 'interpretGoal', handler: 'interpretGoal' }];

/** This is called ONLY after K external Effect Permit and Host policy gates.
 * Its one dependency resolves only through the trusted fixed import map.
 */
export async function interpretGoal(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).sort().join('|') !==
        ['llmRequest','currentnessRef','approvalRef'].sort().join('|') ||
      typeof input.approvalRef !== 'string' ||
      typeof input.currentnessRef !== 'string') {
    throw new Error('SHUN_LLM_EFFECT_INPUT_REFUSED');
  }
  const request = input.llmRequest;
  if (!request || typeof request !== 'object' || Array.isArray(request) ||
      Object.keys(request).sort().join('|') !==
        ['contractVersion','deadlineUnixMs','maxOutputTokens','messages',
         'modelId','outputFormat','requestId'].sort().join('|') ||
      request.contractVersion !== 'dh.llm.generate/1' ||
      request.modelId !== 'deepseek-flash' || request.outputFormat !== 'text' ||
      typeof request.requestId !== 'string' ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(request.requestId) ||
      !Number.isSafeInteger(request.deadlineUnixMs) ||
      !Number.isSafeInteger(request.maxOutputTokens) ||
      request.maxOutputTokens < 1 || request.maxOutputTokens > 8192 ||
      !Array.isArray(request.messages) || request.messages.length !== 1 ||
      request.messages[0]?.role !== 'user' ||
      typeof request.messages[0].content !== 'string' ||
      request.messages[0].content.length < 1 ||
      request.messages[0].content.length > 8192) {
    throw new Error('SHUN_LLM_REQUEST_CONTRACT_REFUSED');
  }
  // The existing trusted T04 host rechecks actual deadline, consent, Journal,
  // immutable bytes and cost. This C has no credential or network handle.
  return generate(request);
}
