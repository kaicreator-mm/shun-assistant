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
        ['request','currentnessRef','approvalRef'].sort().join('|') ||
      typeof input.approvalRef !== 'string' ||
      typeof input.currentnessRef !== 'string' ||
      !input.request || typeof input.request !== 'object') {
    throw new Error('SHUN_LLM_EFFECT_INPUT_REFUSED');
  }
  return generate(input);
}
