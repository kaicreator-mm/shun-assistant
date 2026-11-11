// Exact selected capability C from DomainHarness v0.10.3
// 061376f4a023070f215f9feffad5c24d96d503cb
// Source blob: 68d7adecb524247d0dcb819297fa373db93ef78a
// Kept verbatim so this test exercises the real C -> static Host binding contract.
// Trusted deployment supplies this Host binding; the sealed App never carries keys.
import { generate as hostGenerate } from 'domain-harness-openai-host';
export const MODULE_ID = 'capability-llm-openai-compatible';
export const PACKAGE_KIND = 'capability';
export const ABI_VERSION = 'v08-capability-abi/1';
export const CAPABILITY_ID = 'llm.openai';
export const ENDPOINTS = [{ endpointId: 'capability:llm.openai', kind: 'capability-endpoint' }];
export const EXTERNAL_EFFECT = true;
export const HANDLERS = [{ operationId: 'llm.openai.generate', handler: 'generate' }];
export async function generate(payload) {
  const result = await hostGenerate(payload);
  if (result.status === 'unknown') {
    const error = new Error('OpenAI external outcome requires reconciliation');
    error.code = 'OPENAI_OUTCOME_UNKNOWN';
    throw error; // Existing K Journal/fence owns UNKNOWN, never a terminal success.
  }
  return { phase: 'terminal', externalRef: result.providerRequestId ?? `local-correlation:${result.requestId}`,
    outcome: { ok: true, output: result } };
}
