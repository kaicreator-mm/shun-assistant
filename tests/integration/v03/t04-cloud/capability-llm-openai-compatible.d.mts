import type { ShunLlmGenerateRequestV1, ShunLlmGenerateResultV1 } from '../../../../packages/domain-computer/src/contracts/llm-generate-v1.ts';

export const MODULE_ID: 'capability-llm-openai-compatible';
export const PACKAGE_KIND: 'capability';
export const ABI_VERSION: 'v08-capability-abi/1';
export const CAPABILITY_ID: 'llm.openai';
export const ENDPOINTS: readonly { endpointId: 'capability:llm.openai'; kind: 'capability-endpoint' }[];
export const EXTERNAL_EFFECT: true;
export const HANDLERS: readonly { operationId: 'llm.openai.generate'; handler: 'generate' }[];
export function generate(payload: ShunLlmGenerateRequestV1): Promise<Readonly<{
  phase: 'terminal';
  externalRef: string;
  outcome: Readonly<{ ok: true; output: ShunLlmGenerateResultV1 }>;
}>>;
