/**
 * Non-authoritative internal Shun DTO adapter for the selected public SDK
 * LLM generate contract `dh.llm.generate/1`.
 *
 * Shapes mirror the public exports of `@kaicreator/domain-harness-contracts`
 * at DomainHarness v0.10.3 (Git tag 061376f4a023070f215f9feffad5c24d96d503cb,
 * tree 099cdc831aef63befd62aaede7e7a853d1be468f). These internal types carry
 * no authority: a proposal is data, never an Effect permit; no transport,
 * provider, Host or Kernel behavior exists here. `requestId` is local
 * correlation data only and never self-authorizes a send; physical effects
 * stay behind K Permit plus Shun ActionController authorization (T01/T04/T11).
 */

export const SHUN_LLM_GENERATE_CONTRACT_V1 = 'dh.llm.generate/1' as const;

export type ShunLlmProviderKindV1 = 'openai-compatible' | 'anthropic-messages';

export type ShunLlmErrorCategoryV1 =
  | 'UNAVAILABLE'
  | 'UNSUPPORTED_FEATURE'
  | 'RATE_LIMITED'
  | 'AUTH_DENIED'
  | 'MALFORMED_RESPONSE'
  | 'CONTEXT_OVERFLOW'
  | 'CANCELLED'
  | 'DEADLINE'
  | 'OUTCOME_UNKNOWN';

export type ShunLlmFinishReasonV1 =
  | 'stop'
  | 'length'
  | 'tool_proposal'
  | 'content_filtered'
  | 'other';

export type ShunLlmTokenUsageV1 =
  | {
      readonly evidenceMode: 'unavailable';
    }
  | {
      readonly evidenceMode: 'provider-reported' | 'measured';
      readonly inputTokens: number;
      readonly outputTokens: number;
    };

export interface ShunLlmGenerateRequestV1 {
  readonly contractVersion: typeof SHUN_LLM_GENERATE_CONTRACT_V1;
  /** Local correlation only. Not a remote idempotency or retry grant. */
  readonly requestId: string;
  /** Host checks selected B/BUILD model identity and its trusted allowlist. */
  readonly modelId: string;
  /** Safe epoch-millisecond integer. Host enforces current time/window. */
  readonly deadlineUnixMs: number;
  readonly messages: readonly {
    readonly role: 'system' | 'user' | 'assistant';
    readonly content: string;
  }[];
  readonly maxOutputTokens: number;
  readonly outputFormat: 'text' | 'json';
  readonly temperature?: number;
  /** Ref is data only; Host must bind it to an approved schema/catalog. */
  readonly outputSchemaRef?: string;
  readonly toolCatalogRef?: string;
}

export interface ShunLlmToolProposalV1 {
  readonly name: string;
  /** JSON object data, not an invocation and not an executable grant. */
  readonly argumentsJson: string;
}

interface ShunLlmGenerateResultCommonV1 {
  readonly contractVersion: typeof SHUN_LLM_GENERATE_CONTRACT_V1;
  readonly requestId: string;
  /** Must come from the bound Host route/model, not model text. */
  readonly providerKind: ShunLlmProviderKindV1;
  readonly modelId: string;
  readonly providerRequestId?: string;
  readonly usage: ShunLlmTokenUsageV1;
  readonly receiptRef?: string;
}

export type ShunLlmGenerateResultV1 =
  | (ShunLlmGenerateResultCommonV1 & {
      readonly status: 'completed';
      readonly text: string;
      readonly finishReason: ShunLlmFinishReasonV1;
      readonly toolProposals?: readonly ShunLlmToolProposalV1[];
    })
  | (ShunLlmGenerateResultCommonV1 & {
      /** Sent call with ambiguous external outcome MUST stay 'unknown'. */
      readonly status: 'refused' | 'failed' | 'unknown';
      readonly errorCategory: ShunLlmErrorCategoryV1;
      /** Sanitized finite Host code, never raw provider exception text. */
      readonly reasonCode: string;
    });
