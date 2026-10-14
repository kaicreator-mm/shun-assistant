// v0.2 typed, non-executable consent/LLM/Recipe/JIT contracts.
// Authority: Product re-freeze #96, L2 Freeze #101 §§2.4–2.7, DAG Freeze #102.
// Parsing a record or observing an integrity envelope NEVER authorizes outbound
// HTTP or execution. The T08 private interactive issuer and T01 trusted,
// transactional send gate must independently validate these values.
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { canonicalJson } from './plan.ts';
import { IsoDateTimeSchema, Sha256HexSchema } from './taxonomy.ts';

const Ref = z.string().min(1);
const NonNegative = z.number().int().nonnegative();
const Positive = z.number().int().positive();

export const CloudDisclosureScopeSchema = z
  .strictObject({
    taskId: Ref,
    principalId: Ref,
    sessionId: Ref,
    providerId: z.literal('deepseek'),
    modelId: z.literal('deepseek-flash'),
    /** Actual endpoint must also pass trusted host/path allowlisting at T01. */
    destination: z.literal('https://api.deepseek.com/chat/completions'),
    /** Digest of the EXACT approved disclosure-bearing projection, not a draft. */
    approvedProjectionSha256: Sha256HexSchema,
    registryRevision: Ref,
    policyRevision: Ref,
    pricingRevision: Ref,
    revocationEpoch: NonNegative,
    maxCalls: Positive,
    maxInputTokens: Positive,
    maxOutputTokens: Positive,
    maxCostMicros: Positive,
    issuedAt: IsoDateTimeSchema,
    expiresAt: IsoDateTimeSchema,
  })
  .superRefine((scope, ctx) => {
    if (Date.parse(scope.expiresAt) <= Date.parse(scope.issuedAt)) {
      ctx.addIssue({ code: 'custom', message: 'consent expiry must follow issuance' });
    }
  });
export type CloudDisclosureScope = z.infer<typeof CloudDisclosureScopeSchema>;

/**
 * Private broker assertion. Structural presence of proof is NOT authentication.
 * T01/T08 must invoke a trusted, non-caller supplied issuer verifier, check
 * current principal/session/nonce and source authority, and use an atomic
 * durable budget reservation. The public localhost API CANNOT mint this.
 */
export const CloudConsentApprovalSchema = z
  .strictObject({
    consentId: Ref,
    scope: CloudDisclosureScopeSchema,
    confirmationNonce: Ref,
    displayedProjectionSha256: Sha256HexSchema,
    issuer: z.strictObject({
      brokerId: Ref,
      brokerRevision: Ref,
      assertionId: Ref,
      channel: z.literal('AUTHENTICATED_PRIVATE_IPC'),
      /** Cryptographic or private-channel proof; never an arbitrary HTTP token. */
      proof: Ref,
    }),
  })
  .superRefine((record, ctx) => {
    if (record.displayedProjectionSha256 !== record.scope.approvedProjectionSha256) {
      ctx.addIssue({ code: 'custom', message: 'displayed projection differs from approved scope' });
    }
  });
export type CloudConsentApproval = z.infer<typeof CloudConsentApprovalSchema>;

export const CloudConsentCurrentnessSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('CURRENT'),
    taskId: Ref,
    principalId: Ref,
    sessionId: Ref,
    registryRevision: Ref,
    policyRevision: Ref,
    revocationEpoch: NonNegative,
    /** Broker-sourced confirmation nonce that has not yet been consumed. */
    nonceIsUnused: z.boolean(),
  }),
  z.strictObject({ kind: z.literal('UNRESOLVABLE') }),
]);
export type CloudConsentCurrentness = z.infer<typeof CloudConsentCurrentnessSchema>;

export type CloudConsentVerdict =
  | { ok: true; consent: CloudConsentApproval }
  | { ok: false; code: 'CONSENT_REFUSED' | 'CONSENT_EXPIRED' | 'CONSENT_STALE' };

/** Pure fail-closed eligibility: the trusted backend supplies BOTH authority and verifier. */
export function validateCloudConsent(input: {
  approval: unknown;
  currentness: unknown;
  now: string;
  verifyBroker: (approval: CloudConsentApproval) => boolean;
}): CloudConsentVerdict {
  const parsed = CloudConsentApprovalSchema.safeParse(input.approval);
  const current = CloudConsentCurrentnessSchema.safeParse(input.currentness);
  if (!parsed.success || !current.success || !IsoDateTimeSchema.safeParse(input.now).success) {
    return { ok: false, code: 'CONSENT_REFUSED' };
  }
  const approval = parsed.data;
  const state = current.data;
  if (state.kind !== 'CURRENT') return { ok: false, code: 'CONSENT_STALE' };
  if (
    state.taskId !== approval.scope.taskId ||
    state.principalId !== approval.scope.principalId ||
    state.sessionId !== approval.scope.sessionId ||
    state.registryRevision !== approval.scope.registryRevision ||
    state.policyRevision !== approval.scope.policyRevision ||
    state.revocationEpoch !== approval.scope.revocationEpoch ||
    !state.nonceIsUnused
  )
    return { ok: false, code: 'CONSENT_STALE' };
  if (
    Date.parse(approval.scope.issuedAt) > Date.parse(input.now) ||
    Date.parse(approval.scope.expiresAt) <= Date.parse(input.now)
  )
    return { ok: false, code: 'CONSENT_EXPIRED' };
  try {
    if (!input.verifyBroker(approval)) return { ok: false, code: 'CONSENT_REFUSED' };
  } catch {
    return { ok: false, code: 'CONSENT_REFUSED' };
  }
  return { ok: true, consent: approval };
}

export const CloudCallReservationSchema = z.strictObject({
  attemptId: Ref,
  consentId: Ref,
  scopeRevision: Ref,
  taskId: Ref,
  callSequence: Positive,
  requestBytesSha256: Sha256HexSchema,
  disclosureProjectionSha256: Sha256HexSchema,
  reservedTokens: Positive,
  reservedCostMicros: Positive,
  reservedAt: IsoDateTimeSchema,
  /** RESERVATION is recorded durably before *any* outbound I/O. */
  state: z.enum([
    'RESERVED',
    'NOT_SENT_PROVEN',
    'CANCELLED_BEFORE_SEND',
    'SENT',
    'SETTLED',
    'UNKNOWN_COST',
  ]),
});
export type CloudCallReservation = z.infer<typeof CloudCallReservationSchema>;

export const CloudCallReceiptSchema = z.strictObject({
  attemptId: Ref,
  consentId: Ref,
  status: z.enum(['NOT_SENT_PROVEN', 'SENT', 'SETTLED', 'UNKNOWN_COST']),
  sentAt: IsoDateTimeSchema.optional(),
  observedModel: Ref.optional(),
  /** May be absent for floating cloud model aliases; NEVER fabricate a model SHA. */
  systemFingerprint: Ref.optional(),
  responseId: Ref.optional(),
  inputTokens: NonNegative.optional(),
  outputTokens: NonNegative.optional(),
  observedCostMicros: NonNegative.optional(),
  recordedAt: IsoDateTimeSchema,
}).superRefine((receipt, ctx) => {
  if (receipt.status === 'UNKNOWN_COST' && receipt.observedCostMicros !== undefined) {
    ctx.addIssue({ code: 'custom', message: 'unknown provider charge is not a settled cost' });
  }
});
export type CloudCallReceipt = z.infer<typeof CloudCallReceiptSchema>;

/** Only a proven no-send can release a reserved slot, never UNKNOWN_COST. */
export function mayRefundCloudAttempt(
  reservation: CloudCallReservation,
  receipt: CloudCallReceipt,
): boolean {
  return reservation.attemptId === receipt.attemptId &&
    reservation.consentId === receipt.consentId &&
    receipt.status === 'NOT_SENT_PROVEN' &&
    (reservation.state === 'RESERVED' ||
      reservation.state === 'NOT_SENT_PROVEN' ||
      reservation.state === 'CANCELLED_BEFORE_SEND');
}

export const RecipeActionNodeSchema = z.strictObject({
  actionId: Ref,
  /** Closed-world vocabulary only. No shell/JS/eval/FFI code carriers. */
  op: z.enum([
    'system.inventory',
    'system.storage.diagnose',
    'file.search',
    'file.copy',
    'file.move',
    'file.rename',
    'file.duplicates.report',
    'image.batch_process',
    'software.jit_capability_lifecycle',
  ]),
  parameters: z.record(z.string(), z.unknown()),
});
export const RecipeActionGraphSchema = z.strictObject({
  nodes: z.array(RecipeActionNodeSchema).min(1),
  edges: z.array(z.strictObject({ from: Ref, to: Ref })),
}).superRefine((graph, ctx) => {
  const ids = new Set(graph.nodes.map((node) => node.actionId));
  if (ids.size !== graph.nodes.length) {
    ctx.addIssue({ code: 'custom', message: 'duplicate actionId in Recipe graph' });
  }
  for (const edge of graph.edges) {
    if (!ids.has(edge.from) || !ids.has(edge.to)) {
      ctx.addIssue({ code: 'custom', message: 'Recipe graph references unknown actionId' });
    }
  }
});
export type RecipeActionGraph = z.infer<typeof RecipeActionGraphSchema>;

export const RecipeRevisionIdentitySchema = z.strictObject({
  recipeId: Ref,
  sourceSha256: Sha256HexSchema,
  actionGraphSha256: Sha256HexSchema,
  compiledSha256: Sha256HexSchema,
  compilerRevision: Ref,
  contractRevision: Ref,
  /** Digest of all representation pins; mutable source/graph cannot inherit approval. */
  revisionSha256: Sha256HexSchema,
});
export type RecipeRevisionIdentity = z.infer<typeof RecipeRevisionIdentitySchema>;

export function computeRecipeRevision(
  identity: Omit<RecipeRevisionIdentity, 'revisionSha256'>,
): string {
  return createHash('sha256').update(canonicalJson(identity), 'utf8').digest('hex');
}

export function verifyRecipeRevision(identity: RecipeRevisionIdentity): boolean {
  return identity.revisionSha256 === computeRecipeRevision(identity);
}

export const ProviderCatalogArtifactSchema = z.strictObject({
  providerId: Ref,
  version: Ref,
  capabilityId: Ref,
  artifactKind: z.enum(['CLI', 'NATIVE_ADDON']),
  platform: z.literal('windows-x64'),
  artifactSha256: Sha256HexSchema,
  origin: z.url(),
  entrypoint: Ref,
  abiRevision: Ref,
  signerKeyId: Ref,
  /** Not a proof of trusted signing; T05 verifies against pinned curator roots. */
  curatorSignature: Ref,
  dependencySha256: z.array(Sha256HexSchema),
});
export type ProviderCatalogArtifact = z.infer<typeof ProviderCatalogArtifactSchema>;
