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

const DisclosureCategoriesSchema = z.array(z.enum([
  'GOAL_TEXT',
  'SYSTEM_INVENTORY',
  'FILE_METADATA',
  'USER_SELECTED_CONTENT',
])).min(1);

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
    /** Stable revision of the exact approved consent scope. */
    scopeRevision: Ref,
    disclosureCategories: DisclosureCategoriesSchema,
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
    displayedDisclosureCategories: DisclosureCategoriesSchema,
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
    if (
      canonicalJson(record.displayedDisclosureCategories) !==
      canonicalJson(record.scope.disclosureCategories)
    ) {
      ctx.addIssue({ code: 'custom', message: 'displayed categories differ from approved scope' });
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
    pricingRevision: Ref,
    scopeRevision: Ref,
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
    state.pricingRevision !== approval.scope.pricingRevision ||
    state.scopeRevision !== approval.scope.scopeRevision ||
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
  pricingRevision: Ref,
  /** Stable per-transport-attempt idempotency binding; no free retries. */
  idempotencyKey: Ref,
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

export const CloudCallReceiptSchema = z
  .strictObject({
    attemptId: Ref,
    consentId: Ref,
    status: z.enum(['NOT_SENT_PROVEN', 'SENT', 'SETTLED', 'UNKNOWN_COST']),
    /** Only a trusted journal attestation can establish definitive no-send. */
    noSendProofRef: Ref.optional(),
    sentAt: IsoDateTimeSchema.optional(),
    observedModel: Ref.optional(),
    /** May be absent for floating cloud model aliases; NEVER fabricate a model SHA. */
    systemFingerprint: Ref.optional(),
    responseId: Ref.optional(),
    inputTokens: NonNegative.optional(),
    outputTokens: NonNegative.optional(),
    observedCostMicros: NonNegative.optional(),
    recordedAt: IsoDateTimeSchema,
  })
  .superRefine((receipt, ctx) => {
    if (receipt.status === 'UNKNOWN_COST' && receipt.observedCostMicros !== undefined) {
      ctx.addIssue({ code: 'custom', message: 'unknown provider charge is not a settled cost' });
    }
    if (receipt.status === 'NOT_SENT_PROVEN') {
      if (
        !receipt.noSendProofRef ||
        receipt.sentAt !== undefined ||
        receipt.observedCostMicros !== undefined ||
        receipt.inputTokens !== undefined ||
        receipt.outputTokens !== undefined ||
        receipt.observedModel !== undefined ||
        receipt.systemFingerprint !== undefined ||
        receipt.responseId !== undefined
      ) {
        ctx.addIssue({
          code: 'custom',
          message: 'no-send receipt requires a proof and must not claim observed send or billing',
        });
      }
    } else if (receipt.noSendProofRef !== undefined) {
      ctx.addIssue({ code: 'custom', message: 'no-send proof only allowed on no-send receipt' });
    }
  });
export type CloudCallReceipt = z.infer<typeof CloudCallReceiptSchema>;

/** Only a proven no-send can release a reserved slot, never UNKNOWN_COST. */
export function mayRefundCloudAttempt(
  reservation: CloudCallReservation,
  receipt: CloudCallReceipt,
  /** Required independent durable-journal proof verifier, never caller self-attestation. */
  verifyNoSendProof: (reservation: CloudCallReservation, proofRef: string) => boolean,
): boolean {
  if (
    !CloudCallReservationSchema.safeParse(reservation).success ||
    !CloudCallReceiptSchema.safeParse(receipt).success ||
    !receipt.noSendProofRef
  ) return false;
  let verified = false;
  try {
    verified = verifyNoSendProof(reservation, receipt.noSendProofRef);
  } catch {
    return false;
  }
  return (
    verified &&
    reservation.attemptId === receipt.attemptId &&
    reservation.consentId === receipt.consentId &&
    receipt.status === 'NOT_SENT_PROVEN' &&
    (reservation.state === 'RESERVED' ||
      reservation.state === 'NOT_SENT_PROVEN' ||
      reservation.state === 'CANCELLED_BEFORE_SEND')
  );
}

const RecipeOpSchema = z.discriminatedUnion('op', [
  z.strictObject({
    op: z.literal('system.inventory'),
    parameters: z.strictObject({ includeProcesses: z.boolean().optional() }),
  }),
  z.strictObject({
    op: z.literal('system.storage.diagnose'),
    parameters: z.strictObject({ volumeId: Ref }),
  }),
  z.strictObject({
    op: z.literal('file.search'),
    parameters: z.strictObject({ root: Ref, query: Ref }),
  }),
  z.strictObject({
    op: z.literal('file.copy'),
    parameters: z.strictObject({ sourcePath: Ref, destinationPath: Ref }),
  }),
  z.strictObject({
    op: z.literal('file.move'),
    parameters: z.strictObject({ sourcePath: Ref, destinationPath: Ref }),
  }),
  z.strictObject({
    op: z.literal('file.rename'),
    parameters: z.strictObject({ sourcePath: Ref, newName: Ref }),
  }),
  z.strictObject({
    op: z.literal('file.duplicates.report'),
    parameters: z.strictObject({ root: Ref }),
  }),
  z.strictObject({
    op: z.literal('image.batch_process'),
    parameters: z.strictObject({ sourceFolder: Ref, outputFolder: Ref }),
  }),
  z.strictObject({
    op: z.literal('software.jit_capability_lifecycle'),
    parameters: z.strictObject({ providerId: Ref, operation: z.enum(['ACQUIRE', 'ACTIVATE', 'RELEASE']) }),
  }),
]);
export const RecipeActionNodeSchema = z.discriminatedUnion('op', [
  ...RecipeOpSchema.options.map((option) => option.safeExtend({ actionId: Ref })),
] as [typeof RecipeOpSchema.options[number], ...typeof RecipeOpSchema.options[number][]]);
export const RecipeActionGraphSchema = z
  .strictObject({
    nodes: z.array(RecipeActionNodeSchema).min(1),
    edges: z.array(z.strictObject({ from: Ref, to: Ref })),
  })
  .superRefine((graph, ctx) => {
    const ids = new Set(graph.nodes.map((node) => node.actionId));
    if (ids.size !== graph.nodes.length) {
      ctx.addIssue({ code: 'custom', message: 'duplicate actionId in Recipe graph' });
    }
    const degree = new Map([...ids].map((id) => [id, 0]));
    const out = new Map([...ids].map((id) => [id, [] as string[]]));
    for (const edge of graph.edges) {
      if (!ids.has(edge.from) || !ids.has(edge.to)) {
        ctx.addIssue({ code: 'custom', message: 'Recipe graph references unknown actionId' });
        continue;
      }
      degree.set(edge.to, (degree.get(edge.to) ?? 0) + 1);
      out.get(edge.from)?.push(edge.to);
    }
    const ready = [...ids].filter((id) => degree.get(id) === 0);
    let visited = 0;
    while (ready.length > 0) {
      const id = ready.pop();
      if (!id) break;
      visited++;
      for (const next of out.get(id) ?? []) {
        const remaining = (degree.get(next) ?? 0) - 1;
        degree.set(next, remaining);
        if (remaining === 0) ready.push(next);
      }
    }
    if (visited !== ids.size) {
      ctx.addIssue({ code: 'custom', message: 'Recipe action graph must be acyclic' });
    }
  });
export type RecipeActionGraph = z.infer<typeof RecipeActionGraphSchema>;

export const RecipeRevisionIdentitySchema = z
  .strictObject({
    recipeId: Ref,
    sourceSha256: Sha256HexSchema,
    actionGraphSha256: Sha256HexSchema,
    compiledSha256: Sha256HexSchema,
    compilerRevision: Ref,
    contractRevision: Ref,
    declaredEffectsSha256: Sha256HexSchema,
    verifierId: Ref,
    verifierRevision: Ref,
    /** Digest of all representation pins; mutable source/graph cannot inherit approval. */
    revisionSha256: Sha256HexSchema,
  })
  .superRefine((identity, ctx) => {
    if (identity.revisionSha256 !== computeRecipeRevision(identity)) {
      ctx.addIssue({ code: 'custom', message: 'Recipe revision identity digest mismatch' });
    }
  });
export type RecipeRevisionIdentity = z.infer<typeof RecipeRevisionIdentitySchema>;

export function computeRecipeRevision(
  identity: Omit<RecipeRevisionIdentity, 'revisionSha256'>,
): string {
  const {
    recipeId,
    sourceSha256,
    actionGraphSha256,
    compiledSha256,
    compilerRevision,
    contractRevision,
    declaredEffectsSha256,
    verifierId,
    verifierRevision,
  } = identity;
  return createHash('sha256')
    .update(
      canonicalJson({
        recipeId,
        sourceSha256,
        actionGraphSha256,
        compiledSha256,
        compilerRevision,
        contractRevision,
        declaredEffectsSha256,
        verifierId,
        verifierRevision,
      }),
      'utf8',
    )
    .digest('hex');
}

export function verifyRecipeRevision(identity: RecipeRevisionIdentity): boolean {
  return identity.revisionSha256 === computeRecipeRevision(identity);
}

export const ProviderCatalogArtifactSchema = z.strictObject({
  providerId: Ref,
  catalogRevision: Ref,
  bindingId: Ref,
  scopedVerifierId: Ref,
  version: Ref,
  capabilityId: Ref,
  artifactKind: z.enum(['CLI', 'NATIVE_ADDON']),
  platform: z.literal('windows-x64'),
  artifactSha256: Sha256HexSchema,
  origin: z.url().refine((value) => {
    try {
      const u = new URL(value);
      return u.protocol === 'https:' && u.username === '' && u.password === '';
    } catch {
      return false;
    }
  }, 'provider acquisition origin must be credential-free HTTPS'),
  entrypoint: Ref,
  /** Explicit CLI sentinel or exact native ABI, never arbitrary executable ABI inference. */
  abiRevision: Ref,
  signerKeyId: Ref,
  /** Not a proof of trusted signing; T05 verifies against pinned curator roots. */
  curatorSignature: Ref,
  dependencySha256: z.array(Sha256HexSchema),
});
export type ProviderCatalogArtifact = z.infer<typeof ProviderCatalogArtifactSchema>;
