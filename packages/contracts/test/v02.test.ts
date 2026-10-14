import { describe, expect, it } from 'vitest';
import {
  CloudCallReceiptSchema,
  CloudCallReservationSchema,
  CloudConsentApprovalSchema,
  CloudDisclosureScopeSchema,
  computeRecipeRevision,
  mayRefundCloudAttempt,
  ProviderCatalogArtifactSchema,
  RecipeActionGraphSchema,
  RecipeRevisionIdentitySchema,
  validateCloudConsent,
} from '../src/v02.ts';

const SHA = 'a'.repeat(64);
const B = 'b'.repeat(64);
const NOW = '2026-10-14T10:00:00.000Z';
const scope = {
  taskId: 'task-1',
  principalId: 'windows-user-1',
  sessionId: 'shun-broker-session-1',
  providerId: 'deepseek',
  modelId: 'deepseek-flash',
  destination: 'https://api.deepseek.com/chat/completions',
  approvedProjectionSha256: SHA,
  registryRevision: 'registry-r3',
  policyRevision: 'policy-r9',
  pricingRevision: 'deepseek-price-r1',
  revocationEpoch: 2,
  maxCalls: 1,
  maxInputTokens: 512,
  maxOutputTokens: 512,
  maxCostMicros: 10000,
  issuedAt: '2026-10-14T09:00:00.000Z',
  expiresAt: '2026-10-14T11:00:00.000Z',
} as const;

const approval = {
  consentId: 'consent-1',
  scope,
  confirmationNonce: 'single-use-nonce',
  displayedProjectionSha256: SHA,
  issuer: {
    brokerId: 'shun-trusted-broker',
    brokerRevision: 'broker-r1',
    assertionId: 'assertion-1',
    channel: 'AUTHENTICATED_PRIVATE_IPC',
    proof: 'nonempty-structural-envelope-only',
  },
};
const current = {
  kind: 'CURRENT',
  taskId: scope.taskId,
  principalId: scope.principalId,
  sessionId: scope.sessionId,
  registryRevision: scope.registryRevision,
  policyRevision: scope.policyRevision,
  revocationEpoch: scope.revocationEpoch,
  nonceIsUnused: true,
} as const;

describe('v0.2: cloud disclosure contracts', () => {
  it('accepts typed scope only with bounded issuer/session, projection and cost', () => {
    expect(CloudDisclosureScopeSchema.safeParse(scope).success).toBe(true);
    expect(CloudConsentApprovalSchema.safeParse(approval).success).toBe(true);
    expect(CloudDisclosureScopeSchema.safeParse({ ...scope, maxCalls: 0 }).success).toBe(false);
    expect(CloudDisclosureScopeSchema.safeParse({ ...scope, endpoint: 'anything' }).success).toBe(
      false,
    );
    expect(
      CloudConsentApprovalSchema.safeParse({
        ...approval,
        displayedProjectionSha256: B,
      }).success,
    ).toBe(false);
  });

  it('refuses arbitrary remote model, unapproved host and local-only masquerade', () => {
    expect(
      CloudDisclosureScopeSchema.safeParse({
        ...scope,
        modelId: 'unknown-model',
      }).success,
    ).toBe(false);
    expect(
      CloudDisclosureScopeSchema.safeParse({
        ...scope,
        destination: 'http://localhost:9000/chat/completions',
      }).success,
    ).toBe(false);
    expect(
      CloudDisclosureScopeSchema.safeParse({
        ...scope,
        localOnly: false,
        externalDisclosure: 'ALLOWED',
      }).success,
    ).toBe(false);
  });

  it('treats proof presence as data, not verification: injected trusted verifier is mandatory', () => {
    const input = { approval, currentness: current, now: NOW };
    expect(validateCloudConsent({ ...input, verifyBroker: () => false })).toEqual({
      ok: false,
      code: 'CONSENT_REFUSED',
    });
    expect(validateCloudConsent({ ...input, verifyBroker: () => true }).ok).toBe(true);
    // @ts-expect-error a caller must not omit the mandatory verifier port.
    const invalid: Parameters<typeof validateCloudConsent>[0] = input;
    expect(invalid.approval).toBe(approval);
  });

  it('rejects forged session, replayed nonce, unresolvable registry and expiration', () => {
    const input = { approval, now: NOW, verifyBroker: () => true };
    expect(
      validateCloudConsent({ ...input, currentness: { ...current, sessionId: 'forged' } }),
    ).toEqual({
      ok: false,
      code: 'CONSENT_STALE',
    });
    expect(
      validateCloudConsent({
        ...input,
        currentness: { ...current, nonceIsUnused: false },
      }).ok,
    ).toBe(false);
    expect(validateCloudConsent({ ...input, currentness: { kind: 'UNRESOLVABLE' } }).ok).toBe(
      false,
    );
    expect(validateCloudConsent({ ...input, currentness: current, now: scope.expiresAt })).toEqual({
      ok: false,
      code: 'CONSENT_EXPIRED',
    });
  });
});

const reservation = CloudCallReservationSchema.parse({
  attemptId: 'attempt-1',
  consentId: 'consent-1',
  scopeRevision: 'scope-r1',
  taskId: 'task-1',
  callSequence: 1,
  requestBytesSha256: SHA,
  disclosureProjectionSha256: SHA,
  reservedTokens: 1000,
  reservedCostMicros: 5000,
  reservedAt: NOW,
  state: 'RESERVED',
});
const notSent = CloudCallReceiptSchema.parse({
  attemptId: reservation.attemptId,
  consentId: reservation.consentId,
  status: 'NOT_SENT_PROVEN',
  recordedAt: NOW,
});

describe('v0.2: cloud reservation and uncertain charges', () => {
  it('accepts a durable typed reservation and proves refunds only on no-send', () => {
    expect(CloudCallReservationSchema.safeParse(reservation).success).toBe(true);
    expect(mayRefundCloudAttempt(reservation, notSent)).toBe(true);
    expect(mayRefundCloudAttempt(reservation, { ...notSent, status: 'UNKNOWN_COST' })).toBe(false);
    expect(mayRefundCloudAttempt(reservation, { ...notSent, attemptId: 'other' })).toBe(false);
    expect(mayRefundCloudAttempt({ ...reservation, state: 'SENT' }, notSent)).toBe(false);
  });

  it('rejects a fabricated cost under UNKNOWN_COST', () => {
    expect(
      CloudCallReceiptSchema.safeParse({
        ...notSent,
        status: 'UNKNOWN_COST',
        observedCostMicros: 100,
      }).success,
    ).toBe(false);
    expect(CloudCallReservationSchema.safeParse({ ...reservation, callSequence: 0 }).success).toBe(
      false,
    );
  });
});

describe('v0.2: exact Recipe identity and closed-world actions', () => {
  const graph = {
    nodes: [
      { actionId: 'one', op: 'file.search', parameters: { root: 'C:/approved' } },
      { actionId: 'two', op: 'file.copy', parameters: { target: 'C:/approved/copy' } },
    ],
    edges: [{ from: 'one', to: 'two' }],
  };
  it('rejects raw JS, shell execution, duplicate nodes and dangling edges', () => {
    expect(RecipeActionGraphSchema.safeParse(graph).success).toBe(true);
    expect(
      RecipeActionGraphSchema.safeParse({
        ...graph,
        nodes: [{ actionId: 'one', op: 'node.eval', parameters: { code: 'process.exit()' } }],
      }).success,
    ).toBe(false);
    expect(
      RecipeActionGraphSchema.safeParse({
        ...graph,
        nodes: [graph.nodes[0], graph.nodes[0]],
      }).success,
    ).toBe(false);
    expect(
      RecipeActionGraphSchema.safeParse({
        ...graph,
        edges: [{ from: 'one', to: 'third' }],
      }).success,
    ).toBe(false);
  });

  it('binds source, graph and compiled representation in one immutable revision', () => {
    const base = {
      recipeId: 'r-1',
      sourceSha256: SHA,
      actionGraphSha256: B,
      compiledSha256: SHA,
      compilerRevision: 'compiler-r1',
      contractRevision: 'contract-r2',
    };
    const revisionSha256 = computeRecipeRevision(base);
    const record = RecipeRevisionIdentitySchema.parse({ ...base, revisionSha256 });
    expect(record.revisionSha256).toHaveLength(64);
    expect(computeRecipeRevision({ ...record, actionGraphSha256: SHA })).not.toBe(
      record.revisionSha256,
    );
    expect(
      RecipeRevisionIdentitySchema.safeParse({
        ...record,
        compiledSha256: 'tampered',
      }).success,
    ).toBe(false);
  });
});

describe('v0.2: curated signed Provider catalog is data only', () => {
  it('rejects missing signer, wrong hash, arbitrary OS and unknown carrier type', () => {
    const artifact = {
      providerId: 'rg',
      version: '14.1',
      capabilityId: 'file.search',
      artifactKind: 'CLI',
      platform: 'windows-x64',
      artifactSha256: SHA,
      origin: 'https://example.org/pinned.exe',
      entrypoint: 'rg.exe',
      abiRevision: 'abi-r1',
      signerKeyId: 'curator-key-1',
      curatorSignature: 'base64-signature-value',
      dependencySha256: [B],
    };
    expect(ProviderCatalogArtifactSchema.safeParse(artifact).success).toBe(true);
    expect(ProviderCatalogArtifactSchema.safeParse({
      ...artifact,
      signerKeyId: '',
    }).success).toBe(false);
    expect(ProviderCatalogArtifactSchema.safeParse({
      ...artifact,
      artifactSha256: '00',
    }).success).toBe(false);
    expect(ProviderCatalogArtifactSchema.safeParse({
      ...artifact,
      platform: 'linux',
    }).success).toBe(false);
    expect(ProviderCatalogArtifactSchema.safeParse({
      ...artifact,
      artifactKind: 'ARBITRARY_JS',
    }).success).toBe(false);
  });
});
