import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import { V02_CONTRACTS } from '../src/registry.ts';
import { computeRecipeRevision } from '../src/v02.ts';

const SHA = 'a'.repeat(64);
const B = 'b'.repeat(64);
const NOW = '2026-10-14T10:00:00.000Z';
const scope = {
  taskId: 'task-1',
  principalId: 'principal-1',
  sessionId: 'session-1',
  providerId: 'deepseek',
  modelId: 'deepseek-flash',
  destination: 'https://api.deepseek.com/chat/completions',
  approvedProjectionSha256: SHA,
  scopeRevision: 'scope-1',
  disclosureCategories: ['GOAL_TEXT'],
  registryRevision: 'registry-1',
  policyRevision: 'policy-1',
  pricingRevision: 'pricing-1',
  revocationEpoch: 1,
  maxCalls: 1,
  maxInputTokens: 512,
  maxOutputTokens: 512,
  maxCostMicros: 1000,
  issuedAt: NOW,
  expiresAt: '2026-10-14T11:00:00.000Z',
};
const scopeApproval = {
  consentId: 'consent-1',
  scope,
  confirmationNonce: 'nonce-1',
  displayedProjectionSha256: SHA,
  displayedDisclosureCategories: ['GOAL_TEXT'],
  issuer: {
    brokerId: 'broker-1',
    brokerRevision: 'broker-v1',
    assertionId: 'assertion-1',
    channel: 'AUTHENTICATED_PRIVATE_IPC',
    proof: 'structural-proof-only',
  },
};
const recipeBase = {
  recipeId: 'recipe-1',
  sourceSha256: SHA,
  actionGraphSha256: B,
  compiledSha256: SHA,
  compilerRevision: 'compiler-1',
  contractRevision: 'contract-1',
  declaredEffectsSha256: B,
  verifierId: 'verifier-1',
  verifierRevision: 'verify-1',
};
const cases = [
  { name: 'v02-cloud-disclosure-scope', good: scope, bad: { ...scope, modelId: 'attacker-model' } },
  {
    name: 'v02-cloud-consent-approval',
    good: scopeApproval,
    bad: { ...scopeApproval, issuer: { ...scopeApproval.issuer, channel: 'OPEN_HTTP' } },
  },
  {
    name: 'v02-cloud-consent-currentness',
    good: {
      kind: 'CURRENT',
      taskId: scope.taskId,
      principalId: scope.principalId,
      sessionId: scope.sessionId,
      registryRevision: scope.registryRevision,
      policyRevision: scope.policyRevision,
      pricingRevision: scope.pricingRevision,
      scopeRevision: scope.scopeRevision,
      revocationEpoch: scope.revocationEpoch,
      nonceIsUnused: true,
    },
    bad: { kind: 'CURRENT', taskId: scope.taskId },
  },
  {
    name: 'v02-cloud-call-reservation',
    good: {
      attemptId: 'attempt-1',
      consentId: 'consent-1',
      scopeRevision: 'scope-1',
      pricingRevision: 'pricing-1',
      idempotencyKey: 'attempt-key-1',
      taskId: scope.taskId,
      callSequence: 1,
      requestBytesSha256: SHA,
      disclosureProjectionSha256: SHA,
      reservedTokens: 100,
      reservedCostMicros: 250,
      reservedAt: NOW,
      state: 'RESERVED',
    },
    bad: {
      attemptId: 'attempt-1',
      consentId: 'consent-1',
      callSequence: 0,
    },
  },
  {
    name: 'v02-cloud-call-receipt',
    good: {
      attemptId: 'attempt-1',
      consentId: 'consent-1',
      status: 'NOT_SENT_PROVEN',
      noSendProofRef: 'journal-attestation',
      recordedAt: NOW,
    },
    bad: {
      attemptId: 'attempt-1',
      consentId: 'consent-1',
      status: 'NOT_SENT_PROVEN',
      noSendProofRef: 'journal-attestation',
      sentAt: NOW,
      recordedAt: NOW,
    },
  },
  {
    name: 'v02-recipe-action-graph',
    good: {
      nodes: [
        { actionId: 'find', op: 'file.search', parameters: { root: 'C:/safe', query: '*.txt' } },
      ],
      edges: [],
    },
    bad: {
      nodes: [
        {
          actionId: 'danger',
          op: 'file.copy',
          parameters: {
            sourcePath: 'C:/safe/a',
            destinationPath: 'C:/safe/b',
            command: 'powershell',
          },
        },
      ],
      edges: [],
    },
  },
  {
    name: 'v02-recipe-revision-identity',
    good: { ...recipeBase, revisionSha256: computeRecipeRevision(recipeBase) },
    bad: { ...recipeBase, revisionSha256: 'BAD' },
  },
  {
    name: 'v02-provider-catalog-artifact',
    good: {
      providerId: 'rg',
      catalogRevision: 'catalog-1',
      bindingId: 'file-search',
      scopedVerifierId: 'curator-1',
      catalogManifestSha256: SHA,
      bindingEvidenceSha256: B,
      version: '14.1',
      capabilityId: 'file.search',
      artifactKind: 'CLI',
      platform: 'windows-x64',
      artifactSha256: SHA,
      origin: 'https://example.org/rg.exe',
      entrypoint: 'rg.exe',
      signerKeyId: 'key-1',
      curatorSignature: 'signed-manifest',
      dependencySha256: [B],
    },
    bad: {
      providerId: 'rg',
      catalogRevision: 'catalog-1',
      bindingId: 'file-search',
      scopedVerifierId: 'curator-1',
      catalogManifestSha256: SHA,
      bindingEvidenceSha256: B,
      version: '14.1',
      capabilityId: 'file.search',
      artifactKind: 'CLI',
      platform: 'windows-x64',
      artifactSha256: SHA,
      origin: 'http://example.org/rg.exe',
      entrypoint: 'rg.exe',
      abiRevision: 'cli-none',
      signerKeyId: 'key-1',
      curatorSignature: 'signed-manifest',
      dependencySha256: [B],
    },
  },
];

describe('v0.2 public JSON Schema and typed Zod parity', () => {
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(ajv);
  it('refuses Provider URLs carrying userinfo or noncanonical HTTPS on both public surfaces', () => {
    const entry = V02_CONTRACTS.find((c) => c.name === 'v02-provider-catalog-artifact');
    const fixture = cases.find((c) => c.name === 'v02-provider-catalog-artifact');
    expect(entry).toBeDefined();
    expect(fixture).toBeDefined();
    if (!entry || !fixture) return;
    const schemaPath = join(
      import.meta.dirname,
      '../src/schema/v02-provider-catalog-artifact.schema.json',
    );
    const validate = ajv.compile(JSON.parse(readFileSync(schemaPath, 'utf8')));
    for (const origin of [
      'https://user:secret@example.org/rg.exe',
      'https://user@example.org/rg.exe',
      'HTTPS://example.org/rg.exe',
    ]) {
      const candidate = { ...fixture.good, origin };
      expect(entry.schema.safeParse(candidate).success).toBe(false);
      expect(validate(candidate)).toBe(false);
    }
  });

  for (const fixture of cases) {
    it(`${fixture.name} accepts valid and refuses structural attack in both validators`, () => {
      const entry = V02_CONTRACTS.find((c) => c.name === fixture.name);
      expect(entry).toBeDefined();
      if (!entry) return;
      const source = join(import.meta.dirname, '../src/schema', `${fixture.name}.schema.json`);
      const emitted = JSON.parse(readFileSync(source, 'utf8'));
      expect(emitted['x-semantic-validation']).toBeDefined();
      const jsonValidate = ajv.compile(emitted);
      expect(entry.schema.safeParse(fixture.good).success).toBe(true);
      expect(jsonValidate(fixture.good)).toBe(true);
      expect(entry.schema.safeParse(fixture.bad).success).toBe(false);
      expect(jsonValidate(fixture.bad)).toBe(false);
    });
  }
});
