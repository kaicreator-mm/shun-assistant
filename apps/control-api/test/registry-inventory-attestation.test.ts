import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJson } from '@shun/contracts';
import { type RegistrySnapshot, snapshotFactsRevision } from '@shun/resolver';
import { describe, expect, it } from 'vitest';
import { BUILTIN_INVENTORY_RECIPE_ID } from '../src/inventory-recipe.ts';
import { runAuthorizedInventoryRecipe } from '../src/recipe-inventory-run.ts';
import {
  ISSUANCE_SCHEMA,
  type RegistryIssuanceBody,
  verifyRegistryIssuance,
} from '../src/real-storage/registry-issuance.ts';
import { verifyPinnedRegistryPublicKey } from '../src/real-storage/registry-key-pin.ts';
import {
  createInventoryRegistrySnapshot,
  createStorageRegistrySnapshot,
  hasExactIssuedInventoryBinding,
} from '../src/real-storage/registry-snapshot.ts';

const WORKSPACE = 'C:\\operator-owned';
const NOW = '2026-10-27T16:00:30.000Z';
const ENV: RegistrySnapshot['environment'] = {
  environmentId: 'shun-real-storage-x64',
  backendKind: 'LOCAL_WINDOWS',
  os: 'WINDOWS-10.0.1',
  arch: 'X64',
  observationRevision: 'issuer:independent-test',
  runtimeCapabilities: ['windows-storage-metadata'],
  privilegeMode: 'STANDARD_USER',
  guiSession: true,
  filesystemCapabilities: ['read', 'write'],
  networkPolicy: 'OFFLINE',
  resources: { cpuCores: 8, memoryMb: 16384, freeDiskMb: 4096 },
};
const signer = generateKeyPairSync('ed25519');
const pem = signer.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const fingerprint = createHash('sha256')
  .update(signer.publicKey.export({ type: 'spki', format: 'der' }))
  .digest('hex');
const legacy = createStorageRegistrySnapshot(ENV);
const extended = createInventoryRegistrySnapshot(ENV);
const candidate = {
  ok: true,
  saved: true,
  state: 'PERSISTED_CANDIDATE_ONLY',
  recipeId: BUILTIN_INVENTORY_RECIPE_ID,
  revisionSha256: 'a'.repeat(64),
  executionAuthorized: false,
  modelCalls: 0,
} as const;
const snapshot = {
  schema: 'shun.system-inventory.v02',
  localOnly: true,
  externalDisclosures: [],
  provenance: 'node:os+node:fs:statfs',
  platform: 'win32',
  cpuLogicalCount: 8,
  memoryTotalBytes: 16000000,
  memoryFreeBytes: 8000000,
  diskTotalBytes: 20000000,
  diskFreeBytes: 8000000,
  uptimeSeconds: 600,
} as const;

function externallySign(snapshotFacts: RegistrySnapshot) {
  const body: RegistryIssuanceBody = {
    schema: ISSUANCE_SCHEMA,
    workspace: WORKSPACE,
    issuedAt: '2026-10-27T16:00:00.000Z',
    expiresAt: '2026-10-27T16:01:00.000Z',
    snapshot: snapshotFacts,
    currentRevision: snapshotFactsRevision(snapshotFacts),
  };
  return {
    ...body,
    signature: sign(
      null,
      Buffer.from(canonicalJson(body), 'utf8'),
      signer.privateKey,
    ).toString('base64'),
  };
}

function checkedSource(proof: ReturnType<typeof externallySign>) {
  verifyPinnedRegistryPublicKey(pem, fingerprint);
  const issued = verifyRegistryIssuance(proof, pem, WORKSPACE, NOW);
  if (!hasExactIssuedInventoryBinding(issued.snapshot)) {
    return { kind: 'UNRESOLVABLE' as const };
  }
  return {
    kind: 'CURRENT' as const,
    policyRevision: 'operator-approved-r0',
    registryRevision: issued.currentRevision,
  };
}

function approved(plan: { planHash: string }) {
  return {
    ok: true,
    authorization: {
      plan,
      actions: [
        {
          actionId: 'read-system-inventory',
          authorizationRef: 'g1',
          authorizationKind: 'AUTOMATIC',
          planHash: plan.planHash,
          action: { op: 'system.inventory', sideEffectClass: 'R0' },
        },
      ],
      grants: [{ grantId: 'g1' }],
    },
  } as never;
}

describe('T08 C07R independently issued Registry inventory provenance', () => {
  it('signed storage-only catalog refuses BEFORE ActionController or T06', async () => {
    let approvedCalls = 0;
    let collected = 0;
    const result = await runAuthorizedInventoryRecipe({
      readCandidate: () => candidate,
      current: async () => checkedSource(externallySign(legacy)),
      controller: {
        authorizePlan: async () => {
          approvedCalls++;
          throw new Error('storage-only catalog cannot approve inventory');
        },
        authorizeEffect: async () => {
          throw new Error('no grant');
        },
      },
      collect: () => {
        collected++;
        return { ok: true, snapshot };
      },
    });
    expect(result).toEqual({ ok: false, code: 'RECIPE_AUTHORITY_UNAVAILABLE' });
    expect(approvedCalls).toBe(0);
    expect(collected).toBe(0);
  });

  it('operator-signed exact extended catalog supports the fixed authorized read', async () => {
    let reads = 0;
    let sourceChecks = 0;
    expect(hasExactIssuedInventoryBinding(extended)).toBe(true);
    const result = await runAuthorizedInventoryRecipe({
      readCandidate: () => candidate,
      current: async () => {
        sourceChecks++;
        return checkedSource(externallySign(extended));
      },
      controller: {
        authorizePlan: async ({ plan }) => approved(plan),
        authorizeEffect: async () => ({ ok: true }) as never,
      },
      collect: () => {
        reads++;
        return { ok: true, snapshot };
      },
    });
    expect(result).toMatchObject({
      ok: true,
      status: 'VERIFIED_READONLY_OBSERVATION',
    });
    expect(sourceChecks).toBe(2);
    expect(reads).toBe(1);
  });

  it('changed signed binding at second gate refuses with zero T06 reads', async () => {
    const changed: RegistrySnapshot = {
      ...extended,
      bindings: extended.bindings.map((binding) =>
        binding.bindingId === 'binding/shun-local-system-inventory'
          ? { ...binding, adapterId: 'adapter.untrusted' }
          : binding,
      ),
    };
    expect(hasExactIssuedInventoryBinding(changed)).toBe(false);
    const original = externallySign(extended);
    const altered = externallySign(changed);
    expect(() =>
      verifyRegistryIssuance(
        { ...original, snapshot: changed },
        pem,
        WORKSPACE,
        NOW,
      ),
    ).toThrow('REAL_STORAGE_REGISTRY_ISSUANCE_REVISION_MISMATCH');
    let sourceChecks = 0;
    let reads = 0;
    const result = await runAuthorizedInventoryRecipe({
      readCandidate: () => candidate,
      current: async () => {
        sourceChecks++;
        return checkedSource(sourceChecks === 1 ? original : altered);
      },
      controller: {
        authorizePlan: async ({ plan }) => approved(plan),
        authorizeEffect: async () => {
          throw new Error('no effect after signed binding change');
        },
      },
      collect: () => {
        reads++;
        return { ok: true, snapshot };
      },
    });
    expect(result).toEqual({ ok: false, code: 'RECIPE_AUTHORITY_UNAVAILABLE' });
    expect(sourceChecks).toBe(2);
    expect(reads).toBe(0);
  });
});
