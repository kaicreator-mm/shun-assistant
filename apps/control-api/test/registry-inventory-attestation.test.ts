import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJson } from '@shun/contracts';
import { snapshotFactsRevision } from '@shun/resolver';
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

const ENV = {
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
} as const;
const WORKSPACE = 'C:\\operator-root';
const NOW = '2026-10-27T16:00:30.000Z';
const ISSUED = '2026-10-27T16:00:00.000Z';
const EXPIRES = '2026-10-27T16:01:00.000Z';
const signing = generateKeyPairSync('ed25519');
const publicPem = signing.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const pin = createHash('sha256')
  .update(signing.publicKey.export({ type: 'spki', format: 'der' }))
  .digest('hex');
const legacy = createStorageRegistrySnapshot(ENV as never);
const dual = createInventoryRegistrySnapshot(ENV as never);
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

function issue(issuedSnapshot: typeof dual) {
  const unsigned: RegistryIssuanceBody = {
    schema: ISSUANCE_SCHEMA,
    workspace: WORKSPACE,
    issuedAt: ISSUED,
    expiresAt: EXPIRES,
    snapshot: issuedSnapshot,
    currentRevision: snapshotFactsRevision(issuedSnapshot),
  };
  return {
    ...unsigned,
    signature: sign(null, Buffer.from(canonicalJson(unsigned), 'utf8'), signing.privateKey).toString('base64'),
  };
}

function source(raw: ReturnType<typeof issue>) {
  verifyPinnedRegistryPublicKey(publicPem, pin);
  const proof = verifyRegistryIssuance(raw, publicPem, WORKSPACE, NOW);
  return hasExactIssuedInventoryBinding(proof.snapshot)
    ? { kind: 'CURRENT' as const, policyRevision: 'operator-approved-r0', registryRevision: proof.currentRevision }
    : { kind: 'UNRESOLVABLE' as const };
}

describe('T08 C07R — independently signed inventory Registry source P1', () => {
  it('refuses a legitimately signed STORAGE-ONLY catalog, before any plan or collector', async () => {
    let planCalls = 0;
    let collectCalls = 0;
    const result = await runAuthorizedInventoryRecipe({
      readCandidate: () => candidate,
      current: async () => source(issue(legacy)),
      controller: {
        authorizePlan: async () => {
          planCalls++;
          throw new Error('Unsigned inventory source cannot enter controller');
        },
        authorizeEffect: async () => {
          throw new Error('No effect may be authorized');
        },
      },
      collect: () => {
        collectCalls++;
        return { ok: true, snapshot };
      },
    });
    expect(result).toEqual({ ok: false, code: 'RECIPE_AUTHORITY_UNAVAILABLE' });
    expect(planCalls).toBe(0);
    expect(collectCalls).toBe(0);
  });

  it('independently signed exact inventory capability/provider/binding verifies and allows one gated read', async () => {
    let collectCalls = 0;
    let gates = 0;
    const verified = source(issue(dual));
    expect(verified.kind).toBe('CURRENT');
    expect(hasExactIssuedInventoryBinding(dual)).toBe(true);
    expect(dual.bindings.some((b) => b.bindingId === 'binding/shun-local-system-inventory')).toBe(true);
    const output = await runAuthorizedInventoryRecipe({
      readCandidate: () => candidate,
      current: async () => {
        gates++;
        return verified;
      },
      controller: {
        authorizePlan: async ({ plan }) => ({
          ok: true,
          authorization: {
            plan,
            actions: [{
              actionId: 'read-system-inventory',
              authorizationRef: 'signed-g1',
              authorizationKind: 'AUTOMATIC',
              planHash: plan.planHash,
              action: { op: 'system.inventory', sideEffectClass: 'R0' },
            }],
            grants: [{ grantId: 'signed-g1' }],
          },
        }) as never,
        authorizeEffect: async () => ({ ok: true }) as never,
      },
      collect: () => {
        collectCalls++;
        return { ok: true, snapshot };
      },
    });
    expect(output).toMatchObject({ ok: true, status: 'VERIFIED_READONLY_OBSERVATION' });
    expect(collectCalls).toBe(1);
    expect(gates).toBe(2);
  });

  it('refuses signed catalog changes before effect, and rejects tampered signatures', async () => {
    const original = issue(dual);
    expect(() => source({ ...original, snapshot: legacy })).toThrow(
      'REAL_STORAGE_REGISTRY_ISSUANCE_REVISION_MISMATCH',
    );
    const wrong = { ...dual, bindings: dual.bindings.map((b) =>
      b.bindingId === 'binding/shun-local-system-inventory'
        ? { ...b, adapterId: 'adapter.not-the-inventory-host' }
        : b,
    ) };
    const wrongIssued = issue(wrong);
    expect(hasExactIssuedInventoryBinding(source(wrongIssued).kind === 'CURRENT' ? dual : wrong))
      .toBe(false);
    let calls = 0;
    let observations = 0;
    const result = await runAuthorizedInventoryRecipe({
      readCandidate: () => candidate,
      current: async () => {
        calls++;
        return source(calls === 1 ? original : wrongIssued);
      },
      controller: {
        authorizePlan: async ({ plan }) => ({
          ok: true,
          authorization: {
            plan,
            actions: [{
              actionId: 'read-system-inventory',
              authorizationRef: 'g1',
              authorizationKind: 'AUTOMATIC',
              planHash: plan.planHash,
              action: { op: 'system.inventory', sideEffectClass: 'R0' },
            }],
            grants: [{ grantId: 'g1' }],
          },
        }) as never,
        authorizeEffect: async () => {
          throw new Error('Changed binding cannot cross effect gate');
        },
      },
      collect: () => {
        observations++;
        return { ok: true, snapshot };
      },
    });
    expect(result).toEqual({ ok: false, code: 'RECIPE_AUTHORITY_UNAVAILABLE' });
    expect(calls).toBe(2);
    expect(observations).toBe(0);
  });
});
