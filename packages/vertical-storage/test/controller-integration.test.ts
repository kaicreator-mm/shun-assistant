import { promises as fsp } from 'node:fs';
import * as path from 'node:path';
import {
  ActionController,
  type AuthorityRecord,
  AuthorizationAuthority,
  type PolicySnapshotRecord,
  type PolicyStateStore,
  type StoredGrantRecord,
} from '@shun/authorization';
import type { ApprovalPort } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import {
  runStorageDiagnose,
  type StorageDiagnoseRuntime,
  StorageVerticalError,
} from '../src/index.ts';
import { makeClock, makeFixtureRoot, plantFiles, volumeOf } from './helpers.ts';

const d = process.platform === 'win32' ? describe : describe.skip;
const AUTHORITY: AuthorityRecord = {
  authorityId: 'shun.storage-controller.test',
  authorityRevision: 'auth-storage-1',
  updatedAt: '2026-10-12T00:00:00.000Z',
};
const POLICY_REVISION = 'policy-storage-1';
const ISSUANCE_SECRET = 'storage-controller-issuance-secret';
const INTEGRITY_SECRET = 'storage-controller-integrity-secret';

function controllerWorld(options?: { wrongApprovalHash?: boolean; approve?: boolean }) {
  let authoritySlot: unknown = structuredClone(AUTHORITY);
  let policySlot: unknown = {
    policySnapshotRevision: POLICY_REVISION,
    status: 'ACTIVE',
    authorityId: AUTHORITY.authorityId,
    authorityRevision: AUTHORITY.authorityRevision,
    revokedGrantIds: [],
    rules: [],
    riskGuards: [],
    updatedAt: '2026-10-12T00:00:00.000Z',
  } satisfies PolicySnapshotRecord;
  const consumed = new Set<string>();
  const state: PolicyStateStore = {
    async loadAuthorityRecord() {
      return structuredClone(authoritySlot);
    },
    async loadCurrentPolicy() {
      return structuredClone(policySlot);
    },
    async saveAuthorityRecord(record) {
      authoritySlot = structuredClone(record);
    },
    async savePolicySnapshot(snapshot) {
      policySlot = structuredClone(snapshot);
    },
    async compareAndSavePolicySnapshot(snapshot, expectedPrior) {
      if (JSON.stringify(policySlot) !== JSON.stringify(expectedPrior)) return false;
      policySlot = structuredClone(snapshot);
      return true;
    },
    async compareAndSaveAuthorityRecord(record, expectedPrior) {
      if (JSON.stringify(authoritySlot) !== JSON.stringify(expectedPrior)) return false;
      authoritySlot = structuredClone(record);
      return true;
    },
    async consumeIssuanceNonce(nonce) {
      if (consumed.has(nonce)) return false;
      consumed.add(nonce);
      return true;
    },
  };

  const grants = new Map<string, StoredGrantRecord>();
  const grantStore = {
    async put(record: StoredGrantRecord) {
      grants.set(record.grantId, structuredClone(record));
    },
    async get(grantId: string) {
      return grants.get(grantId) ?? null;
    },
    async hasAnyGrant() {
      return grants.size > 0;
    },
  };

  const clock = makeClock('2026-10-12T01:00:00.000Z');
  const authority = new AuthorizationAuthority({
    state,
    grants: grantStore,
    integritySecret: INTEGRITY_SECRET,
    issuanceSecret: ISSUANCE_SECRET,
    clock: clock.now,
  });
  const approvalRequests: Array<{ taskId: string; planHash: string }> = [];
  const approvals: ApprovalPort = {
    async requestApproval(request) {
      approvalRequests.push({ taskId: request.taskId, planHash: request.planHash });
      return {
        approvalId: 'approval-storage-1',
        taskId: request.taskId,
        planHash: options?.wrongApprovalHash ? 'f'.repeat(64) : request.planHash,
        approved: options?.approve ?? true,
        approvedBy: 'USER_APPROVAL',
      };
    },
  };
  const controller = new ActionController({
    authority,
    policyState: state,
    approvals,
    issuanceSecret: ISSUANCE_SECRET,
    clock: clock.now,
  });

  return {
    controller,
    clock,
    grants,
    approvalRequests,
    revoke(grantId: string) {
      const policy = policySlot as PolicySnapshotRecord;
      policySlot = { ...policy, revokedGrantIds: [...policy.revokedGrantIds, grantId] };
    },
  };
}

async function fixture(label: string, options?: { includeTemp?: boolean }) {
  const root = await makeFixtureRoot(label);
  const scope = path.join(root, 'scope');
  const growth = path.join(scope, 'growth');
  const cache = path.join(growth, 'cache');
  const temp = path.join(growth, 'temp');
  const keep = path.join(scope, 'keep');
  const protectedDir = path.join(keep, 'protected');
  await plantFiles(cache, [{ relativePath: 'cache.bin', bytes: 4096 }]);
  if (options?.includeTemp) {
    await plantFiles(temp, [{ relativePath: 'temp.bin', bytes: 2048 }]);
  }
  await plantFiles(protectedDir, [{ relativePath: 'keep.bin', bytes: 1024 }]);
  return { root, growth, cache, temp, keep, protectedDir, volume: volumeOf(scope) };
}

function runtime(
  f: Awaited<ReturnType<typeof fixture>>,
  world: ReturnType<typeof controllerWorld>,
  controller: StorageDiagnoseRuntime['controller'] = world.controller,
): StorageDiagnoseRuntime {
  return {
    controller,
    scope: { roots: [f.growth, f.keep] },
    evidenceDir: path.join(f.root, 'evidence'),
    policySnapshotRevision: POLICY_REVISION,
    rankingPolicyRevision: 'ranking-storage-controller-1',
    environmentId: 'env-real-windows-controller-test',
    providerId: 'storage.cleaner.local-windows',
    providerVersion: '0.1.0',
    clock: world.clock.now,
  };
}

function input(
  f: Awaited<ReturnType<typeof fixture>>,
  eligibleCategories: readonly ('CACHE' | 'TEMP')[] = ['CACHE'],
) {
  return {
    taskId: 'task-storage-controller-integration',
    targetVolume: f.volume,
    protectedAssets: [{ path: f.protectedDir }],
    cleanupPolicy: { eligibleCategories: [...eligibleCategories] },
  };
}

describe('controller wiring fails closed before filesystem execution', () => {
  it('refuses a runtime with neither legacy ports nor ActionController', async () => {
    const broken = {
      scope: { roots: ['C:\\fixture'] },
      evidenceDir: 'C:\\evidence',
      policySnapshotRevision: POLICY_REVISION,
      rankingPolicyRevision: 'rank-1',
      environmentId: 'env-1',
      providerId: 'provider-1',
      providerVersion: '1',
      clock: () => '2026-10-12T01:00:00.000Z',
    } as StorageDiagnoseRuntime;
    await expect(
      runStorageDiagnose(broken, {
        taskId: 'task-no-controller',
        targetVolume: 'C:',
        protectedAssets: [{ path: 'C:\\keep' }],
        cleanupPolicy: { eligibleCategories: ['CACHE'] },
      }),
    ).rejects.toMatchObject({ code: 'R2_GATE_MISSING' });
  });
});

d('C-003 real ActionController integration', () => {
  it('authorizes the exact storage plan and gates the real cleanup effect', async () => {
    const f = await fixture('controller-happy');
    const world = controllerWorld();
    const result = await runStorageDiagnose(runtime(f, world), input(f));

    expect(world.approvalRequests).toHaveLength(1);
    expect(world.grants.size).toBe(1);
    expect(result.output.cleanupPlan?.r2Gate.approvedBy).toBe('USER_APPROVAL');
    expect(result.output.executionEvidence?.terminal).toBe('SUCCEEDED');
    expect(await fsp.readdir(f.cache)).toEqual([]);
    expect(await fsp.readFile(path.join(f.protectedDir, 'keep.bin'))).toHaveLength(1024);
  });

  it('rejects an approval bound to the wrong plan hash before any deletion', async () => {
    const f = await fixture('controller-wrong-approval');
    const world = controllerWorld({ wrongApprovalHash: true });

    await expect(runStorageDiagnose(runtime(f, world), input(f))).rejects.toMatchObject({
      code: 'R2_GATE_MISSING',
    });
    expect((await fsp.readdir(f.cache)).length).toBe(1);
    expect(world.grants.size).toBe(0);
  });

  it('revocation between two effects is enforced by ActionController.authorizeEffect', async () => {
    const f = await fixture('controller-revoke-between-effects', { includeTemp: true });
    const world = controllerWorld();
    let effectCalls = 0;
    const controller: StorageDiagnoseRuntime['controller'] = {
      authorizePlan: (request) => world.controller.authorizePlan(request),
      async authorizeEffect(request) {
        effectCalls += 1;
        if (effectCalls === 2) {
          world.revoke((request.grant as { grantId: string }).grantId);
        }
        return world.controller.authorizeEffect(request);
      },
    };

    await expect(
      runStorageDiagnose(runtime(f, world, controller), input(f, ['CACHE', 'TEMP'] as const)),
    ).rejects.toThrow(StorageVerticalError);
    expect(effectCalls).toBeGreaterThanOrEqual(2);
    expect(await fsp.readdir(f.cache)).toEqual([]);
    expect((await fsp.readdir(f.temp)).length).toBe(1);
    expect(await fsp.readFile(path.join(f.protectedDir, 'keep.bin'))).toHaveLength(1024);
  });
});
