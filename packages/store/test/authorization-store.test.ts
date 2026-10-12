import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ActionController,
  AuthorizationAuthority,
  type AuthorityRecord,
  type PolicySnapshotRecord,
} from '@shun/authorization';
import { computePlanHash, type ActionPlan, type ApprovalPort } from '@shun/contracts';
import { afterEach, describe, expect, it } from 'vitest';
import { DurableAuthorizationStore } from '../src/authorization-store.ts';

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0)) {
    await rm(root, { recursive: true, force: true });
  }
});

async function dbFile(label: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `shun-auth-store-${label}-`));
  roots.push(root);
  return join(root, 'shun.sqlite');
}

const AUTHORITY: AuthorityRecord = {
  authorityId: 'shun.durable.test',
  authorityRevision: 'auth-1',
  policyInitialized: true,
  priorAuthorityRevisions: [],
  updatedAt: '2026-10-12T00:00:00.000Z',
};

const POLICY: PolicySnapshotRecord = {
  policySnapshotRevision: 'policy-1',
  status: 'ACTIVE',
  authorityId: AUTHORITY.authorityId,
  authorityRevision: AUTHORITY.authorityRevision,
  revokedGrantIds: [],
  priorRevisions: [],
  rules: [],
  riskGuards: [],
  updatedAt: '2026-10-12T00:00:00.000Z',
};

function plan(): ActionPlan {
  const draft: Omit<ActionPlan, 'planHash'> = {
    taskId: 'task-durable-auth',
    capabilityId: 'system.storage.diagnose_bounded_action',
    bindingRefs: ['binding/shun-storage-local-windows'],
    rankingPolicyRevision: 'rank-1',
    policySnapshotRevision: POLICY.policySnapshotRevision,
    actions: [
      {
        actionId: 'cleanup-1',
        bindingRef: 'binding/shun-storage-local-windows',
        op: 'storage.delete_classified_directory',
        parameters: { classification: 'CACHE' },
        sideEffectClass: 'R2',
        requiredPrivilege: 'NONE',
        filesystemScope: {
          read: ['C:\\managed\\cache'],
          write: ['C:\\managed\\cache'],
        },
        networkScope: { allowed: false },
        timeoutMs: 60_000,
        cancellation: { supported: true, mode: 'COOPERATIVE' },
        expectedState: { absent: true },
      },
    ],
    verificationPlan: {
      verifierId: 'verifier.storage',
      verifierRevision: '1',
      checks: [{ checkId: 'post-state' }],
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
  };
  return { ...draft, planHash: computePlanHash(draft as ActionPlan) };
}

function approvals(): ApprovalPort {
  return {
    async requestApproval(request) {
      return {
        approvalId: 'approval-durable-1',
        taskId: request.taskId,
        planHash: request.planHash,
        approved: true,
        approvedBy: 'USER_APPROVAL',
      };
    },
  };
}

describe('DurableAuthorizationStore atomic persistence', () => {
  it('persists authority, policy, grants and consumed nonces across reopen', async () => {
    const file = await dbFile('reopen');
    const first = new DurableAuthorizationStore({ file });
    await first.saveAuthorityRecord(AUTHORITY);
    await first.savePolicySnapshot(POLICY);
    expect(await first.consumeIssuanceNonce('nonce-1', 2_000, 1_000)).toBe(true);

    const record = {
      grantId: 'grant-1',
      grant: {
        grantId: 'grant-1',
        issuer: {
          authorityId: AUTHORITY.authorityId,
          authorityRevision: AUTHORITY.authorityRevision,
        },
        taskId: 'task-1',
        planHash: 'a'.repeat(64),
        policySnapshotRevision: POLICY.policySnapshotRevision,
        actionScope: { actionIds: ['action-1'], privilegeLevel: 'NONE' },
        issuedAt: '2026-10-12T00:00:00.000Z',
        expiresAt: '2026-10-12T00:15:00.000Z',
        integrity: { scheme: 'HMAC_SHA256', value: 'a'.repeat(64) },
      },
      storedAt: '2026-10-12T00:00:00.000Z',
    } as const;
    await first.put(record);
    await first.close();

    const second = new DurableAuthorizationStore({ file });
    expect(await second.loadAuthorityRecord()).toEqual(AUTHORITY);
    expect(await second.loadCurrentPolicy()).toEqual(POLICY);
    expect(await second.get('grant-1')).toEqual(record);
    expect(await second.hasAnyGrant()).toBe(true);
    expect(await second.consumeIssuanceNonce('nonce-1', 2_000, 1_500)).toBe(false);
    await second.close();
  });

  it('CAS has exactly one winner across adapter instances', async () => {
    const file = await dbFile('cas');
    const first = new DurableAuthorizationStore({ file });
    const second = new DurableAuthorizationStore({ file });
    await first.saveAuthorityRecord(AUTHORITY);
    const expected = await first.loadAuthorityRecord();

    const nextA = { ...AUTHORITY, authorityRevision: 'auth-2', updatedAt: '2026-10-12T00:01:00.000Z' };
    const nextB = { ...AUTHORITY, authorityRevision: 'auth-3', updatedAt: '2026-10-12T00:01:01.000Z' };
    expect(await first.compareAndSaveAuthorityRecord(nextA, expected)).toBe(true);
    expect(await second.compareAndSaveAuthorityRecord(nextB, expected)).toBe(false);
    expect(await second.loadAuthorityRecord()).toEqual(nextA);

    await first.close();
    await second.close();
  });

  it('one issuance nonce has one winner across instances and restart', async () => {
    const file = await dbFile('nonce');
    const first = new DurableAuthorizationStore({ file });
    const second = new DurableAuthorizationStore({ file });

    const [a, b] = await Promise.all([
      first.consumeIssuanceNonce('shared-nonce', 10_000, 1_000),
      second.consumeIssuanceNonce('shared-nonce', 10_000, 1_000),
    ]);
    expect([a, b].filter(Boolean)).toHaveLength(1);
    await first.close();
    await second.close();

    const reopened = new DurableAuthorizationStore({ file });
    expect(await reopened.consumeIssuanceNonce('shared-nonce', 10_000, 2_000)).toBe(false);
    expect(await reopened.consumeIssuanceNonce('expired-proof', 1_999, 2_000)).toBe(false);
    await reopened.close();
  });

  it('never overwrites a conflicting durable grant identity', async () => {
    const file = await dbFile('grant-conflict');
    const store = new DurableAuthorizationStore({ file });
    const base = {
      grantId: 'grant-conflict',
      grant: {
        grantId: 'grant-conflict',
        issuer: {
          authorityId: AUTHORITY.authorityId,
          authorityRevision: AUTHORITY.authorityRevision,
        },
        taskId: 'task-1',
        planHash: 'a'.repeat(64),
        policySnapshotRevision: POLICY.policySnapshotRevision,
        actionScope: { actionIds: ['action-1'], privilegeLevel: 'NONE' },
        issuedAt: '2026-10-12T00:00:00.000Z',
        expiresAt: '2026-10-12T00:15:00.000Z',
        integrity: { scheme: 'HMAC_SHA256', value: 'a'.repeat(64) },
      },
      storedAt: '2026-10-12T00:00:00.000Z',
    } as const;
    await store.put(base);
    await store.put(base);
    await expect(
      store.put({
        ...base,
        grant: { ...base.grant, taskId: 'task-other' },
      }),
    ).rejects.toThrow(/grant identity conflict/);
    expect(await store.get(base.grantId)).toEqual(base);
    await store.close();
  });
});

describe('real authorization domain over durable store', () => {
  it('survives authority reconstruction and enforces persisted revocation', async () => {
    const file = await dbFile('domain');
    const state = new DurableAuthorizationStore({ file });
    await state.saveAuthorityRecord(AUTHORITY);
    await state.savePolicySnapshot(POLICY);

    const fixedNow = () => '2026-10-12T00:05:00.000Z';
    const authority = new AuthorizationAuthority({
      state,
      grants: state,
      integritySecret: 'durable-integrity-secret',
      issuanceSecret: 'durable-issuance-secret',
      clock: fixedNow,
      newGrantId: () => 'grant-durable-domain',
    });
    const controller = new ActionController({
      authority,
      policyState: state,
      approvals: approvals(),
      issuanceSecret: 'durable-issuance-secret',
      clock: fixedNow,
    });
    const actionPlan = plan();
    const authorized = await controller.authorizePlan({ plan: actionPlan });
    if (!authorized.ok) throw new Error(`authorization failed: ${authorized.code}`);
    const action = authorized.authorization.actions[0];
    const grant = authorized.authorization.grants[0];
    if (!action || !grant) throw new Error('missing durable action/grant');
    expect(await controller.authorizeEffect({ plan: actionPlan, action, grant })).toMatchObject({
      ok: true,
    });
    await state.close();

    const reopened = new DurableAuthorizationStore({ file });
    const authorityAfterRestart = new AuthorizationAuthority({
      state: reopened,
      grants: reopened,
      integritySecret: 'durable-integrity-secret',
      issuanceSecret: 'durable-issuance-secret',
      clock: fixedNow,
    });
    expect((await authorityAfterRestart.storedGrant(grant.grantId))?.grant).toEqual(grant);
    await authorityAfterRestart.revokeGrant(grant.grantId);

    const controllerAfterRestart = new ActionController({
      authority: authorityAfterRestart,
      policyState: reopened,
      approvals: approvals(),
      issuanceSecret: 'durable-issuance-secret',
      clock: fixedNow,
    });
    expect(
      await controllerAfterRestart.authorizeEffect({ plan: actionPlan, action, grant }),
    ).toMatchObject({ ok: false, code: 'GRANT_REVOKED' });
    await reopened.close();
  });
});
