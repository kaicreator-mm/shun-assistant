import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ActionController,
  type AuthorityRecord,
  AuthorizationAuthority,
  computeIssuanceProof,
  type PolicySnapshotRecord,
  type StoredGrantRecord,
} from '@shun/authorization';
import { type ActionPlan, type ApprovalPort, computePlanHash } from '@shun/contracts';
import { afterEach, describe, expect, it } from 'vitest';
import {
  ShunStore,
  ShunStoreAuthorizationAdapter,
  ShunStoreAuthorizationConflictError,
  ShunStoreInvalidMutationError,
} from '../src/index.ts';

const CLOCK = '2026-10-12T03:00:00.000Z';
const INTEGRITY_SECRET = 'i58-integrity-secret';
const ISSUANCE_SECRET = 'i58-issuance-secret';
const roots: string[] = [];

afterEach(() => {
  while (roots.length > 0) {
    const root = roots.pop();
    if (root) rmSync(root, { recursive: true, force: true });
  }
});

function dbFile(label: string): string {
  const root = mkdtempSync(join(tmpdir(), `shun-i58-${label}-`));
  roots.push(root);
  return join(root, 'shun.sqlite');
}

function authorityRecord(revision = 'auth-r1'): AuthorityRecord {
  return {
    authorityId: 'shun-action-controller',
    authorityRevision: revision,
    updatedAt: CLOCK,
    policyInitialized: true,
    priorAuthorityRevisions: revision === 'auth-r1' ? [] : ['auth-r1'],
  };
}

function policyRecord(authorityRevision = 'auth-r1'): PolicySnapshotRecord {
  return {
    policySnapshotRevision: 'policy-r1',
    status: 'ACTIVE',
    authorityId: 'shun-action-controller',
    authorityRevision,
    revokedGrantIds: [],
    priorRevisions: [],
    rules: [],
    riskGuards: [],
    updatedAt: CLOCK,
  };
}

async function seed(adapter: ShunStoreAuthorizationAdapter): Promise<void> {
  await adapter.saveAuthorityRecord(authorityRecord());
  await adapter.savePolicySnapshot(policyRecord());
}

function authority(adapter: ShunStoreAuthorizationAdapter): AuthorizationAuthority {
  return new AuthorizationAuthority({
    state: adapter,
    grants: adapter,
    integritySecret: INTEGRITY_SECRET,
    issuanceSecret: ISSUANCE_SECRET,
    clock: () => CLOCK,
    newGrantId: () => 'grant-i58-1',
  });
}

function request() {
  return {
    taskId: 'task-i58',
    planHash: 'a'.repeat(64),
    policySnapshotRevision: 'policy-r1',
    actionScope: {
      actionIds: ['action-i58-1'],
      privilegeLevel: 'USER' as const,
      network: { allowed: false },
    },
    authorizationKind: 'EXPLICIT_APPROVAL' as const,
    approvalRef: 'approval-i58-1',
  };
}

function approvalPort(): ApprovalPort {
  return {
    async requestApproval(approval) {
      return {
        approvalId: 'approval-i58-controller',
        taskId: approval.taskId,
        planHash: approval.planHash,
        approved: true,
        approvedBy: 'USER_APPROVAL',
      };
    },
  };
}

function actionPlan(): ActionPlan {
  const draft: Omit<ActionPlan, 'planHash'> = {
    taskId: 'task-i58-controller',
    capabilityId: 'system.storage.diagnose_bounded_action',
    bindingRefs: ['binding/shun-storage-local-windows'],
    rankingPolicyRevision: 'rank-i58-1',
    policySnapshotRevision: 'policy-r1',
    actions: [
      {
        actionId: 'action-i58-controller-1',
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
      verifierRevision: 'r1',
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

describe('durable ShunStore authorization adapter', () => {
  it('composes with the real AuthorizationAuthority and survives close/reopen', async () => {
    const file = dbFile('restart');
    const firstStore = new ShunStore({ file });
    const first = new ShunStoreAuthorizationAdapter(firstStore);
    await seed(first);

    const issuer = authority(first);
    expect(await issuer.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      authorityRevision: 'auth-r1',
      policySnapshotRevision: 'policy-r1',
    });

    const issueRequest = request();
    const proof = computeIssuanceProof(ISSUANCE_SECRET, issueRequest, { issuedAt: CLOCK });
    const grant = await issuer.issue(issueRequest, proof);
    expect(grant.grantId).toBe('grant-i58-1');
    expect(await first.hasAnyGrant()).toBe(true);
    expect(await first.get(grant.grantId)).toMatchObject({ grantId: grant.grantId, grant });

    await firstStore.close();

    const reopenedStore = new ShunStore({ file });
    const reopened = new ShunStoreAuthorizationAdapter(reopenedStore);
    const restartedIssuer = authority(reopened);
    expect(await restartedIssuer.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      authorityRevision: 'auth-r1',
      policySnapshotRevision: 'policy-r1',
    });
    expect(await reopened.hasAnyGrant()).toBe(true);
    expect(await reopened.get(grant.grantId)).toMatchObject({ grantId: grant.grantId });

    // The issuance proof nonce was consumed before the restart. Replaying the
    // same valid MAC after reopening the database must remain refused.
    await expect(restartedIssuer.issue(issueRequest, proof)).rejects.toMatchObject({
      code: 'GRANT_NOT_AUTHENTIC',
    });
    await reopenedStore.close();
  });

  it('serializes stale compare-and-save decisions across two SQLite connections', async () => {
    const file = dbFile('cas');
    const storeA = new ShunStore({ file });
    const storeB = new ShunStore({ file });
    const a = new ShunStoreAuthorizationAdapter(storeA);
    const b = new ShunStoreAuthorizationAdapter(storeB);
    await seed(a);

    const stale = await a.loadAuthorityRecord();
    const winner = authorityRecord('auth-r2');
    expect(await b.compareAndSaveAuthorityRecord(winner, stale)).toBe(true);

    const loser = {
      ...authorityRecord('auth-r3'),
      priorAuthorityRevisions: ['auth-r1', 'auth-r2'],
    };
    expect(await a.compareAndSaveAuthorityRecord(loser, stale)).toBe(false);
    expect(await a.loadAuthorityRecord()).toEqual(winner);

    await storeA.close();
    await storeB.close();
  });

  it('shares the one-shot nonce ledger across connections and permits reuse only after expiry', async () => {
    const file = dbFile('nonce');
    const storeA = new ShunStore({ file });
    const storeB = new ShunStore({ file });
    const a = new ShunStoreAuthorizationAdapter(storeA);
    const b = new ShunStoreAuthorizationAdapter(storeB);

    expect(await a.consumeIssuanceNonce('nonce-i58', 200, 100)).toBe(true);
    expect(await b.consumeIssuanceNonce('nonce-i58', 200, 100)).toBe(false);
    expect(await b.consumeIssuanceNonce('nonce-i58', 200, 200)).toBe(false);
    expect(await b.consumeIssuanceNonce('nonce-i58', 300, 201)).toBe(true);

    await storeA.close();
    await storeB.close();
  });

  it('accepts an idempotent identical grant record but refuses identity reuse with different bytes', async () => {
    const file = dbFile('grant-conflict');
    const store = new ShunStore({ file });
    const adapter = new ShunStoreAuthorizationAdapter(store);
    await seed(adapter);

    const issuer = authority(adapter);
    const issueRequest = request();
    const proof = computeIssuanceProof(ISSUANCE_SECRET, issueRequest, { issuedAt: CLOCK });
    const grant = await issuer.issue(issueRequest, proof);
    const stored = (await adapter.get(grant.grantId)) as StoredGrantRecord;
    await expect(adapter.put(stored)).resolves.toBeUndefined();

    const conflict: StoredGrantRecord = {
      ...stored,
      storedAt: '2026-10-12T03:00:01.000Z',
    };
    await expect(adapter.put(conflict)).rejects.toBeInstanceOf(ShunStoreAuthorizationConflictError);
    await store.close();
  });

  it('refuses a grant record whose outer identity does not match the embedded grant', async () => {
    const file = dbFile('grant-id');
    const store = new ShunStore({ file });
    const adapter = new ShunStoreAuthorizationAdapter(store);
    await expect(
      adapter.put({
        grantId: 'outer',
        grant: {
          grantId: 'inner',
          issuer: { authorityId: 'a', authorityRevision: 'r1' },
          taskId: 'task',
          planHash: 'a'.repeat(64),
          policySnapshotRevision: 'p1',
          actionScope: { actionIds: ['x'], privilegeLevel: 'USER' },
          issuedAt: CLOCK,
          expiresAt: '2026-10-12T03:15:00.000Z',
          integrity: { scheme: 'HMAC_SHA256', value: 'x' },
        },
        storedAt: CLOCK,
      }),
    ).rejects.toBeInstanceOf(ShunStoreInvalidMutationError);
    await store.close();
  });

  it('runs the real ActionController across restart and enforces persisted revocation', async () => {
    const file = dbFile('controller-restart');
    const firstStore = new ShunStore({ file });
    const first = new ShunStoreAuthorizationAdapter(firstStore);
    await seed(first);

    const firstAuthority = authority(first);
    const firstController = new ActionController({
      authority: firstAuthority,
      policyState: first,
      approvals: approvalPort(),
      issuanceSecret: ISSUANCE_SECRET,
      clock: () => CLOCK,
    });
    const plan = actionPlan();
    const authorized = await firstController.authorizePlan({ plan });
    if (!authorized.ok) {
      throw new Error(`controller authorization failed: ${authorized.code}`);
    }
    const action = authorized.authorization.actions[0];
    const grant = authorized.authorization.grants[0];
    if (!action || !grant) throw new Error('controller returned no action/grant');
    expect(await firstController.authorizeEffect({ plan, action, grant })).toMatchObject({
      ok: true,
    });
    await firstStore.close();

    const reopenedStore = new ShunStore({ file });
    const reopened = new ShunStoreAuthorizationAdapter(reopenedStore);
    const restartedAuthority = authority(reopened);
    expect((await restartedAuthority.storedGrant(grant.grantId))?.grant).toEqual(grant);
    await restartedAuthority.revokeGrant(grant.grantId);

    const restartedController = new ActionController({
      authority: restartedAuthority,
      policyState: reopened,
      approvals: approvalPort(),
      issuanceSecret: ISSUANCE_SECRET,
      clock: () => CLOCK,
    });
    expect(await restartedController.authorizeEffect({ plan, action, grant })).toMatchObject({
      ok: false,
      code: 'GRANT_REVOKED',
    });
    await reopenedStore.close();
  });
});
