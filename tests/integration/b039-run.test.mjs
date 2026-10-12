import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { ShunStore, ShunStoreAuthorizationAdapter } from '../../packages/store/src/index.ts';
import { computePlanHash } from '../../packages/contracts/src/index.ts';
import { ActionController, AuthorizationAuthority } from '../../packages/authorization/src/index.ts';
import { test } from 'node:test';
import { join, resolve } from 'node:path';
import {
  CANDIDATE_ROOT,
  makeDurableControllerWorld,
  deriveEvidenceEvents,
  refineGrowthFile,
  REPORT_CASE,
  resolveStorageForB039,
} from './b039-run.mjs';

function facts(overrides = {}) {
  return {
    environmentId: 'source-test-local-windows',
    backendKind: 'LOCAL_WINDOWS',
    os: 'WINDOWS',
    arch: 'X64',
    observationRevision: 'source-test-b039-1',
    runtimeCapabilities: ['windows-storage-metadata'],
    privilegeMode: 'STANDARD_USER',
    guiSession: true,
    filesystemCapabilities: ['read', 'write'],
    networkPolicy: 'OFFLINE',
    resources: { cpuCores: 4, memoryMb: 4096, freeDiskMb: 1024 },
    ...overrides,
  };
}

test('shared resolver selects the native local storage binding with no network', async () => {
  const record = await resolveStorageForB039(facts());
  assert.equal(record.resolvedCapabilityId, 'system.storage.diagnose_bounded_action');
  assert.equal(record.selectedBindingId, 'binding/shun-storage-local-windows');
  assert.equal(record.privacyDisclosurePlan.externalDisclosure, 'FORBIDDEN');
  assert.ok(record.hardGateDispositions.length >= 4);
  assert.ok(record.hardGateDispositions.every((row) => row.outcome === 'PASS'));
  assert.ok(record.selectionReasons.some((reason) => reason.includes('single trusted binding')));
});

test('resolver fails closed when the observed backend is not local Windows', async () => {
  await assert.rejects(
    () => resolveStorageForB039(facts({ backendKind: 'LOCAL_POSIX', os: 'LINUX' })),
    /B039_SHARED_RESOLUTION_FAILED/,
  );
});

test('adapter source never imports or reads T09 private gold', async () => {
  const source = await readFile(new URL('./b039-run.mjs', import.meta.url), 'utf8');
  assert.equal(source.includes('private/gold'), false);
  assert.equal(source.includes('injection-receipt'), false);
  assert.equal(REPORT_CASE, 'B-039');
  assert.equal(CANDIDATE_ROOT, 'candidate/B-039');
});

test('growth refinement uses only checkpoint metadata and rejects an ambiguous largest file', () => {
  const root = resolve('synthetic-b039-root');
  const cache = join(root, 'inputs', 'B-039', 'workspace', 'cache');
  const result = {
    output: { attribution: { growthSourcePath: cache } },
    proposal: {
      checkpoint: {
        targets: [{
          path: cache,
          files: [
            { path: join(cache, 'base-cache.bin'), sizeBytes: 128 * 1024 },
            { path: join(cache, 'hidden-growth.bin'), sizeBytes: 256 * 1024 },
          ],
        }],
      },
    },
  };
  assert.equal(
    refineGrowthFile(root, result),
    'inputs/B-039/workspace/cache/hidden-growth.bin',
  );

  result.proposal.checkpoint.targets[0].files[0].sizeBytes = 256 * 1024;
  assert.throws(() => refineGrowthFile(root, result), /B039_GROWTH_FILE_AMBIGUOUS/);
});

test('event sequence is emitted only when production evidence proves every phase', () => {
  const base = {
    output: {
      attribution: {
        growthSourcePath: 'C:/fixture/cache',
        evidenceRefs: ['evidence://task/observation-task.json'],
      },
      cleanupPlan: {
        r2Gate: {
          phases: ['PLAN', 'PREVIEW', 'CHECKPOINT', 'APPROVAL', 'EXECUTE', 'VERIFY'],
          approvedBy: 'USER_APPROVAL',
        },
      },
      protectedAssetVerification: [{ path: 'C:/fixture/protected', unchanged: true }],
      reclaimed: { grossBytes: 1, postActionStateBytes: 0 },
    },
    proposal: { targets: [{ path: 'C:/fixture/cache' }], plan: { planHash: 'a'.repeat(64) } },
    preview: 'bounded cleanup preview',
    receipts: [{ terminal: 'SUCCEEDED' }],
  };
  assert.deepEqual(
    deriveEvidenceEvents(base).map((event) => event.phase),
    ['observe', 'attribute', 'classify', 'plan', 'preview', 'approval_or_durable_policy', 'execute', 'verify'],
  );

  assert.throws(
    () => deriveEvidenceEvents({ ...base, receipts: [{ terminal: 'REFUSED' }] }),
    /B039_EXECUTION_RECEIPT_NOT_SUCCEEDED/,
  );
  assert.throws(
    () => deriveEvidenceEvents({
      ...base,
      output: { ...base.output, protectedAssetVerification: [] },
    }),
    /B039_SEMANTIC_VERIFICATION_EVIDENCE_MISSING/,
  );
});

test('B-039 real SQLite authority adapter preserves initial policy across close/reopen', async () => {
  const root = await mkdtemp(join(tmpdir(), 'shun-b039-durable-'));
  const file = join(root, 'authority.sqlite');
  try {
    const world = await makeDurableControllerWorld(true, file);
    try {
      const current = await world.authority.currentAuthority();
      assert.equal(current.kind, 'CURRENT');
      assert.equal(current.policySnapshotRevision, 't10-storage-policy-v1');
    } finally {
      await world.store.close();
    }
    // A replay of the fixture setup is never allowed to rewind durable
    // policy or authority lineage on the same database.
    await assert.rejects(
      () => makeDurableControllerWorld(true, file),
      /B039_DURABLE_STATE_RESEED_REFUSED/,
    );
    const reopened = new ShunStore({ file });
    try {
      const adapter = new ShunStoreAuthorizationAdapter(reopened);
      const stored = await adapter.loadAuthorityRecord();
      const policy = await adapter.loadCurrentPolicy();
      assert.equal(stored.policyInitialized, true);
      assert.equal(policy.policySnapshotRevision, 't10-storage-policy-v1');
      assert.equal(await adapter.hasAnyGrant(), false);
    } finally {
      await reopened.close();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('B-039 durable grant survives restart, and persisted revocation refuses the effect', async () => {
  const root = await mkdtemp(join(tmpdir(), 'shun-b039-grant-'));
  const file = join(root, 'authority.sqlite');
  const issuanceSecret = 't10-b039-controller-issuance';
  const integritySecret = 't10-b039-controller-integrity';
  const action = {
    actionId: 't10-b039-verified-action',
    bindingRef: 'binding/shun-storage-local-windows',
    op: 'storage.delete_classified_directory',
    parameters: { classification: 'CACHE' },
    sideEffectClass: 'R2',
    requiredPrivilege: 'NONE',
    filesystemScope: { read: ['C:\\managed\\cache'], write: ['C:\\managed\\cache'] },
    networkScope: { allowed: false },
    timeoutMs: 60_000,
    cancellation: { supported: true, mode: 'COOPERATIVE' },
    expectedState: { absent: true },
  };
  const draft = {
    taskId: 't10-b039-durable-restart',
    capabilityId: 'system.storage.diagnose_bounded_action',
    bindingRefs: ['binding/shun-storage-local-windows'],
    rankingPolicyRevision: 't10-b039-r1',
    policySnapshotRevision: 't10-storage-policy-v1',
    actions: [action],
    verificationPlan: {
      verifierId: 'verifier.storage-c003',
      verifierRevision: 'r1',
      checks: [{ checkId: 'protected-assets-unchanged' }],
    },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
  };
  const plan = { ...draft, planHash: computePlanHash(draft) };
  try {
    const first = await makeDurableControllerWorld(true, file);
    let grant;
    let authorizedAction;
    try {
      const authorized = await first.controller.authorizePlan({ plan });
      assert.equal(authorized.ok, true);
      grant = authorized.authorization.grants[0];
      authorizedAction = authorized.authorization.actions[0];
      assert.ok(grant && authorizedAction);
      assert.equal((await first.controller.authorizeEffect({ plan, grant, action: authorizedAction })).ok, true);
      assert.equal(await first.state.hasAnyGrant(), true);
    } finally {
      await first.store.close();
    }
    const reopened = new ShunStore({ file });
    try {
      const state = new ShunStoreAuthorizationAdapter(reopened);
      const authority = new AuthorizationAuthority({
        state,
        grants: state,
        integritySecret,
        issuanceSecret,
        clock: () => new Date().toISOString(),
      });
      assert.deepEqual((await authority.storedGrant(grant.grantId))?.grant, grant);
      await authority.revokeGrant(grant.grantId);
      const controller = new ActionController({
        authority,
        policyState: state,
        approvals: { async requestApproval() { throw new Error('reopened effect must not reapprove'); } },
        issuanceSecret,
        clock: () => new Date().toISOString(),
      });
      assert.deepEqual(
        { ...(await controller.authorizeEffect({ plan, action: authorizedAction, grant })) }.code,
        'GRANT_REVOKED',
      );
    } finally {
      await reopened.close();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
