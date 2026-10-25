// T07 F03 durable gate falsifiers: the same-local-store STARTED reservation
// ledger and the ActionController re-entry boundary for ONE authorized file
// mutation. The boundary must rehydrate the REAL issued SQLite grant and
// immutable plan, re-enter the REAL controller per effect, durably reserve +
// re-read STARTED BEFORE any injected trusted IO runs, and refuse EVERY
// second attempt of the same (task, action) identity — an interrupted effect
// stays UNKNOWN and is never auto-replayed. The final describe composes the
// real boundary with the real anchored vertical-files executor on Windows.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import { type ActionPlan, type AuthorizedAction, computePlanHash } from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import { afterEach, describe, expect, it } from 'vitest';
import { executeAuthorizedFileMutation } from '../../vertical-files/src/file-mutation-host.ts';
import { SqliteFileMutationAuthorizationBoundary } from '../src/sqlite-file-mutation-host.ts';
import { SqliteFileMutationJournal } from '../src/sqlite-file-mutation-journal.ts';

const fixedNow = '2026-10-26T04:00:00.000Z';
const SRC = 'C:\\approved\\src\\a.txt';
const DST = 'C:\\approved\\dst\\b.txt';

const dispose: Array<() => Promise<void> | void> = [];
afterEach(() => {
  for (const fn of dispose.splice(0).reverse()) fn();
});

function mutationPlan(op: 'file.copy' | 'file.move' | 'file.rename' = 'file.copy'): ActionPlan {
  const sourceDir = SRC.slice(0, SRC.lastIndexOf('\\'));
  const destDir = DST.slice(0, DST.lastIndexOf('\\'));
  const write =
    op === 'file.copy'
      ? [destDir]
      : [...new Set([sourceDir, destDir].map((d) => d.toLowerCase()))].sort();
  const plan: ActionPlan = {
    taskId: 'task-f03',
    capabilityId: op,
    bindingRefs: ['binding-1'],
    recipeRef: `r1@${'b'.repeat(64)}`,
    rankingPolicyRevision: 'rank-1',
    policySnapshotRevision: 'policy-1',
    actions: [
      {
        actionId: 'mut-1',
        bindingRef: 'binding-1',
        op,
        parameters: { sourcePath: SRC, destinationPath: DST },
        sideEffectClass: 'R2',
        requiredPrivilege: 'USER',
        filesystemScope: { read: [sourceDir], write },
      },
    ],
    verificationPlan: { verifierId: 'v1', verifierRevision: '1', checks: [{ checkId: 'post' }] },
    recoveryPlan: {
      classificationStrategy: 'JOURNAL_AND_POST_STATE',
      reconcileBeforeRetry: true,
      retryAllowedWhen: 'PROVEN_NOT_EXECUTED',
    },
    planHash: 'a'.repeat(64),
  };
  plan.planHash = computePlanHash(plan);
  return plan;
}

function validReceipt(actionId: string, startedAt = fixedNow) {
  return {
    actionId,
    environmentId: 'local-windows-user',
    providerId: 'shun-win32-file-mutation',
    providerVersion: '0.2.0',
    startedAt,
    finishedAt: startedAt,
    terminal: 'SUCCEEDED',
    outputRefs: [],
    sideEffectEvidence: {
      sideEffectClass: 'R2',
      recoveryClassification: 'COMPLETED_VERIFIED',
      postStateVerified: true,
    },
  };
}

async function world(options: { clock?: () => string; plan?: ActionPlan } = {}) {
  const folder = mkdtempSync(join(tmpdir(), 'shun-f03-gate-'));
  const file = join(folder, 'gate.sqlite');
  const store = new ShunStore({ file });
  dispose.push(async () => {
    await store.close();
    rmSync(folder, { recursive: true, force: true });
  });
  const adapter = new ShunStoreAuthorizationAdapter(store);
  const clock = options.clock ?? (() => fixedNow);
  await adapter.saveAuthorityRecord({
    authorityId: 'auth-1',
    authorityRevision: 'rev-1',
    updatedAt: fixedNow,
    policyInitialized: true,
  });
  const plan = options.plan ?? mutationPlan();
  const sourceDir = SRC.slice(0, SRC.lastIndexOf('\\'));
  const destDir = DST.slice(0, DST.lastIndexOf('\\'));
  await adapter.savePolicySnapshot({
    policySnapshotRevision: 'policy-1',
    status: 'ACTIVE',
    authorityId: 'auth-1',
    authorityRevision: 'rev-1',
    revokedGrantIds: [],
    rules: [
      {
        ruleId: 'allow-f03-mutation',
        capabilityId: plan.capabilityId,
        op: plan.actions[0]?.op ?? 'file.copy',
        maxRiskClass: 'R2',
        privilegeLevel: 'USER',
        filesystem: { read: [sourceDir], write: [destDir] },
      },
    ],
    riskGuards: [],
    updatedAt: fixedNow,
  });
  const authority = new AuthorizationAuthority({
    state: adapter,
    grants: adapter,
    integritySecret: 'private-test-integrity',
    issuanceSecret: 'private-test-issuance',
    clock,
  });
  const controller = new ActionController({
    authority,
    policyState: adapter,
    approvals: {
      requestApproval: async () => {
        throw new Error('approval cannot be reached');
      },
    },
    issuanceSecret: 'private-test-issuance',
    clock,
  });
  const authorized = await controller.authorizePlan({ plan });
  if (!authorized.ok) throw new Error(`fixture failed to authorize: ${authorized.code}`);
  const action = authorized.authorization.actions[0];
  if (!action) throw new Error('fixture has no authorized action');
  return { folder, file, store, adapter, controller, plan, action };
}

describe('T07 F03 SQLite mutation journal (durable STARTED CAS)', () => {
  it('refuses an in-memory store: no crash-safe reservation is possible', () => {
    const ephemeral = new ShunStore({ file: ':memory:' });
    dispose.push(() => ephemeral.close());
    expect(() => new SqliteFileMutationJournal(ephemeral)).toThrow(
      'FILE_MUTATION_JOURNAL_CONFIGURATION_REFUSED',
    );
  });

  it('reserves STARTED once, re-reads it, and refuses every replay across a real reopen', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    expect(journal.reserve(v.action)).toEqual({ ok: true, state: 'DURABLY_RESERVED' });
    expect(journal.lookup(v.action)).toEqual({
      ok: true,
      state: 'STARTED',
      evidenceSha256: null,
    });
    // Same intent: reconcile-first, never replay.
    expect(journal.reserve(v.action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });
    // The row survives a full store close/reopen (durability).
    await v.store.close();
    const reopened = new ShunStore({ file: v.file });
    dispose.push(async () => {
      await reopened.close();
    });
    const journal2 = new SqliteFileMutationJournal(reopened);
    expect(journal2.lookup(v.action)).toEqual({ ok: true, state: 'STARTED', evidenceSha256: null });
    expect(journal2.reserve(v.action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });
  });

  it('refuses a different intent for the same (task, action) identity', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    expect(journal.reserve(v.action)).toEqual({ ok: true, state: 'DURABLY_RESERVED' });
    const mutated: AuthorizedAction = {
      ...v.action,
      action: {
        ...v.action.action,
        parameters: { sourcePath: SRC, destinationPath: 'C:\\approved\\dst\\OTHER.txt' },
      },
    };
    expect(journal.reserve(mutated)).toEqual({ ok: false, code: 'JOURNAL_REFUSED' });
  });

  it('records COMMITTED_VERIFIED once from STARTED; divergence and replay of outcomes refuse', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    journal.reserve(v.action);
    const evidence = 'c'.repeat(64);
    expect(journal.recordOutcome(v.action, 'COMMITTED_VERIFIED', evidence)).toBe(true);
    expect(journal.recordOutcome(v.action, 'COMMITTED_VERIFIED', evidence)).toBe(true);
    expect(journal.recordOutcome(v.action, 'UNCERTAIN', 'd'.repeat(64))).toBe(false);
    expect(journal.lookup(v.action)).toEqual({
      ok: true,
      state: 'COMMITTED_VERIFIED',
      evidenceSha256: evidence,
    });
    // A committed attempt still never authorizes a replay.
    expect(journal.reserve(v.action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });
    expect(journal.recordOutcome(v.action, 'UNCERTAIN', 'not-a-hash')).toBe(false);
  });

  it('refuses non-mutation intents at the journal gate', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    const search: unknown = {
      ...v.action,
      action: { ...v.action.action, op: 'file.search', sideEffectClass: 'R0' },
    };
    expect(journal.reserve(search)).toEqual({ ok: false, code: 'JOURNAL_REFUSED' });
    expect(journal.lookup(search)).toEqual({ ok: false, code: 'JOURNAL_REFUSED' });
  });
});

describe('T07 F03 mutation authorization boundary (REAL grant re-entry + STARTED-before-IO)', () => {
  it('runs one real rehydrated-grant effect with durable STARTED re-read before any IO', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    let dispatches = 0;
    let stateSeenByEffect: string | null = null;
    const backend = new SqliteFileMutationAuthorizationBoundary({
      store: v.store,
      controller: v.controller,
      loadPlanByHash: async () => v.plan,
      executeFileMutation: async (action) => {
        dispatches++;
        const readback = journal.lookup(action);
        stateSeenByEffect = readback.ok ? readback.state : null;
        return { ok: true, receipt: validReceipt(action.actionId) };
      },
    });
    const result = await backend.execute(v.action);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.receipt.terminal).toBe('SUCCEEDED');
    expect(dispatches).toBe(1);
    // THE ordering proof: the durable row was already STARTED when the
    // trusted effect ran, and is COMMITTED_VERIFIED afterwards.
    expect(stateSeenByEffect).toBe('STARTED');
    expect(journal.lookup(v.action)).toMatchObject({ ok: true, state: 'COMMITTED_VERIFIED' });
  });

  it('refuses a forged grant reference, tampered plan and revoked policy with ZERO dispatch', async () => {
    const v = await world();
    let dispatches = 0;
    let brokenPlan = false;
    const backend = new SqliteFileMutationAuthorizationBoundary({
      store: v.store,
      controller: v.controller,
      loadPlanByHash: async () => (brokenPlan ? { ...v.plan, planHash: '0'.repeat(64) } : v.plan),
      executeFileMutation: async () => {
        dispatches++;
        return null;
      },
    });
    const forged: AuthorizedAction = { ...v.action, authorizationRef: 'nonexistent-grant' };
    expect(await backend.execute(forged)).toEqual({ ok: false, code: 'FILE_MUTATION_REFUSED' });
    brokenPlan = true;
    expect(await backend.execute(v.action)).toEqual({ ok: false, code: 'FILE_MUTATION_REFUSED' });
    brokenPlan = false;
    const policy = await v.adapter.loadCurrentPolicy();
    if (policy === null || typeof policy !== 'object') throw new Error('fixture has no policy');
    await v.adapter.savePolicySnapshot({ ...policy, status: 'REVOKED' } as never);
    expect(await backend.execute(v.action)).toEqual({ ok: false, code: 'FILE_MUTATION_REFUSED' });
    expect(dispatches).toBe(0);
    // Nothing was journaled either: the refusals happened at the gate.
    const journal = new SqliteFileMutationJournal(v.store);
    expect(journal.lookup(v.action)).toEqual({ ok: false, code: 'NOT_FOUND' });
  });

  it('refuses a non-mutation or widened plan with ZERO dispatch', async () => {
    const v = await world();
    let dispatches = 0;
    const backend = new SqliteFileMutationAuthorizationBoundary({
      store: v.store,
      controller: v.controller,
      loadPlanByHash: async () => v.plan,
      executeFileMutation: async () => {
        dispatches++;
        return null;
      },
    });
    const escalated: AuthorizedAction = {
      ...v.action,
      action: { ...v.action.action, op: 'windows.proc.exec', requiredPrivilege: 'ELEVATED' },
    };
    expect(await backend.execute(escalated)).toEqual({ ok: false, code: 'FILE_MUTATION_REFUSED' });
    const widened: AuthorizedAction = {
      ...v.action,
      action: {
        ...v.action.action,
        filesystemScope: { read: ['C:\\approved\\src'], write: ['C:\\elsewhere'] },
      },
    };
    expect(await backend.execute(widened)).toEqual({ ok: false, code: 'FILE_MUTATION_REFUSED' });
    expect(dispatches).toBe(0);
  });

  it('never replays an interrupted effect: executor failure leaves UNCERTAIN, second attempt refused', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    let dispatches = 0;
    const backend = new SqliteFileMutationAuthorizationBoundary({
      store: v.store,
      controller: v.controller,
      loadPlanByHash: async () => v.plan,
      // Simulates a crash mid-effect: the trusted IO started and threw.
      executeFileMutation: async () => {
        dispatches++;
        throw new Error('EFFECT_INTERRUPTED');
      },
    });
    expect(await backend.execute(v.action)).toEqual({ ok: false, code: 'FILE_MUTATION_REFUSED' });
    expect(dispatches).toBe(1);
    expect(journal.lookup(v.action)).toMatchObject({ ok: true, state: 'UNCERTAIN' });
    // The replay attempt never dispatches and surfaces reconcile-first.
    expect(await backend.execute(v.action)).toEqual({
      ok: false,
      code: 'FILE_MUTATION_RECONCILE_REQUIRED',
    });
    expect(dispatches).toBe(1);
  });

  it('refuses an invalid or unverified executor receipt and journals UNCERTAIN', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    const backend = new SqliteFileMutationAuthorizationBoundary({
      store: v.store,
      controller: v.controller,
      loadPlanByHash: async () => v.plan,
      executeFileMutation: async (action) => ({
        ok: true,
        receipt: { ...validReceipt(action.actionId), terminal: 'FAILED' },
      }),
    });
    expect(await backend.execute(v.action)).toEqual({ ok: false, code: 'FILE_MUTATION_REFUSED' });
    expect(journal.lookup(v.action)).toMatchObject({ ok: true, state: 'UNCERTAIN' });
  });

  it('refuses one attempt identity forever even after a full verified success', async () => {
    const v = await world();
    let dispatches = 0;
    const backend = new SqliteFileMutationAuthorizationBoundary({
      store: v.store,
      controller: v.controller,
      loadPlanByHash: async () => v.plan,
      executeFileMutation: async (action) => {
        dispatches++;
        return { ok: true, receipt: validReceipt(action.actionId) };
      },
    });
    expect((await backend.execute(v.action)).ok).toBe(true);
    expect(await backend.execute(v.action)).toEqual({
      ok: false,
      code: 'FILE_MUTATION_RECONCILE_REQUIRED',
    });
    expect(dispatches).toBe(1);
  });

  it('fails closed on structural fakes instead of a true controller/store', async () => {
    const v = await world();
    expect(
      () =>
        new SqliteFileMutationAuthorizationBoundary({
          store: v.store,
          controller: {} as ActionController,
          loadPlanByHash: async () => v.plan,
          executeFileMutation: async () => null,
        }),
    ).toThrow('FILE_MUTATION_BOUNDARY_CONFIGURATION_REFUSED');
  });
});

describe.skipIf(process.platform !== 'win32')(
  'T07 F03 real end-to-end: REAL boundary + REAL anchored vertical-files executor',
  () => {
    it('performs one authorized physical copy with verified post-state, then refuses replay', async () => {
      const folder = mkdtempSync(join(tmpdir(), 'shun-f03-e2e-'));
      mkdirSync(join(folder, 'src'));
      mkdirSync(join(folder, 'dst'));
      writeFileSync(join(folder, 'src', 'a.txt'), 'F03-E2E-CONTENT');
      const file = join(folder, 'e2e.sqlite');
      const store = new ShunStore({ file });
      dispose.push(async () => {
        await store.close();
        rmSync(folder, { recursive: true, force: true });
      });
      const adapter = new ShunStoreAuthorizationAdapter(store);
      const clock = () => new Date().toISOString();
      await adapter.saveAuthorityRecord({
        authorityId: 'auth-1',
        authorityRevision: 'rev-1',
        updatedAt: fixedNow,
        policyInitialized: true,
      });
      const sourceDir = join(folder, 'src');
      const destDir = join(folder, 'dst');
      await adapter.savePolicySnapshot({
        policySnapshotRevision: 'policy-1',
        status: 'ACTIVE',
        authorityId: 'auth-1',
        authorityRevision: 'rev-1',
        revokedGrantIds: [],
        rules: [
          {
            ruleId: 'allow-f03-e2e',
            capabilityId: 'file.copy',
            op: 'file.copy',
            maxRiskClass: 'R2',
            privilegeLevel: 'USER',
            filesystem: { read: [sourceDir], write: [destDir] },
          },
        ],
        riskGuards: [],
        updatedAt: fixedNow,
      });
      const authority = new AuthorizationAuthority({
        state: adapter,
        grants: adapter,
        integritySecret: 'private-test-integrity',
        issuanceSecret: 'private-test-issuance',
        clock,
      });
      const controller = new ActionController({
        authority,
        policyState: adapter,
        approvals: {
          requestApproval: async () => {
            throw new Error('approval cannot be reached');
          },
        },
        issuanceSecret: 'private-test-issuance',
        clock,
      });
      const sourcePath = join(sourceDir, 'a.txt');
      const destinationPath = join(destDir, 'b.txt');
      const plan = mutationPlan();
      const oneAction = plan.actions[0];
      if (!oneAction) throw new Error('fixture plan has no action');
      oneAction.parameters = { sourcePath, destinationPath };
      oneAction.filesystemScope = { read: [sourceDir], write: [destDir] };
      plan.planHash = computePlanHash(plan);
      const authorized = await controller.authorizePlan({ plan });
      if (!authorized.ok) throw new Error(`e2e authorization failed: ${authorized.code}`);
      const action = authorized.authorization.actions[0];
      if (!action) throw new Error('fixture has no authorized action');
      const backend = new SqliteFileMutationAuthorizationBoundary({
        store,
        controller,
        loadPlanByHash: async () => plan,
        executeFileMutation: async (authorizedAction) =>
          executeAuthorizedFileMutation(authorizedAction),
      });
      const result = await backend.execute(action);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.receipt.sideEffectEvidence.recoveryClassification).toBe('COMPLETED_VERIFIED');
        expect(result.receipt.sideEffectEvidence.postStateVerified).toBe(true);
      }
      expect(readFileSync(destinationPath, 'utf8')).toBe('F03-E2E-CONTENT');
      expect(readFileSync(sourcePath, 'utf8')).toBe('F03-E2E-CONTENT');
      const journal = new SqliteFileMutationJournal(store);
      expect(journal.lookup(action)).toMatchObject({ ok: true, state: 'COMMITTED_VERIFIED' });
      // Replay of the same attempt identity: refused, file state untouched.
      expect(await backend.execute(action)).toEqual({
        ok: false,
        code: 'FILE_MUTATION_RECONCILE_REQUIRED',
      });
      console.log('F03_E2E_REAL_BOUNDARY_REAL_EXECUTOR_COPY=PASS REPLAY_REFUSED');
    });

    it('routes a physical collision through the full gate to UNCERTAIN, never overwriting', async () => {
      const folder = mkdtempSync(join(tmpdir(), 'shun-f03-e2ec-'));
      mkdirSync(join(folder, 'src'));
      mkdirSync(join(folder, 'dst'));
      writeFileSync(join(folder, 'src', 'a.txt'), 'SOURCE');
      writeFileSync(join(folder, 'dst', 'b.txt'), 'PRE-EXISTING');
      const file = join(folder, 'e2e.sqlite');
      const store = new ShunStore({ file });
      dispose.push(async () => {
        await store.close();
        rmSync(folder, { recursive: true, force: true });
      });
      const adapter = new ShunStoreAuthorizationAdapter(store);
      const clock = () => new Date().toISOString();
      await adapter.saveAuthorityRecord({
        authorityId: 'auth-1',
        authorityRevision: 'rev-1',
        updatedAt: fixedNow,
        policyInitialized: true,
      });
      const sourceDir = join(folder, 'src');
      const destDir = join(folder, 'dst');
      await adapter.savePolicySnapshot({
        policySnapshotRevision: 'policy-1',
        status: 'ACTIVE',
        authorityId: 'auth-1',
        authorityRevision: 'rev-1',
        revokedGrantIds: [],
        rules: [
          {
            ruleId: 'allow-f03-e2ec',
            capabilityId: 'file.copy',
            op: 'file.copy',
            maxRiskClass: 'R2',
            privilegeLevel: 'USER',
            filesystem: { read: [sourceDir], write: [destDir] },
          },
        ],
        riskGuards: [],
        updatedAt: fixedNow,
      });
      const authority = new AuthorizationAuthority({
        state: adapter,
        grants: adapter,
        integritySecret: 'private-test-integrity',
        issuanceSecret: 'private-test-issuance',
        clock,
      });
      const controller = new ActionController({
        authority,
        policyState: adapter,
        approvals: {
          requestApproval: async () => {
            throw new Error('approval cannot be reached');
          },
        },
        issuanceSecret: 'private-test-issuance',
        clock,
      });
      const sourcePath = join(sourceDir, 'a.txt');
      const destinationPath = join(destDir, 'b.txt');
      const plan = mutationPlan();
      const oneAction = plan.actions[0];
      if (!oneAction) throw new Error('fixture plan has no action');
      oneAction.parameters = { sourcePath, destinationPath };
      oneAction.filesystemScope = { read: [sourceDir], write: [destDir] };
      plan.planHash = computePlanHash(plan);
      const authorized = await controller.authorizePlan({ plan });
      if (!authorized.ok) throw new Error(`e2e authorization failed: ${authorized.code}`);
      const action = authorized.authorization.actions[0];
      if (!action) throw new Error('fixture has no authorized action');
      const backend = new SqliteFileMutationAuthorizationBoundary({
        store,
        controller,
        loadPlanByHash: async () => plan,
        executeFileMutation: async (authorizedAction) =>
          executeAuthorizedFileMutation(authorizedAction),
      });
      expect(await backend.execute(action)).toEqual({ ok: false, code: 'FILE_MUTATION_REFUSED' });
      // Byte-identical no-overwrite proof through the FULL authorized path.
      expect(readFileSync(destinationPath, 'utf8')).toBe('PRE-EXISTING');
      expect(readFileSync(sourcePath, 'utf8')).toBe('SOURCE');
      const journal = new SqliteFileMutationJournal(store);
      expect(journal.lookup(action)).toMatchObject({ ok: true, state: 'UNCERTAIN' });
      expect(await backend.execute(action)).toEqual({
        ok: false,
        code: 'FILE_MUTATION_RECONCILE_REQUIRED',
      });
      console.log('F03_E2E_COLLISION_NO_OVERWRITE_UNCERTAIN_NO_REPLAY=PASS');
    });
  },
);
