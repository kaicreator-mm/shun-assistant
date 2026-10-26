// T07 F04B2 falsifiers: the durable write-once pre-effect commitment
// (F04B2a), the boundary wiring that hands journal-backed checkpoints to
// the trusted mutation capability, and the trusted reconcile glue (F04B2c).
// The commitment must be persisted BEFORE the first destination IO and only
// while the row is STARTED for the same intent; the reconciler must join
// journal + precommit + a trusted OS verifier into an atomic idempotent
// disposition, NEVER rewrite the STARTED/UNCERTAIN row, and NEVER authorize
// a retry. Reconciler glue tests on non-Windows use an injected verifier
// DOUBLE to exercise the join logic only — real OS poststate proof is the
// vertical-files Windows suite plus the final Windows describe here, which
// composes the REAL boundary, REAL journal, REAL anchored executor and REAL
// poststate verifier, including a STARTED-crash simulation.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import { type ActionPlan, type AuthorizedAction, computePlanHash } from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import { afterEach, describe, expect, it } from 'vitest';
import {
  executeVerifiedFileMutation,
  type FileMutationInstrument,
} from '../../vertical-files/src/file-mutation-host.ts';
import { observeFileMutationPoststate } from '../../vertical-files/src/file-mutation-poststate.ts';
import {
  SqliteFileMutationAuthorizationBoundary,
  SqliteFileMutationReconciler,
} from '../src/sqlite-file-mutation-host.ts';
import { SqliteFileMutationJournal } from '../src/sqlite-file-mutation-journal.ts';

const fixedNow = '2026-10-26T04:00:00.000Z';

const dispose: Array<() => Promise<void> | void> = [];
afterEach(() => {
  for (const fn of dispose.splice(0).reverse()) fn();
});

/** A structurally valid commitment bound to one action's exact intent. */
function commitmentFor(
  action: AuthorizedAction,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const parameters = action.action.parameters as Record<string, unknown>;
  return {
    kind: 'file-mutation-precommit-v1',
    actionId: action.actionId,
    op: action.action.op,
    sourcePath: parameters.sourcePath,
    destinationPath: parameters.destinationPath,
    source: { fileId: '123456789', volumeSerial: 1918219760, size: 3, sha256: 'c'.repeat(64) },
    destinationPrestate: { destinationExisted: false },
    ...overrides,
  };
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

/** Full authorization world around ONE mutation intent (real store,
 * controller, issued grant). Paths default to the literal fixed-drive
 * fixtures; a caller-supplied store is used as the single source of truth
 * (grants live where the boundary reads them). */
async function world(
  options: { store?: ShunStore; sourcePath?: string; destinationPath?: string; op?: string } = {},
) {
  const sourcePath = options.sourcePath ?? 'C:\\approved\\src\\a.txt';
  const destinationPath = options.destinationPath ?? 'C:\\approved\\dst\\b.txt';
  const op = options.op ?? 'file.copy';
  let folder: string | null = null;
  let file = '';
  let store = options.store;
  if (store === undefined) {
    folder = mkdtempSync(join(tmpdir(), 'shun-f04b2-gate-'));
    file = join(folder, 'gate.sqlite');
    store = new ShunStore({ file });
    const owned = store;
    dispose.push(async () => {
      await owned.close();
      if (folder !== null) rmSync(folder, { recursive: true, force: true });
    });
  }
  const adapter = new ShunStoreAuthorizationAdapter(store);
  const clock = () => fixedNow;
  await adapter.saveAuthorityRecord({
    authorityId: 'auth-1',
    authorityRevision: 'rev-1',
    updatedAt: fixedNow,
    policyInitialized: true,
  });
  const sourceDir = sourcePath.slice(0, sourcePath.lastIndexOf('\\'));
  const destDir = destinationPath.slice(0, destinationPath.lastIndexOf('\\'));
  const write =
    op === 'file.copy'
      ? [destDir]
      : [...new Set([sourceDir, destDir].map((d) => d.toLowerCase()))].sort();
  const plan: ActionPlan = {
    taskId: 'task-f04b2',
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
        parameters: { sourcePath, destinationPath },
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
  await adapter.savePolicySnapshot({
    policySnapshotRevision: 'policy-1',
    status: 'ACTIVE',
    authorityId: 'auth-1',
    authorityRevision: 'rev-1',
    revokedGrantIds: [],
    rules: [
      {
        ruleId: 'allow-f04b2-mutation',
        capabilityId: op,
        op,
        maxRiskClass: 'R2',
        privilegeLevel: 'USER',
        filesystem: { read: [sourceDir], write },
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
  return { store, file, controller, plan, action };
}

// ---------------------------------------------------------------------------
// F04B2a journal: durable write-once precommitment.
// ---------------------------------------------------------------------------

describe('T07 F04B2a journal precommitment (write-once CAS + durable readback)', () => {
  it('refuses a precommit without a STARTED row for the same intent', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    expect(journal.writePrecommit(v.action, commitmentFor(v.action))).toEqual({
      ok: false,
      code: 'PRECOMMIT_REFUSED',
    });
    // No journal row exists at all: the intent was never attempted.
    expect(journal.readPrecommit(v.action)).toEqual({ ok: false, code: 'JOURNAL_REFUSED' });
    // A STARTED row without a commitment (crash before the checkpoint).
    journal.reserve(v.action);
    expect(journal.readPrecommit(v.action)).toEqual({ ok: false, code: 'NOT_FOUND' });
  });

  it('persists the commitment while STARTED, survives a reopen, and is idempotent', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    expect(journal.reserve(v.action)).toEqual({ ok: true, state: 'DURABLY_RESERVED' });
    const commitment = commitmentFor(v.action);
    expect(journal.writePrecommit(v.action, commitment)).toEqual({
      ok: true,
      state: 'DURABLY_PRECOMMITTED',
    });
    const back = journal.readPrecommit(v.action);
    expect(back.ok).toBe(true);
    if (back.ok) {
      expect(back.commitment).toEqual(commitment);
      expect(back.commitmentSha256).toMatch(/^[a-f0-9]{64}$/);
    }
    // Identical re-write: idempotent.
    expect(journal.writePrecommit(v.action, commitmentFor(v.action))).toEqual({
      ok: true,
      state: 'DURABLY_PRECOMMITTED',
    });
    // Divergent payload for the same identity: refused forever.
    const divergent = commitmentFor(v.action, {
      source: { fileId: '123456789', volumeSerial: 1918219761, size: 3, sha256: 'c'.repeat(64) },
    });
    expect(journal.writePrecommit(v.action, divergent)).toEqual({
      ok: false,
      code: 'PRECOMMIT_DIVERGENT',
    });
    // The commitment outlives a full store close/reopen (durability).
    await v.store.close();
    const reopened = new ShunStore({ file: v.file });
    dispose.push(async () => {
      await reopened.close();
    });
    const journal2 = new SqliteFileMutationJournal(reopened);
    const back2 = journal2.readPrecommit(v.action);
    expect(back2.ok).toBe(true);
    if (back2.ok) expect(back2.commitment).toEqual(commitment);
    // And the STARTED row still refuses every replay.
    expect(journal2.reserve(v.action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });
  });

  it('refuses commitments not bound to the exact action intent', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    journal.reserve(v.action);
    const bad: unknown[] = [
      null,
      42,
      'commitment',
      commitmentFor(v.action, { kind: 'file-mutation-precommit-v2' }),
      commitmentFor(v.action, { actionId: 'other-action' }),
      commitmentFor(v.action, { op: 'file.move' }),
      commitmentFor(v.action, { sourcePath: 'C:\\elsewhere\\a.txt' }),
      commitmentFor(v.action, { destinationPath: 'C:\\elsewhere\\b.txt' }),
      commitmentFor(v.action, {
        source: { fileId: '12x456789', volumeSerial: 1, size: 3, sha256: 'c'.repeat(64) },
      }),
      commitmentFor(v.action, {
        source: {
          fileId: '123456789',
          volumeSerial: 1,
          size: (8 << 20) + 1,
          sha256: 'c'.repeat(64),
        },
      }),
      commitmentFor(v.action, { destinationPrestate: { destinationExisted: true } }),
      { ...commitmentFor(v.action), extra: 1 },
    ];
    for (const malformed of bad) {
      expect(journal.writePrecommit(v.action, malformed)).toEqual({
        ok: false,
        code: 'PRECOMMIT_REFUSED',
      });
    }
  });

  it('refuses a precommit after the row left STARTED, and a tampered readback refuses', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    journal.reserve(v.action);
    journal.recordOutcome(v.action, 'COMMITTED_VERIFIED', 'd'.repeat(64));
    expect(journal.writePrecommit(v.action, commitmentFor(v.action))).toEqual({
      ok: false,
      code: 'PRECOMMIT_REFUSED',
    });
    const w = await world();
    const journal2 = new SqliteFileMutationJournal(w.store);
    journal2.reserve(w.action);
    journal2.writePrecommit(w.action, commitmentFor(w.action));
    // A tampered stored payload (hash no longer matches the bytes) refuses
    // on read instead of being served as durable fact.
    w.store.database
      .prepare(
        `UPDATE recipe_file_mutation_precommit_v02 SET commitment_json='{"kind":"tampered"}'`,
      )
      .run();
    expect(journal2.readPrecommit(w.action)).toEqual({ ok: false, code: 'JOURNAL_REFUSED' });
  });
});

// ---------------------------------------------------------------------------
// F04B2a boundary wiring: journal-backed checkpoints handed to the trusted
// mutation capability.
// ---------------------------------------------------------------------------

describe('T07 F04B2a boundary hands journal-backed durable checkpoints to the effect', () => {
  it('durable checkpoint runs while STARTED and before a verified receipt is accepted', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    let dispatches = 0;
    let stateBeforeCheckpoint: string | null = null;
    let precommitReadableAtEffect = false;
    const backend = new SqliteFileMutationAuthorizationBoundary({
      store: v.store,
      controller: v.controller,
      loadPlanByHash: async () => v.plan,
      executeFileMutation: async (action, checkpoints) => {
        dispatches++;
        const row = journal.lookup(action);
        stateBeforeCheckpoint = row.ok ? row.state : null;
        const wrote = checkpoints.durablePrecommit(commitmentFor(action));
        precommitReadableAtEffect = wrote && journal.readPrecommit(action).ok === true;
        return wrote ? { ok: true, receipt: validReceipt(action.actionId) } : null;
      },
    });
    const result = await backend.execute(v.action);
    expect(result.ok).toBe(true);
    expect(dispatches).toBe(1);
    // THE ordering proof: the durable row was STARTED when the checkpoint
    // ran, the commitment was durably readable before the receipt existed,
    // and the terminal state is COMMITTED_VERIFIED with the commitment intact.
    expect(stateBeforeCheckpoint).toBe('STARTED');
    expect(precommitReadableAtEffect).toBe(true);
    expect(journal.lookup(v.action)).toMatchObject({ ok: true, state: 'COMMITTED_VERIFIED' });
    expect(journal.readPrecommit(v.action).ok).toBe(true);
    console.log('F04B2A_BOUNDARY_PRECOMMIT_BEFORE_RECEIPT=PASS');
  });

  it('a refused durable checkpoint routes the attempt to UNCERTAIN without a receipt', async () => {
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    const backend = new SqliteFileMutationAuthorizationBoundary({
      store: v.store,
      controller: v.controller,
      loadPlanByHash: async () => v.plan,
      // The trusted capability offers a MALFORMED commitment (exactly what
      // a compromised or buggy injector would do): the journal refuses the
      // durable write, the effect reports no receipt, and the attempt is
      // conservatively UNCERTAIN — never silently retried.
      executeFileMutation: async (_action, checkpoints) =>
        checkpoints.durablePrecommit({ kind: 'not-a-commitment' })
          ? { ok: true, receipt: validReceipt('mut-1') }
          : null,
    });
    expect(await backend.execute(v.action)).toMatchObject({ ok: false });
    expect(journal.lookup(v.action)).toMatchObject({ ok: true, state: 'UNCERTAIN' });
    expect(await backend.execute(v.action)).toEqual({
      ok: false,
      code: 'FILE_MUTATION_RECONCILE_REQUIRED',
    });
  });

  it('keeps the F03-era un-checkpointed injected capability admissible (compat)', async () => {
    // An injected capability that IGNORES the checkpoints (legacy F03 test
    // composition) still completes: the checkpoints are the trusted host's
    // composition contract, not a caller callback gate. Documented for the
    // reviewer; the trusted bootstrap must always consume them (proven
    // physically in the Windows describe below).
    const v = await world();
    const journal = new SqliteFileMutationJournal(v.store);
    const backend = new SqliteFileMutationAuthorizationBoundary({
      store: v.store,
      controller: v.controller,
      loadPlanByHash: async () => v.plan,
      executeFileMutation: async () => ({ ok: true, receipt: validReceipt('mut-1') }),
    });
    expect((await backend.execute(v.action)).ok).toBe(true);
    expect(journal.readPrecommit(v.action)).toEqual({ ok: false, code: 'NOT_FOUND' });
  });
});

// ---------------------------------------------------------------------------
// F04B2c trusted reconcile glue. Non-Windows runs use an injected verifier
// DOUBLE (join-logic coverage only); physical OS proof is Windows-only.
// ---------------------------------------------------------------------------

describe('T07 F04B2c reconciler joins journal + precommit + trusted verifier', () => {
  function doubleVerifier(verdict: string) {
    let next: unknown = { ok: true, verdict, evidence: { observed: true } };
    return {
      set: (value: unknown) => {
        next = value;
      },
      fn: () => next,
    };
  }

  async function interrupted(v: Awaited<ReturnType<typeof world>>) {
    const journal = new SqliteFileMutationJournal(v.store);
    journal.reserve(v.action);
    journal.writePrecommit(v.action, commitmentFor(v.action));
    return journal;
  }

  it('persists an atomic idempotent disposition and NEVER touches the row state or replay ban', async () => {
    const v = await world();
    const journal = await interrupted(v);
    const verifier = doubleVerifier('PROVEN_COMPLETED');
    const reconciler = new SqliteFileMutationReconciler({
      store: v.store,
      verifyPoststate: verifier.fn,
    });
    const first = await reconciler.reconcile(v.action);
    expect(first.ok).toBe(true);
    if (first.ok) {
      expect(first.disposition).toBe('COMPLETED_PROVEN');
      expect(first.automaticRetryAllowed).toBe(false);
      expect(first.evidenceSha256).toMatch(/^[a-f0-9]{64}$/);
    }
    // The journal row is STILL the interrupted STARTED fact — a disposition
    // is an analysis record, never a state rewrite.
    expect(journal.lookup(v.action)).toMatchObject({ ok: true, state: 'STARTED' });
    expect(journal.readReconcileDisposition(v.action)).toMatchObject({
      ok: true,
      disposition: 'COMPLETED_PROVEN',
      automaticRetryAllowed: false,
    });
    // Idempotent: the same verdict reconciles to the same record...
    expect(await reconciler.reconcile(v.action)).toEqual(first);
    // ...and a CHANGED world (divergent verdict) can never rewrite it.
    verifier.set({ ok: true, verdict: 'UNKNOWN', evidence: { observed: false } });
    expect(await reconciler.reconcile(v.action)).toEqual({ ok: false, code: 'RECONCILE_REFUSED' });
    // Replay of the attempt identity stays refused regardless.
    expect(journal.reserve(v.action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });
    console.log('F04B2C_DISPOSITION_ATOMIC_IDEMPOTENT_ROW_UNTOUCHED=PASS');
  });

  it('maps every verdict conservatively: UNKNOWN becomes MANUAL_RECONCILE_REQUIRED', async () => {
    const cases: ReadonlyArray<[string, string]> = [
      ['PROVEN_COMPLETED', 'COMPLETED_PROVEN'],
      ['CONSISTENT_WITH_COMPLETION', 'COMPLETED_CONSISTENT'],
      ['PROVEN_NOT_EXECUTED', 'NOT_EXECUTED_PROVEN'],
      ['CONSISTENT_WITH_NOT_EXECUTED', 'NOT_EXECUTED_CONSISTENT'],
      ['UNKNOWN', 'MANUAL_RECONCILE_REQUIRED'],
    ];
    for (const [verdict, disposition] of cases) {
      const v = await world();
      await interrupted(v);
      const reconciler = new SqliteFileMutationReconciler({
        store: v.store,
        verifyPoststate: () => ({ ok: true, verdict, evidence: { observed: true } }),
      });
      expect(await reconciler.reconcile(v.action)).toMatchObject({
        ok: true,
        disposition,
        automaticRetryAllowed: false,
      });
    }
  });

  it('an unobservable world persists NOTHING and stays retryable', async () => {
    const v = await world();
    await interrupted(v);
    const verifier = doubleVerifier('PROVEN_COMPLETED');
    verifier.set({ ok: false, code: 'POSTSTATE_DRIVE_REFUSED' });
    const reconciler = new SqliteFileMutationReconciler({
      store: v.store,
      verifyPoststate: verifier.fn,
    });
    expect(await reconciler.reconcile(v.action)).toEqual({ ok: false, code: 'RECONCILE_REFUSED' });
    const journal = new SqliteFileMutationJournal(v.store);
    expect(journal.readReconcileDisposition(v.action)).toEqual({ ok: false, code: 'NOT_FOUND' });
    // Later, the world becomes observable: the same reconcile succeeds.
    verifier.set({ ok: true, verdict: 'UNKNOWN', evidence: { observed: false } });
    expect(await reconciler.reconcile(v.action)).toMatchObject({
      ok: true,
      disposition: 'MANUAL_RECONCILE_REQUIRED',
    });
  });

  it('refuses malformed verifier output instead of minting any disposition', async () => {
    const v = await world();
    await interrupted(v);
    for (const garbage of [
      null,
      42,
      'PASS',
      [],
      new Proxy({ ok: true, verdict: 'PROVEN_COMPLETED', evidence: {} }, {}),
      { ok: true, verdict: 'DEFINITELY_DONE', evidence: {} },
      { ok: true, verdict: 'PROVEN_COMPLETED' },
      { ok: true, verdict: 'PROVEN_COMPLETED', evidence: {}, extra: 1 },
    ]) {
      const reconciler = new SqliteFileMutationReconciler({
        store: v.store,
        verifyPoststate: () => garbage,
      });
      expect(await reconciler.reconcile(v.action)).toEqual({
        ok: false,
        code: 'RECONCILE_REFUSED',
      });
    }
    const journal = new SqliteFileMutationJournal(v.store);
    expect(journal.readReconcileDisposition(v.action)).toEqual({ ok: false, code: 'NOT_FOUND' });
  });

  it('refuses nothing-to-reconcile and forged-identity cases with zero persistence', async () => {
    // COMMITTED_VERIFIED row: already terminal.
    const done = await world();
    const journalDone = new SqliteFileMutationJournal(done.store);
    journalDone.reserve(done.action);
    journalDone.writePrecommit(done.action, commitmentFor(done.action));
    journalDone.recordOutcome(done.action, 'COMMITTED_VERIFIED', 'e'.repeat(64));
    const reconcilerDone = new SqliteFileMutationReconciler({
      store: done.store,
      verifyPoststate: () => ({ ok: true, verdict: 'PROVEN_COMPLETED', evidence: {} }),
    });
    expect(await reconcilerDone.reconcile(done.action)).toEqual({
      ok: false,
      code: 'RECONCILE_REFUSED',
    });

    // STARTED without a precommit (crash before the checkpoint): nothing to
    // reconcile against — honest refusal, manual path.
    const bare = await world();
    const journalBare = new SqliteFileMutationJournal(bare.store);
    journalBare.reserve(bare.action);
    const reconcilerBare = new SqliteFileMutationReconciler({
      store: bare.store,
      verifyPoststate: () => ({ ok: true, verdict: 'PROVEN_COMPLETED', evidence: {} }),
    });
    expect(await reconcilerBare.reconcile(bare.action)).toEqual({
      ok: false,
      code: 'RECONCILE_REFUSED',
    });

    // Forged presentation: a DIFFERENT intent for the same identity cannot
    // even read the journal facts.
    const v = await world();
    await interrupted(v);
    const forged: AuthorizedAction = {
      ...v.action,
      action: {
        ...v.action.action,
        parameters: {
          sourcePath: 'C:\\approved\\src\\a.txt',
          destinationPath: 'C:\\approved\\dst\\EVIL.txt',
        },
      },
    };
    const reconciler = new SqliteFileMutationReconciler({
      store: v.store,
      verifyPoststate: () => ({ ok: true, verdict: 'PROVEN_COMPLETED', evidence: {} }),
    });
    expect(await reconciler.reconcile(forged)).toEqual({ ok: false, code: 'RECONCILE_REFUSED' });
  });

  it('fails closed on a structurally fake configuration', async () => {
    const v = await world();
    expect(
      () =>
        new SqliteFileMutationReconciler({
          store: {} as ShunStore,
          verifyPoststate: () => null,
        }),
    ).toThrow('FILE_MUTATION_RECONCILER_CONFIGURATION_REFUSED');
    expect(
      () => new SqliteFileMutationReconciler({ store: v.store, verifyPoststate: 'nope' as never }),
    ).toThrow('FILE_MUTATION_RECONCILER_CONFIGURATION_REFUSED');
  });
});

// ---------------------------------------------------------------------------
// Windows-only real composition: REAL boundary + REAL journal + REAL
// anchored executor + REAL independent poststate verifier.
// ---------------------------------------------------------------------------

describe.skipIf(process.platform !== 'win32')(
  'T07 F04B2 real end-to-end (Windows Standard User, real Win32 handles)',
  () => {
    /** One temp folder with src/dst fixtures and a dedicated durable store. */
    function physicalWorld(content: string) {
      const folder = mkdtempSync(join(tmpdir(), 'shun-f04b2-e2e-'));
      mkdirSync(join(folder, 'src'));
      mkdirSync(join(folder, 'dst'));
      writeFileSync(join(folder, 'src', 'a.txt'), content);
      const store = new ShunStore({ file: join(folder, 'e2e.sqlite') });
      dispose.push(async () => {
        await store.close();
        rmSync(folder, { recursive: true, force: true });
      });
      return {
        folder,
        store,
        sourcePath: join(folder, 'src', 'a.txt'),
        destinationPath: join(folder, 'dst', 'b.txt'),
      };
    }

    it('runs a checkpointed authorized copy with the commitment durable before destination IO', async () => {
      const stage = physicalWorld('F04B2-E2E-CONTENT');
      const v = await world({
        store: stage.store,
        sourcePath: stage.sourcePath,
        destinationPath: stage.destinationPath,
      });
      const journal = new SqliteFileMutationJournal(stage.store);
      let precommitReadableAtDestCreate = false;
      const instrument: FileMutationInstrument = {
        onDestCreate: () => {
          precommitReadableAtDestCreate = journal.readPrecommit(v.action).ok === true;
        },
      };
      const backend = new SqliteFileMutationAuthorizationBoundary({
        store: stage.store,
        controller: v.controller,
        loadPlanByHash: async () => v.plan,
        executeFileMutation: async (action, checkpoints) => {
          const parameters = action.action.parameters as Record<string, unknown>;
          return executeVerifiedFileMutation(
            {
              op: action.action.op,
              sourcePath: parameters.sourcePath,
              destinationPath: parameters.destinationPath,
            },
            action.actionId,
            instrument,
            checkpoints,
          );
        },
      });
      const result = await backend.execute(v.action);
      expect(result.ok).toBe(true);
      // THE physical ordering proof at the real composition: when the first
      // destination IO happened, the immutable commitment was already
      // durably readable on the same store.
      expect(precommitReadableAtDestCreate).toBe(true);
      expect(readFileSync(stage.destinationPath, 'utf8')).toBe('F04B2-E2E-CONTENT');
      expect(journal.lookup(v.action)).toMatchObject({ ok: true, state: 'COMMITTED_VERIFIED' });
      const commitment = journal.readPrecommit(v.action);
      expect(commitment.ok).toBe(true);
      if (commitment.ok) {
        const payload = commitment.commitment as Record<string, unknown>;
        expect(payload.sourcePath).toBe(stage.sourcePath);
        expect((payload.source as Record<string, unknown>).size).toBe('F04B2-E2E-CONTENT'.length);
      }
      // Replay of the attempt identity stays refused.
      expect(await backend.execute(v.action)).toEqual({
        ok: false,
        code: 'FILE_MUTATION_RECONCILE_REQUIRED',
      });
      console.log('F04B2_E2E_PRECOMMIT_DURABLE_BEFORE_DEST_IO=PASS REPLAY_REFUSED');
    });

    it('reconciles a hard-crash STARTED move to COMPLETED_PROVEN without touching the row', async () => {
      // Crash simulation WITHOUT a process kill (the true kill matrix is
      // F04B3): the STARTED row and the durable commitment exist, the
      // physical relocation then runs OUTSIDE the boundary (exactly what a
      // process would leave behind after dying between the effect and the
      // journal COMMIT), and the reconciler must prove completion from OS
      // evidence alone while the row stays STARTED and unreplayable.
      const stage = physicalWorld('F04B2-RECONCILE-MOVE');
      const destination = join(stage.folder, 'dst', 'moved.txt');
      const v = await world({
        store: stage.store,
        sourcePath: stage.sourcePath,
        destinationPath: destination,
        op: 'file.move',
      });
      const journal = new SqliteFileMutationJournal(stage.store);
      journal.reserve(v.action);
      let checkpointed = false;
      const effect = executeVerifiedFileMutation(
        { op: 'file.move', sourcePath: stage.sourcePath, destinationPath: destination },
        v.action.actionId,
        {},
        {
          durablePrecommit: (commitment) => {
            const wrote = journal.writePrecommit(v.action, commitment);
            checkpointed = wrote.ok;
            return wrote.ok;
          },
        },
      );
      expect(effect.ok).toBe(true);
      expect(checkpointed).toBe(true);
      // The world after the "crash": row STARTED + durable commitment.
      expect(journal.lookup(v.action)).toMatchObject({ ok: true, state: 'STARTED' });
      expect(journal.readPrecommit(v.action).ok).toBe(true);
      // The trusted reconciler joins the REAL poststate verifier.
      const reconciler = new SqliteFileMutationReconciler({
        store: stage.store,
        verifyPoststate: (precommit) => observeFileMutationPoststate(precommit),
      });
      expect(await reconciler.reconcile(v.action)).toMatchObject({
        ok: true,
        disposition: 'COMPLETED_PROVEN',
        automaticRetryAllowed: false,
      });
      // Row STILL STARTED; disposition persisted; replay STILL refused.
      expect(journal.lookup(v.action)).toMatchObject({ ok: true, state: 'STARTED' });
      expect(journal.readReconcileDisposition(v.action)).toMatchObject({
        ok: true,
        disposition: 'COMPLETED_PROVEN',
      });
      expect(journal.reserve(v.action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });
      console.log('F04B2_E2E_CRASH_SIM_STARTED_RECONCILE_PROVEN_NO_REPLAY=PASS');
    });

    it('reconciles an interrupted copy (checkpoint written, effect refused) to NOT_EXECUTED_CONSISTENT', async () => {
      const stage = physicalWorld('F04B2-RECONCILE-COPY');
      const v = await world({
        store: stage.store,
        sourcePath: stage.sourcePath,
        destinationPath: stage.destinationPath,
      });
      const journal = new SqliteFileMutationJournal(stage.store);
      journal.reserve(v.action);
      // The checkpoint is durably written and then the effect dies before
      // any destination IO: exactly the post-checkpoint interruption window.
      const effect = executeVerifiedFileMutation(
        { op: 'file.copy', sourcePath: stage.sourcePath, destinationPath: stage.destinationPath },
        v.action.actionId,
        {},
        {
          durablePrecommit: (commitment) =>
            journal.writePrecommit(v.action, commitment).ok === true && false,
        },
      );
      expect(effect).toEqual({ ok: false, code: 'FILE_MUTATION_EFFECT_REFUSED' });
      expect(journal.lookup(v.action)).toMatchObject({ ok: true, state: 'STARTED' });
      const reconciler = new SqliteFileMutationReconciler({
        store: stage.store,
        verifyPoststate: (precommit) => observeFileMutationPoststate(precommit),
      });
      expect(await reconciler.reconcile(v.action)).toMatchObject({
        ok: true,
        disposition: 'NOT_EXECUTED_CONSISTENT',
        automaticRetryAllowed: false,
      });
      console.log('F04B2_E2E_INTERRUPTED_COPY_RECONCILE_CONSISTENT_NOT_EXECUTED=PASS');
    });
  },
);
