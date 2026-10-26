// T07 F04B3b: REAL Windows process-termination matrix at the four effect
// phases of ONE authorized file mutation. F04B3a (PR #187) proves P0 — a
// kill after the durable STARTED reservation but before any effect. This
// suite kills a REAL separate Node24 OS process INSIDE the trusted
// composition at every subsequent phase of the REAL physical pipeline:
//   P1 after the durable pre-effect snapshot (PRECOMMIT_DURABLE), before
//      any destination IO — file.copy;
//   P2 after the exclusive destination creation (FILE_CREATE), before any
//      source byte is written — file.copy;
//   P3 after the no-replace relocation, before any post-state
//      verification — file.move;
//   P4 after the fully verified completed effect, BEFORE the journal's
//      terminal-state commit — file.move.
// After each forced death a FRESH host process (this one) reopens the same
// fixed-disk SQLite store and proves the five invariants: the journal row
// and immutable commitment survived (SQLite persistence), the world's
// object identity matches the commitment through the anchored poststate
// observer (file identity), the bytes are exactly the committed bytes
// (byte integrity), the attempt identity is refused forever — same and
// divergent intent — and the full trusted boundary re-execution performs
// ZERO dispatch (no replay / no overwrite). The REAL trusted reconciler
// then classifies each phase world and STILL never licenses a retry.
// No mocked exception, no in-memory store, no simulated native effect: the
// child runs the REAL store, REAL boundary, REAL committed Win32 addon; the
// parent only observes and kills. Windows-only (the anchored addon and
// fixed-drive attestation are Win32), matching the existing e2e lanes.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import { type ActionPlan, type AuthorizedAction, computePlanHash } from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import { afterEach, describe, expect, it } from 'vitest';
import { observeFileMutationPoststate } from '../../vertical-files/src/file-mutation-poststate.ts';
import {
  SqliteFileMutationAuthorizationBoundary,
  SqliteFileMutationReconciler,
} from '../src/sqlite-file-mutation-host.ts';
import { SqliteFileMutationJournal } from '../src/sqlite-file-mutation-journal.ts';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CHILD = join(packageRoot, 'test', 'sqlite-file-mutation-phase-kill-child.ts');
const FIXED_NOW = '2026-10-26T04:00:00.000Z';
const INTEGRITY_SECRET = 'private-test-integrity';
const ISSUANCE_SECRET = 'private-test-issuance';

type Phase = 'P1' | 'P2' | 'P3' | 'P4';
type Op = 'file.copy' | 'file.move';

const dispose: Array<() => Promise<void> | void> = [];
afterEach(() => {
  for (const fn of dispose.splice(0).reverse()) fn();
});

/** Deterministic per-phase payload: unique header/fill/tail so a byte swap
 * between phases can never satisfy another phase's digest. */
function phasePayload(phase: Phase): Buffer {
  return Buffer.concat([
    Buffer.from(`F04B3B-${phase}-SOURCE-BYTES\n`, 'utf8'),
    Buffer.alloc(4096, '0'.charCodeAt(0) + Number(phase.slice(1))),
    Buffer.from(`-${phase}-END`, 'utf8'),
  ]);
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

// ---------------------------------------------------------------------------
// Forced-death evidence (the T04 discipline: only the PARENT's explicit
// kill from an observed still-running child counts).
// ---------------------------------------------------------------------------

type DeathEvidence = Readonly<{
  acknowledged: boolean;
  parentKillAccepted: boolean;
  code: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
}>;

function isProvenForcedDeath(evidence: DeathEvidence): boolean {
  if (!evidence.acknowledged || !evidence.parentKillAccepted) return false;
  if (evidence.signal === 'SIGKILL' && evidence.code === null) return true;
  // Windows TerminateProcess can report exit code 1 rather than a POSIX
  // signal. This branch is valid ONLY after the PARENT explicitly requested
  // SIGKILL from an observed still-running child; a normal exit cannot pass.
  return process.platform === 'win32' && evidence.signal === null && evidence.code === 1;
}

async function killChildAtPhase(
  phase: Phase,
  sqliteFile: string,
  fixturesFile: string,
): Promise<DeathEvidence> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(
      process.execPath,
      ['--experimental-transform-types', CHILD, sqliteFile, fixturesFile, phase],
      { cwd: packageRoot, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    let output = '';
    let stderr = '';
    let parentKillAccepted = false;
    let timedOut = false;
    const watchdog = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, 30_000);
    child.stdout.on('data', (chunk: Buffer) => {
      output += chunk.toString('utf8');
      if (output.includes(`PHASE_READY:${phase}`) && !parentKillAccepted) {
        // The phase point is observed inside the REAL composition; only the
        // parent (not the child) issues the real process-kill request.
        parentKillAccepted = child.kill('SIGKILL');
      }
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });
    child.once('error', (error: Error) => {
      clearTimeout(watchdog);
      rejectPromise(error);
    });
    child.once('close', (code, signal) => {
      clearTimeout(watchdog);
      if (timedOut) {
        rejectPromise(new Error('KILL_CANARY_TIMED_OUT'));
        return;
      }
      resolvePromise({
        acknowledged: output.includes(`PHASE_READY:${phase}`),
        parentKillAccepted,
        code,
        signal,
        stderr,
      });
    });
  });
}

// ---------------------------------------------------------------------------
// Real authorization world for ONE mutation intent (fresh store per phase;
// real clock so the 15-minute grant stays valid across both processes).
// ---------------------------------------------------------------------------

function controllerOver(store: ShunStore): ActionController {
  const adapter = new ShunStoreAuthorizationAdapter(store);
  const clock = () => new Date().toISOString();
  return new ActionController({
    authority: new AuthorizationAuthority({
      state: adapter,
      grants: adapter,
      integritySecret: INTEGRITY_SECRET,
      issuanceSecret: ISSUANCE_SECRET,
      clock,
    }),
    policyState: adapter,
    approvals: {
      requestApproval: async () => {
        throw new Error('approval cannot be reached');
      },
    },
    issuanceSecret: ISSUANCE_SECRET,
    clock,
  });
}

async function authorizeOneMutation(
  store: ShunStore,
  op: Op,
  sourcePath: string,
  destinationPath: string,
): Promise<{ plan: ActionPlan; action: AuthorizedAction }> {
  const adapter = new ShunStoreAuthorizationAdapter(store);
  await adapter.saveAuthorityRecord({
    authorityId: 'auth-1',
    authorityRevision: 'rev-1',
    updatedAt: FIXED_NOW,
    policyInitialized: true,
  });
  const sourceDir = sourcePath.slice(0, sourcePath.lastIndexOf('\\'));
  const destDir = destinationPath.slice(0, destinationPath.lastIndexOf('\\'));
  const write =
    op === 'file.copy'
      ? [destDir]
      : [...new Set([sourceDir, destDir].map((d) => d.toLowerCase()))].sort();
  const plan: ActionPlan = {
    taskId: 'task-f04b3b',
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
        ruleId: 'allow-f04b3b-mutation',
        capabilityId: op,
        op,
        maxRiskClass: 'R2',
        privilegeLevel: 'USER',
        filesystem: { read: [sourceDir], write },
      },
    ],
    riskGuards: [],
    updatedAt: FIXED_NOW,
  });
  const controller = controllerOver(store);
  const authorized = await controller.authorizePlan({ plan });
  if (!authorized.ok) throw new Error(`fixture failed to authorize: ${authorized.code}`);
  const action = authorized.authorization.actions[0];
  if (!action) throw new Error('fixture has no authorized action');
  return { plan, action };
}

// ---------------------------------------------------------------------------
// The phase matrix: kill, then prove all five invariants from a fresh host.
// ---------------------------------------------------------------------------

type PhaseExpectation = Readonly<{
  op: Op;
  /** Expected raw world after the kill (verified through BOTH the anchored
   * observer and plain fs reads in this fresh host). */
  sourcePresent: boolean;
  destPresent: boolean;
  destBytes: 'absent' | 'empty' | 'exact-source';
  verdict: 'CONSISTENT_WITH_COMPLETION' | 'CONSISTENT_WITH_NOT_EXECUTED' | 'UNKNOWN';
  disposition: 'COMPLETED_CONSISTENT' | 'NOT_EXECUTED_CONSISTENT' | 'MANUAL_RECONCILE_REQUIRED';
}>;

async function killAndVerifyPhase(phase: Phase, expected: PhaseExpectation): Promise<void> {
  expect(process.version, 'F04B3b runs on the pinned Node 24 runtime').toMatch(/^v24\./);
  const folder = mkdtempSync(join(tmpdir(), `shun-f04b3b-${phase.toLowerCase()}-`));
  mkdirSync(join(folder, 'src'));
  mkdirSync(join(folder, 'dst'));
  const payload = phasePayload(phase);
  const sourcePath = join(folder, 'src', 'a.txt');
  const destinationPath = join(folder, 'dst', expected.op === 'file.move' ? 'moved.txt' : 'b.txt');
  writeFileSync(sourcePath, payload);
  const sqliteFile = join(folder, 'phase.sqlite');
  const fixturesFile = join(folder, 'fixtures.json');

  // Phase 1 also carries the false-proof control: a child that merely
  // PRINTS the readiness marker and exits normally can never be counted as
  // a forced death by the evidence gate.
  if (phase === 'P1') {
    const ordinaryExit = spawnSync(
      process.execPath,
      ['-e', `process.stdout.write('PHASE_READY:P1'); process.exit(13);`],
      { encoding: 'utf8', timeout: 5_000 },
    );
    expect(ordinaryExit.status).toBe(13);
    expect(
      isProvenForcedDeath({
        acknowledged: (ordinaryExit.stdout ?? '').includes('PHASE_READY:P1'),
        parentKillAccepted: false,
        code: ordinaryExit.status,
        signal: ordinaryExit.signal,
        stderr: ordinaryExit.stderr ?? '',
      }),
    ).toBe(false);
  }

  const firstHost = new ShunStore({ file: sqliteFile });
  const { plan, action } = await authorizeOneMutation(
    firstHost,
    expected.op,
    sourcePath,
    destinationPath,
  );
  writeFileSync(fixturesFile, JSON.stringify({ action, plan }));
  await firstHost.close();

  const death = await killChildAtPhase(phase, sqliteFile, fixturesFile);
  expect(death.acknowledged, death.stderr).toBe(true);
  expect(death.parentKillAccepted, death.stderr).toBe(true);
  expect(isProvenForcedDeath(death), death.stderr).toBe(true);

  // Everything below runs in a FRESH host: a new process reopening the same
  // fixed-disk store, exactly what a restart after a crash does.
  const recovered = new ShunStore({ file: sqliteFile });
  dispose.push(async () => {
    await recovered.close();
    rmSync(folder, { recursive: true, force: true });
  });
  const journal = new SqliteFileMutationJournal(recovered);

  // (1) SQLite persistence: the STARTED reservation and the immutable
  // pre-effect commitment both survived the forced process death. For P4
  // this is also the no-false-terminal proof: a COMPLETED world must never
  // mint a COMMITTED_VERIFIED row the dying process did not journal.
  expect(journal.lookup(action)).toEqual({
    ok: true,
    state: 'STARTED',
    evidenceSha256: null,
  });
  const precommit = journal.readPrecommit(action);
  expect(precommit.ok).toBe(true);
  const commitment = precommit.ok ? (precommit.commitment as Record<string, unknown>) : null;
  expect(commitment).not.toBeNull();
  const committedSource = commitment?.source as Record<string, unknown>;
  expect(commitment?.sourcePath).toBe(sourcePath);
  expect(commitment?.destinationPath).toBe(destinationPath);
  // The durable snapshot pins the EXACT bytes this fresh host can read.
  expect(committedSource.size).toBe(payload.length);
  expect(committedSource.sha256).toBe(sha256(payload));

  // (2) File identity + (3) byte integrity through the REAL anchored
  // poststate observer (kernel FileId/volume + exact digest/EOF proof).
  const observed = observeFileMutationPoststate(commitment);
  expect(observed.ok).toBe(true);
  if (observed.ok) {
    expect(observed.verdict).toBe(expected.verdict);
    expect(observed.evidence.sourcePresent).toBe(expected.sourcePresent);
    expect(observed.evidence.destPresent).toBe(expected.destPresent);
    if (expected.sourcePresent) {
      expect(observed.evidence.sourceMatchesCommitment).toBe(true);
    }
    if (expected.op === 'file.move' && expected.destPresent) {
      // The relocated destination IS the committed object: 64-bit FileId +
      // volume continuity held across the real process death.
      expect(observed.evidence.destIdentityContinuity).toBe(true);
      expect(observed.evidence.destMatchesCommitment).toBe(true);
    }
    if (expected.destBytes === 'empty') {
      expect(observed.evidence.destMatchesCommitment).toBe(false);
    }
  }
  // Plain-fs cross-check in this fresh host (independent of the observer).
  expect(existsSync(sourcePath)).toBe(expected.sourcePresent);
  if (expected.sourcePresent) {
    expect(readFileSync(sourcePath).equals(payload)).toBe(true);
  }
  expect(existsSync(destinationPath)).toBe(expected.destPresent);
  let destBeforeReplay: Buffer | null = null;
  if (expected.destBytes === 'empty') {
    destBeforeReplay = readFileSync(destinationPath);
    expect(destBeforeReplay.length).toBe(0);
  } else if (expected.destBytes === 'exact-source') {
    destBeforeReplay = readFileSync(destinationPath);
    expect(destBeforeReplay.equals(payload)).toBe(true);
  }

  // (4) No replay: the attempt identity is refused forever — same intent
  // reconcile-first, divergent intent hard-refused — and the REAL trusted
  // reconciler's disposition never lifts the refusal.
  expect(journal.reserve(action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });
  expect(journal.reserve({ ...action, planHash: 'f'.repeat(64) })).toEqual({
    ok: false,
    code: 'JOURNAL_REFUSED',
  });
  const reconciler = new SqliteFileMutationReconciler({
    store: recovered,
    verifyPoststate: (snapshot) => observeFileMutationPoststate(snapshot),
  });
  expect(await reconciler.reconcile(action)).toMatchObject({
    ok: true,
    disposition: expected.disposition,
    automaticRetryAllowed: false,
  });
  expect(journal.readReconcileDisposition(action)).toMatchObject({
    ok: true,
    disposition: expected.disposition,
  });
  // The disposition NEVER rewrites the journal row and NEVER re-licenses a
  // dispatch: the row stays STARTED and the identity stays refused.
  expect(journal.lookup(action)).toMatchObject({ ok: true, state: 'STARTED' });
  expect(journal.reserve(action)).toEqual({ ok: false, code: 'RECONCILE_REQUIRED' });

  // (5) No overwrite: the FULL trusted boundary re-execution of the same
  // attempt identity performs ZERO physical dispatch — the world (present
  // source bytes, absent/empty/exact destination) is bit-for-bit untouched.
  let dispatches = 0;
  const boundary = new SqliteFileMutationAuthorizationBoundary({
    store: recovered,
    controller: controllerOver(recovered),
    loadPlanByHash: async () => plan,
    executeFileMutation: async () => {
      dispatches++;
      return null;
    },
  });
  expect(await boundary.execute(action)).toEqual({
    ok: false,
    code: 'FILE_MUTATION_RECONCILE_REQUIRED',
  });
  expect(dispatches).toBe(0);
  expect(existsSync(sourcePath)).toBe(expected.sourcePresent);
  if (expected.sourcePresent) {
    expect(readFileSync(sourcePath).equals(payload)).toBe(true);
  }
  expect(existsSync(destinationPath)).toBe(expected.destPresent);
  if (destBeforeReplay !== null) {
    expect(readFileSync(destinationPath).equals(destBeforeReplay)).toBe(true);
  }

  console.log(
    `F04B3B_${phase}_FORCED_DEATH=PASS childExit=${death.code === null ? 'null' : death.code}` +
      ` signal=${death.signal ?? 'null'} state=STARTED verdict=${expected.verdict}` +
      ` disposition=${expected.disposition} dispatches=0 node=${process.version}`,
  );
}

describe.skipIf(process.platform !== 'win32')(
  'T07 F04B3b real process-termination phase matrix (Windows Node24)',
  () => {
    it('P1: kill after the durable pre-effect snapshot — nothing executed, NOT_EXECUTED_CONSISTENT, unreplayable', async () => {
      await killAndVerifyPhase('P1', {
        op: 'file.copy',
        sourcePresent: true,
        destPresent: false,
        destBytes: 'absent',
        verdict: 'CONSISTENT_WITH_NOT_EXECUTED',
        disposition: 'NOT_EXECUTED_CONSISTENT',
      });
    }, 90_000);

    it('P2: kill after the exclusive destination creation — zero bytes written, MANUAL_RECONCILE_REQUIRED, unreplayable, no overwrite', async () => {
      await killAndVerifyPhase('P2', {
        op: 'file.copy',
        sourcePresent: true,
        destPresent: true,
        destBytes: 'empty',
        verdict: 'UNKNOWN',
        disposition: 'MANUAL_RECONCILE_REQUIRED',
      });
    }, 90_000);

    it('P3: kill after the no-replace relocation — identity-continuous destination, COMPLETED_CONSISTENT, unreplayable', async () => {
      await killAndVerifyPhase('P3', {
        op: 'file.move',
        sourcePresent: false,
        destPresent: true,
        destBytes: 'exact-source',
        verdict: 'CONSISTENT_WITH_COMPLETION',
        disposition: 'COMPLETED_CONSISTENT',
      });
    }, 90_000);

    it('P4: kill after the fully verified effect but before the journal terminal commit — world complete, row still STARTED, unreplayable', async () => {
      await killAndVerifyPhase('P4', {
        op: 'file.move',
        sourcePresent: false,
        destPresent: true,
        destBytes: 'exact-source',
        verdict: 'CONSISTENT_WITH_COMPLETION',
        disposition: 'COMPLETED_CONSISTENT',
      });
    }, 90_000);
  },
);
