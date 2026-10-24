// T04 Windows Host minimal end-to-end closed loop (physical, standard user).
// REAL file-backed SQLite authorization -> real ActionController plan/effect
// grant -> durable STARTED journal -> ONE genuine native Rust/NAPI-RS R0 scan
// -> independent post-state oracle -> conservative receipt -> SEPARATE task
// semantic verifier -> restart/duplicate replay refusal.
//
// Every negative here is a real host falsifier: junction reparse, 8.3 short
// paths, subst drive alias, missing native addon, optionally a REAL SMB
// mapped drive via SHUN_E2E_SMB_DRIVE_ROOT. Nothing is mocked into a PASS.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ActionPlan } from '@shun/contracts';
import { ShunStore } from '@shun/store';
import { afterEach, describe, expect, it } from 'vitest';
import { captureOracleWalk, oracleWalksEqual } from '../src/r0-independent-poststate-oracle.ts';
import { verifyR0SearchTaskSemantics } from '../src/r0-task-semantic-verifier.ts';
import { SqliteR0EffectJournal } from '../src/sqlite-r0-effect-journal.ts';
import { executeTrustedWindowsR0Search } from '../src/trusted-windows-r0-effect.ts';
import {
  activatePolicy,
  buildAuthorityStack,
  buildCurrentness,
  buildLoadExpectedPlan,
  expectedMatches,
  FIXTURE,
  type HostFixture,
  makeHostFixture,
  recipeSourceFor,
} from './helpers/win-e2e-fixture.ts';

const here = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ADDON = join(here, 'native', 'impl', 'shun_win32_impl.node');
const SYSTEM32 = join(process.env.SystemRoot ?? 'C:Windows', 'System32');

/** Absolute System32 paths: Git-Bash POSIX shims shadow PATH utilities here. */
function runSystem32(exe: string, args: readonly string[]) {
  return spawnSync(join(SYSTEM32, exe), args, { encoding: 'utf8' });
}

/** cmd.exe builtins need verbatim arguments or node quoting mangles mklink. */
function runCmd(command: string) {
  return spawnSync(join(SYSTEM32, 'cmd.exe'), ['/d', '/c', command], {
    encoding: 'utf8',
    windowsVerbatimArguments: true,
  });
}

const cleanup: Array<() => Promise<void>> = [];
const live: HostFixture[] = [];
async function newFixture(prefix: string, query = '*.txt') {
  const f = await makeHostFixture(prefix, query);
  live.push(f);
  return f;
}
afterEach(async () => {
  for (const task of cleanup.splice(0).reverse()) await task();
  for (const f of live.splice(0).reverse()) await f.dispose();
});

describe.skipIf(process.platform !== 'win32')('T04 Windows host minimal E2E closed loop', () => {
  it('runs the standard-user privilege gate before any host loop evidence', () => {
    const groups = runSystem32('whoami.exe', ['/groups']);
    expect(groups.status).toBe(0);
    const text = groups.stdout ?? '';
    const high = text.includes('S-1-16-12288');
    const medium = text.includes('S-1-16-8192');
    const low = text.includes('S-1-16-4096');
    // The canary property is the operative UAC-filtered token: never High.
    expect(high, 'E2E must run under a standard (non-elevated) token').toBe(false);
    console.log(
      `E2E_PRIVILEGE_TOKEN=${high ? 'HIGH' : medium ? 'MEDIUM' : low ? 'LOW' : 'UNKNOWN'}`,
    );
    expect(medium || low).toBe(true);
  });

  it('closes the loop: grant -> durable STARTED -> native scan -> oracle -> semantic PASS, then refuses replay', async () => {
    const f = await newFixture('shun-e2e-ok');
    const { plan, host } = f.compose();
    expect(plan.actions).toHaveLength(1);
    const before = captureOracleWalk(f.tree.rootNative, '*.txt');
    if (!before.ok) throw new Error('fixture oracle pre-walk failed');
    expect(before.walk.matches).toEqual(expectedMatches());

    const run = await host.runner.run(f.identity);
    expect(run).toEqual({
      ok: true,
      state: 'EXECUTED_NOT_SEMANTICALLY_VERIFIED',
      actionCount: 1,
      taskPass: false,
    });
    expect(f.scans()).toBe(1);
    expect(await f.adapter.hasAnyGrant()).toBe(true);

    const receipt = f.lastReceipt();
    const action = f.lastAction();
    const evidence = f.lastEvidence();
    if (!receipt || !action || !evidence) throw new Error('host effect evidence missing');
    expect(receipt.terminal).toBe('SUCCEEDED');
    expect(receipt.sideEffectEvidence).toMatchObject({
      sideEffectClass: 'R0',
      recoveryClassification: 'COMPLETED_VERIFIED',
      postStateVerified: true,
    });
    // The receipt cites the REAL durable phase receipt of this attempt
    // (R2 P1-02), never a constant table name.
    const journalRef = receipt.sideEffectEvidence.journalRef;
    expect(typeof journalRef).toBe('string');
    expect(journalRef?.startsWith('recipe_r0_effect_phase_v02:')).toBe(true);
    const phaseDigest = journalRef?.slice('recipe_r0_effect_phase_v02:'.length) ?? '';
    const phaseReadback = f.phaseJournal().lookupEffectPhase(action);
    expect(phaseReadback.ok).toBe(true);
    if (phaseReadback.ok) {
      expect(phaseReadback.phaseReceiptSha256).toBe(phaseDigest);
      expect(evidence.postStateSha256).toBe(phaseReadback.commitment.postStateSha256);
      expect(phaseReadback.commitment.expectedStateSha256).not.toBe('');
    }
    expect(evidence).toMatchObject({
      effectObserved: true,
      fingerprintUnchanged: true,
      independentMatchesEqual: true,
      matchedCount: expectedMatches().length,
    });

    const journal = new SqliteR0EffectJournal(f.store);
    expect(journal.lookup(action)).toMatchObject({
      ok: true,
      state: 'OBSERVED_NOT_SEMANTICALLY_VERIFIED',
      semanticVerified: false,
    });
    expect(action.action.parameters.root).toBe(f.tree.rootForward);

    // Separate task semantic verifier: own expectation + evidence + journal.
    const semantic = verifyR0SearchTaskSemantics({
      action,
      journal,
      receipt,
      evidence,
    });
    expect(semantic).toMatchObject({ ok: true, taskSemantic: 'PASS' });

    // Restart the process view of the same durable store: replay refused.
    const after = captureOracleWalk(f.tree.rootNative, '*.txt');
    if (!after.ok) throw new Error('fixture oracle post-walk failed');
    expect(oracleWalksEqual(before.walk, after.walk)).toBe(true);
    const replay = await host.runner.run(f.identity);
    expect(replay).toEqual({ ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN' });
    expect(f.scans()).toBe(1);
    console.log('E2E_POSITIVE_LOOP=PASS E2E_REPLAY_REFUSED=PASS E2E_SEMANTIC=PASS');
  });

  it('refuses an in-scope junction reparse point without following it, and never replays', async () => {
    const f = await newFixture('shun-e2e-junc');
    // Junction inside the scope pointing OUTSIDE it, containing a match.
    const outside = mkdtempSync(join(tmpdir(), 'shun-e2e-outside-'));
    cleanup.push(async () => rmSync(outside, { recursive: true, force: true }));
    writeFileSync(join(outside, 'escape.txt'), 'outside\n');
    const junction = join(f.tree.rootNative, 'link-out');
    const made = runCmd(`mklink /J "${junction}" "${outside}"`);
    expect(made.status, made.stderr).toBe(0);
    expect(existsSync(junction)).toBe(true);
    cleanup.push(async () => void runCmd(`rmdir "${junction}"`));
    const { host } = f.compose();

    const run = await host.runner.run(f.identity);
    expect(run).toEqual({ ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN' });
    expect(f.scans()).toBe(1);
    const receipt = f.lastReceipt();
    expect(receipt?.terminal).toBe('UNCERTAIN');
    expect(receipt?.sideEffectEvidence.postStateVerified).toBe(false);
    const journal = new SqliteR0EffectJournal(f.store);
    expect(journal.lookup(f.lastAction())).toMatchObject({ ok: true, state: 'UNCERTAIN' });

    // The durable UNCERTAIN row is never auto-replayed, even on retry.
    const retry = await host.runner.run(f.identity);
    expect(retry).toEqual({ ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN' });
    expect(f.scans()).toBe(1);
    console.log('E2E_JUNCTION_REFUSED=PASS E2E_JUNCTION_NO_REPLAY=PASS');
  });

  it('accepts a legitimate 8.3 short-path spelling of the same approved scope', async () => {
    const f = await newFixture('shun-e2e-short');
    const probe = spawnSync(
      join(SYSTEM32, 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
      [
        '-NoProfile',
        '-Command',
        `(New-Object -ComObject Scripting.FileSystemObject).GetFolder('${f.tree.rootNative}').ShortPath`,
      ],
      { encoding: 'utf8' },
    );
    const short = (probe.stdout ?? '').trim().split(/\r?\n/).filter(Boolean).at(-1) ?? '';
    if (probe.status !== 0 || !/~\d/.test(short) || !existsSync(short)) {
      console.log(`E2E_SHORT_PATH=SKIPPED_NO_83_ALIAS rc=${probe.status} out=${short}`);
      return;
    }
    console.log(`E2E_SHORT_PATH_ALIAS_LEN=${short.length}`);
    const shortForward = short.split('\\').join('/');
    const { adapter, controller } = buildAuthorityStack(f.store);
    await activatePolicy(adapter, [shortForward]);
    const { createSqliteAuthorizedRecipeEffectHost, createSqliteRecipeReadService } = await import(
      '../src/index.ts'
    );
    const service = createSqliteRecipeReadService({
      store: f.store,
      controller,
      currentness: buildCurrentness(f.store),
      loadExpectedPlan: buildLoadExpectedPlan(shortForward),
    });
    const saved = service.registerLiteral(recipeSourceFor(shortForward), {
      recipeId: 'e2e-recipe-short',
      contractRevision: FIXTURE.contractRevision,
      verifierId: FIXTURE.verifierId,
      verifierRevision: FIXTURE.verifierRevision,
    });
    if (!saved.ok) throw new Error('short-path fixture register failed');
    const identity = {
      taskId: 'task-short',
      recipeId: saved.recipeId,
      revisionSha256: saved.revisionSha256,
    };
    const preview = service.previewExact(identity);
    if (!preview.ok) throw new Error('fixture preview failed');
    const plan = buildLoadExpectedPlan(shortForward)({
      ...identity,
      actionGraphSha256: preview.actionGraphSha256,
    }) as ActionPlan;
    const host = createSqliteAuthorizedRecipeEffectHost({
      store: f.store,
      controller,
      currentness: buildCurrentness(f.store),
      loadExpectedPlan: buildLoadExpectedPlan(shortForward),
      loadPlanByHash: async (hash) => (hash === plan.planHash ? plan : null),
      executeScopedSearch: async (action) =>
        executeTrustedWindowsR0Search(action, {
          phaseJournal: new SqliteR0EffectJournal(f.store),
        }),
    });
    const run = await host.runner.run(identity);
    expect(run).toEqual({
      ok: true,
      state: 'EXECUTED_NOT_SEMANTICALLY_VERIFIED',
      actionCount: 1,
      taskPass: false,
    });
    console.log('E2E_SHORT_PATH_ACCEPTED=PASS');
  }, 20_000);

  it('refuses a subst drive-letter alias as scope root by final-path provenance', async () => {
    const f = await newFixture('shun-e2e-subst');
    // Pick a free drive letter.
    const letters = 'VWXYZ';
    let drive: string | null = null;
    for (const letter of letters) {
      if (!existsSync(`${letter}:\\`)) {
        drive = letter;
        break;
      }
    }
    if (drive === null) {
      console.log('E2E_SUBST_NEGATIVE=SKIPPED_NO_FREE_LETTER');
      return;
    }
    const made = runSystem32('subst.exe', [`${drive}:`, f.tree.rootNative]);
    if (made.status !== 0) {
      console.log(`E2E_SUBST_NEGATIVE=SKIPPED_SUBST_UNAVAILABLE rc=${made.status}`);
      return;
    }
    cleanup.push(async () => void runSystem32('subst.exe', [`${drive}:`, '/D']));
    expect(existsSync(`${drive}:\\`)).toBe(true);
    console.log(`E2E_SUBST_DRIVE=${drive}:`);

    // A plan scoped to the subst drive letter must be refused end to end.
    const aliasForward = `${drive}:/`;
    const { adapter, controller } = buildAuthorityStack(f.store);
    await activatePolicy(adapter, [aliasForward]);
    const { createSqliteAuthorizedRecipeEffectHost, createSqliteRecipeReadService } = await import(
      '../src/index.ts'
    );
    const source = recipeSourceFor(aliasForward);
    const service = createSqliteRecipeReadService({
      store: f.store,
      controller,
      currentness: buildCurrentness(f.store),
      loadExpectedPlan: buildLoadExpectedPlan(aliasForward),
    });
    const saved = service.registerLiteral(source, {
      recipeId: 'e2e-recipe-subst',
      contractRevision: FIXTURE.contractRevision,
      verifierId: FIXTURE.verifierId,
      verifierRevision: FIXTURE.verifierRevision,
    });
    if (!saved.ok) throw new Error('subst fixture register failed');
    const identity = {
      taskId: 'task-subst',
      recipeId: saved.recipeId,
      revisionSha256: saved.revisionSha256,
    };
    const preview = service.previewExact(identity);
    if (!preview.ok) throw new Error('fixture preview failed');
    const plan = buildLoadExpectedPlan(aliasForward)({
      ...identity,
      actionGraphSha256: preview.actionGraphSha256,
    }) as ActionPlan;
    const host = createSqliteAuthorizedRecipeEffectHost({
      store: f.store,
      controller,
      currentness: buildCurrentness(f.store),
      loadExpectedPlan: buildLoadExpectedPlan(aliasForward),
      loadPlanByHash: async (hash) => (hash === plan.planHash ? plan : null),
      executeScopedSearch: async (action) =>
        executeTrustedWindowsR0Search(action, {
          phaseJournal: new SqliteR0EffectJournal(f.store),
        }),
    });
    const run = await host.runner.run(identity);
    expect(run).toEqual({ ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN' });
    console.log('E2E_SUBST_REFUSED=PASS');
  });

  it('fails closed in a fresh process when the native addon is missing, then recovers', async () => {
    const f = await newFixture('shun-e2e-addon');
    const { plan } = f.compose();
    expect(existsSync(ADDON)).toBe(true);
    const hidden = `${ADDON}.hidden-by-e2e`;
    renameSync(ADDON, hidden);
    try {
      expect(existsSync(ADDON)).toBe(false);
      // A fresh child process proves the load-time fail-closed path; the
      // in-process addon module may already be cached in this worker.
      const child = spawnSync(
        process.execPath,
        [
          '--experimental-transform-types',
          'test/helpers/hardkill-child.ts',
          f.dbPath,
          JSON.stringify(f.identity),
          JSON.stringify(plan),
          'effect',
        ],
        { cwd: here, encoding: 'utf8', timeout: 45_000 },
      );
      const done = (child.stdout ?? '')
        .split('\n')
        .find((line) => line.startsWith('CHILD_RUN_DONE '));
      if (!done) {
        throw new Error(`missing-addon child produced no result: ${child.stderr ?? ''}`);
      }
      const result = JSON.parse(done.slice('CHILD_RUN_DONE '.length)) as {
        ok: boolean;
        code?: string;
      };
      expect(result).toEqual({ ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN' });
      // The child's own durable row records the conservative UNCERTAIN state
      // (readback-only observation: the parent holds no AuthorizedAction).
      const rows = f.store.database
        .prepare('SELECT task_id, action_id, state FROM recipe_r0_effect_journal_v02')
        .all() as Array<{ task_id: string; action_id: string; state: string }>;
      expect(rows).toEqual([{ task_id: f.identity.taskId, action_id: 'read', state: 'UNCERTAIN' }]);
      console.log('E2E_MISSING_ADDON_FAIL_CLOSED=PASS');
    } finally {
      if (existsSync(hidden) && !existsSync(ADDON)) renameSync(hidden, ADDON);
    }
    expect(existsSync(ADDON)).toBe(true);

    // A fresh identity on the same host works again after the addon returns.
    const f2 = await newFixture('shun-e2e-addon-ok');
    const { host: host2 } = f2.compose();
    expect(await host2.runner.run(f2.identity)).toMatchObject({ ok: true });
    expect(f2.scans()).toBe(1);
  });

  it('refuses a real SMB mapped drive scope when one is provided', async () => {
    const smbRoot = process.env.SHUN_E2E_SMB_DRIVE_ROOT;
    if (!smbRoot) {
      console.log('E2E_SMB_MAPPED_DRIVE_NEGATIVE=SKIPPED_NO_SMB_DRIVE_PROVIDED');
      return;
    }
    expect(existsSync(smbRoot)).toBe(true);
    console.log(`E2E_SMB_DRIVE_ROOT_PROBED=${existsSync(smbRoot) ? 'reachable' : 'unreachable'}`);
    const dir = mkdtempSync(join(tmpdir(), 'shun-e2e-smb-db-'));
    cleanup.push(async () => rmSync(dir, { recursive: true, force: true }));
    const store = new ShunStore({ file: join(dir, 'business.sqlite') });
    const { adapter, controller } = buildAuthorityStack(store);
    const rootForward = smbRoot.split('\\').join('/');
    await activatePolicy(adapter, [rootForward]);
    const { createSqliteAuthorizedRecipeEffectHost, createSqliteRecipeReadService } = await import(
      '../src/index.ts'
    );
    const service = createSqliteRecipeReadService({
      store,
      controller,
      currentness: buildCurrentness(store),
      loadExpectedPlan: buildLoadExpectedPlan(rootForward),
    });
    const saved = service.registerLiteral(recipeSourceFor(rootForward), {
      recipeId: 'e2e-recipe-smb',
      contractRevision: FIXTURE.contractRevision,
      verifierId: FIXTURE.verifierId,
      verifierRevision: FIXTURE.verifierRevision,
    });
    if (!saved.ok) throw new Error('smb fixture register failed');
    const identity = {
      taskId: 'task-smb',
      recipeId: saved.recipeId,
      revisionSha256: saved.revisionSha256,
    };
    const preview = service.previewExact(identity);
    if (!preview.ok) throw new Error('fixture preview failed');
    const plan = buildLoadExpectedPlan(rootForward)({
      ...identity,
      actionGraphSha256: preview.actionGraphSha256,
    }) as ActionPlan;
    const host = createSqliteAuthorizedRecipeEffectHost({
      store,
      controller,
      currentness: buildCurrentness(store),
      loadExpectedPlan: buildLoadExpectedPlan(rootForward),
      loadPlanByHash: async (hash) => (hash === plan.planHash ? plan : null),
      executeScopedSearch: async (action) =>
        executeTrustedWindowsR0Search(action, {
          phaseJournal: new SqliteR0EffectJournal(store),
        }),
    });
    const run = await host.runner.run(identity);
    expect(run).toEqual({ ok: false, code: 'RECIPE_EXECUTION_UNCERTAIN' });
    console.log('E2E_SMB_MAPPED_DRIVE_REFUSED=PASS');
  });
});
