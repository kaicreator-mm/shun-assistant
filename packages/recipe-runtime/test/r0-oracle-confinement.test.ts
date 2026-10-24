// T04 oracle confinement falsifiers (R2 P1-01). The independent oracle opens
// NOTHING by pathname: every handle is anchored at a verified parent, drive
// letters are attested as fixed local volumes by purely-local kernel
// questions before any open, and every opened object is identity-checked
// against the FileId enumerated from its parent. These tests mechanically
// prove the zero-first-unauthorized-read property:
//   - a junction ANCESTOR is refused at that component with zero opens below
//     it (the target's files are never touched);
//   - a subst alias root is refused by device attestation with zero opens
//     AT ALL — the same gate that refuses a mapped SMB root
//     (\Device\LanmanRedirector\...), unit-covered in decision form;
//   - under an ACTIVE concurrent swap of the ancestor and an in-tree
//     directory, every admitted walk observed exactly the real tree (byte
//     -identical fingerprint lines outside the toggled subtree) and never
//     the mirror world;
//   - a content swap preserving names/size/mtime changes the fingerprint and
//     the task semantic verdict refuses.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuthorizedActionSchema, canonicalJson, ExecutionReceiptSchema } from '@shun/contracts';
import { ShunStore } from '@shun/store';
import { describe, expect, it } from 'vitest';
import {
  attestsFixedLocalDrive,
  captureOracleWalk,
  type OracleInstrument,
} from '../src/r0-independent-poststate-oracle.ts';
import { verifyR0SearchTaskSemantics } from '../src/r0-task-semantic-verifier.ts';
import { SqliteR0EffectJournal } from '../src/sqlite-r0-effect-journal.ts';

const here = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SYSTEM32 = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32');

function runCmd(command: string) {
  return spawnSync(join(SYSTEM32, 'cmd.exe'), ['/d', '/c', command], {
    encoding: 'utf8',
    windowsVerbatimArguments: true,
  });
}

type OpenLog = { dirs: string[]; files: string[]; stages: string[] };

function instrument(log: OpenLog): OracleInstrument {
  return {
    onStage: (stage, detail) => log.stages.push(`${stage}:${detail}`),
    onDirOpen: (_depth, name) => log.dirs.push(name),
    onFileOpen: (rel) => log.files.push(rel),
  };
}

function makeScope(prefix: string, files: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), `${prefix}-`));
  for (const [rel, content] of Object.entries(files)) {
    const target = join(dir, rel);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return { dir, dispose: () => rmSync(dir, { recursive: true, force: true }) };
}

describe.skipIf(process.platform !== 'win32')('T04 oracle confinement falsifiers', () => {
  it('refuses a junction ancestor at that component with zero opens below it', () => {
    const scope = makeScope('shun-oracle-anc', {
      'real/scope/a.txt': 'alpha',
      'outside/escape.txt': 'outside',
    });
    try {
      const junction = join(scope.dir, 'real', 'jn');
      const made = runCmd(`mklink /J "${junction}" "${join(scope.dir, 'outside')}"`);
      expect(made.status, made.stderr).toBe(0);
      const log: OpenLog = { dirs: [], files: [], stages: [] };
      const result = captureOracleWalk(join(junction, 'scope'), '*.txt', instrument(log));
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe('ORACLE_SCOPE_REFUSED');
      // The admitted prefix stops exactly at the junction component; nothing
      // below it — neither the scope directory nor the target's files — was
      // ever opened.
      expect(log.dirs.at(-1)).toBe('jn');
      expect(log.files).toEqual([]);
      expect(log.stages.some((stage) => stage.startsWith('ADMITTED'))).toBe(false);
      console.log('ORACLE_JUNCTION_ANCESTOR_ZERO_IO=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('refuses an in-tree junction from enumeration metadata alone', () => {
    const scope = makeScope('shun-oracle-tree', {
      'scope/a.txt': 'alpha',
      'outside/escape.txt': 'outside',
    });
    try {
      const junction = join(scope.dir, 'scope', 'link-out');
      const made = runCmd(`mklink /J "${junction}" "${join(scope.dir, 'outside')}"`);
      expect(made.status, made.stderr).toBe(0);
      const log: OpenLog = { dirs: [], files: [], stages: [] };
      const result = captureOracleWalk(join(scope.dir, 'scope'), '*.txt', instrument(log));
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe('ORACLE_MUTATION_RISK');
      // The walk may legitimately have opened earlier in-scope files before
      // reaching the junction; the junction TARGET must stay untouched.
      expect(log.files).not.toContain('escape.txt');
      expect(log.dirs).not.toContain('outside');
      expect(log.stages.some((stage) => stage.startsWith('ANCESTOR_OPENED:link-out'))).toBe(false);
      console.log('ORACLE_INTREE_JUNCTION_REFUSED=PASS');
    } finally {
      scope.dispose();
    }
  });

  it('refuses a subst alias root by device attestation with zero opens at all', () => {
    const scope = makeScope('shun-oracle-subst', { 'scope/a.txt': 'alpha' });
    try {
      const letters = 'VWXYZ';
      let drive: string | null = null;
      for (const letter of letters) {
        if (!existsSync(`${letter}:\\`)) {
          drive = letter;
          break;
        }
      }
      if (drive === null) {
        console.log('ORACLE_SUBST_ZERO_IO=SKIPPED_NO_FREE_LETTER');
        return;
      }
      const made = runCmd(`subst ${drive}: "${scope.dir}"`);
      if (made.status !== 0) {
        console.log('ORACLE_SUBST_ZERO_IO=SKIPPED_SUBST_UNAVAILABLE');
        return;
      }
      try {
        expect(existsSync(`${drive}:\\`)).toBe(true);
        const log: OpenLog = { dirs: [], files: [], stages: [] };
        const result = captureOracleWalk(`${drive}:\\`, '*.txt', instrument(log));
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.code).toBe('ORACLE_SCOPE_REFUSED');
        // Attestation refused before a single handle existed on that drive.
        expect(log.dirs).toEqual([]);
        expect(log.files).toEqual([]);
        expect(log.stages.some((stage) => stage.startsWith('REFUSED:drive-attestation'))).toBe(
          true,
        );
        console.log(`ORACLE_SUBST_ZERO_IO=PASS DRIVE=${drive}:`);
      } finally {
        runCmd(`subst ${drive}: /D`);
      }
    } finally {
      scope.dispose();
    }
  });

  it('attests fixed local volumes only, refusing the mapped SMB device form', () => {
    // Real C: answers (recorded by the physical run): HarddiskVolume + FIXED.
    expect(attestsFixedLocalDrive('\\Device\\HarddiskVolume3', 3)).toBe(true);
    // Mapped network drive: the redirector device, never a volume device.
    expect(
      attestsFixedLocalDrive('\\Device\\LanmanRedirector\\;Q:0000000000123456\\server\\share', 4),
    ).toBe(false);
    expect(
      attestsFixedLocalDrive('\\Device\\LanmanRedirector\\;Q:0000000000123456\\server\\share', 3),
    ).toBe(false);
    // Subst alias and any other device namespace form.
    expect(attestsFixedLocalDrive('\\??\\C:\\some\\path', 3)).toBe(false);
    expect(attestsFixedLocalDrive('\\Device\\CdRom0', 5)).toBe(false);
    expect(attestsFixedLocalDrive(null, 3)).toBe(false);
    expect(attestsFixedLocalDrive('', 3)).toBe(false);
    expect(attestsFixedLocalDrive('\\Device\\HarddiskVolume3', 4)).toBe(false);
    expect(attestsFixedLocalDrive('\\Device\\HarddiskVolume3', null)).toBe(false);
    console.log('ORACLE_DRIVE_ATTESTATION_MATRIX=PASS');
  });

  it('fails closed with zero opens on a real mapped SMB drive when one is provided', () => {
    const smbRoot = process.env.SHUN_T04_SMB_DRIVE_ROOT;
    if (!smbRoot) {
      // Honest boundary: this workstation provides no mapped SMB drive
      // (root-caused in the evidence doc). The falsifier below runs wherever
      // a real mapped drive IS provided.
      console.log('ORACLE_SMB_MAPPED_ZERO_IO=SKIPPED_NO_SMB_DRIVE_PROVIDED');
      return;
    }
    const log: OpenLog = { dirs: [], files: [], stages: [] };
    const result = captureOracleWalk(smbRoot, '*.txt', instrument(log));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('ORACLE_SCOPE_REFUSED');
    expect(log.dirs).toEqual([]);
    expect(log.files).toEqual([]);
    expect(log.stages.some((stage) => stage.startsWith('REFUSED:drive-attestation'))).toBe(true);
    console.log('ORACLE_SMB_MAPPED_ZERO_IO=PASS ROOT_PROVIDED=yes');
  });

  it('never verifies a foreign world while the ancestor and an in-tree directory are concurrently swapped', async () => {
    const base = mkdtempSync(join(tmpdir(), 'shun-oracle-race-'));
    const holder = join(base, 'holder');
    const outside = join(base, 'outside');
    const anchor = join(base, 'A');
    mkdirSync(join(holder, 'scope', 'inner'), { recursive: true });
    mkdirSync(join(outside, 'scope'), { recursive: true });
    writeFileSync(join(holder, 'scope', 'a.txt'), 'real-alpha');
    writeFileSync(join(holder, 'scope', 'inner', 'b.txt'), 'real-bravo');
    writeFileSync(join(holder, 'scope', 'skip.log'), 'real-log');
    // The mirror carries the SAME names plus an extra matching file: any
    // oracle exposure to it must be mechanically visible.
    writeFileSync(join(outside, 'scope', 'a.txt'), 'MIRROR-alpha');
    writeFileSync(join(outside, 'scope', 'inner.txt'), 'MIRROR-inner');
    writeFileSync(join(outside, 'scope', 'skip.log'), 'MIRROR-log');

    const cleanLog: OpenLog = { dirs: [], files: [], stages: [] };
    let cleanLines: readonly string[] = [];
    const clean = captureOracleWalk(join(holder, 'scope'), '*.txt', {
      ...instrument(cleanLog),
      onWalkLines: (lines) => {
        cleanLines = lines;
      },
    });
    expect(clean.ok).toBe(true);
    const cleanMatches = clean.ok ? clean.walk.matches : [];
    expect(cleanMatches).toEqual(['a.txt', join('inner', 'b.txt')].sort());
    // Fingerprint lines of the actively toggled inner subtree are excluded
    // (it legitimately appears as real/junction/absent across the race);
    // every other line must be byte-identical to the clean walk.
    const stableLines = (lines: readonly string[]) =>
      lines.filter((line) => !/^[df]\tinner(\t|\\|$)/.test(line)).sort();
    const cleanLinesStable = stableLines(cleanLines);

    symlinkSync(outside, anchor, 'junction');
    const child = spawn(
      process.execPath,
      ['--experimental-transform-types', 'test/helpers/race-swapper-child.ts', base, '4000'],
      { cwd: here, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    let oks = 0;
    let refusals = 0;
    let foreignWorld: string | null = null;
    let matchDrift: string | null = null;
    try {
      for (;;) {
        let walkedLines: readonly string[] = [];
        const result = captureOracleWalk(join(anchor, 'scope'), '*.txt', {
          onWalkLines: (lines) => {
            walkedLines = lines;
          },
        });
        if (result.ok) {
          oks++;
          // Every admitted walk saw the REAL world: outside the actively
          // toggled inner subtree the identity lines are byte-identical to
          // the clean walk — a mirror exposure or a mixed world would change
          // a.txt/skip.log lines or add inner.txt.
          const walkedStable = stableLines(walkedLines);
          const drifted =
            walkedStable.length !== cleanLinesStable.length ||
            walkedStable.some((line, index) => line !== cleanLinesStable[index]);
          if (drifted && foreignWorld === null) {
            foreignWorld = walkedLines.join('\n');
            console.log('RACE_DRIFT_CLEAN:', JSON.stringify(cleanLinesStable));
            console.log('RACE_DRIFT_SEEN:', JSON.stringify(walkedStable));
          }
          if (
            matchDrift === null &&
            !(
              result.walk.matches.length === cleanMatches.length ||
              // The inner subtree legitimately appears absent mid-recreation;
              // any other deviation (e.g. the mirror's inner.txt) is foreign.
              (result.walk.matches.length === cleanMatches.length - 1 &&
                result.walk.matches.every((match) => cleanMatches.includes(match)))
            )
          )
            matchDrift = result.walk.matches.join('|');
        } else {
          refusals++;
        }
        if (child.exitCode !== null || child.signalCode !== null) break;
        if (refusals + oks > 4000) break;
      }
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await new Promise<void>((resolveExit) => {
        if (child.exitCode !== null || child.signalCode !== null) return resolveExit();
        child.once('close', () => resolveExit());
      });
    }
    expect(foreignWorld).toBeNull();
    expect(matchDrift).toBeNull();
    expect(oks).toBeGreaterThan(0);
    console.log(
      `ORACLE_RACE_NO_FOREIGN_WORLD=PASS OK=${oks} REFUSED=${refusals} SWAP_RACE_EXERCISED=${refusals > 0}`,
    );

    // After the swapper settles the real tree verifies cleanly again (the
    // recreated inner directory legitimately carries a new file identity).
    if (existsSync(anchor)) {
      if (lstatSync(anchor).isSymbolicLink()) rmSync(anchor);
      else renameSync(anchor, holder);
    }
    const settled = captureOracleWalk(join(holder, 'scope'), '*.txt');
    expect(settled.ok).toBe(true);
    if (settled.ok) expect(settled.walk.matches).toEqual(cleanMatches);
    rmSync(base, { recursive: true, force: true });
  }, 30_000);

  it('binds the task semantic verdict to the content fingerprint, refusing a size/mtime-preserving swap', () => {
    const scope = makeScope('shun-oracle-swap', { 'scope/a.txt': 'aaaa' });
    const store = new ShunStore({ file: join(scope.dir, 'phase.sqlite') });
    try {
      const rootNative = join(scope.dir, 'scope');
      const rootForward = rootNative.split('\\').join('/');
      const action = AuthorizedActionSchema.parse({
        taskId: 'task-swap',
        actionId: 'swap-1',
        planHash: 'a'.repeat(64),
        policySnapshotRevision: 'policy-1',
        authorizationKind: 'AUTOMATIC',
        authorizationRef: 'grant-1',
        action: {
          actionId: 'swap-1',
          bindingRef: 'binding-1',
          op: 'file.search',
          parameters: { root: rootForward, query: '*.txt' },
          sideEffectClass: 'R0',
          requiredPrivilege: 'USER',
          filesystemScope: { read: [rootForward], write: [] },
        },
      });
      const journal = new SqliteR0EffectJournal(store);
      expect(journal.reserve(action)).toMatchObject({ ok: true });

      const clean = captureOracleWalk(rootNative, '*.txt');
      expect(clean.ok).toBe(true);
      if (!clean.ok) return;
      const fingerprint = clean.walk.fingerprint;
      const recorded = journal.recordEffectPhase(action, {
        expectedStateSha256: fingerprint,
        observationSha256: 'b'.repeat(64),
        postStateSha256: fingerprint,
      });
      expect(recorded.ok).toBe(true);
      const phaseDigest = recorded.ok ? recorded.phaseReceiptSha256 : '';

      const receipt = ExecutionReceiptSchema.parse({
        actionId: action.actionId,
        environmentId: 'local-windows-user',
        providerId: 'shun-win32-r0-native',
        providerVersion: '0.2.0',
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        terminal: 'SUCCEEDED',
        outputRefs: [],
        sideEffectEvidence: {
          sideEffectClass: 'R0',
          recoveryClassification: 'COMPLETED_VERIFIED',
          postStateVerified: true,
          journalRef: `recipe_r0_effect_phase_v02:${phaseDigest}`,
        },
      });
      const observationDigest = createHash('sha256').update(canonicalJson(receipt)).digest('hex');
      expect(
        journal.recordObservation(action, 'OBSERVED_NOT_SEMANTICALLY_VERIFIED', observationDigest),
      ).toBe(true);
      const evidence = {
        effectObserved: true,
        fingerprintUnchanged: true,
        independentMatchesEqual: true,
        inspectedEntries: clean.walk.inspectedEntries,
        matchedCount: clean.walk.matches.length,
        verificationTimeIso: new Date().toISOString(),
        postStateSha256: fingerprint,
      };
      // Positive control: with the world unchanged the chain is all green.
      expect(verifyR0SearchTaskSemantics({ action, journal, receipt, evidence })).toMatchObject({
        ok: true,
        taskSemantic: 'PASS',
      });

      // Swap the file content under identical name/size/mtime.
      const stamp = new Date('2020-05-06T07:08:09.012Z');
      utimesSync(join(rootNative, 'a.txt'), stamp, stamp);
      writeFileSync(join(rootNative, 'a.txt'), 'bbbb');
      utimesSync(join(rootNative, 'a.txt'), stamp, stamp);
      const swapped = captureOracleWalk(rootNative, '*.txt');
      expect(swapped.ok).toBe(true);
      if (swapped.ok) {
        expect(swapped.walk.fingerprint).not.toBe(fingerprint);
        expect(swapped.walk.matches).toEqual(clean.walk.matches);
      }
      // The verifier refuses: the fresh identity fingerprint no longer
      // equals the effect-time post-state commitment.
      expect(verifyR0SearchTaskSemantics({ action, journal, receipt, evidence })).toMatchObject({
        ok: false,
        taskSemantic: 'UNCERTAIN',
        code: 'SEMANTIC_EXPECTATION_MISMATCH',
      });
      console.log('ORACLE_CONTENT_SWAP_REFUSED_BY_SEMANTIC_VERIFIER=PASS');
    } finally {
      store.close();
      scope.dispose();
    }
  });
});
