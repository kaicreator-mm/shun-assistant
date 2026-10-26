// T07 F04B2 falsifiers: the durable pre-effect checkpoint inside the
// physical mutation bridge (F04B2a) and the read-only independent poststate
// verifier (F04B2b). The bridge must persist the immutable commitment
// (source 64-bit FileId/volume/size/full SHA256 + destination-absence
// prestate) BEFORE the first destination IO exists, refuse when the durable
// write refuses, refuse when the source drifted after the checkpoint, and
// never call the checkpoint for an already-colliding destination. The
// authorized entry REQUIRES the checkpoints (PR #186 R1 P1-01). The
// poststate verifier must independently reopen BOTH verified parent chains
// and classify the world against the commitment — the ceiling is
// CONSISTENT_* / UNKNOWN because a single snapshot cannot witness THIS
// attempt's causality (PR #186 R1 P1-03), absence is a kernel verdict only
// (PR #186 R1 P1-02), and UNKNOWN wherever evidence is insufficient.
// Structural negatives run everywhere; physical canaries run on real
// Windows Standard User.
import { spawn, spawnSync } from 'node:child_process';
import {
  appendFileSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  executeAuthorizedFileMutation,
  executeVerifiedFileMutation,
  type FileMutationCheckpoints,
  type FileMutationInstrument,
  type FileMutationPrecommitment,
} from '../src/file-mutation-host.ts';
import {
  admittedPoststatePrecommitment,
  classifyPoststate,
  observeFileMutationPoststate,
} from '../src/file-mutation-poststate.ts';
import * as publicApi from '../src/index.ts';

const SYSTEM32 = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32');
const POWERSHELL = join(
  process.env.SystemRoot ?? 'C:\\Windows',
  'System32',
  'WindowsPowerShell',
  'v1.0',
  'powershell.exe',
);

function runCmd(command: string) {
  return spawnSync(join(SYSTEM32, 'cmd.exe'), ['/d', '/c', command], {
    encoding: 'utf8',
    windowsVerbatimArguments: true,
  });
}

/** True when an exclusive (FileShare::None) holder owns `path`: a probe
 * open with ReadWrite/None fails exactly while the holder keeps it. */
function probeExclusivelyLocked(path: string): boolean {
  const probe = spawnSync(
    POWERSHELL,
    [
      '-NoProfile',
      '-Command',
      `try { $f=[System.IO.File]::Open('${path}','Open','ReadWrite','None'); $f.Close(); exit 0 } catch { exit 1 }`,
    ],
    { encoding: 'utf8', windowsHide: true },
  );
  return probe.status === 1;
}

function waitFor(predicate: () => boolean, timeoutMs: number): boolean {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return true;
    if (Date.now() >= deadline) return false;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
  }
}

/** Hold `path` exclusively (FileShare::None) for the remainder of the test.
 * A NORMAL child (NOT detached/unref'd): on this Windows host a detached
 * PowerShell child dies before acquiring the handle, while a piped child
 * holds it immediately. The holder writes `marker` ONLY AFTER the open
 * succeeded, so waiting for the marker proves acquisition without polling
 * PowerShell probes (cold starts under load can take seconds). The caller
 * must stopHolder() it in finally. */
function holdExclusively(
  path: string,
  marker: string,
): { holder: ReturnType<typeof spawn>; marker: string } {
  const holder = spawn(
    POWERSHELL,
    [
      '-NoProfile',
      '-Command',
      `$f=[System.IO.File]::Open('${path}','Open','Read','None'); Set-Content -Path '${marker}' -Value ok; Start-Sleep -Seconds 60; $f.Close()`,
    ],
    { stdio: 'ignore', windowsHide: true },
  );
  return { holder, marker };
}

/** Wait for the holder's acquisition marker (plain fs poll). */
function waitForLockMarker(marker: string): boolean {
  return waitFor(() => existsSync(marker), 30_000);
}

/** Kill the holder and wait until the exclusive handle is really gone:
 * TerminateProcess is asynchronous, and disposing the scope folder while
 * the kernel still owns the handle fails with EPERM. */
function stopHolder(holder: ReturnType<typeof spawn>, path: string): void {
  try {
    holder.kill();
  } catch {
    // Already exited; nothing to release.
  }
  waitFor(() => !probeExclusivelyLocked(path), 15_000);
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

type IoLog = { destCreates: string[]; renames: string[]; stages: string[] };

function instrument(log: IoLog): FileMutationInstrument {
  return {
    onStage: (stage, detail) => log.stages.push(`${stage}:${detail}`),
    onDestCreate: (rel) => log.destCreates.push(rel),
    onRename: (from, to) => log.renames.push(`${from}>${to}`),
  };
}

/** Minimal structurally valid AuthorizedAction literal for one mutation. */
function mutationAction(input: {
  op: 'file.copy' | 'file.move' | 'file.rename';
  sourcePath: string;
  destinationPath: string;
}): Record<string, unknown> {
  const sourceDir = input.sourcePath.slice(0, input.sourcePath.lastIndexOf('\\'));
  const destDir = input.destinationPath.slice(0, input.destinationPath.lastIndexOf('\\'));
  const write =
    input.op === 'file.copy'
      ? [destDir]
      : [...new Set([sourceDir, destDir].map((d) => d.toLowerCase()))].sort();
  return {
    taskId: 'task-f04b2',
    actionId: 'mut-1',
    planHash: 'a'.repeat(64),
    policySnapshotRevision: 'policy-1',
    authorizationKind: 'DURABLE_POLICY',
    authorizationRef: 'grant-1',
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    action: {
      actionId: 'mut-1',
      bindingRef: 'binding-1',
      op: input.op,
      parameters: { sourcePath: input.sourcePath, destinationPath: input.destinationPath },
      sideEffectClass: 'R2',
      requiredPrivilege: 'USER',
      filesystemScope: { read: [sourceDir], write },
    },
  };
}

function mutationRequest(
  op: 'file.copy' | 'file.move' | 'file.rename',
  source: string,
  dest: string,
): Record<string, unknown> {
  return { op, sourcePath: source, destinationPath: dest };
}

/** A commitment fixture bound to literal in-scope paths. */
function commitmentFixture(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'file-mutation-precommit-v1',
    actionId: 'mut-1',
    op: 'file.copy',
    sourcePath: 'C:\\s\\a.txt',
    destinationPath: 'C:\\d\\b.txt',
    source: { fileId: '123456789', volumeSerial: 1918219760, size: 3, sha256: 'b'.repeat(64) },
    destinationPrestate: { destinationExisted: false },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Platform-neutral structural admission (CI-safe: zero IO).
// ---------------------------------------------------------------------------

describe('T07 F04B2 structural admission (no IO)', () => {
  it('exports no checkpoint or poststate surface through the package public API', () => {
    expect(Object.hasOwn(publicApi, 'executeAuthorizedFileMutation')).toBe(false);
    expect(Object.hasOwn(publicApi, 'observeFileMutationPoststate')).toBe(false);
    expect(Object.hasOwn(publicApi, 'executeVerifiedFileMutation')).toBe(false);
  });

  it('refuses a missing or malformed checkpoints object before any IO (P1-01)', () => {
    // PR #186 R1 P1-01: the authorized production entry REQUIRES the durable
    // precommit checkpoints. An absent (one-argument legacy F03 composition)
    // or malformed object refuses structurally with zero IO.
    const action = mutationAction({
      op: 'file.copy',
      sourcePath: 'C:\\s\\a.txt',
      destinationPath: 'C:\\d\\b.txt',
    });
    const bad: unknown[] = [
      undefined,
      null,
      42,
      {},
      { durablePrecommit: 'not-a-function' },
      { durablePrecommit: () => true, extra: 1 },
      new Proxy({ durablePrecommit: () => true }, {}),
    ];
    for (const malformed of bad) {
      expect(executeAuthorizedFileMutation(action, malformed as FileMutationCheckpoints)).toEqual({
        ok: false,
        code: 'FILE_MUTATION_AUTHORIZATION_REFUSED',
      });
    }
  });

  it('admits only exact commitment shapes at the poststate gate', () => {
    expect(admittedPoststatePrecommitment(commitmentFixture()) !== null).toBe(true);
    const bad: unknown[] = [
      null,
      42,
      'commitment',
      commitmentFixture({ kind: 'file-mutation-precommit-v2' }),
      commitmentFixture({ actionId: '' }),
      commitmentFixture({ op: 'files.duplicates.observe' }),
      commitmentFixture({ sourcePath: '\\\\server\\share\\a.txt' }),
      commitmentFixture({ sourcePath: 'C:\\s\\a.txt\\' }),
      commitmentFixture({ destinationPath: 'C:\\d\\b.txt:hidden' }),
      commitmentFixture({ sourcePath: 'C:\\s\\a.txt', destinationPath: 'c:\\s\\a.txt' }),
      commitmentFixture({ source: { fileId: '123', volumeSerial: 1, size: 3, sha256: 'b' } }),
      commitmentFixture({
        source: { fileId: '12x', volumeSerial: 1, size: 3, sha256: 'b'.repeat(64) },
      }),
      commitmentFixture({
        source: { fileId: '123', volumeSerial: -1, size: 3, sha256: 'b'.repeat(64) },
      }),
      commitmentFixture({
        source: { fileId: '123', volumeSerial: 1, size: 8 << 21, sha256: 'b'.repeat(64) },
      }),
      commitmentFixture({ destinationPrestate: { destinationExisted: true } }),
      commitmentFixture({ destinationPrestate: {} }),
      { ...commitmentFixture(), extra: 1 },
    ];
    for (const malformed of bad) {
      expect(admittedPoststatePrecommitment(malformed)).toBeNull();
    }
  });

  it('refuses a non-Windows platform and malformed precommit shapes without IO', () => {
    // The shape gate runs before the platform/native gates on every
    // platform; on non-Windows a structurally valid commitment then hits
    // the fail-closed platform gate (Linux CI control for the entry).
    expect(observeFileMutationPoststate({ nope: true })).toEqual({
      ok: false,
      code: 'POSTSTATE_PRECOMMIT_REFUSED',
    });
    expect(observeFileMutationPoststate(null)).toEqual({
      ok: false,
      code: 'POSTSTATE_PRECOMMIT_REFUSED',
    });
    if (process.platform !== 'win32') {
      expect(observeFileMutationPoststate(commitmentFixture())).toEqual({
        ok: false,
        code: 'POSTSTATE_NATIVE_UNAVAILABLE',
      });
    }
  });

  it('classifies the pure verdict matrix: no PROVEN exists, identity is not causality (P1-03)', () => {
    // PR #186 R1 P1-03: a single snapshot cannot witness that THIS attempt
    // caused the world. FileId continuity through a relocation is necessary
    // evidence but NOT a causality witness (an unrelated actor can perform
    // the same id-preserving move), so even the identity-continuous move
    // world caps at CONSISTENT_WITH_COMPLETION.
    const move = (
      o: Partial<{
        sourcePresent: boolean;
        destPresent: boolean;
        sourceMatches: boolean | null;
        destMatches: boolean | null;
        destIdentityContinuity: boolean | null;
      }>,
    ) =>
      classifyPoststate('file.move', {
        sourcePresent: false,
        destPresent: true,
        sourceMatches: null,
        destMatches: true,
        destIdentityContinuity: true,
        ...o,
      });
    // Move completion: identity-continuous destination, source name gone —
    // the honest ceiling is CONSISTENT, never PROVEN.
    expect(move({})).toBe('CONSISTENT_WITH_COMPLETION');
    expect(move({ destIdentityContinuity: false })).toBe('UNKNOWN');
    expect(move({ destMatches: false })).toBe('UNKNOWN');
    expect(move({ sourcePresent: true, destIdentityContinuity: null })).toBe('UNKNOWN');
    // A recreated same-byte destination (fresh FileId) is not even consistent.
    expect(move({ destIdentityContinuity: false, destMatches: true, sourcePresent: false })).toBe(
      'UNKNOWN',
    );
    // Hardlink-shaped world: identity at BOTH names is not a completed rename.
    expect(
      move({
        sourcePresent: true,
        sourceMatches: true,
        destPresent: true,
        destMatches: true,
        destIdentityContinuity: true,
      }),
    ).toBe('UNKNOWN');
    // Move not executed: committed object intact at its name, destination
    // kernel-confirmed absent — the ceiling is CONSISTENT (an unrelated
    // actor can have run the move and moved the same object back).
    expect(
      move({
        sourcePresent: true,
        sourceMatches: true,
        destPresent: false,
        destIdentityContinuity: null,
      }),
    ).toBe('CONSISTENT_WITH_NOT_EXECUTED');
    expect(move({ sourcePresent: true, sourceMatches: false, destPresent: false })).toBe('UNKNOWN');
    // Copy: identical bytes can never establish causality either.
    const copy = (
      o: Partial<{
        sourcePresent: boolean;
        destPresent: boolean;
        sourceMatches: boolean | null;
        destMatches: boolean | null;
      }>,
    ) =>
      classifyPoststate('file.copy', {
        sourcePresent: true,
        destPresent: true,
        sourceMatches: true,
        destMatches: true,
        destIdentityContinuity: null,
        ...o,
      });
    expect(copy({})).toBe('CONSISTENT_WITH_COMPLETION');
    expect(copy({ destPresent: false })).toBe('CONSISTENT_WITH_NOT_EXECUTED');
    expect(copy({ sourcePresent: false, sourceMatches: null })).toBe('UNKNOWN');
    expect(copy({ destMatches: false })).toBe('UNKNOWN');
    expect(copy({ sourceMatches: false, destPresent: false })).toBe('UNKNOWN');
  });
});

// ---------------------------------------------------------------------------
// Physical canaries (Windows Standard User).
// ---------------------------------------------------------------------------

describe.skipIf(process.platform !== 'win32')(
  'T07 F04B2a physical precommit checkpoint (Windows Standard User)',
  () => {
    it('persists the commitment BEFORE any destination IO, then completes the copy', () => {
      const scope = makeScope('shun-f04b2-cp', {
        'src/a.txt': 'CHECKPOINT-CONTENT',
        'out/.keep': '',
      });
      const log: IoLog = { destCreates: [], renames: [], stages: [] };
      const dest = join(scope.dir, 'out', 'b.txt');
      let captured: FileMutationPrecommitment | undefined;
      let destIoAtCheckpoint = -1;
      try {
        const checkpoints: FileMutationCheckpoints = {
          durablePrecommit: (commitment) => {
            captured = commitment;
            destIoAtCheckpoint = log.destCreates.length + log.renames.length;
            return true;
          },
        };
        const result = executeVerifiedFileMutation(
          mutationRequest('file.copy', join(scope.dir, 'src', 'a.txt'), dest),
          'mut-f04b2-cp',
          instrument(log),
          checkpoints,
        );
        expect(result.ok).toBe(true);
        // THE ordering proof: when the durable write ran, ZERO destination
        // IO had happened yet and the destination object did not exist.
        expect(destIoAtCheckpoint).toBe(0);
        expect(existsSync(dest)).toBe(true);
        expect(readFileSync(dest, 'utf8')).toBe('CHECKPOINT-CONTENT');
        // The commitment pins the exact physical facts of the source.
        expect(captured).toBeDefined();
        const c = captured as FileMutationPrecommitment;
        expect(c.kind).toBe('file-mutation-precommit-v1');
        expect(c.actionId).toBe('mut-f04b2-cp');
        expect(c.op).toBe('file.copy');
        expect(c.sourcePath).toBe(join(scope.dir, 'src', 'a.txt'));
        expect(c.destinationPath).toBe(dest);
        expect(c.source.size).toBe('CHECKPOINT-CONTENT'.length);
        expect(c.source.sha256).toMatch(/^[a-f0-9]{64}$/);
        expect(c.source.fileId).toMatch(/^\d{1,20}$/);
        expect(Number.isSafeInteger(c.source.volumeSerial)).toBe(true);
        expect(c.destinationPrestate).toEqual({ destinationExisted: false });
        expect(Object.isFrozen(c)).toBe(true);
        expect(Object.isFrozen(c.source)).toBe(true);
        expect(log.stages).toContain(`PRECOMMIT_DURABLE:${'CHECKPOINT-CONTENT'.length}B`);
        console.log('F04B2A_PRECOMMIT_BEFORE_DEST_IO=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses with ZERO destination IO when the durable write refuses', () => {
      const scope = makeScope('shun-f04b2-nw', { 'src/a.txt': 'WILL-NOT-LAND', 'out/.keep': '' });
      const log: IoLog = { destCreates: [], renames: [], stages: [] };
      const dest = join(scope.dir, 'out', 'b.txt');
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest('file.copy', join(scope.dir, 'src', 'a.txt'), dest),
          'mut-f04b2-nw',
          instrument(log),
          { durablePrecommit: () => false },
        );
        expect(result).toEqual({ ok: false, code: 'FILE_MUTATION_EFFECT_REFUSED' });
        expect(log.destCreates).toHaveLength(0);
        expect(log.renames).toHaveLength(0);
        expect(log.stages).not.toContain(expect.stringMatching(/^PRECOMMIT_DURABLE/));
        expect(existsSync(dest)).toBe(false);
        console.log('F04B2A_DURABLE_WRITE_REFUSED_ZERO_DEST_IO=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses with ZERO destination IO when the source drifted after the checkpoint', () => {
      // The adversarial window: a concurrent actor modifies the source
      // BETWEEN the durable checkpoint and the effect. The re-observation
      // through the SAME verified handle must refuse the mutation before
      // any destination IO exists (the attempt is then conservatively
      // UNCERTAIN at the journal layer — never silently retried).
      const scope = makeScope('shun-f04b2-dr', { 'src/a.txt': 'ORIGINAL', 'out/.keep': '' });
      const log: IoLog = { destCreates: [], renames: [], stages: [] };
      const source = join(scope.dir, 'src', 'a.txt');
      const dest = join(scope.dir, 'out', 'b.txt');
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest('file.copy', source, dest),
          'mut-f04b2-dr',
          instrument(log),
          {
            durablePrecommit: () => {
              appendFileSync(source, '-DRIFTED-BY-CONCURRENT-ACTOR');
              return true;
            },
          },
        );
        expect(result).toEqual({ ok: false, code: 'FILE_MUTATION_EFFECT_REFUSED' });
        expect(log.destCreates).toHaveLength(0);
        expect(log.renames).toHaveLength(0);
        expect(existsSync(dest)).toBe(false);
        expect(readFileSync(source, 'utf8')).toBe('ORIGINAL-DRIFTED-BY-CONCURRENT-ACTOR');
        console.log('F04B2A_POSTCHECKPOINT_SOURCE_DRIFT_REFUSED=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses an existing destination BEFORE any checkpoint write (no-overwrite preserved)', () => {
      const scope = makeScope('shun-f04b2-coll', {
        'src/a.txt': 'SOURCE',
        'dst/b.txt': 'PRE-EXISTING',
      });
      const log: IoLog = { destCreates: [], renames: [], stages: [] };
      let checkpointCalls = 0;
      try {
        const result = executeVerifiedFileMutation(
          mutationRequest(
            'file.copy',
            join(scope.dir, 'src', 'a.txt'),
            join(scope.dir, 'dst', 'b.txt'),
          ),
          'mut-f04b2-coll',
          instrument(log),
          {
            durablePrecommit: () => {
              checkpointCalls++;
              return true;
            },
          },
        );
        expect(result).toEqual({ ok: false, code: 'FILE_MUTATION_COLLISION_REFUSED' });
        expect(checkpointCalls).toBe(0);
        expect(log.destCreates).toHaveLength(0);
        expect(readFileSync(join(scope.dir, 'dst', 'b.txt'), 'utf8')).toBe('PRE-EXISTING');
        expect(readFileSync(join(scope.dir, 'src', 'a.txt'), 'utf8')).toBe('SOURCE');
        console.log('F04B2A_COLLISION_BEFORE_PRECOMMIT_ZERO_WRITES=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('completes a real move through the checkpointed authorized path', () => {
      const scope = makeScope('shun-f04b2-mv', { 'src/a.txt': 'MOVE-CONTENT', 'dst/.keep': '' });
      try {
        const action = mutationAction({
          op: 'file.move',
          sourcePath: join(scope.dir, 'src', 'a.txt'),
          destinationPath: join(scope.dir, 'dst', 'moved.txt'),
        });
        const result = executeAuthorizedFileMutation(action, { durablePrecommit: () => true });
        expect(result.ok).toBe(true);
        expect(readFileSync(join(scope.dir, 'dst', 'moved.txt'), 'utf8')).toBe('MOVE-CONTENT');
        expect(existsSync(join(scope.dir, 'src', 'a.txt'))).toBe(false);
        console.log('F04B2A_AUTHORIZED_MOVE_CHECKPOINTED=PASS');
      } finally {
        scope.dispose();
      }
    });
  },
);

describe.skipIf(process.platform !== 'win32')(
  'T07 F04B2b physical independent poststate (Windows Standard User)',
  () => {
    /** Capture a REAL commitment for on-disk files with zero effect: the
     * durable write observes the commitment and refuses the effect. */
    function captureCommitment(
      scope: { dir: string; dispose: () => void },
      op: 'file.copy' | 'file.move',
      sourceRel: string,
      destRel: string,
      owner: string,
    ): FileMutationPrecommitment {
      let captured: FileMutationPrecommitment | undefined;
      const result = executeVerifiedFileMutation(
        mutationRequest(op, join(scope.dir, sourceRel), join(scope.dir, destRel)),
        owner,
        {},
        {
          durablePrecommit: (commitment) => {
            captured = commitment;
            return false;
          },
        },
      );
      expect(result).toEqual({ ok: false, code: 'FILE_MUTATION_EFFECT_REFUSED' });
      expect(captured).toBeDefined();
      return captured as FileMutationPrecommitment;
    }

    it('CONSISTENT_WITH_COMPLETION (never PROVEN) when an UNRELATED actor relocated the committed object (P1-03)', () => {
      // PR #186 R1 P1-03 negative, relocation direction: the effect happens
      // OUTSIDE the checkpointed attempt — an unrelated actor performs the
      // same id-preserving relocation. The observed world (dest carries the
      // committed FileId, source name gone) is EXACTLY what this attempt
      // would have left, so identity continuity cannot witness causality:
      // the ceiling is CONSISTENT_WITH_COMPLETION and no PROVEN verdict
      // exists to return.
      const scope = makeScope('shun-f04b2-ps1', { 'src/a.txt': 'MOVE-ME', 'dst/.keep': '' });
      try {
        const commitment = captureCommitment(
          scope,
          'file.move',
          'src/a.txt',
          'dst/moved.txt',
          'mut-ps1',
        );
        const moved = executeVerifiedFileMutation(
          mutationRequest(
            'file.move',
            join(scope.dir, 'src', 'a.txt'),
            join(scope.dir, 'dst', 'moved.txt'),
          ),
          'mut-ps1-later',
        );
        expect(moved.ok).toBe(true);
        const result = observeFileMutationPoststate(commitment);
        expect(result).toMatchObject({ ok: true, verdict: 'CONSISTENT_WITH_COMPLETION' });
        if (result.ok) {
          expect(result.evidence.sourcePresent).toBe(false);
          expect(result.evidence.destPresent).toBe(true);
          expect(result.evidence.destIdentityContinuity).toBe(true);
          expect(result.evidence.destMatchesCommitment).toBe(true);
        }
        console.log('F04B2B_THIRD_PARTY_RELOCATION_CONSISTENT_NOT_PROVEN=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('CONSISTENT_WITH_COMPLETION for a completed copy (bytes cannot prove causality)', () => {
      const scope = makeScope('shun-f04b2-ps2', { 'src/a.txt': 'COPY-ME', 'dst/.keep': '' });
      try {
        const commitment = captureCommitment(
          scope,
          'file.copy',
          'src/a.txt',
          'dst/copied.txt',
          'mut-ps2',
        );
        const copied = executeVerifiedFileMutation(
          mutationRequest(
            'file.copy',
            join(scope.dir, 'src', 'a.txt'),
            join(scope.dir, 'dst', 'copied.txt'),
          ),
          'mut-ps2-later',
        );
        expect(copied.ok).toBe(true);
        const result = observeFileMutationPoststate(commitment);
        expect(result).toMatchObject({ ok: true, verdict: 'CONSISTENT_WITH_COMPLETION' });
        console.log('F04B2B_COPY_CONSISTENT_NOT_PROVEN=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('CONSISTENT_WITH_NOT_EXECUTED (never PROVEN) for an intact committed object and kernel-absent destination', () => {
      const scope = makeScope('shun-f04b2-ps3', { 'src/a.txt': 'STILL-HERE', 'dst/.keep': '' });
      try {
        const commitment = captureCommitment(
          scope,
          'file.move',
          'src/a.txt',
          'dst/moved.txt',
          'mut-ps3',
        );
        const result = observeFileMutationPoststate(commitment);
        expect(result).toMatchObject({ ok: true, verdict: 'CONSISTENT_WITH_NOT_EXECUTED' });
        if (result.ok) {
          expect(result.evidence.sourcePresent).toBe(true);
          expect(result.evidence.sourceMatchesCommitment).toBe(true);
          expect(result.evidence.destPresent).toBe(false);
        }
        console.log('F04B2B_MOVE_CONSISTENT_NOT_EXECUTED_KERNEL_ABSENCE=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('CONSISTENT_WITH_NOT_EXECUTED (never PROVEN) when the move RAN and an unrelated actor moved the object BACK (P1-03)', () => {
      // PR #186 R1 P1-03 negative, move-back direction: the relocation
      // really executes (here by an unrelated actor), then the SAME object
      // is relocated back to its original name — a same-volume rename that
      // preserves the FileId and every byte. The resulting world is
      // indistinguishable from "the attempt never ran", so the honest
      // verdict is CONSISTENT_WITH_NOT_EXECUTED and no PROVEN_NOT_EXECUTED
      // could ever be justified from this snapshot.
      const scope = makeScope('shun-f04b2-ps10', { 'src/a.txt': 'ROUND-TRIP', 'dst/.keep': '' });
      try {
        const commitment = captureCommitment(
          scope,
          'file.move',
          'src/a.txt',
          'dst/moved.txt',
          'mut-ps10',
        );
        const moved = executeVerifiedFileMutation(
          mutationRequest(
            'file.move',
            join(scope.dir, 'src', 'a.txt'),
            join(scope.dir, 'dst', 'moved.txt'),
          ),
          'mut-ps10-unrelated',
        );
        expect(moved.ok).toBe(true);
        // The unrelated actor undoes the relocation: same volume, same
        // object, original name.
        renameSync(join(scope.dir, 'dst', 'moved.txt'), join(scope.dir, 'src', 'a.txt'));
        const result = observeFileMutationPoststate(commitment);
        expect(result).toMatchObject({ ok: true, verdict: 'CONSISTENT_WITH_NOT_EXECUTED' });
        if (result.ok) {
          expect(result.evidence.sourcePresent).toBe(true);
          expect(result.evidence.sourceMatchesCommitment).toBe(true);
          expect(result.evidence.destPresent).toBe(false);
        }
        console.log('F04B2B_MOVE_BACK_WORLD_CONSISTENT_NOT_PROVEN=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses (no verdict at all) when an exclusive handle makes the EXISTING destination unopenable (P1-02)', () => {
      // PR #186 R1 P1-02 canary: a detached PowerShell process holds the
      // destination with FileShare::None. The destination EXISTS while the
      // original source exists and matches — the old null-only openFile
      // conflated the sharing violation with absence and minted a false
      // not-executed verdict. The status-aware observation must treat the
      // ambiguous failure as unobservable: the whole observation refuses,
      // and no CONSISTENT/PROVEN negative verdict is issued.
      const scope = makeScope('shun-f04b2-ps11', { 'src/a.txt': 'SOURCE-INTACT', 'dst/.keep': '' });
      let holder: ReturnType<typeof spawn> | null = null;
      let heldPath = '';
      try {
        const commitment = captureCommitment(
          scope,
          'file.move',
          'src/a.txt',
          'dst/moved.txt',
          'mut-ps11',
        );
        const dest = join(scope.dir, 'dst', 'moved.txt');
        writeFileSync(dest, 'PRESENT-BUT-LOCKED');
        heldPath = dest;
        const held = holdExclusively(dest, join(scope.dir, 'dst', 'held.marker'));
        holder = held.holder;
        expect(waitForLockMarker(held.marker)).toBe(true);
        // The lock is real: an incompatible probe open fails.
        expect(probeExclusivelyLocked(dest)).toBe(true);
        const result = observeFileMutationPoststate(commitment);
        expect(result).toEqual({ ok: false, code: 'POSTSTATE_OBSERVATION_REFUSED' });
        console.log('F04B2B_LOCKED_DEST_SHARING_VIOLATION_NO_NEGATIVE_VERDICT=PASS');
      } finally {
        if (holder !== null) stopHolder(holder, heldPath);
        scope.dispose();
      }
    }, 90_000);

    it('refuses (no verdict at all) when an exclusive handle makes the MATCHING source unopenable (P1-02)', () => {
      // PR #186 R1 P1-02 converse canary: the source exists and would match
      // its commitment, but an exclusive holder makes its open ambiguous.
      // With a matching destination present, the old conflated "absent"
      // reading of the source could have minted a false completion verdict;
      // the observation must refuse instead.
      const scope = makeScope('shun-f04b2-ps12', { 'src/a.txt': 'LOCKED-SOURCE', 'dst/.keep': '' });
      let holder: ReturnType<typeof spawn> | null = null;
      let heldPath = '';
      try {
        const commitment = captureCommitment(
          scope,
          'file.move',
          'src/a.txt',
          'dst/moved.txt',
          'mut-ps12',
        );
        const source = join(scope.dir, 'src', 'a.txt');
        heldPath = source;
        const held = holdExclusively(source, join(scope.dir, 'held.marker'));
        holder = held.holder;
        expect(waitForLockMarker(held.marker)).toBe(true);
        // The lock is real: an incompatible probe open fails.
        expect(probeExclusivelyLocked(source)).toBe(true);
        const result = observeFileMutationPoststate(commitment);
        expect(result).toEqual({ ok: false, code: 'POSTSTATE_OBSERVATION_REFUSED' });
        console.log('F04B2B_LOCKED_SOURCE_SHARING_VIOLATION_NO_VERDICT=PASS');
      } finally {
        if (holder !== null) stopHolder(holder, heldPath);
        scope.dispose();
      }
    }, 90_000);

    it('CONSISTENT_WITH_NOT_EXECUTED for an unexecuted copy (created-then-deleted race stays honest)', () => {
      const scope = makeScope('shun-f04b2-ps4', { 'src/a.txt': 'UNTOUCHED', 'dst/.keep': '' });
      try {
        const commitment = captureCommitment(
          scope,
          'file.copy',
          'src/a.txt',
          'dst/copied.txt',
          'mut-ps4',
        );
        const result = observeFileMutationPoststate(commitment);
        expect(result).toMatchObject({ ok: true, verdict: 'CONSISTENT_WITH_NOT_EXECUTED' });
        console.log('F04B2B_COPY_CONSISTENT_NOT_EXECUTED=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('UNKNOWN when the source drifted after the commitment', () => {
      const scope = makeScope('shun-f04b2-ps5', { 'src/a.txt': 'BEFORE', 'dst/.keep': '' });
      try {
        const commitment = captureCommitment(
          scope,
          'file.move',
          'src/a.txt',
          'dst/moved.txt',
          'mut-ps5',
        );
        appendFileSync(join(scope.dir, 'src', 'a.txt'), '-AFTER');
        const result = observeFileMutationPoststate(commitment);
        expect(result).toMatchObject({ ok: true, verdict: 'UNKNOWN' });
        console.log('F04B2B_SOURCE_DRIFT_UNKNOWN=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('UNKNOWN when an identical-byte destination was recreated with a fresh identity', () => {
      // The F04B2 admission's own falsifier: content match alone is NOT
      // proof of the original attempt. A separately recreated same-byte
      // destination (different FileId), with the original object gone,
      // must stay UNKNOWN for a move commitment.
      const scope = makeScope('shun-f04b2-ps6', { 'src/a.txt': 'TWIN-BYTES', 'dst/.keep': '' });
      try {
        const commitment = captureCommitment(
          scope,
          'file.move',
          'src/a.txt',
          'dst/moved.txt',
          'mut-ps6',
        );
        // Another actor "completes" the intent by copy+delete instead of
        // relocating the committed object.
        copyFileSync(join(scope.dir, 'src', 'a.txt'), join(scope.dir, 'dst', 'moved.txt'));
        rmSync(join(scope.dir, 'src', 'a.txt'));
        const result = observeFileMutationPoststate(commitment);
        expect(result).toMatchObject({ ok: true, verdict: 'UNKNOWN' });
        if (result.ok) expect(result.evidence.destIdentityContinuity).toBe(false);
        console.log('F04B2B_RECREATED_TWIN_BYTES_NOT_PROVEN=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('UNKNOWN when the destination grew past the committed exact length', () => {
      const scope = makeScope('shun-f04b2-ps7', { 'src/a.txt': 'EXACT', 'dst/.keep': '' });
      try {
        const commitment = captureCommitment(
          scope,
          'file.copy',
          'src/a.txt',
          'dst/copied.txt',
          'mut-ps7',
        );
        const copied = executeVerifiedFileMutation(
          mutationRequest(
            'file.copy',
            join(scope.dir, 'src', 'a.txt'),
            join(scope.dir, 'dst', 'copied.txt'),
          ),
          'mut-ps7-later',
        );
        expect(copied.ok).toBe(true);
        appendFileSync(join(scope.dir, 'dst', 'copied.txt'), 'TAIL');
        const result = observeFileMutationPoststate(commitment);
        expect(result).toMatchObject({ ok: true, verdict: 'UNKNOWN' });
        console.log('F04B2B_DEST_LONGER_THAN_COMMITTED_UNKNOWN=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('refuses a junction ancestor with zero leaf opens', () => {
      const scope = makeScope('shun-f04b2-ps8', { 'real/a.txt': 'CONTENT' });
      try {
        const junction = join(scope.dir, 'jn');
        runCmd(`mklink /J "${junction}" "${join(scope.dir, 'real')}"`);
        expect(existsSync(junction)).toBe(true);
        const commitment = captureCommitment(
          scope,
          'file.copy',
          'real/a.txt',
          'real/b.txt',
          'mut-ps8',
        );
        // The commitment's SOURCE path is re-spelled through the junction:
        // the verified-chain open must refuse the reparse alias before ANY
        // leaf object is opened.
        const throughJunction = {
          ...commitment,
          sourcePath: join(junction, 'a.txt'),
        } as Record<string, unknown>;
        let opens = 0;
        const result = observeFileMutationPoststate(throughJunction, {
          onSourceOpened: () => {
            opens++;
          },
          onDestOpened: () => {
            opens++;
          },
        });
        expect(result).toEqual({ ok: false, code: 'POSTSTATE_ALIAS_REFUSED' });
        expect(opens).toBe(0);
        console.log('F04B2B_JUNCTION_ANCESTOR_REFUSED_ZERO_LEAF_OPENS=PASS');
      } finally {
        scope.dispose();
      }
    });

    it('performs ZERO writes: a full observation leaves every byte and both identities intact', () => {
      const scope = makeScope('shun-f04b2-ps9', {
        'src/a.txt': 'FROZEN-SOURCE',
        'dst/b.txt': 'FROZEN-DEST',
      });
      try {
        const commitment = captureCommitment(
          scope,
          'file.copy',
          'src/a.txt',
          'dst/c.txt',
          'mut-ps9',
        );
        // Observe against a world where another file exists under an
        // unrelated name: the classification is the honest unexecuted-copy
        // verdict, and both files must be byte-identical afterwards with
        // the absent destination still absent.
        const result = observeFileMutationPoststate(commitment);
        expect(result).toMatchObject({ ok: true, verdict: 'CONSISTENT_WITH_NOT_EXECUTED' });
        expect(readFileSync(join(scope.dir, 'src', 'a.txt'), 'utf8')).toBe('FROZEN-SOURCE');
        expect(readFileSync(join(scope.dir, 'dst', 'b.txt'), 'utf8')).toBe('FROZEN-DEST');
        expect(existsSync(join(scope.dir, 'dst', 'c.txt'))).toBe(false);
        console.log('F04B2B_READ_ONLY_ZERO_WRITES=PASS');
      } finally {
        scope.dispose();
      }
    });
  },
);
