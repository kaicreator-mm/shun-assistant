// T04 N-2 — windows.proc.exec program BYTE identity (the C12 audit's actual
// negative recipe). The plan hash binds the program PATH string only, the
// grant-scope preflight deliberately exempts the program ("plan-pinned
// infrastructure"), and the interpreter merely statSync+spawn: replacing the
// executable's bytes at the same path after the grant leaves the plan hash
// untouched and the privileged helper would elevate and run the substitute.
//
// Fix shape (inside the write set, no frozen-contract change):
//   launcher preflight (BEFORE any UAC work): resolve the program to its
//   canonical real path, measure sha256, record it in the authority store
//   keyed by that path (ProgramPin — "no pin = unpinned");
//   helper (pre-journal): re-canonicalize + re-measure and REQUIRE a matching
//   pin — pin missing or bytes changed ⇒ REFUSED with NOTHING written (no
//   journal, no receipt, no effect).
//
// Honest boundary (documented, not hidden): bytes swapped BEFORE the
// launcher's preflight are pinned AS-SWAPPED — the pin attests what was
// measured at provisioning time, and that identity lands in the journal
// evidence. Attackers who can win that race are same-user attackers who can
// also rewrite the authority store itself: the C06 open boundary, escalated;
// no in-write-set mechanism claims to close it.
import { copyFileSync, existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { writeEnvelopeFile } from '../src/envelope.ts';
import { journalPhases, readJournal } from '../src/journal.ts';
import { PrivilegedWindowsExecutionBackend } from '../src/privileged-backend.ts';
import { canonicalProgramPath, pinProgram, verifyPinnedProgram } from '../src/program-pinning.ts';
import { readProgramPin } from '../src/trusted-store.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  IS_ELEVATED_HOST,
  ON_WINDOWS,
  runHelperDirectly,
  type TestAuthority,
} from './helpers.ts';

/** A real executable COPY whose bytes the test controls (overwrite freely). */
function executableCopy(authority: TestAuthority, name: string): string {
  const copy = join(authority.workspaceRoot, name);
  writeFileSync(copy, 'placeholder — overwritten by pinProgram/verify tests', 'utf8');
  return copy;
}

describe('N-2 — program identity pin core (canonical path + measured bytes)', () => {
  const created: string[] = [];
  afterAll(() => {
    for (const dir of created) rmSync(dir, { recursive: true, force: true });
  });

  it('pinProgram records the measured bytes keyed by the canonical path', async () => {
    const authority = await createTestAuthority('shun-n2-core-');
    created.push(authority.root);
    const program = join(authority.workspaceRoot, 'tool.exe');
    writeFileSync(program, 'version-1-bytes', 'utf8');
    const pinned = pinProgram(authority.authorityDir, program);
    expect(pinned.ok).toBe(true);
    if (!pinned.ok) return;
    const record = readProgramPin(authority.authorityDir, pinned.canonicalPath);
    expect(record).toBeDefined();
    expect(record?.programSha256).toBe(await shaOf(program));
    expect(record?.programPath.toLowerCase()).toBe(pinned.canonicalPath.toLowerCase());
  });

  it('verifyPinnedProgram passes unchanged bytes and REFUSES replaced bytes', async () => {
    const authority = await createTestAuthority('shun-n2-swap-');
    created.push(authority.root);
    const program = join(authority.workspaceRoot, 'tool.exe');
    writeFileSync(program, 'version-1-bytes', 'utf8');
    expect(pinProgram(authority.authorityDir, program).ok).toBe(true);

    const ok = verifyPinnedProgram(authority.authorityDir, program);
    expect(ok.ok).toBe(true);

    // The audit's negative recipe: same path, different bytes, after the grant.
    writeFileSync(program, 'attacker-substitute-bytes', 'utf8');
    const bad = verifyPinnedProgram(authority.authorityDir, program);
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.reason).toContain('identity');
  });

  it('verifyPinnedProgram fails closed when NO pin exists for the path', async () => {
    const authority = await createTestAuthority('shun-n2-nopin-');
    created.push(authority.root);
    const program = join(authority.workspaceRoot, 'unpinned.exe');
    writeFileSync(program, 'never-pinned', 'utf8');
    const verdict = verifyPinnedProgram(authority.authorityDir, program);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) expect(verdict.reason).toContain('pin');
  });

  it('canonicalProgramPath refuses missing files and non-files', async () => {
    const authority = await createTestAuthority('shun-n2-canon-');
    created.push(authority.root);
    const missing = canonicalProgramPath(join(authority.workspaceRoot, 'no-such.exe'));
    expect(missing.ok).toBe(false);
    const dir = join(authority.workspaceRoot, 'a-directory');
    mkdirSync(dir, { recursive: true });
    const notFile = canonicalProgramPath(dir);
    expect(notFile.ok).toBe(false);
  });
});

describe.skipIf(!ON_WINDOWS)('N-2 — privileged helper enforces the pin (real helper)', () => {
  let authority: TestAuthority;
  let workspace: string;

  beforeAll(async () => {
    authority = await createTestAuthority('shun-n2-');
    workspace = join(authority.workspaceRoot, 'runs');
    mkdirSync(workspace, { recursive: true });
  });

  afterAll(() => disposeTestAuthority(authority));

  /** A real Windows executable copy (whoami.exe) the tests can overwrite. */
  function toolCopy(name: string, content?: string): string {
    const copy = join(authority.workspaceRoot, name);
    if (content !== undefined) {
      writeFileSync(copy, content, 'utf8');
    } else {
      copyFileSync(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'whoami.exe'), copy);
    }
    return copy;
  }

  function procExecEnvelope(program: string, args: string[] = []) {
    const built = buildAuthorizedAction(authority, {
      op: 'windows.proc.exec',
      parameters: { program, args, expectExitCode: 0 },
      requiredPrivilege: 'ELEVATED',
      sideEffectClass: 'R2',
    });
    const runDir = join(workspace, `n2-${Math.random().toString(36).slice(2)}`);
    mkdirSync(runDir, { recursive: true });
    const journalFile = join(runDir, 'journal.jsonl');
    const receiptFile = join(runDir, 'receipt.json');
    writeEnvelopeFile(join(runDir, 'envelope.json'), {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: { journalFile, receiptFile, evidenceDir: join(runDir, 'evidence') },
    });
    return { built, runDir, envelopeFile: join(runDir, 'envelope.json'), journalFile, receiptFile };
  }

  it('helper refuses an UNPINNED program pre-journal — no journal, no receipt, no effect', () => {
    const program = executableCopy(authority, 'n2-unpinned-tool.exe');
    const env = procExecEnvelope(program);
    const run = runHelperDirectly(authority, env.envelopeFile, env.journalFile, env.receiptFile);
    expect(run.exitCode).toBe(2);
    expect(run.stderr).toContain('pin');
    expect(existsSync(env.journalFile)).toBe(false);
    expect(existsSync(env.receiptFile)).toBe(false);
  });

  it('helper refuses a program whose bytes were REPLACED after pinning — nothing written', () => {
    const program = toolCopy('n2-swap-tool.exe');
    expect(pinProgram(authority.authorityDir, program).ok).toBe(true);
    // Same path, different bytes, after the (launcher) pin: the audit recipe.
    writeFileSync(program, 'totally not an executable — attacker substitute', 'utf8');
    const env = procExecEnvelope(program);
    const run = runHelperDirectly(authority, env.envelopeFile, env.journalFile, env.receiptFile);
    expect(run.exitCode).toBe(2);
    expect(run.stderr).toContain('identity');
    expect(existsSync(env.journalFile)).toBe(false);
    expect(existsSync(env.receiptFile)).toBe(false);
  });

  it('a pinned, unchanged program passes the pre-journal identity check (journal opens)', () => {
    // node.exe itself: pinned unchanged, and on an elevated host it executes
    // successfully (exit 0), proving the gate is a pass-through, not a blocker.
    const program = process.execPath;
    expect(pinProgram(authority.authorityDir, program).ok).toBe(true);
    const env = procExecEnvelope(program, ['-e', 'process.exit(0)']);
    const run = runHelperDirectly(authority, env.envelopeFile, env.journalFile, env.receiptFile);
    // The identity gate passed: the journal opened (identity recorded at
    // EXEC_START). What follows is host-dependent: a filtered token refuses
    // the ELEVATED action at elevation consistency; an elevated host executes.
    expect(existsSync(env.journalFile)).toBe(true);
    expect(journalPhases(readJournal(env.journalFile))).toContain('RECEIVED');
    if (IS_ELEVATED_HOST) {
      expect(run.exitCode).toBe(0);
    } else {
      expect(run.exitCode).toBe(2);
      expect(run.receipt).toBeDefined();
    }
  });

  it('launcher preflight refuses a MISSING program before any UAC/relay artifact', async () => {
    const program = join(authority.workspaceRoot, 'never-existed.exe');
    const { built } = procExecEnvelope(program);
    const backend = new PrivilegedWindowsExecutionBackend({
      authorityDir: authority.authorityDir,
      workspaceRoot: workspace,
      uacGraceMs: 0,
    });
    const receipt = await backend.execute(built.action, built.grant);
    expect(receipt.terminal).toBe('REFUSED');
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('NOT_STARTED');
    // No privileged artifacts at all: refusal precedes envelope/journal/relay.
    const runsDir = join(workspace, 'executions');
    if (existsSync(runsDir)) {
      for (const entry of readdirSync(runsDir)) {
        const files = readdirSync(join(runsDir, entry));
        expect(files).not.toContain('relay.json');
        expect(files).not.toContain('journal.jsonl');
      }
    }
  });
});

async function shaOf(file: string): Promise<string> {
  const { createHash } = await import('node:crypto');
  const { readFileSync } = await import('node:fs');
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}
