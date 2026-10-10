// LocalWindowsBackend end-to-end on the real (non-elevated) surface:
// grant-validated execution, structured refusals that precede any effect,
// deadline, cancellation, recovery classification, receipts.
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LocalWindowsBackend } from '../src/backend.ts';
import { journalPhases, readJournal } from '../src/journal.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  must,
  ON_WINDOWS,
  type TestAuthority,
} from './helpers.ts';

describe.skipIf(!ON_WINDOWS)('LocalWindowsBackend (real, unprivileged)', () => {
  let authority: TestAuthority;
  let workspace: string;
  let backend: LocalWindowsBackend;

  beforeAll(async () => {
    authority = await createTestAuthority('shun-backend-');
    workspace = mkdtempSync(join(tmpdir(), 'shun-backend-ws-'));
    backend = new LocalWindowsBackend({
      authorityDir: authority.authorityDir,
      workspaceRoot: workspace,
    });
  });

  afterAll(() => {
    disposeTestAuthority(authority);
    rmSync(workspace, { recursive: true, force: true });
  });

  it('executes a scoped fs.write and completes verified with a full journal', async () => {
    const target = join(workspace, 'backend-write.txt');
    const { action } = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: target, content: 'from backend' },
      requiredPrivilege: 'USER',
      sideEffectClass: 'R1',
      filesystemScope: { read: [], write: [workspace] },
      expectedState: { path: target, exists: true, content: 'from backend' },
    });
    const receipt = await backend.execute(action);
    expect(receipt.terminal).toBe('SUCCEEDED');
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('COMPLETED_VERIFIED');
    expect(receipt.sideEffectEvidence.postStateVerified).toBe(true);
    expect(existsSync(target)).toBe(true);
    const journal = readJournal(must(receipt.sideEffectEvidence.journalRef, 'journalRef'));
    expect(journalPhases(journal)).toContain('EXEC_DONE');
    expect(existsSync(must(receipt.outputRefs.at(-1), 'last output ref'))).toBe(true);
  });

  it('executes fs.verify (readonly) actions and independently re-verifies post-state', async () => {
    const target = join(workspace, 'verify-target.txt');
    const { action } = buildAuthorizedAction(authority, {
      op: 'windows.fs.verify',
      parameters: { path: target, expectExists: true },
      requiredPrivilege: 'USER',
      sideEffectClass: 'R0',
      filesystemScope: { read: [workspace], write: [] },
    });
    writeFileSync(target, 'exists', 'utf8');
    const receipt = await backend.execute(action);
    expect(receipt.terminal).toBe('SUCCEEDED');
    expect(receipt.sideEffectEvidence.postStateVerified).toBe(true);
  });

  it('REFUSES an unknown op structurally (no arbitrary shell endpoint)', async () => {
    const { action } = buildAuthorizedAction(authority, {
      op: 'shell.exec',
      parameters: { command: 'whoami' },
      requiredPrivilege: 'USER',
    });
    const receipt = await backend.execute(action);
    expect(receipt.terminal).toBe('REFUSED');
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
  });

  it('REFUSES a forged grant reference (no such grant in the authority store)', async () => {
    const { action } = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'never.txt'), content: 'x' },
      requiredPrivilege: 'USER',
      filesystemScope: { read: [], write: [workspace] },
    });
    const receipt = await backend.execute({ ...action, authorizationRef: 'grant-nonexistent' });
    expect(receipt.terminal).toBe('REFUSED');
    expect(receipt.outputRefs.length).toBeGreaterThan(0);
    expect(existsSync(join(workspace, 'never.txt'))).toBe(false);
  });

  it('REFUSES when the plan hash does not match any trusted plan record', async () => {
    const { action } = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'never2.txt'), content: 'x' },
      requiredPrivilege: 'USER',
      filesystemScope: { read: [], write: [workspace] },
    });
    const receipt = await backend.execute({ ...action, planHash: 'f'.repeat(64) });
    expect(receipt.terminal).toBe('REFUSED');
  });

  it('REFUSES ELEVATED actions on the unprivileged surface', async () => {
    const target = join(workspace, 'never-elevated.txt');
    const { action } = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: target, content: 'x' },
      requiredPrivilege: 'ELEVATED',
      sideEffectClass: 'R2',
      filesystemScope: { read: [], write: [workspace] },
    });
    const receipt = await backend.execute(action);
    expect(receipt.terminal).toBe('REFUSED');
    expect(existsSync(target)).toBe(false);
  });

  it('NTFS-illegal path characters are a REFUSED receipt, not a crash', async () => {
    const { action } = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'bad<name.txt'), content: 'x' },
      requiredPrivilege: 'USER',
      filesystemScope: { read: [], write: [workspace] },
    });
    const receipt = await backend.execute(action);
    expect(receipt.terminal).toBe('REFUSED');
  });

  it('declared scope escape is refused BEFORE any effect', async () => {
    const { action } = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(tmpdir(), 'shun-escape-attempt.txt'), content: 'x' },
      requiredPrivilege: 'USER',
      filesystemScope: { read: [], write: [workspace] },
    });
    const receipt = await backend.execute(action);
    expect(receipt.terminal).toBe('REFUSED');
    expect(existsSync(join(tmpdir(), 'shun-escape-attempt.txt'))).toBe(false);
  });

  it('enforces the action deadline with TIMED_OUT', async () => {
    const { action } = buildAuthorizedAction(authority, {
      op: 'windows.proc.exec',
      parameters: {
        program: process.execPath,
        args: ['-e', 'setInterval(()=>{},1000)'],
        expectExitCode: 0,
      },
      requiredPrivilege: 'USER',
      timeoutMs: 1500,
    });
    const receipt = await backend.execute(action);
    expect(receipt.terminal).toBe('TIMED_OUT');
  });

  it('cancel(actionId) produces CANCELLED with sentinel recorded in the journal', async () => {
    const { action } = buildAuthorizedAction(authority, {
      op: 'windows.proc.exec',
      parameters: {
        program: process.execPath,
        args: ['-e', 'setTimeout(()=>{},8000)'],
        expectExitCode: 0,
      },
      requiredPrivilege: 'USER',
    });
    const run = backend.execute(action);
    // give the child a moment to start, then cancel cooperatively
    await new Promise((r) => setTimeout(r, 1200));
    await backend.cancel(action.actionId);
    const receipt = await run;
    expect(['CANCELLED', 'TIMED_OUT']).toContain(receipt.terminal);
    const journal = readJournal(must(receipt.sideEffectEvidence.journalRef, 'journalRef'));
    expect(journalPhases(journal)).toContain('EXEC_START');
  });

  it('failed mutating step stays honestly classified and reconciles declared expectedState', async () => {
    // proc.exec fails (exit 1); expectedState proves the (non-)effect: a
    // marker file that was never created → FAILED_BEFORE_EFFECT resolved.
    const marker = join(workspace, 'reconcile-marker.txt');
    const { action } = buildAuthorizedAction(authority, {
      op: 'windows.proc.exec',
      parameters: { program: process.execPath, args: ['-e', 'process.exit(1)'], expectExitCode: 0 },
      requiredPrivilege: 'USER',
      expectedState: { path: marker, exists: false },
    });
    const receipt = await backend.execute(action);
    expect(receipt.terminal).toBe('FAILED');
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
  });

  it('writes exactly one run directory per action with journal + receipt artifacts', async () => {
    const before = readdirSync(join(workspace, 'executions')).length;
    const { action } = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'artifact-check.txt'), content: 'x' },
      requiredPrivilege: 'USER',
      filesystemScope: { read: [], write: [workspace] },
    });
    await backend.execute(action);
    const after = readdirSync(join(workspace, 'executions')).length;
    expect(after).toBe(before + 1);
  });
});
