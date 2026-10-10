// Issue #15 REQUIRED EVIDENCE — real Windows 11 / UAC runs.
//
// Gated behind SHUN_EXECUTOR_EVIDENCE=1 (see vitest.evidence.config.ts):
// these cases pop real secure-desktop UAC prompts and must never fire from
// `pnpm test` / CI. Artifacts land in evidence/<case>/ and are committed as
// the run's durable record (exact journals, receipts, relay files, summary).
//
// Cases:
//   E1  UAC positive — elevated HKLM registry lifecycle (consent required)
//   E1b UAC positive — elevated cleanup delete (consent required)
//   E2  UAC refusal — declined or consent-timeout → UAC_DECLINED +
//       empty journal + NOT_STARTED
//   E3  process kill inside the effect window → MAY_HAVE_EXECUTED_UNCERTAIN
//       (honest UNCERTAIN terminal; no UAC needed — the one-shot helper
//       process mechanics are the subject, not the launch seam)
//   E4  process kill + reconcile-first with declared expectedState → resolved
//   E5  typed metacharacters byte-exact across the privilege boundary
//       (elevated fs.write; consent required)
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { writeEnvelopeFile } from '../../src/envelope.ts';
import type { InterpreterScope } from '../../src/interpreter.ts';
import { JournalWriter, journalPhases, readJournal } from '../../src/journal.ts';
import { reconcileExpectedState } from '../../src/poststate.ts';
import { PrivilegedWindowsExecutionBackend } from '../../src/privileged-backend.ts';
import { classifyRecovery, terminalForClassification } from '../../src/recovery.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  must,
  type TestAuthority,
} from '../helpers.ts';

const EVIDENCE = process.env.SHUN_EXECUTOR_EVIDENCE === '1';
const GATED = !EVIDENCE || process.platform !== 'win32';
const d = GATED ? describe.skip : describe;

const EVIDENCE_ROOT = join(import.meta.dirname, '..', '..', 'evidence');
const UAC_GRACE_MS = 180000; // Windows consent UI auto-cancels ≈120s; stay above it

function caseDir(name: string): string {
  const dir = join(EVIDENCE_ROOT, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}

function copyArtifact(from: string, toDir: string, name: string): void {
  if (existsSync(from)) writeFileSync(join(toDir, name), readFileSync(from));
}

const powershell = join(
  process.env.SystemRoot ?? 'C:\\Windows',
  'System32',
  'WindowsPowerShell',
  'v1.0',
  'powershell.exe',
);
const taskkill = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'taskkill.exe');

d('EVIDENCE — real Windows 11 / UAC (Issue #15 required set)', () => {
  let authority: TestAuthority;
  let workspace: string;

  const uacPolicy = JSON.parse(
    execFileSync(
      powershell,
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop | ConvertTo-Json",
      ],
      { encoding: 'utf8', windowsHide: true },
    ),
  ) as Record<string, number>;

  it('E3 — helper killed inside the effect window, no expected state → honestly UNCERTAIN', async () => {
    authority = await createTestAuthority('shun-ev-');
    workspace = join(authority.workspaceRoot, 'e3');
    mkdirSync(workspace, { recursive: true });
    const dir = caseDir('E3-kill-uncertain');

    const built = buildAuthorizedAction(authority, {
      actionId: 'e3-kill-uncertain',
      op: 'windows.proc.exec',
      parameters: {
        program: process.execPath,
        args: ['-e', 'setInterval(()=>{},60000)'],
        expectExitCode: 0,
      },
      requiredPrivilege: 'USER',
      sideEffectClass: 'R1',
      timeoutMs: 120000,
    });
    const runDir = join(workspace, 'run');
    mkdirSync(runDir, { recursive: true });
    writeEnvelopeFile(join(runDir, 'envelope.json'), {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: {
        journalFile: join(runDir, 'journal.jsonl'),
        receiptFile: join(runDir, 'receipt.json'),
        evidenceDir: join(runDir, 'evidence'),
      },
    });

    const child = spawn(
      process.execPath,
      [
        authority.helperBundle,
        join(runDir, 'envelope.json'),
        join(runDir, 'journal.jsonl'),
        join(runDir, 'receipt.json'),
      ],
      { windowsHide: true, stdio: 'ignore' },
    );
    // wait for the effect window to open, then kill the helper mid-window
    await waitFor(
      () => journalPhases(readJournal(join(runDir, 'journal.jsonl'))).includes('EXEC_START'),
      30000,
    );
    execFileSync(taskkill, ['/PID', String(child.pid), '/F'], { windowsHide: true });
    await new Promise<void>((resolve) => child.on('exit', () => resolve()));

    const journal = readJournal(join(runDir, 'journal.jsonl'));
    const scope: InterpreterScope = {
      filesystem: built.grant.actionScope.filesystem,
      registry: built.grant.actionScope.registry,
    };
    const postState = await reconcileExpectedState(
      built.action,
      scope,
      new JournalWriter(join(dir, 'reconcile.log'), 0),
    );
    const classification = classifyRecovery({ journal, receipt: undefined, postState });
    expect(classification.recoveryClassification).toBe('MAY_HAVE_EXECUTED_UNCERTAIN');
    expect(terminalForClassification(classification)).toBe('UNCERTAIN');
    expect(existsSync(join(runDir, 'receipt.json'))).toBe(false); // crash: no receipt — journal only

    copyArtifact(join(runDir, 'journal.jsonl'), dir, 'journal.jsonl');
    writeFileSync(
      join(dir, 'summary.json'),
      JSON.stringify(
        {
          case: 'E3-kill-uncertain',
          terminal: 'UNCERTAIN',
          recoveryClassification: classification.recoveryClassification,
          basis: classification.basis,
          journalPhases: journalPhases(journal),
          helperKilledPid: child.pid,
          startedAt: null,
        },
        null,
        2,
      ),
    );
    disposeTestAuthority(authority);
  }, 120000);

  it('E4 — helper killed inside the effect window, declared expectedState → reconcile-first resolves', async () => {
    authority = await createTestAuthority('shun-ev-');
    workspace = join(authority.workspaceRoot, 'e4');
    mkdirSync(workspace, { recursive: true });
    const dir = caseDir('E4-kill-reconciled');
    const marker = join(workspace, 'e4-marker.txt');
    const markerContent = 'E4 side effect landed before the kill';

    const built = buildAuthorizedAction(authority, {
      actionId: 'e4-kill-reconciled',
      op: 'windows.proc.exec',
      // the child IS the side effect: writes the marker, then parks — so the
      // kill provably happens after the effect landed, inside the window
      parameters: {
        program: process.execPath,
        args: [
          '-e',
          `require('node:fs').writeFileSync(${JSON.stringify(marker)}, ${JSON.stringify(markerContent)}); setInterval(()=>{},60000)`,
        ],
        expectExitCode: 0,
      },
      requiredPrivilege: 'USER',
      sideEffectClass: 'R2',
      timeoutMs: 120000,
      // declared verifiable expected state must be verifiable within the
      // declared read scope (production posture)
      filesystemScope: { read: [workspace], write: [] },
      expectedState: { path: marker, exists: true, content: markerContent },
    });
    const runDir = join(workspace, 'run');
    mkdirSync(runDir, { recursive: true });
    writeEnvelopeFile(join(runDir, 'envelope.json'), {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: {
        journalFile: join(runDir, 'journal.jsonl'),
        receiptFile: join(runDir, 'receipt.json'),
        evidenceDir: join(runDir, 'evidence'),
      },
    });

    const child = spawn(
      process.execPath,
      [
        authority.helperBundle,
        join(runDir, 'envelope.json'),
        join(runDir, 'journal.jsonl'),
        join(runDir, 'receipt.json'),
      ],
      { windowsHide: true, stdio: 'ignore' },
    );
    // kill only after the marker exists: the effect landed, the window is open
    await waitFor(() => existsSync(marker), 30000);
    await waitFor(
      () => journalPhases(readJournal(join(runDir, 'journal.jsonl'))).includes('EXEC_START'),
      30000,
    );
    execFileSync(taskkill, ['/PID', String(child.pid), '/F'], { windowsHide: true });
    await new Promise<void>((resolve) => child.on('exit', () => resolve()));

    const journal = readJournal(join(runDir, 'journal.jsonl'));
    const scope: InterpreterScope = {
      filesystem: built.grant.actionScope.filesystem,
      registry: built.grant.actionScope.registry,
    };
    const postState = await reconcileExpectedState(
      built.action,
      scope,
      new JournalWriter(join(dir, 'reconcile.log'), 0),
    );
    expect(postState.verified).toBe(true);
    if (postState.verified) expect(postState.holds).toBe(true);
    const classification = classifyRecovery({ journal, receipt: undefined, postState });
    expect(classification.recoveryClassification).toBe('COMPLETED_VERIFIED');
    expect(classification.resolvedByPostState).toBe(true);

    copyArtifact(join(runDir, 'journal.jsonl'), dir, 'journal.jsonl');
    copyArtifact(marker, dir, 'e4-marker.txt');
    writeFileSync(
      join(dir, 'summary.json'),
      JSON.stringify(
        {
          case: 'E4-kill-reconciled',
          resolved: true,
          recoveryClassification: classification.recoveryClassification,
          basis: classification.basis,
          journalPhases: journalPhases(journal),
          helperKilledPid: child.pid,
        },
        null,
        2,
      ),
    );
    disposeTestAuthority(authority);
  }, 120000);

  it('E2 — UAC refusal (decline or consent timeout) → UAC_DECLINED, empty journal, NOT_STARTED', async () => {
    authority = await createTestAuthority('shun-ev-');
    workspace = join(authority.workspaceRoot, 'e2');
    mkdirSync(workspace, { recursive: true });
    const dir = caseDir('E2-uac-refused');

    const built = buildAuthorizedAction(authority, {
      actionId: 'e2-uac-refused',
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'never-written.txt'), content: 'must never exist' },
      requiredPrivilege: 'ELEVATED',
      sideEffectClass: 'R2',
      filesystemScope: { read: [], write: [workspace] },
    });
    const backend = new PrivilegedWindowsExecutionBackend({
      authorityDir: authority.authorityDir,
      workspaceRoot: authority.workspaceRoot,
      helperBundlePath: authority.helperBundle,
      relayScriptPath: authority.relayScript,
      uacGraceMs: UAC_GRACE_MS,
    });
    const receipt = await backend.execute(built.action, built.grant);
    const journal = readJournal(must(receipt.sideEffectEvidence.journalRef, 'journalRef'));

    expect(receipt.terminal).toBe('UAC_DECLINED');
    expect(receipt.sideEffectEvidence.recoveryClassification).toBe('NOT_STARTED');
    expect(journal).toHaveLength(0); // helper provably never started
    expect(existsSync(join(workspace, 'never-written.txt'))).toBe(false);

    copyArtifact(must(receipt.sideEffectEvidence.journalRef, 'journalRef'), dir, 'journal.jsonl');
    copyArtifact(
      join(dirname(must(receipt.outputRefs[0], 'output ref')), 'relay.json'),
      dir,
      'relay.json',
    );
    writeFileSync(
      join(dir, 'receipt.json'),
      readFileSync(must(receipt.outputRefs.at(-1), 'receipt ref')),
    );
    writeFileSync(
      join(dir, 'summary.json'),
      JSON.stringify(
        {
          case: 'E2-uac-refused',
          terminal: receipt.terminal,
          recoveryClassification: receipt.sideEffectEvidence.recoveryClassification,
          journalEmpty: journal.length === 0,
          uacPolicy,
          host: { hostname: hostname(), filteredToken: true },
        },
        null,
        2,
      ),
    );
    disposeTestAuthority(authority);
  }, 400000);

  it('E1 — UAC positive: elevated HKLM registry lifecycle (consent required)', async () => {
    authority = await createTestAuthority('shun-ev-');
    workspace = join(authority.workspaceRoot, 'e1');
    mkdirSync(workspace, { recursive: true });
    const dir = caseDir('E1-uac-positive-hklm');
    const key = 'HKLM\\SOFTWARE\\ShunT04Evidence';

    const backend = new PrivilegedWindowsExecutionBackend({
      authorityDir: authority.authorityDir,
      workspaceRoot: authority.workspaceRoot,
      helperBundlePath: authority.helperBundle,
      relayScriptPath: authority.relayScript,
      uacGraceMs: UAC_GRACE_MS,
    });

    const create = buildAuthorizedAction(authority, {
      actionId: 'e1-hklm-create',
      op: 'windows.registry.setValue',
      parameters: {
        key: `${key}\\probe`,
        valueName: 'InstalledBy',
        type: 'REG_SZ',
        data: 'shun-executor-windows T04 evidence',
      },
      requiredPrivilege: 'ELEVATED',
      sideEffectClass: 'R2',
      registryScope: { write: [key] },
      expectedState: {
        key: `${key}\\probe`,
        expectKeyExists: true,
        expectValues: { installedby: 'shun-executor-windows T04 evidence' },
      },
    });
    const createReceipt = await backend.execute(create.action, create.grant);
    expect(createReceipt.terminal).toBe('SUCCEEDED');

    const cleanup = buildAuthorizedAction(authority, {
      actionId: 'e1-hklm-delete',
      op: 'windows.registry.deleteKey',
      parameters: { key },
      requiredPrivilege: 'ELEVATED',
      sideEffectClass: 'R2',
      registryScope: { write: [key] },
      expectedState: { key, expectKeyExists: false },
    });
    const cleanupReceipt = await backend.execute(cleanup.action, cleanup.grant);
    expect(cleanupReceipt.terminal).toBe('SUCCEEDED');

    for (const [name, receipt] of [
      ['create', createReceipt],
      ['cleanup', cleanupReceipt],
    ] as const) {
      copyArtifact(
        must(receipt.sideEffectEvidence.journalRef, 'journalRef'),
        dir,
        `${name}.journal.jsonl`,
      );
      writeFileSync(
        join(dir, `${name}.receipt.json`),
        readFileSync(must(receipt.outputRefs.at(-1), 'receipt ref')),
      );
    }
    writeFileSync(
      join(dir, 'summary.json'),
      JSON.stringify(
        {
          case: 'E1-uac-positive-hklm',
          create: {
            terminal: createReceipt.terminal,
            classification: createReceipt.sideEffectEvidence.recoveryClassification,
            postStateVerified: createReceipt.sideEffectEvidence.postStateVerified,
          },
          cleanup: {
            terminal: cleanupReceipt.terminal,
            classification: cleanupReceipt.sideEffectEvidence.recoveryClassification,
          },
          uacPolicy,
        },
        null,
        2,
      ),
    );
    disposeTestAuthority(authority);
  }, 600000);

  it('E5 — typed metacharacters byte-exact across the privilege boundary (elevated, consent required)', async () => {
    authority = await createTestAuthority('shun-ev-');
    workspace = join(authority.workspaceRoot, 'e5');
    mkdirSync(workspace, { recursive: true });
    const dir = caseDir('E5-metachars-elevated');
    const target = join(workspace, 'e5 & ; %PX%.txt');
    const hostile = 'a & b | c; d%PATH%e "f" <g> $(h) `i` — 恶意参数; DEL /S /Q C:\\';

    const built = buildAuthorizedAction(authority, {
      actionId: 'e5-metachars',
      op: 'windows.fs.write',
      parameters: { path: target, content: hostile },
      requiredPrivilege: 'ELEVATED',
      sideEffectClass: 'R1',
      filesystemScope: { read: [], write: [workspace] },
      expectedState: { path: target, exists: true, content: hostile },
    });
    const backend = new PrivilegedWindowsExecutionBackend({
      authorityDir: authority.authorityDir,
      workspaceRoot: authority.workspaceRoot,
      helperBundlePath: authority.helperBundle,
      relayScriptPath: authority.relayScript,
      uacGraceMs: UAC_GRACE_MS,
    });
    const receipt = await backend.execute(built.action, built.grant);
    expect(receipt.terminal).toBe('SUCCEEDED');
    expect(readFileSync(target, 'utf8')).toBe(hostile); // byte-exact, no shell ever saw it

    copyArtifact(must(receipt.sideEffectEvidence.journalRef, 'journalRef'), dir, 'journal.jsonl');
    writeFileSync(
      join(dir, 'receipt.json'),
      readFileSync(must(receipt.outputRefs.at(-1), 'receipt ref')),
    );
    copyArtifact(target, dir, 'e5-landed.txt');
    writeFileSync(
      join(dir, 'summary.json'),
      JSON.stringify(
        {
          case: 'E5-metachars-elevated',
          terminal: receipt.terminal,
          byteExact: true,
          hostileSample: hostile,
        },
        null,
        2,
      ),
    );
    disposeTestAuthority(authority);
  }, 400000);
});

async function waitFor(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error('waitFor timeout');
    await new Promise((r) => setTimeout(r, 100));
  }
}
