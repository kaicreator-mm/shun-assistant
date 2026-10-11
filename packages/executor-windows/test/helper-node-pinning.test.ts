// T04 C12 — the elevated process identity is pinned end to end. The helper
// BUNDLE hash alone is theater if the INTERPRETER running it is arbitrary:
// the launcher chooses node.exe (an attacker-run launcher points it at its
// own node), and Start-Process -Verb RunAs would elevate that substitute.
// The authority pin therefore records node.exe's sha256; the launcher
// measures before the relay spawn and the helper re-measures its own
// process image inside the privileged boundary.
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { writeEnvelopeFile } from '../src/envelope.ts';
import { verifyPinnedHelper } from '../src/helper-pinning.ts';
import { journalPhases, readJournal } from '../src/journal.ts';
import { readHelperPin, sha256File, writeHelperPin } from '../src/trusted-store.ts';
import {
  buildAuthorizedAction,
  buildHelperBundle,
  createTestAuthority,
  disposeTestAuthority,
  IS_ELEVATED_HOST,
  must,
  ON_WINDOWS,
  runHelperDirectly,
  type TestAuthority,
} from './helpers.ts';

describe.skipIf(!ON_WINDOWS)('C12 — elevated interpreter identity pinning (real helper)', () => {
  let authority: TestAuthority;
  let workspace: string;

  beforeAll(async () => {
    authority = await createTestAuthority('shun-c12-');
    workspace = join(authority.workspaceRoot, 'runs');
    mkdirSync(workspace, { recursive: true });
  });

  afterAll(() => disposeTestAuthority(authority));

  it('launcher-side identity check refuses a node.exe that is not the pinned one', () => {
    const pin = readHelperPin(authority.authorityDir);
    expect(pin).toBeDefined();
    // Any other file stands in for a substitute interpreter (same observable:
    // measured sha256 != pinned sha256).
    const substitute = authority.helperBundle; // a real file whose hash != node.exe's
    const check = verifyPinnedHelper(
      authority.helperBundle,
      authority.relayScript,
      substitute,
      pin,
    );
    expect(check.ok).toBe(false);
    if (!check.ok) expect(check.reason).toContain('node.exe identity mismatch');
  });

  it('helper refuses to run on an unpinned interpreter — pre-journal, nothing written', async () => {
    // The pin must be read from a store this helper bundle actually trusts,
    // so build a bundle with a BOGUS authority dir baked in and pin a bogus
    // node.exe digest there. The bundle self-check passes and only the
    // interpreter identity refuses — pre-journal, via stderr + exit code.
    const bogusDir = mkdtempSync(join(tmpdir(), 'shun-c12-bogus-'));
    try {
      const bogusBundle = join(bogusDir, 'executor-helper.mjs');
      await buildHelperBundle(bogusDir, bogusBundle);
      writeHelperPin(bogusDir, {
        schemaVersion: 'shun.executor-windows.helper-pin/1',
        helperRevision: 'shun.executor-windows.helper/test',
        helperSha256: sha256File(bogusBundle),
        relaySha256: sha256File(authority.relayScript),
        // A 64-hex value that is NOT this process's node.exe digest:
        nodeExeSha256: sha256File(authority.helperBundle),
        workspaceRoot: authority.workspaceRoot,
        pinnedAt: new Date().toISOString(),
      });
      const built = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: join(workspace, 'c12-never.txt'), content: 'x' },
        requiredPrivilege: 'ELEVATED',
        sideEffectClass: 'R2',
        filesystemScope: { read: [], write: [workspace] },
      });
      const runDir = join(workspace, 'c12-bogus-node');
      mkdirSync(runDir, { recursive: true });
      const journalFile = join(runDir, 'journal.jsonl');
      const receiptFile = join(runDir, 'receipt.json');
      writeEnvelopeFile(join(runDir, 'envelope.json'), {
        action: built.action,
        grant: built.grant,
        plan: built.plan,
        io: { journalFile, receiptFile, evidenceDir: join(runDir, 'evidence') },
      });
      const run = runHelperDirectly(
        { ...authority, helperBundle: bogusBundle },
        join(runDir, 'envelope.json'),
        journalFile,
        receiptFile,
      );
      expect(run.exitCode).toBe(2);
      expect(run.stderr).toContain('node.exe');
      expect(existsSync(journalFile)).toBe(false);
      expect(existsSync(receiptFile)).toBe(false);
      expect(existsSync(join(workspace, 'c12-never.txt'))).toBe(false);
    } finally {
      rmSync(bogusDir, { recursive: true, force: true });
    }
  });

  it('a correctly pinned interpreter passes startup (journal opens)', () => {
    const built = buildAuthorizedAction(authority, {
      op: 'windows.fs.write',
      parameters: { path: join(workspace, 'c12-ok.txt'), content: 'x' },
      requiredPrivilege: 'ELEVATED',
      sideEffectClass: 'R2',
      filesystemScope: { read: [], write: [workspace] },
    });
    const runDir = join(workspace, 'c12-pinned-node');
    mkdirSync(runDir, { recursive: true });
    const journalFile = join(runDir, 'journal.jsonl');
    const receiptFile = join(runDir, 'receipt.json');
    writeEnvelopeFile(join(runDir, 'envelope.json'), {
      action: built.action,
      grant: built.grant,
      plan: built.plan,
      io: { journalFile, receiptFile, evidenceDir: join(runDir, 'evidence') },
    });
    const run = runHelperDirectly(
      authority,
      join(runDir, 'envelope.json'),
      journalFile,
      receiptFile,
    );
    // Startup passed: the journal opened (interpreter pin honored).
    expect(existsSync(journalFile)).toBe(true);
    expect(journalPhases(readJournal(journalFile))).toContain('RECEIVED');
    if (IS_ELEVATED_HOST) {
      // On an elevated host the ELEVATED write executes and succeeds.
      expect(run.exitCode).toBe(0);
      expect(existsSync(join(workspace, 'c12-ok.txt'))).toBe(true);
    } else {
      // On a filtered-token host the ELEVATED action refuses at elevation
      // consistency (exit 2) — after startup, with a structured receipt.
      expect(run.exitCode).toBe(2);
      expect(run.receipt).toBeDefined();
    }
  });

  it('launcher-side ok check now carries the interpreter measurement', () => {
    const pin = must(readHelperPin(authority.authorityDir), 'pin');
    const check = verifyPinnedHelper(
      authority.helperBundle,
      authority.relayScript,
      process.execPath,
      pin,
    );
    expect(check.ok).toBe(true);
    if (check.ok) expect(check.nodeExeSha256).toBe(sha256File(process.execPath));
  });
});
