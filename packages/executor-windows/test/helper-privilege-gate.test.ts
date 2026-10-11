// T04 C08 — the one-shot helper is the ELEVATED execution surface; the
// privileged backend launcher is its transport. Accepting a USER/NONE grant
// there would execute user-level actions with admin rights (privilege gain
// across the boundary) — the helper and the launcher must both refuse.
import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { writeEnvelopeFile } from '../src/envelope.ts';
import { journalPhases, readJournal } from '../src/journal.ts';
import { PrivilegedWindowsExecutionBackend } from '../src/privileged-backend.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  must,
  ON_WINDOWS,
  runHelperDirectly,
  type TestAuthority,
} from './helpers.ts';

describe.skipIf(!ON_WINDOWS)(
  'C08 — privileged surfaces reject USER/NONE grants (real helper)',
  () => {
    let authority: TestAuthority;
    let workspace: string;

    beforeAll(async () => {
      authority = await createTestAuthority('shun-c08-');
      workspace = join(authority.workspaceRoot, 'runs');
      mkdirSync(workspace, { recursive: true });
    });

    afterAll(() => disposeTestAuthority(authority));

    function runWithPrivilege(
      name: string,
      privilege: 'NONE' | 'USER' | 'ELEVATED',
    ): ReturnType<typeof runHelperDirectly> & { target: string; journalFile: string } {
      const target = join(workspace, `c08-${privilege.toLowerCase()}-target.txt`);
      const built = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: target, content: 'must never land' },
        requiredPrivilege: privilege,
        sideEffectClass: privilege === 'ELEVATED' ? 'R2' : 'R1',
        filesystemScope: { read: [], write: [workspace] },
      });
      const runDir = join(workspace, name);
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
      return { ...run, target, journalFile };
    }

    it('helper refuses a USER grant inside the privileged boundary (negative control for C08)', () => {
      const run = runWithPrivilege('c08-user', 'USER');
      expect(run.exitCode).toBe(2);
      const receipt = JSON.parse(must(run.receipt, 'receipt'));
      expect(receipt.terminal).toBe('REFUSED');
      expect(receipt.detail.reason).toContain(
        'USER/NONE actions must run on the unprivileged surface',
      );
      expect(journalPhases(readJournal(run.journalFile))).not.toContain('EXEC_START');
      expect(journalPhases(readJournal(run.journalFile))).not.toContain('PRIVILEGE_OK');
      expect(existsSync(run.target)).toBe(false);
    });

    it('helper refuses a NONE grant inside the privileged boundary', () => {
      const run = runWithPrivilege('c08-none', 'NONE');
      expect(run.exitCode).toBe(2);
      const receipt = JSON.parse(must(run.receipt, 'receipt'));
      expect(receipt.terminal).toBe('REFUSED');
      expect(existsSync(run.target)).toBe(false);
      expect(journalPhases(readJournal(run.journalFile))).not.toContain('EXEC_START');
    });

    it('launcher refuses a non-ELEVATED action BEFORE any pin read, UAC or relay spawn', async () => {
      const target = join(workspace, 'c08-launcher-target.txt');
      const built = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: target, content: 'must never land' },
        requiredPrivilege: 'USER',
        filesystemScope: { read: [], write: [workspace] },
      });
      const backend = new PrivilegedWindowsExecutionBackend({
        authorityDir: authority.authorityDir,
        workspaceRoot: workspace,
        uacGraceMs: 0,
      });
      const receipt = await backend.execute(built.action, built.grant);
      expect(receipt.terminal).toBe('REFUSED');
      expect(receipt.sideEffectEvidence.recoveryClassification).toBe('NOT_STARTED');
      expect(existsSync(target)).toBe(false);
      // No relay/helper artifacts: the refusal precedes pin read, UAC and spawn.
      const runsDir = join(workspace, 'executions');
      if (existsSync(runsDir)) {
        const { readdirSync } = await import('node:fs');
        for (const entry of readdirSync(runsDir)) {
          expect(readdirSync(join(runsDir, entry))).not.toContain('relay.json');
          expect(readdirSync(join(runsDir, entry))).not.toContain('journal.jsonl');
        }
      }
    });
  },
);
