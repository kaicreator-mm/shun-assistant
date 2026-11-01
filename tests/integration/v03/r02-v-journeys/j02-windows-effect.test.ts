/**
 * R02-V J02 — REAL scoped Windows effect journey (physical leg), executed
 * under Owner authorization OWNER_SHUN_V030_R02_J02030509_DISPOSITION_APPROVE
 * (#259). Runs ONLY when SHUN_R02V_PHYSICAL=1 on a real Windows host; every
 * filesystem effect is bounded to this test's own mkdtemp fixture root.
 *
 * Journey shape (PRD J02): plan authored as a separate trusted record → an
 * independent operator R2 grant (real HMAC grant record in the trusted
 * authority store, a distinct artifact from the plan) → real OS-currentness +
 * ActionController recheck inside the executor → real scoped `windows.fs.write`
 * effect → independent `windows.fs.verify` poststate (exact canary bytes) →
 * journal + recovery-classification receipts.
 *
 * R2-precedes-effect falsifiers (PRD negatives): an expired grant, a revoked
 * grant and an out-of-scope target each refuse with ZERO effect artifacts.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LocalWindowsBackend } from '../../../../packages/executor-windows/src/backend.ts';
import { journalPhases, readJournal } from '../../../../packages/executor-windows/src/journal.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  must,
  ON_WINDOWS,
  type TestAuthority,
} from '../../../../packages/executor-windows/test/helpers.ts';

const RUN_PHYSICAL =
  process.env.SHUN_R02V_PHYSICAL === '1' && process.platform === 'win32' && ON_WINDOWS;

describe.skipIf(!RUN_PHYSICAL)(
  'R02-V J02: real scoped Windows effect journey (physical, operator-owned fixture root)',
  () => {
    let authority: TestAuthority;
    let workspace: string;
    let backend: LocalWindowsBackend;

    beforeAll(async () => {
      authority = await createTestAuthority('shun-r02v-j02-');
      workspace = mkdtempSync(join(tmpdir(), 'shun-r02v-j02-ws-'));
      backend = new LocalWindowsBackend({
        authorityDir: authority.authorityDir,
        workspaceRoot: workspace,
      });
    });

    afterAll(() => {
      disposeTestAuthority(authority);
      if (workspace) rmSync(workspace, { recursive: true, force: true });
    });

    it('R2 falsifier: an EXPIRED grant refuses with zero effect artifacts', async () => {
      const target = join(workspace, 'expired-grant.txt');
      const { action } = buildAuthorizedAction(
        authority,
        {
          op: 'windows.fs.write',
          parameters: { path: target, content: 'never' },
          requiredPrivilege: 'USER',
          sideEffectClass: 'R1',
          filesystemScope: { read: [], write: [workspace] },
          expectedState: { path: target, exists: true, content: 'never' },
        },
        { expiresAt: new Date(Date.now() - 60_000).toISOString() },
      );
      const receipt = await backend.execute(action);
      expect(receipt.terminal).toBe('REFUSED');
      expect(receipt.sideEffectEvidence.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
      expect(existsSync(target)).toBe(false);
    });

    it('R2 falsifier: a REVOKED grant refuses with zero effect artifacts', async () => {
      const target = join(workspace, 'revoked-grant.txt');
      const { action } = buildAuthorizedAction(
        authority,
        {
          op: 'windows.fs.write',
          parameters: { path: target, content: 'never' },
          requiredPrivilege: 'USER',
          sideEffectClass: 'R1',
          filesystemScope: { read: [], write: [workspace] },
        },
        { revoked: true },
      );
      const receipt = await backend.execute(action);
      expect(receipt.terminal).toBe('REFUSED');
      expect(receipt.sideEffectEvidence.recoveryClassification).toBe('FAILED_BEFORE_EFFECT');
      expect(existsSync(target)).toBe(false);
    });

    it('R2 falsifier: an out-of-scope target refuses with zero effect anywhere', async () => {
      const inside = join(workspace, 'escape-attempt.txt');
      const outside = join(tmpdir(), 'shun-r02v-j02-escape-proof.txt');
      const { action } = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        // The write target sits OUTSIDE the granted write scope; the executor
        // must refuse before any byte lands anywhere.
        parameters: { path: outside, content: 'never' },
        requiredPrivilege: 'USER',
        sideEffectClass: 'R1',
        filesystemScope: { read: [], write: [workspace] },
      });
      const receipt = await backend.execute(action);
      expect(receipt.terminal).toBe('REFUSED');
      expect(existsSync(outside)).toBe(false);
      expect(existsSync(inside)).toBe(false);
    });

    it('REAL journey: plan + separate R2 grant → scoped fs.write → verified poststate + journal', async () => {
      const canary = `shun-r02v-j02-canary ${Date.now()}`;
      const target = join(workspace, 'r2-approved-write.txt');
      // The R2 operator grant is minted as its OWN artifact in the authority
      // store (plan record and grant record are separate files); the executor
      // revalidates OS currentness + grant before any effect.
      const { action, plan, grant } = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: target, content: canary },
        requiredPrivilege: 'USER',
        sideEffectClass: 'R1',
        filesystemScope: { read: [], write: [workspace] },
        expectedState: { path: target, exists: true, content: canary },
      });
      expect(grant.integrity).toBeTruthy();
      expect(action.planHash).toBe(plan.planHash);

      const receipt = await backend.execute(action);
      expect(receipt.terminal).toBe('SUCCEEDED');
      expect(receipt.sideEffectEvidence.postStateVerified).toBe(true);
      expect(receipt.sideEffectEvidence.recoveryClassification).toBe('COMPLETED_VERIFIED');
      expect(existsSync(target)).toBe(true);
      const journal = readJournal(must(receipt.sideEffectEvidence.journalRef, 'journalRef'));
      expect(journalPhases(journal)).toContain('EXEC_DONE');

      // Independent poststate verification: a SEPARATE read-only R0 action
      // re-reads the file and the exact canary bytes are asserted again.
      const verify = buildAuthorizedAction(authority, {
        op: 'windows.fs.verify',
        parameters: { path: target, expectExists: true },
        requiredPrivilege: 'USER',
        sideEffectClass: 'R0',
        filesystemScope: { read: [workspace], write: [] },
      });
      const verifyReceipt = await backend.execute(verify.action);
      expect(verifyReceipt.terminal).toBe('SUCCEEDED');
      expect(verifyReceipt.sideEffectEvidence.postStateVerified).toBe(true);
      expect(readFileSync(target, 'utf8')).toBe(canary);

      console.log(
        '[J02] real effect journey receipt:',
        JSON.stringify({
          actionId: action.actionId,
          grantId: grant.grantId,
          planHash: plan.planHash.slice(0, 16),
          terminal: receipt.terminal,
          recovery: receipt.sideEffectEvidence.recoveryClassification,
          target,
          canaryBytes: Buffer.byteLength(canary, 'utf8'),
        }),
      );
    });
  },
);
