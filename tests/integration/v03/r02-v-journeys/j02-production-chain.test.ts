/**
 * R03-INT J02 — FULL production Windows-effect chain through the selected
 * v0.3 DomainApp (R03-F01 repair, OWNER_SHUN_V030_R03_F01F02Q01_REPAIR_APPROVE).
 * Runs ONLY when SHUN_R02V_PHYSICAL=1 on a real Windows host.
 *
 * The chain is the REAL production topology, no test doubles:
 *   Control API HTTP → reference-authenticated journey gateway → selected
 *   public v0.10.3 Kernel (live K-minted Effect Permit) → trusted Host
 *   binding (real plan/grant authority records + real grant-presentation
 *   validation + OS currentness) → REAL scoped LocalWindowsBackend effect
 *   bounded to the operator-owned fixture workspace.
 * Negatives: permitless probe, unknown plan, expired grant and forged
 * reference pairs all refuse with ZERO filesystem effects.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  ON_WINDOWS,
  type TestAuthority,
} from '../../../../packages/executor-windows/test/helpers.ts';
import { bootLiveStack, json, type LiveStack } from './stack-harness.ts';

const RUN_PHYSICAL =
  process.env.SHUN_R02V_PHYSICAL === '1' && process.platform === 'win32' && ON_WINDOWS;

describe.skipIf(!RUN_PHYSICAL)(
  'R03-INT J02: production windows-effect chain over the selected K (physical)',
  () => {
    let authority: TestAuthority;
    let workspace: string;
    let stack: LiveStack;
    let dir: string;
    let canaryFile: string;
    let canaryText: string;
    let closed = false;

    const closeStack = async (): Promise<void> => {
      if (stack && !closed) {
        await stack.close();
        closed = true;
      }
    };

    beforeAll(async () => {
      // Operator provisioning: a REAL executor authority store (helper pins,
      // HMAC grant key, current authority) plus the bounded effect workspace.
      authority = await createTestAuthority('shun-r03int-j02-');
      workspace = mkdtempSync(join(tmpdir(), 'shun-r03int-j02-ws-'));
      stack = await bootLiveStack({
        interpreter: {
          status: () => ({
            enabled: false,
            provider: 'deepseek' as const,
            model: 'deepseek-flash' as const,
            osConsentRequired: true as const,
          }),
          interpretGoal: async () => ({ ok: false, code: 'CLOUD_UNAVAILABLE' }),
        },
        prefix: 'shun-r03int-j02-stack-',
        journeys: {
          manifest: { windows: true },
          bindings: { windows: { authorityDir: authority.authorityDir, workspaceRoot: workspace } },
        },
      });
      // The interpreter is disabled here: this journey never pays or leaves
      // the host; the disabled cloud port simply fails closed if touched.
    });

    afterAll(async () => {
      await closeStack();
      disposeTestAuthority(authority);
      if (workspace) rmSync(workspace, { recursive: true, force: true });
    });

    it('boots the selected DomainApp with the journey manifest and live bindings', () => {
      expect(stack.caseId).toBeTruthy();
      expect(stack.production.journeys).toBeTruthy();
      if (dir === undefined) dir = stack.dir;
    });

    it('REAL chain: HTTP submit → K permit → Host ActionController → scoped write → verified poststate', async () => {
      canaryText = `r03int-j02-canary-${Date.now()}`;
      canaryFile = join(workspace, 'production-chain-write.txt');
      const { action, plan, grant } = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: canaryFile, content: canaryText },
        requiredPrivilege: 'USER',
        sideEffectClass: 'R1',
        filesystemScope: { read: [], write: [workspace] },
        expectedState: { path: canaryFile, exists: true, content: canaryText },
      });
      const refs = stack.submitRefs();
      const result = await json(stack.port, 'POST', '/api/v03/effect/submit', {
        caseId: stack.caseId,
        actionRef: action.actionId,
        planRef: plan.planHash,
        grantRef: grant.grantId,
        currentnessRef: refs.currentnessRef,
        approvalRef: refs.approvalRef,
      });
      expect(result.status).toBe(200);
      expect((result.body as { status: string }).status).toBe('COMPLETED');
      // The REAL effect landed on disk with the exact canary bytes.
      expect(existsSync(canaryFile)).toBe(true);
      expect(readFileSync(canaryFile, 'utf8')).toBe(canaryText);
      // The selected Kernel minted a live Effect Permit for this dispatch.
      const kDocs = new DatabaseSync(join(stack.dir, 'k-docs.sqlite'));
      try {
        const permits = kDocs
          .prepare('SELECT doc_key FROM k_v10_docs WHERE doc_key LIKE ?')
          .all('%effect-permit%') as { doc_key: string }[];
        expect(permits.length).toBeGreaterThanOrEqual(1);
      } finally {
        kDocs.close();
      }
      console.log(
        '[J02-production] real full-chain receipt:',
        JSON.stringify({
          actionId: action.actionId,
          grantId: grant.grantId,
          target: canaryFile,
          canaryBytes: Buffer.byteLength(canaryText, 'utf8'),
          httpStatus: result.status,
        }),
      );
    });

    it('NEGATIVE: the permitless probe intent is refused by the K gate with zero effect', async () => {
      const probeTarget = join(workspace, 'probe-never.txt');
      const { action, plan, grant } = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: probeTarget, content: 'never' },
        requiredPrivilege: 'USER',
        sideEffectClass: 'R1',
        filesystemScope: { read: [], write: [workspace] },
      });
      const refs = stack.submitRefs();
      const result = await json(stack.port, 'POST', '/api/v03/effect/probe', {
        caseId: stack.caseId,
        actionRef: action.actionId,
        planRef: plan.planHash,
        grantRef: grant.grantId,
        currentnessRef: refs.currentnessRef,
        approvalRef: refs.approvalRef,
      });
      // The K gate refused the permitless probe; the surfaced vocabulary is
      // a truthful refusal/UNKNOWN (never success) and NOTHING landed.
      expect([409, 422]).toContain(result.status);
      expect(['KERNEL_REFUSED', 'UNKNOWN', 'REFUSED']).toContain(
        (result.body as { status: string }).status,
      );
      expect(existsSync(probeTarget)).toBe(false);
    });

    it('NEGATIVE: an unknown plan hash refuses with zero effect', async () => {
      const neverFile = join(workspace, 'unknown-plan-never.txt');
      const { action, grant } = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: neverFile, content: 'never' },
        requiredPrivilege: 'USER',
        sideEffectClass: 'R1',
        filesystemScope: { read: [], write: [workspace] },
      });
      const refs = stack.submitRefs();
      const result = await json(stack.port, 'POST', '/api/v03/effect/submit', {
        caseId: stack.caseId,
        actionRef: action.actionId,
        planRef: 'f'.repeat(64), // no such plan record
        grantRef: grant.grantId,
        currentnessRef: refs.currentnessRef,
        approvalRef: refs.approvalRef,
      });
      expect(result.status).toBe(422);
      expect(['KERNEL_REFUSED', 'REFUSED']).toContain((result.body as { status: string }).status);
      expect(existsSync(neverFile)).toBe(false);
    });

    it('NEGATIVE: an EXPIRED grant refuses with zero effect', async () => {
      const expiredTarget = join(workspace, 'expired-grant-never.txt');
      const { action, plan, grant } = buildAuthorizedAction(
        authority,
        {
          op: 'windows.fs.write',
          parameters: { path: expiredTarget, content: 'never' },
          requiredPrivilege: 'USER',
          sideEffectClass: 'R1',
          filesystemScope: { read: [], write: [workspace] },
        },
        { expiresAt: new Date(Date.now() - 60_000).toISOString() },
      );
      const refs = stack.submitRefs();
      const result = await json(stack.port, 'POST', '/api/v03/effect/submit', {
        caseId: stack.caseId,
        actionRef: action.actionId,
        planRef: plan.planHash,
        grantRef: grant.grantId,
        currentnessRef: refs.currentnessRef,
        approvalRef: refs.approvalRef,
      });
      expect(result.status).toBe(422);
      expect(['KERNEL_REFUSED', 'REFUSED']).toContain((result.body as { status: string }).status);
      expect(existsSync(expiredTarget)).toBe(false);
    });

    it('NEGATIVE: a forged reference pair refuses pre-send', async () => {
      const forgedTarget = join(workspace, 'forged-refs-never.txt');
      const { action, plan, grant } = buildAuthorizedAction(authority, {
        op: 'windows.fs.write',
        parameters: { path: forgedTarget, content: 'never' },
        requiredPrivilege: 'USER',
        sideEffectClass: 'R1',
        filesystemScope: { read: [], write: [workspace] },
      });
      const result = await json(stack.port, 'POST', '/api/v03/effect/submit', {
        caseId: stack.caseId,
        actionRef: action.actionId,
        planRef: plan.planHash,
        grantRef: grant.grantId,
        currentnessRef: `forged-${'a'.repeat(32)}`,
        approvalRef: `forged-${'b'.repeat(32)}`,
      });
      expect(result.status).toBe(422);
      expect((result.body as { status: string }).status).toBe('REFUSED');
      expect(existsSync(forgedTarget)).toBe(false);
    });

    it('fail-closed boot: journey routes without the trusted windows binding refuse activation', async () => {
      await expect(
        bootLiveStack({
          interpreter: {
            status: () => ({
              enabled: false,
              provider: 'deepseek' as const,
              model: 'deepseek-flash' as const,
              osConsentRequired: true as const,
            }),
            interpretGoal: async () => ({ ok: false, code: 'CLOUD_UNAVAILABLE' }),
          },
          prefix: 'shun-r03int-j02-failclosed-',
          journeys: { manifest: { windows: true } },
        }),
      ).rejects.toThrow('V03_PRODUCTION_COMPOSITION_REFUSED');
    });
  },
);
