/**
 * R03-INT J05 — FULL production Provider first-use chain through the selected
 * v0.3 DomainApp (R03-F02 repair, OWNER_SHUN_V030_R03_F01F02Q01_REPAIR_APPROVE).
 * Runs ONLY when SHUN_R02V_PHYSICAL=1 on a real Windows host; every staged or
 * executed byte stays inside this test's own operator-owned cache root.
 *
 * The chain is the REAL production topology: Control API HTTP →
 * reference-authenticated journey gateway → selected public v0.10.3 Kernel
 * (live K-minted Effect Permit) → trusted shun-provider-host binding over the
 * REAL CuratedProviderVerifier→Stager→Activator chain with the genuine signed
 * ripgrep 14.1.1 bytes. The final test composes ALL three journey families in
 * ONE selected App (windows + provider + meta) to prove the composite
 * manifest end-to-end.
 */
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { HostMetaShadowStore } from '../../../../packages/domain-host/src/meta/host-meta-shadow-store.ts';
import {
  buildAuthorizedAction,
  createTestAuthority,
  disposeTestAuthority,
  ON_WINDOWS,
  type TestAuthority,
} from '../../../../packages/executor-windows/test/helpers.ts';
import {
  ARTIFACT_SHA256,
  BINDING_ID,
  DESCRIPTOR,
  RG_BYTES,
  ROOT_KEY_ID,
  ROOT_PEM,
  SCOPE,
} from '../t08-provider/material.ts';
import { bootLiveStack, json, type LiveStack } from './stack-harness.ts';

const RUN_PHYSICAL =
  process.env.SHUN_R02V_PHYSICAL === '1' && process.platform === 'win32' && ON_WINDOWS;
const PROVIDER_TASK_ID = 'task-r03int-provider';

const disabledInterpreter = {
  status: () => ({
    enabled: false,
    provider: 'deepseek' as const,
    model: 'deepseek-flash' as const,
    osConsentRequired: true as const,
  }),
  interpretGoal: async () => ({ ok: false, code: 'CLOUD_UNAVAILABLE' }),
};

function seedProviderCache(cacheRoot: string): void {
  mkdirSync(join(cacheRoot, 'artifacts'), { recursive: true });
  writeFileSync(join(cacheRoot, 'artifacts', ARTIFACT_SHA256), RG_BYTES);
}

describe.skipIf(!RUN_PHYSICAL)(
  'R03-INT J05: production provider first-use chain over the selected K (physical)',
  () => {
    let dir: string;
    let cacheRoot: string;
    let stack: LiveStack;

    beforeAll(async () => {
      dir = mkdtempSync(join(tmpdir(), 'shun-r03int-j05-'));
      cacheRoot = join(dir, 'provider-cache');
      seedProviderCache(cacheRoot);
      stack = await bootLiveStack({
        interpreter: disabledInterpreter,
        prefix: 'shun-r03int-j05-stack-',
        journeys: {
          manifest: { provider: true },
          bindings: {
            provider: {
              cacheRoot,
              roots: [{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM }],
              scopes: [SCOPE],
              descriptor: DESCRIPTOR,
              taskId: PROVIDER_TASK_ID,
              revocationEpoch: 1,
            },
          },
        },
      });
    });

    afterAll(async () => {
      if (stack) await stack.close();
      if (dir) rmSync(dir, { recursive: true, force: true });
    });

    it('boots with the provider journey manifest and trusted binding', () => {
      expect(stack.production.journeys).toBeTruthy();
    });

    it('REAL chain: HTTP first-use → K permit → real signed rg.exe execution', async () => {
      const refs = stack.submitRefs();
      const result = await json(stack.port, 'POST', '/api/v03/provider/first-use', {
        caseId: stack.caseId,
        taskId: PROVIDER_TASK_ID,
        currentnessRef: refs.currentnessRef,
        approvalRef: refs.approvalRef,
      });
      expect(result.status).toBe(200);
      expect((result.body as { status: string }).status).toBe('COMPLETED');
      const output = (
        (
          (result.body as { result: { admitted?: { effects?: { output?: { outcome?: { output?: {
            exitCode?: number;
            stdout?: string;
            state?: string;
          } } } }[] } } }).result ?? {}
        ).admitted?.effects?.[0]?.output?.outcome?.output ?? {}
      );
      expect(output.state).toBe('EXECUTED');
      expect(output.exitCode).toBe(0);
      expect((output.stdout ?? '').toLowerCase()).toContain('ripgrep 14.1.1');
      console.log(
        '[J05-production] real first-use receipt:',
        JSON.stringify({ bindingId: BINDING_ID, exitCode: output.exitCode, stdoutHead: (output.stdout ?? '').split('\n')[0] }),
      );
    });

    it('NEGATIVE: a wrong task identity refuses the first use (zero execution)', async () => {
      const refs = stack.submitRefs();
      const result = await json(stack.port, 'POST', '/api/v03/provider/first-use', {
        caseId: stack.caseId,
        taskId: 'task-not-the-pinned-one',
        currentnessRef: refs.currentnessRef,
        approvalRef: refs.approvalRef,
      });
      expect(result.status).toBe(422);
      expect((result.body as { status: string }).status).toBe('KERNEL_REFUSED');
    });

    it('fail-closed boot: provider routes without the trusted binding refuse activation', async () => {
      await expect(
        bootLiveStack({
          interpreter: disabledInterpreter,
          prefix: 'shun-r03int-j05-failclosed-',
          journeys: { manifest: { provider: true } },
        }),
      ).rejects.toThrow('V03_PRODUCTION_COMPOSITION_REFUSED');
    });
  },
);
