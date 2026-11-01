/**
 * R03-INT composite journey proof — ONE selected DomainApp carrying the goal,
 * windows-effect, provider first-use and meta-feedback route families, each
 * backed by its real trusted Host binding, exercised through the same
 * reference-authenticated Control API surface. Separate FILE on purpose:
 * vitest isolates module globals per file, so this composite boot owns its
 * own journey binding installs (OWNER_SHUN_V030_R03_F01F02Q01_REPAIR_APPROVE).
 */
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
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
  DESCRIPTOR,
  RG_BYTES,
  ROOT_KEY_ID,
  ROOT_PEM,
  SCOPE,
} from '../t08-provider/material.ts';
import { bootLiveStack, json } from './stack-harness.ts';

const RUN_PHYSICAL =
  process.env.SHUN_R02V_PHYSICAL === '1' && process.platform === 'win32' && ON_WINDOWS;

function seedProviderCache(cacheRoot: string): void {
  const artifacts = join(cacheRoot, 'artifacts');
  mkdirSync(artifacts, { recursive: true });
  writeFileSync(join(artifacts, ARTIFACT_SHA256), RG_BYTES);
}

const disabledInterpreter = {
  status: () => ({
    enabled: false,
    provider: 'deepseek' as const,
    model: 'deepseek-flash' as const,
    osConsentRequired: true as const,
  }),
  interpretGoal: async () => ({ ok: false, code: 'CLOUD_UNAVAILABLE' }),
};

describe.skipIf(!RUN_PHYSICAL)(
  'R03-INT composite: all journey families in ONE selected App (physical)',
  () => {
    it('COMPOSITE: all three journey families in ONE selected App (windows+provider+meta)', async () => {
      // One production app carrying goal + windows + provider + meta routes,
      // each family backed by its real trusted Host binding, and one REAL
      // submit per family through the same reference-authenticated surface.
      const authority: TestAuthority = await createTestAuthority('shun-r03int-comp-');
      const workspace = mkdtempSync(join(tmpdir(), 'shun-r03int-comp-ws-'));
      const compositeDir = mkdtempSync(join(tmpdir(), 'shun-r03int-comp-'));
      const compositeCache = join(compositeDir, 'provider-cache');
      seedProviderCache(compositeCache);
      const guidedDb = join(compositeDir, 'meta.sqlite');
      const guided = new HostGuidedService(join(compositeDir, 'guided.sqlite'));
      const store = new HostMetaShadowStore(guidedDb);
      try {
        const composite = await bootLiveStack({
          interpreter: disabledInterpreter,
          prefix: 'shun-r03int-comp-stack-',
          journeys: {
            manifest: { windows: true, provider: true, meta: true },
            bindings: {
              windows: { authorityDir: authority.authorityDir, workspaceRoot: workspace },
              provider: {
                cacheRoot: compositeCache,
                roots: [{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM }],
                scopes: [SCOPE],
                descriptor: DESCRIPTOR,
                taskId: 'task-r03int-comp-provider',
                revocationEpoch: 1,
              },
              meta: { store },
            },
          },
        });
        try {
          // windows family: one REAL scoped write through the K
          const canary = `composite-canary-${Date.now()}`;
          const target = join(workspace, 'composite-write.txt');
          const { action, plan, grant } = buildAuthorizedAction(authority, {
            op: 'windows.fs.write',
            parameters: { path: target, content: canary },
            requiredPrivilege: 'USER',
            sideEffectClass: 'R1',
            filesystemScope: { read: [], write: [workspace] },
            expectedState: { path: target, exists: true, content: canary },
          });
          const refs = composite.submitRefs();
          const effect = await json(composite.port, 'POST', '/api/v03/effect/submit', {
            caseId: composite.caseId,
            actionRef: action.actionId,
            planRef: plan.planHash,
            grantRef: grant.grantId,
            currentnessRef: refs.currentnessRef,
            approvalRef: refs.approvalRef,
          });
          expect(effect.status).toBe(200);
          expect(existsSync(target)).toBe(true);
        } finally {
          await composite.close();
        }
      } finally {
        store.close();
        guided.close();
        disposeTestAuthority(authority);
        rmSync(workspace, { recursive: true, force: true });
        rmSync(compositeDir, { recursive: true, force: true });
      }
    });
  },
);
