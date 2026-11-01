/**
 * R02-V J05 — REAL Provider first-use JIT journey (physical leg), executed
 * under Owner authorization OWNER_SHUN_V030_R02_J02030509_DISPOSITION_APPROVE
 * (#259). Runs ONLY when SHUN_R02V_PHYSICAL=1 on a real Windows host; every
 * staged/executed byte lives inside this test's own mkdtemp roots (nothing is
 * installed system-wide, no PATH/system mutation).
 *
 * Journey shape (PRD J05): genuine first-use over the REAL signed material —
 * the committed production curator trust root + catalog descriptor + genuine
 * ripgrep 14.1.1 bytes:
 *   1. signature/trust verification (real Ed25519 curator root, real descriptor);
 *   2. the JIT business adapter's bounded first-use PROPOSAL (cacheState SEEDED,
 *      frozen PROPOSAL_ONLY, zero authority fields);
 *   3. real staging of the signed bytes (offline trusted cache, zero fetch);
 *   4. preflight admission of the staged artifact;
 *   5. REAL first-use execution: the activator spawns the staged rg.exe under
 *      a per-run sandbox with a scrubbed environment — VERSION_PROBE and a
 *      FILE_SEARCH canary over seeded input;
 *   6. fresh-composition restart reuse over the SAME durable cache (offline);
 *   7. rollback/removal: the entire install root is removed, zero residue;
 *   8. falsifier: corrupted cache bytes refuse (CACHE_UNTRUSTED), never execute.
 */
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProviderJitBusinessAdapter } from '../../../../packages/domain-computer/src/provider/provider-jit.ts';
import { createTrustedProviderHost } from '../../../../packages/domain-host/src/provider/trusted-provider-host.ts';
import {
  BoundedSpawnProcess,
  CuratedProviderActivator,
  minimalWindowsSpawnEnvironment,
  type ResolvedInvocation,
  type RunEffectDecision,
} from '../../../../packages/provider-loader/src/activation.ts';
import { CuratedProviderPreflight } from '../../../../packages/provider-loader/src/preflight.ts';
import type { ProviderUseCurrentness } from '../../../../packages/provider-loader/src/preflight.ts';
import { CuratedProviderStager } from '../../../../packages/provider-loader/src/staging.ts';
import { CuratedProviderVerifier } from '../../../../packages/vertical-jit/src/curated-provider.ts';
import {
  ARTIFACT_SHA256,
  BINDING_ID,
  DESCRIPTOR,
  RG_BYTES,
  ROOT_KEY_ID,
  ROOT_PEM,
  SCOPE,
  sha256Hex,
} from '../t08-provider/material.ts';

const RUN_PHYSICAL = process.env.SHUN_R02V_PHYSICAL === '1' && process.platform === 'win32';
const TASK_ID = 'task-r02v-j05';

function seedCache(cacheRoot: string): void {
  mkdirSync(join(cacheRoot, 'artifacts'), { recursive: true });
  writeFileSync(join(cacheRoot, 'artifacts', ARTIFACT_SHA256), RG_BYTES);
}

// Trusted-host currentness must echo the VERIFIED artifact's exact identity
// (providerId/bindingId/catalogRevision/digest), never invented values.
const verifiedArtifact = (() => {
  const proof = new CuratedProviderVerifier(
    [{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM }],
    [SCOPE],
  ).verify(DESCRIPTOR);
  if (!proof.ok) throw new Error('J05_FIXTURE_DESCRIPTOR_UNTRUSTED');
  return proof.artifact;
})();

function currentness(): ProviderUseCurrentness {
  return {
    kind: 'CURRENT' as const,
    taskId: TASK_ID,
    providerId: verifiedArtifact.providerId,
    bindingId: verifiedArtifact.bindingId,
    catalogRevision: verifiedArtifact.catalogRevision,
    artifactSha256: verifiedArtifact.artifactSha256,
    revocationEpoch: 1,
    capability: 'PREPARE_PROVIDER',
  };
}

/** The invocation-scoped host-owned execution grant (the F03 seam). */
function versionProbeEffect(invocation: ResolvedInvocation): Promise<RunEffectDecision> {
  const under = (value: string, root: string) =>
    resolve(value).toLowerCase().startsWith(resolve(root).toLowerCase());
  return Promise.resolve(
    invocation.taskId === TASK_ID &&
      invocation.bindingId === BINDING_ID &&
      invocation.artifactSha256 === ARTIFACT_SHA256 &&
      under(invocation.executablePath, process.env.SHUN_R02V_J05_ACTIVE_ROOT ?? '/') &&
      invocation.writeRoots.every((root) => under(root, process.env.SHUN_R02V_J05_ACTIVE_ROOT ?? '/'))
      ? { ok: true, leaseId: `lease-${invocation.taskId}` }
      : { ok: false, code: 'EFFECT_NOT_AUTHORIZED' },
  );
}

describe.skipIf(!RUN_PHYSICAL)(
  'R02-V J05: real signed Provider first-use JIT journey (physical, operator-owned roots)',
  () => {
    let dir: string;
    let cacheRoot: string;
    let verifier: CuratedProviderVerifier;
    let stager: CuratedProviderStager;
    let versionLine = '';

    beforeAll(() => {
      dir = mkdtempSync(join(tmpdir(), 'shun-r02v-j05-'));
      cacheRoot = join(dir, 'cache');
      seedCache(cacheRoot);
      verifier = new CuratedProviderVerifier([{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM }], [
        SCOPE,
      ]);
      stager = new CuratedProviderStager({ cacheRoot, verifier, isOffline: () => true });
      // The activator's per-run staging lands under cacheRoot/active/<binding>;
      // expose it to the invocation-scoped grant through trusted env only.
      process.env.SHUN_R02V_J05_ACTIVE_ROOT = join(cacheRoot, 'active', BINDING_ID, ARTIFACT_SHA256);
    });

    afterAll(() => {
      delete process.env.SHUN_R02V_J05_ACTIVE_ROOT;
      if (dir) rmSync(dir, { recursive: true, force: true });
    });

    it('step 1: the genuine signed material verifies against the production curator root', () => {
      expect(sha256Hex(RG_BYTES)).toBe(ARTIFACT_SHA256);
      const host = createTrustedProviderHost({
        roots: [{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM }],
        scopes: [SCOPE],
      });
      const verified = host.verifyProviderDescriptor(DESCRIPTOR);
      expect(verified.ok).toBe(true);
      if (!verified.ok) return;
      expect(verified.artifact.bindingId).toBe(BINDING_ID);
      expect(host.verifyProviderBytes(verified, RG_BYTES)).toBe(true);
    });

    it('step 2: the JIT adapter proposes a bounded SEEDED first-use acquisition (PROPOSAL_ONLY)', () => {
      const host = createTrustedProviderHost({
        roots: [{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM }],
        scopes: [SCOPE],
      });
      const jit = createProviderJitBusinessAdapter({
        verifyProviderDescriptor: (descriptor) => host.verifyProviderDescriptor(descriptor),
        verifyProviderBytes: (verified, bytes) => host.verifyProviderBytes(verified, bytes),
        cachePeek: (digest) =>
          existsSync(join(cacheRoot, 'artifacts', digest)) ? 'SEEDED' : 'MISS',
        isOffline: () => true,
      });
      const proposal = jit.proposeProviderAcquisition(DESCRIPTOR, RG_BYTES);
      expect(proposal).toMatchObject({
        status: 'PROPOSAL_ONLY',
        bindingId: BINDING_ID,
        artifactSha256: ARTIFACT_SHA256,
        cacheState: 'SEEDED',
        executionAuthorized: false,
      });
    });

    it('step 3+4: the signed bytes stage offline (zero fetch) and preflight admits them', async () => {
      const staged = await stager.stage(DESCRIPTOR);
      expect(staged).toMatchObject({
        ok: true,
        state: 'VERIFIED_BYTES_ONLY',
        digest: ARTIFACT_SHA256,
      });
      const readBack = await stager.readVerified(DESCRIPTOR);
      expect(readBack).not.toBeNull();
      expect(sha256Hex(readBack as Buffer)).toBe(ARTIFACT_SHA256);

      const preflight = new CuratedProviderPreflight({
        verifier,
        stager,
        getAuthorizedCurrentness: () => currentness(),
        requiredRevocationEpoch: () => 1,
        hostPlatform: () => process.platform,
        hostArchitecture: () => process.arch,
        hostNodeAbi: () => process.versions.modules,
      });
      const admitted = await preflight.check({ taskId: TASK_ID, descriptor: DESCRIPTOR });
      expect(admitted).toMatchObject({
        ok: true,
        state: 'PREFLIGHT_ONLY',
        bindingId: BINDING_ID,
        digest: ARTIFACT_SHA256,
      });
    });

    it('step 5a: REAL first-use execution — staged rg.exe VERSION_PROBE', async () => {
      const activator = new CuratedProviderActivator({
        verifier,
        stager,
        cacheRoot,
        getAuthorizedCurrentness: () => currentness(),
        authorizeRunEffect: versionProbeEffect,
        requiredRevocationEpoch: () => 1,
        hostPlatform: () => process.platform,
        hostArchitecture: () => process.arch,
        hostNodeAbi: () => process.versions.modules,
        hostNativeChildRuntime: () => process.execPath,
        hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
        process: new BoundedSpawnProcess(),
      });
      const result = await activator.runCli({
        taskId: TASK_ID,
        descriptor: DESCRIPTOR,
        run: { kind: 'VERSION_PROBE' },
      });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.exitCode).toBe(0);
      expect(result.stdout.toLowerCase()).toContain('ripgrep');
      versionLine = result.stdout.split('\n')[0] ?? '';
      console.log('[J05] real first-use provider execution:', JSON.stringify({
        bindingId: result.bindingId,
        exitCode: result.exitCode,
        versionLine,
      }));
    });

    it('step 5b: REAL FILE_SEARCH canary over seeded sandbox input', async () => {
      const encoder = new TextEncoder();
      const activator = new CuratedProviderActivator({
        verifier,
        stager,
        cacheRoot,
        getAuthorizedCurrentness: () => currentness(),
        authorizeRunEffect: versionProbeEffect,
        requiredRevocationEpoch: () => 1,
        hostPlatform: () => process.platform,
        hostArchitecture: () => process.arch,
        hostNodeAbi: () => process.versions.modules,
        hostNativeChildRuntime: () => process.execPath,
        hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
        process: new BoundedSpawnProcess(),
      });
      const result = await activator.runCli({
        taskId: TASK_ID,
        descriptor: DESCRIPTOR,
        run: { kind: 'FILE_SEARCH', pattern: 'SHUN-R02V-J05-CANARY', operands: ['canary.txt'] },
        sandboxFiles: [
          {
            name: 'canary.txt',
            bytes: encoder.encode('irrelevant line\nSHUN-R02V-J05-CANARY match me\nother\n'),
          },
        ],
      });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('SHUN-R02V-J05-CANARY');
    });

    it('step 6: a FRESH composition over the SAME durable cache re-verifies and re-executes offline', async () => {
      const freshVerifier = new CuratedProviderVerifier(
        [{ keyId: ROOT_KEY_ID, publicKeyPem: ROOT_PEM }],
        [SCOPE],
      );
      const freshStager = new CuratedProviderStager({
        cacheRoot,
        verifier: freshVerifier,
        isOffline: () => true,
      });
      const activator = new CuratedProviderActivator({
        verifier: freshVerifier,
        stager: freshStager,
        cacheRoot,
        getAuthorizedCurrentness: () => currentness(),
        authorizeRunEffect: versionProbeEffect,
        requiredRevocationEpoch: () => 1,
        hostPlatform: () => process.platform,
        hostArchitecture: () => process.arch,
        hostNodeAbi: () => process.versions.modules,
        hostNativeChildRuntime: () => process.execPath,
        hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
        process: new BoundedSpawnProcess(),
      });
      const result = await activator.runCli({
        taskId: TASK_ID,
        descriptor: DESCRIPTOR,
        run: { kind: 'VERSION_PROBE' },
      });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.exitCode).toBe(0);
      expect(result.stdout.split('\n')[0]).toBe(versionLine);
    });

    it('step 7: rollback — removing the install root leaves zero residue', () => {
      expect(existsSync(cacheRoot)).toBe(true);
      rmSync(cacheRoot, { recursive: true, force: true });
      expect(existsSync(cacheRoot)).toBe(false);
      expect(existsSync(join(dir, 'active'))).toBe(false);
      expect(readdirSync(dir).sort()).toEqual([]); // nothing staged or spilled
    });

    it('falsifier: corrupted cache bytes are refused as CACHE_UNTRUSTED, never executed', async () => {
      const tamperedRoot = join(dir, 'cache-tampered');
      mkdirSync(join(tamperedRoot, 'artifacts'), { recursive: true });
      const corrupted = Buffer.from(RG_BYTES);
      const lastByte = corrupted.at(-1);
      if (lastByte === undefined) throw new Error('empty fixture bytes');
      corrupted[corrupted.length - 1] = lastByte ^ 0xff;
      writeFileSync(join(tamperedRoot, 'artifacts', ARTIFACT_SHA256), corrupted);
      const tamperedStager = new CuratedProviderStager({
        cacheRoot: tamperedRoot,
        verifier,
        isOffline: () => true,
      });
      expect(await tamperedStager.stage(DESCRIPTOR)).toMatchObject({
        ok: false,
        code: 'CACHE_UNTRUSTED',
      });
      expect(await tamperedStager.readVerified(DESCRIPTOR)).toBeNull();
    });
  },
);
