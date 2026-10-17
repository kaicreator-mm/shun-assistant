import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalJson } from '@shun/contracts';
import { CuratedProviderVerifier, type TrustedProviderScope } from '@shun/vertical-jit';
import { afterEach, describe, expect, it } from 'vitest';
import {
  CuratedProviderPreflight,
  type ProviderUseCurrentness,
  type TrustedPreflightHost,
} from '../src/preflight.ts';
import { CuratedProviderStager } from '../src/staging.ts';

const keyPair = generateKeyPairSync('ed25519');
const bytes = Buffer.from('bounded test provider; never executable');
const sha = createHash('sha256').update(bytes).digest('hex');
const roots: string[] = [];
const scope: TrustedProviderScope = {
  providerId: 'rg',
  capabilityId: 'file.search',
  version: '14.1',
  catalogRevision: 'catalog-r1',
  bindingId: 'rg-binding',
  scopedVerifierId: 'safe-verifier',
  catalogManifestSha256: 'a'.repeat(64),
  bindingEvidenceSha256: 'b'.repeat(64),
  artifactSha256: sha,
  origin: 'https://trusted.invalid/rg.exe',
  platform: 'windows-x64',
  artifactKind: 'CLI',
};

function makeDescriptor(trust: TrustedProviderScope = scope, dependencies: string[] = []) {
  // Host-derived scope config (dependency name pins) is NEVER part of the
  // signed descriptor payload — the wire schema is strict and has no field
  // for it.
  const { dependencyEntries: _hostDerived, ...signedScope } = trust;
  const unsigned = {
    ...signedScope,
    entrypoint: trust.artifactKind === 'CLI' ? 'rg.exe' : 'addon.node',
    signerKeyId: 'key-1',
    dependencySha256: dependencies,
  };
  return {
    ...unsigned,
    curatorSignature: sign(null, Buffer.from(canonicalJson(unsigned)), keyPair.privateKey).toString(
      'base64',
    ),
  };
}
function makeHost(
  trust: TrustedProviderScope = scope,
  overrides: Partial<TrustedPreflightHost> = {},
) {
  const dir = mkdtempSync(join(tmpdir(), 'shun-t05-preflight-'));
  roots.push(dir);
  const verifier = new CuratedProviderVerifier(
    [
      {
        keyId: 'key-1',
        publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      },
    ],
    [trust],
  );
  const stager = new CuratedProviderStager({
    cacheRoot: dir,
    verifier,
    isOffline: () => false,
    fetchArtifact: (async () => new Response(bytes, { status: 200 })) as typeof fetch,
  });
  const state: ProviderUseCurrentness = {
    kind: 'CURRENT',
    taskId: 'task-1',
    providerId: trust.providerId,
    bindingId: trust.bindingId,
    catalogRevision: trust.catalogRevision,
    artifactSha256: trust.artifactSha256,
    revocationEpoch: 1,
    capability: 'PREPARE_PROVIDER',
  };
  const host: TrustedPreflightHost = {
    verifier,
    stager,
    getAuthorizedCurrentness: () => state,
    requiredRevocationEpoch: () => 1,
    hostPlatform: () => 'win32',
    hostArchitecture: () => 'x64',
    hostNodeAbi: () => '115',
    ...overrides,
  };
  return { preflight: new CuratedProviderPreflight(host), stager, state };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('T05 signed Provider activation preflight (NO execution)', () => {
  it('admits only exact signed staged bytes and issues no executable path', async () => {
    const { preflight, stager } = makeHost();
    const desc = makeDescriptor();
    expect(await preflight.check({ taskId: 'task-1', descriptor: desc })).toEqual({
      ok: false,
      code: 'ARTIFACT_NOT_VERIFIED',
    });
    expect((await stager.stage(desc)).ok).toBe(true);
    const result = await preflight.check({ taskId: 'task-1', descriptor: desc });
    expect(result).toEqual({
      ok: true,
      state: 'PREFLIGHT_ONLY',
      bindingId: 'rg-binding',
      digest: sha,
      byteLength: bytes.length,
    });
    expect(JSON.stringify(result)).not.toContain('artifacts/');
  });

  it('refuses unsigned or changed catalog before any authenticated use', async () => {
    const { preflight, stager } = makeHost();
    const desc = makeDescriptor();
    await stager.stage(desc);
    expect(
      await preflight.check({
        taskId: 'task-1',
        descriptor: { ...desc, curatorSignature: 'not-signed' },
      }),
    ).toEqual({ ok: false, code: 'CATALOG_UNTRUSTED' });
    expect(
      await preflight.check({
        taskId: 'task-1',
        descriptor: makeDescriptor({ ...scope, origin: 'https://evil.invalid/rg.exe' }),
      }),
    ).toEqual({ ok: false, code: 'CATALOG_UNTRUSTED' });
  });

  it('pins original signed descriptor against getter substitution at cache reuse', async () => {
    const { preflight, stager } = makeHost();
    const original = makeDescriptor();
    const drifted = makeDescriptor(scope, ['c'.repeat(64)]);
    expect((await stager.stage(original)).ok).toBe(true);
    let reads = 0;
    const changing = {
      taskId: 'task-1',
      get descriptor() {
        reads += 1;
        return reads === 1 ? original : drifted;
      },
    };
    expect(await preflight.check(changing)).toMatchObject({
      ok: true,
      state: 'PREFLIGHT_ONLY',
      digest: sha,
    });
    expect(reads).toBe(1);
    // The drifted descriptor's dependency digest list has no host-curated
    // names in the pinned scope, so it cannot resolve into a verifiable
    // binding at all — it refuses at signature admission.
    expect(await preflight.check({ taskId: 'task-1', descriptor: drifted })).toEqual({
      ok: false,
      code: 'CATALOG_UNTRUSTED',
    });
  });

  it('refuses revoked, wrong-task or missing trusted currentness', async () => {
    const { preflight, stager, state } = makeHost(scope, { requiredRevocationEpoch: () => 2 });
    await stager.stage(makeDescriptor());
    expect(await preflight.check({ taskId: 'task-1', descriptor: makeDescriptor() })).toEqual({
      ok: false,
      code: 'AUTHORITY_STALE',
    });
    const missing = makeHost(scope, { getAuthorizedCurrentness: () => ({ kind: 'UNRESOLVABLE' }) });
    expect(
      await missing.preflight.check({ taskId: 'task-1', descriptor: makeDescriptor() }),
    ).toEqual({
      ok: false,
      code: 'AUTHORITY_STALE',
    });
    const mismatched = makeHost(scope, { getAuthorizedCurrentness: () => state });
    expect(
      await mismatched.preflight.check({ taskId: 'wrong-task', descriptor: makeDescriptor() }),
    ).toEqual({
      ok: false,
      code: 'AUTHORITY_STALE',
    });
  });

  it('refuses non-Windows and wrong native ABI even with signed bytes', async () => {
    const linux = makeHost(scope, { hostPlatform: () => 'linux' });
    expect(await linux.preflight.check({ taskId: 'task-1', descriptor: makeDescriptor() })).toEqual(
      {
        ok: false,
        code: 'HOST_UNSUPPORTED',
      },
    );
    const nativeScope: TrustedProviderScope = {
      ...scope,
      artifactKind: 'NATIVE_ADDON',
      abiRevision: '115',
    };
    const { preflight, stager } = makeHost(nativeScope, { hostNodeAbi: () => '127' });
    await stager.stage(makeDescriptor(nativeScope));
    expect(
      await preflight.check({ taskId: 'task-1', descriptor: makeDescriptor(nativeScope) }),
    ).toEqual({ ok: false, code: 'ABI_MISMATCH' });
  });

  it('admits only resolvable dependency closures; unresolvable sets refuse at admission', async () => {
    const depSha = 'c'.repeat(64);
    // A digest list without host-curated names cannot resolve into a
    // verifiable binding — it refuses at signature admission.
    const unresolved = makeHost();
    const unresolvedDesc = makeDescriptor(scope, [depSha]);
    await unresolved.stager.stage(unresolvedDesc);
    expect(
      await unresolved.preflight.check({ taskId: 'task-1', descriptor: unresolvedDesc }),
    ).toEqual({ ok: false, code: 'CATALOG_UNTRUSTED' });
    // A strictly bijective name↔digest closure resolves, and preflight-only
    // admission proceeds; the closure itself is enforced at activation.
    const depScope: TrustedProviderScope = {
      ...scope,
      artifactKind: 'NATIVE_ADDON',
      abiRevision: '115',
      dependencyEntries: [{ name: 'libdeps.dll', artifactSha256: depSha }],
    };
    const resolved = makeHost(depScope);
    const resolvedDesc = makeDescriptor(depScope, [depSha]);
    await resolved.stager.stage(resolvedDesc);
    expect(
      await resolved.preflight.check({ taskId: 'task-1', descriptor: resolvedDesc }),
    ).toMatchObject({ ok: true, state: 'PREFLIGHT_ONLY', bindingId: depScope.bindingId });
  });

  it('rejects poisoned trusted-host errors with fixed codes and no leaked paths', async () => {
    const { preflight } = makeHost(scope, {
      getAuthorizedCurrentness: () => {
        throw new Error('private C:/Users/Alice/password.txt');
      },
    });
    const result = await preflight.check({ taskId: 'task-1', descriptor: makeDescriptor() });
    expect(result).toEqual({ ok: false, code: 'AUTHORITY_UNAVAILABLE' });
    expect(JSON.stringify(result)).not.toContain('Alice');
  });
});
