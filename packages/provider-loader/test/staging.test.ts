import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalJson } from '@shun/contracts';
import { CuratedProviderVerifier } from '@shun/vertical-jit';
import { afterEach, describe, expect, it } from 'vitest';
import { CuratedProviderStager } from '../src/staging.ts';

const keyPair = generateKeyPairSync('ed25519');
const trustedContents = Buffer.from('trusted curated rg binary fixture', 'utf8');
const sha = (data: Uint8Array) => createHash('sha256').update(data).digest('hex');
const trust = {
  providerId: 'rg',
  capabilityId: 'file.search',
  version: '14.1',
  catalogRevision: 'catalog-v1',
  bindingId: 'rg-binding',
  scopedVerifierId: 'curator-r1',
  catalogManifestSha256: 'a'.repeat(64),
  bindingEvidenceSha256: 'b'.repeat(64),
  artifactSha256: sha(trustedContents),
  origin: 'https://trusted.invalid/rg.exe',
  platform: 'windows-x64' as const,
  artifactKind: 'CLI' as const,
};

function descriptor(overrides: Record<string, unknown> = {}) {
  const signed = {
    ...trust,
    entrypoint: 'rg.exe',
    signerKeyId: 'curator-r1',
    dependencySha256: [],
    ...overrides,
  };
  return {
    ...signed,
    curatorSignature: sign(null, Buffer.from(canonicalJson(signed)), keyPair.privateKey).toString(
      'base64',
    ),
  };
}

function verifier() {
  return new CuratedProviderVerifier(
    [
      {
        keyId: 'curator-r1',
        publicKeyPem: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      },
    ],
    [trust],
  );
}

const roots: string[] = [];
function setup(options?: { offline?: boolean; response?: Response; spy?: (url: string) => void }) {
  const root = mkdtempSync(join(tmpdir(), 'shun-curated-provider-'));
  roots.push(root);
  let calls = 0;
  const stager = new CuratedProviderStager({
    cacheRoot: root,
    verifier: verifier(),
    isOffline: () => options?.offline ?? false,
    fetchArtifact: (async (input: string | URL | Request, init?: RequestInit) => {
      calls += 1;
      options?.spy?.(String(input));
      expect(init?.redirect).toBe('manual');
      expect(init?.credentials).toBe('omit');
      return options?.response ?? new Response(trustedContents, { status: 200 });
    }) as typeof fetch,
  });
  return { stager, root, calls: () => calls };
}
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('T05 signed curated Provider byte acquisition', () => {
  it('stages only signed trusted bytes and re-verifies on cache reuse and restart', async () => {
    const host = setup();
    const signed = descriptor();
    expect(await host.stager.stage(signed)).toEqual({
      ok: true,
      state: 'VERIFIED_BYTES_ONLY',
      digest: trust.artifactSha256,
      byteLength: trustedContents.length,
    });
    expect(host.calls()).toBe(1);
    expect(await host.stager.readVerified(signed)).toEqual(trustedContents);
    expect(await host.stager.stage(signed)).toMatchObject({ ok: true });
    expect(host.calls()).toBe(1);
    expect(readFileSync(join(host.root, 'artifacts', trust.artifactSha256))).toEqual(
      trustedContents,
    );
  });

  it('never contacts network for forged signer, catalog drift or offline policy', async () => {
    const host = setup();
    const invalid = { ...descriptor(), curatorSignature: 'not-a-signature' };
    expect((await host.stager.stage(invalid)).ok).toBe(false);
    expect((await host.stager.stage(descriptor({ origin: 'https://evil.invalid' }))).ok).toBe(
      false,
    );
    expect(host.calls()).toBe(0);
    const offline = setup({ offline: true });
    expect(await offline.stager.stage(descriptor())).toEqual({ ok: false, code: 'OFFLINE' });
    expect(offline.calls()).toBe(0);
  });

  it('rejects HTTP redirect, digest mismatch and large declared response', async () => {
    const redirected = setup({
      response: new Response(null, {
        status: 302,
        headers: { location: 'https://evil.invalid/binary' },
      }),
    });
    expect(await redirected.stager.stage(descriptor())).toEqual({
      ok: false,
      code: 'REDIRECT_REFUSED',
    });
    const bad = setup({ response: new Response('tampered package bytes', { status: 200 }) });
    expect(await bad.stager.stage(descriptor())).toEqual({
      ok: false,
      code: 'ARTIFACT_HASH_MISMATCH',
    });
    const large = setup({
      response: new Response('tiny', {
        status: 200,
        headers: { 'content-length': String(65 * 1024 * 1024) },
      }),
    });
    expect(await large.stager.stage(descriptor())).toEqual({ ok: false, code: 'OVERSIZE' });
    expect(await bad.stager.readVerified(descriptor())).toBeNull();
  });

  it('refuses a transport that silently reports a different final origin', async () => {
    const response = new Response(trustedContents, { status: 200 });
    Object.defineProperty(response, 'url', {
      value: 'https://evil.invalid/rg.exe',
      configurable: true,
    });
    const host = setup({ response });
    expect(await host.stager.stage(descriptor())).toEqual({
      ok: false,
      code: 'REDIRECT_REFUSED',
    });
    expect(await host.stager.readVerified(descriptor())).toBeNull();
  });

  it('never reuses tampered cached binary bytes', async () => {
    const host = setup();
    expect((await host.stager.stage(descriptor())).ok).toBe(true);
    const path = join(host.root, 'artifacts', trust.artifactSha256);
    writeFileSync(path, 'tampered but digest-named');
    expect(await host.stager.stage(descriptor())).toEqual({ ok: false, code: 'CACHE_UNTRUSTED' });
    expect(host.calls()).toBe(1);
    expect(await host.stager.readVerified(descriptor())).toBeNull();
  });

  it('refuses a symlinked cached artifact when the host permits symlink fixtures', async (ctx) => {
    const host = setup();
    expect((await host.stager.stage(descriptor())).ok).toBe(true);
    const path = join(host.root, 'artifacts', trust.artifactSha256);
    const victim = join(host.root, 'other-file');
    writeFileSync(victim, trustedContents);
    rmSync(path);
    try {
      symlinkSync(victim, path);
    } catch (error) {
      // A normal Windows user without Developer Mode cannot create symlinks.
      // The privilege-dependent fixture must be SKIPPED, not misreported
      // as product failure or silently counted as a successful symlink check.
      const code = (error as NodeJS.ErrnoException).code;
      if (process.platform === 'win32' && (code === 'EPERM' || code === 'EACCES')) {
        ctx.skip('WIN_SYMLINK_FIXTURE_PRIVILEGE_UNAVAILABLE');
        return;
      }
      throw error;
    }
    expect(await host.stager.stage(descriptor())).toEqual({ ok: false, code: 'CACHE_UNTRUSTED' });
    expect(readFileSync(victim)).toEqual(trustedContents);
  });

  it('returns verified byte metadata only; never executable path or authority', async () => {
    const host = setup();
    const value = await host.stager.stage(descriptor());
    expect(value.ok).toBe(true);
    expect(JSON.stringify(value)).not.toContain(host.root);
    expect(JSON.stringify(value)).not.toContain('entrypoint');
    expect(JSON.stringify(value)).not.toContain('AuthorizedAction');
  });
});
