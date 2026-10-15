// v0.2 T05 signed acquisition → Shun-owned byte cache. Never executes code.
// This package does not mint a PlanLedger grant or auto-load native addons.
import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, rm } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import type { CuratedProviderVerifier, ProviderVerificationResult } from '@shun/vertical-jit';

const MAX_BYTES = 64 * 1024 * 1024;
const SHA = /^[a-f0-9]{64}$/;

export type StageRefusal =
  | 'CATALOG_UNTRUSTED'
  | 'CATALOG_SCOPE_DRIFT'
  | 'CATALOG_SIGNATURE_INVALID'
  | 'OFFLINE'
  | 'SOURCE_UNAVAILABLE'
  | 'REDIRECT_REFUSED'
  | 'OVERSIZE'
  | 'ARTIFACT_HASH_MISMATCH'
  | 'CACHE_UNTRUSTED'
  | 'CACHE_UNAVAILABLE';

export type StageResult =
  | { ok: true; state: 'VERIFIED_BYTES_ONLY'; digest: string; byteLength: number }
  | { ok: false; code: StageRefusal };

export type StageHost = Readonly<{
  /**
   * Trusted backend-owned cache directory. It must NOT be provided by the
   * model, a Recipe or an unauthenticated localhost request.
   */
  cacheRoot: string;
  verifier: CuratedProviderVerifier;
  /** OS/network policy from trusted host; caller cannot override per-stage. */
  isOffline: () => boolean;
  /** In production: use built-in global fetch. Injectable only for tests. */
  fetchArtifact?: typeof fetch;
}>;

async function safeReadFile(path: string): Promise<Buffer | null | false> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const before = await lstat(path);
    if (!before.isFile() || before.isSymbolicLink() || before.size > MAX_BYTES || before.size < 0)
      return false;
    // Keep all reads on a single opened descriptor: lstat + readFile(path)
    // would follow a swapped symlink between the two operations.
    const flags = constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW);
    handle = await open(path, flags);
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.size > MAX_BYTES ||
      opened.size < 0 ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    )
      return false;
    const bytes = await handle.readFile();
    if (bytes.byteLength > MAX_BYTES) return false;
    const after = await lstat(path);
    if (
      !after.isFile() ||
      after.isSymbolicLink() ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino
    )
      return false;
    return bytes;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    return false;
  } finally {
    try {
      await handle?.close();
    } catch {
      // Read-only cleanup; no trusted cache result is minted on error.
    }
  }
}

async function readBoundedResponse(response: Response): Promise<Buffer | null> {
  if (response.status !== 200 || !response.body) return null;
  const len = response.headers.get('content-length');
  if (len && (!/^\d+$/.test(len) || Number(len) > MAX_BYTES)) return null;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      n += item.value.byteLength;
      if (n > MAX_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(item.value);
    }
    return Buffer.concat(chunks, n);
  } finally {
    reader.releaseLock();
  }
}

/**
 * Host-composed byte staging only. Returned metadata deliberately has no
 * executable path. A separate authorized ActionController/JIT may later
 * re-verify a staged artifact and bind it to a privileged plan.
 */
export class CuratedProviderStager {
  private readonly root: string;
  private readonly verifier: CuratedProviderVerifier;
  private readonly isOffline: () => boolean;
  private readonly fetchArtifact: typeof fetch;

  constructor(host: StageHost) {
    if (
      !isAbsolute(host.cacheRoot) ||
      typeof host.isOffline !== 'function' ||
      !host.verifier ||
      typeof host.verifier.verify !== 'function' ||
      typeof host.verifier.verifyBytes !== 'function'
    )
      throw new Error('STAGER_CONFIGURATION_REFUSED');
    this.root = resolve(host.cacheRoot);
    this.verifier = host.verifier;
    this.isOffline = host.isOffline;
    this.fetchArtifact = host.fetchArtifact ?? fetch;
  }

  private async cachePath(digest: string): Promise<string | null> {
    if (!SHA.test(digest)) return null;
    const cacheRoot = join(this.root, 'artifacts');
    try {
      await mkdir(this.root, { recursive: true, mode: 0o700 });
      await mkdir(cacheRoot, { recursive: true, mode: 0o700 });
      const [parent, child] = await Promise.all([lstat(this.root), lstat(cacheRoot)]);
      if (
        !parent.isDirectory() ||
        parent.isSymbolicLink() ||
        !child.isDirectory() ||
        child.isSymbolicLink()
      )
        return null;
      return join(cacheRoot, digest);
    } catch {
      return null;
    }
  }

  private verifySigned(descriptor: unknown): ProviderVerificationResult {
    try {
      return this.verifier.verify(descriptor);
    } catch {
      return { ok: false, code: 'CATALOG_UNTRUSTED' };
    }
  }

  /**
   * Cached bytes are re-hashed EVERY time against a fresh signature-verified
   * descriptor; cache presence itself is NEVER evidence of trust.
   */
  async readVerified(descriptor: unknown): Promise<Buffer | null> {
    const evidence = this.verifySigned(descriptor);
    if (!evidence.ok) return null;
    const path = await this.cachePath(evidence.artifact.artifactSha256);
    if (!path) return null;
    const bytes = await safeReadFile(path);
    if (!bytes || !this.verifier.verifyBytes(evidence, bytes)) return null;
    return Buffer.from(bytes);
  }

  async stage(descriptor: unknown): Promise<StageResult> {
    const proof = this.verifySigned(descriptor);
    if (!proof.ok) return { ok: false, code: proof.code };
    const digest = proof.artifact.artifactSha256;
    const path = await this.cachePath(digest);
    if (!path) return { ok: false, code: 'CACHE_UNAVAILABLE' };

    const prior = await safeReadFile(path);
    if (prior === false) return { ok: false, code: 'CACHE_UNTRUSTED' };
    if (prior) {
      if (!this.verifier.verifyBytes(proof, prior)) {
        return { ok: false, code: 'CACHE_UNTRUSTED' };
      }
      return { ok: true, state: 'VERIFIED_BYTES_ONLY', digest, byteLength: prior.length };
    }
    let offline: boolean;
    try {
      offline = this.isOffline() !== false;
    } catch {
      return { ok: false, code: 'OFFLINE' };
    }
    if (offline) return { ok: false, code: 'OFFLINE' };

    let response: Response;
    try {
      response = await this.fetchArtifact(proof.artifact.origin, {
        method: 'GET',
        redirect: 'manual',
        credentials: 'omit',
        cache: 'no-store',
        signal: AbortSignal.timeout(30_000),
      });
    } catch {
      return { ok: false, code: 'SOURCE_UNAVAILABLE' };
    }
    // The host may supply a testing transport, but even it must not silently
    // return successful bytes for a different final origin.
    if (response.redirected || (response.url && response.url !== proof.artifact.origin)) {
      try {
        await response.body?.cancel();
      } catch {
        // No execution/activation occurs regardless of cleanup failure.
      }
      return { ok: false, code: 'REDIRECT_REFUSED' };
    }
    if (response.status >= 300 && response.status < 400) {
      try {
        await response.body?.cancel();
      } catch {
        /* cleanup only */
      }
      return { ok: false, code: 'REDIRECT_REFUSED' };
    }
    let bytes: Buffer | null;
    try {
      bytes = await readBoundedResponse(response);
    } catch {
      return { ok: false, code: 'SOURCE_UNAVAILABLE' };
    }
    if (!bytes) return { ok: false, code: 'OVERSIZE' };
    if (!this.verifier.verifyBytes(proof, bytes)) {
      return { ok: false, code: 'ARTIFACT_HASH_MISMATCH' };
    }

    const temp = join(this.root, 'artifacts', `${digest}.${randomUUID()}.partial`);
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      // Exclusive Shun-owned temp file. Crash leaves *.partial but never READY.
      handle = await open(temp, 'wx', 0o600);
      await handle.writeFile(bytes);
      await handle.sync();
      await handle.close();
      handle = undefined;
      // Concurrent staged attempts always have the SAME pinned expected digest.
      // Rehash after rename — no trust assigned merely for successful writes.
      await rename(temp, path);
      const confirmed = await safeReadFile(path);
      if (!confirmed || !this.verifier.verifyBytes(proof, confirmed)) {
        return { ok: false, code: 'CACHE_UNTRUSTED' };
      }
      return { ok: true, state: 'VERIFIED_BYTES_ONLY', digest, byteLength: confirmed.length };
    } catch {
      return { ok: false, code: 'CACHE_UNAVAILABLE' };
    } finally {
      try {
        await handle?.close();
      } catch {
        /* best-effort close */
      }
      try {
        await rm(temp, { force: true });
      } catch {
        /* no false READY */
      }
    }
  }
}
