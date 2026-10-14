// v0.2 curated Provider admission. This is a signed catalog/digest verifier,
// not a downloader, installer, execution grant, or arbitrary plugin loader.
// L2 Freeze #101, Task DAG #102 T05; trusted keys and exact scope MUST come
// from Shun-owned fixed configuration, never a Planner/Recipe or HTTP client.
import {
  createHash,
  createPublicKey,
  type KeyObject,
  timingSafeEqual,
  verify as verifySignature,
} from 'node:crypto';
import {
  canonicalJson,
  type ProviderCatalogArtifact,
  ProviderCatalogArtifactSchema,
} from '@shun/contracts';

export type TrustedProviderScope = Readonly<{
  providerId: string;
  capabilityId: string;
  version: string;
  catalogRevision: string;
  bindingId: string;
  scopedVerifierId: string;
  catalogManifestSha256: string;
  bindingEvidenceSha256: string;
  artifactSha256: string;
  origin: string;
  platform: 'windows-x64';
  artifactKind: 'CLI' | 'NATIVE_ADDON';
  abiRevision?: string;
}>;

export type ProviderVerificationRefusal =
  | 'CATALOG_UNTRUSTED'
  | 'CATALOG_SCOPE_DRIFT'
  | 'CATALOG_SIGNATURE_INVALID'
  | 'ARTIFACT_HASH_MISMATCH';

export type VerifiedProviderArtifact = Readonly<
  Omit<ProviderCatalogArtifact, 'dependencySha256'> & {
    dependencySha256: readonly string[];
  }
>;

export type ProviderVerificationResult =
  | { ok: true; artifact: VerifiedProviderArtifact }
  | { ok: false; code: ProviderVerificationRefusal };

function sha256Bytes(bytes: Uint8Array): Buffer {
  return createHash('sha256').update(bytes).digest();
}

function matchSha(expected: string, observed: Buffer): boolean {
  if (!/^[0-9a-f]{64}$/.test(expected)) return false;
  return timingSafeEqual(Buffer.from(expected, 'hex'), observed);
}

function base64Signature(value: string): Buffer | null {
  if (!/^[A-Za-z0-9+/]{86}==$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== 64 || decoded.toString('base64') !== value) return null;
  return decoded;
}

type PinnedRoot = Readonly<{ keyId: string; publicKeyPem: string }>;

/**
 * A caller cannot inject trusted roots per request: constructor inputs must be
 * pinned by the host's audited product configuration. No user-supplied public
 * key or "trust this certificate" fallback is accepted by verify().
 */
export class CuratedProviderVerifier {
  private readonly keys: ReadonlyMap<string, KeyObject>;
  private readonly scopes: ReadonlyMap<string, TrustedProviderScope>;
  /** Only results minted by THIS verifier instance can attest artifact bytes. */
  private readonly verifiedDigests = new WeakMap<object, string>();

  constructor(roots: readonly PinnedRoot[], trustedScopes: readonly TrustedProviderScope[]) {
    const keys = new Map<string, KeyObject>();
    for (const root of roots) {
      if (!root.keyId || keys.has(root.keyId)) throw new Error('INVALID_TRUST_CONFIGURATION');
      let key: KeyObject;
      try {
        key = createPublicKey(root.publicKeyPem);
      } catch {
        throw new Error('INVALID_TRUST_CONFIGURATION');
      }
      if (key.asymmetricKeyType !== 'ed25519') throw new Error('INVALID_TRUST_CONFIGURATION');
      keys.set(root.keyId, key);
    }
    const scopes = new Map<string, TrustedProviderScope>();
    for (const scope of trustedScopes) {
      if (!scope.bindingId || scopes.has(scope.bindingId)) {
        throw new Error('INVALID_TRUST_CONFIGURATION');
      }
      scopes.set(scope.bindingId, Object.freeze({ ...scope }));
    }
    this.keys = keys;
    this.scopes = scopes;
  }

  verify(descriptor: unknown): ProviderVerificationResult {
    let value: ProviderCatalogArtifact;
    try {
      value = ProviderCatalogArtifactSchema.parse(descriptor);
    } catch {
      return { ok: false, code: 'CATALOG_UNTRUSTED' };
    }
    const scope = this.scopes.get(value.bindingId);
    const key = this.keys.get(value.signerKeyId);
    if (!scope || !key) return { ok: false, code: 'CATALOG_UNTRUSTED' };
    if (
      value.providerId !== scope.providerId ||
      value.capabilityId !== scope.capabilityId ||
      value.version !== scope.version ||
      value.catalogRevision !== scope.catalogRevision ||
      value.bindingId !== scope.bindingId ||
      value.scopedVerifierId !== scope.scopedVerifierId ||
      value.catalogManifestSha256 !== scope.catalogManifestSha256 ||
      value.bindingEvidenceSha256 !== scope.bindingEvidenceSha256 ||
      value.artifactSha256 !== scope.artifactSha256 ||
      value.platform !== scope.platform ||
      value.artifactKind !== scope.artifactKind ||
      value.origin !== scope.origin ||
      value.abiRevision !== scope.abiRevision
    )
      return { ok: false, code: 'CATALOG_SCOPE_DRIFT' };
    const sig = base64Signature(value.curatorSignature);
    if (!sig) return { ok: false, code: 'CATALOG_SIGNATURE_INVALID' };
    try {
      const { curatorSignature: _signature, ...signed } = value;
      const bytes = Buffer.from(canonicalJson(signed), 'utf8');
      if (!verifySignature(null, bytes, key, sig)) {
        return { ok: false, code: 'CATALOG_SIGNATURE_INVALID' };
      }
      const admitted = Object.freeze({
        ok: true as const,
        artifact: Object.freeze({
          ...value,
          dependencySha256: Object.freeze([...value.dependencySha256]),
        }),
      });
      this.verifiedDigests.set(admitted, value.artifactSha256);
      return admitted;
    } catch {
      return { ok: false, code: 'CATALOG_SIGNATURE_INVALID' };
    }
  }

  /**
   * Check bytes against a previously verified descriptor before staging.
   * Digest alone is never a signature or an execution grant.
   */
  verifyBytes(verified: ProviderVerificationResult, bytes: Uint8Array): boolean {
    if (
      !verified ||
      typeof verified !== 'object' ||
      !verified.ok ||
      bytes.byteLength > 64 * 1024 * 1024
    )
      return false;
    // A caller-constructed { ok: true, artifact: { artifactSha256 } } is NEVER
    // evidence of signature verification. The private WeakMap binds this
    // immutable result to the exact digest confirmed by this instance.
    const exactDigest = this.verifiedDigests.get(verified);
    if (!exactDigest) return false;
    try {
      return matchSha(exactDigest, sha256Bytes(bytes));
    } catch {
      return false;
    }
  }
}
