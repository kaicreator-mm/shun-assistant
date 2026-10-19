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

/**
 * One signer-curated transitive dependency of a native addon. The DIGEST is
 * signed (it is part of the descriptor's `dependencySha256`); the exact
 * on-disk NAME the Windows loader must resolve is pinned here by the trusted
 * host composition — never by request input, HTTP content or the descriptor
 * alone. A dep digest without a pinned name is unusable and refused.
 */
export type ProviderDependencyEntry = Readonly<{
  /** Bare DLL/file name (e.g. `libvips-42.dll`); never a path. */
  name: string;
  artifactSha256: string;
}>;

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
  /**
   * Host-curated name↔digest mapping that must bijection-match the signed
   * `dependencySha256` list. Optional only for artifact shapes with no
   * transitive dependencies at all.
   */
  dependencyEntries?: readonly ProviderDependencyEntry[];
}>;

export type ProviderVerificationRefusal =
  | 'CATALOG_UNTRUSTED'
  | 'CATALOG_SCOPE_DRIFT'
  | 'CATALOG_SIGNATURE_INVALID'
  | 'ARTIFACT_HASH_MISMATCH';

export type VerifiedProviderArtifact = Readonly<
  Omit<ProviderCatalogArtifact, 'dependencySha256'> & {
    dependencySha256: readonly string[];
    /**
     * The host-curated name↔digest pairs resolved for this artifact. Nonempty
     * exactly when `dependencySha256` is nonempty (strict bijection is
     * enforced in verify()); a caller can never obtain dep digests without
     * equally many host-pinned names.
     */
    dependencyEntries: readonly ProviderDependencyEntry[];
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

/** Bare DLL/file-name shape for curated dependency names; never a path. */
const DEPENDENCY_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/**
 * Strict bijection between the SIGNED dependency digest list and the
 * host-pinned dependency names. Any mismatch — a digest without a name, a
 * name without a digest, duplicates, a self-referential entry, or an unsafe
 * name shape — is scope drift, because the loader would otherwise materialize
 * files whose identity the curator signature alone cannot bind.
 */
function resolveDependencyEntries(
  scope: TrustedProviderScope,
  declared: readonly string[],
): ProviderDependencyEntry[] | null {
  const entries = scope.dependencyEntries ?? [];
  if (entries.length !== declared.length) return null;
  if (declared.length === 0) return [];
  const declaredSet = new Set(declared);
  if (declaredSet.size !== declared.length) return null;
  const names = new Set<string>();
  const mappedDigests = new Set<string>();
  const resolved: ProviderDependencyEntry[] = [];
  for (const entry of entries) {
    if (
      !entry ||
      !DEPENDENCY_NAME.test(entry.name) ||
      !declaredSet.has(entry.artifactSha256) ||
      entry.artifactSha256 === scope.artifactSha256
    ) {
      return null;
    }
    const lower = entry.name.toLowerCase();
    if (names.has(lower) || mappedDigests.has(entry.artifactSha256)) return null;
    names.add(lower);
    mappedDigests.add(entry.artifactSha256);
    resolved.push(Object.freeze({ name: entry.name, artifactSha256: entry.artifactSha256 }));
  }
  if (mappedDigests.size !== declaredSet.size) return null;
  return resolved;
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
      scopes.set(
        scope.bindingId,
        Object.freeze({
          ...scope,
          dependencyEntries: scope.dependencyEntries
            ? Object.freeze(scope.dependencyEntries.map((entry) => Object.freeze({ ...entry })))
            : undefined,
        }),
      );
    }
    this.keys = keys;
    this.scopes = scopes;
  }

  verify(descriptor: unknown): ProviderVerificationResult {
    // Re-verifying an already-admitted artifact (e.g. the preflight passing
    // the verified artifact back through the stager) carries the DERIVED
    // `dependencyEntries` field, which the strict wire schema rejects. That
    // field is host-derived and NEVER part of the signed payload, so
    // stripping it before parsing verifies exactly the same canonical bytes;
    // any other unknown field still fails the strict schema.
    let candidate: unknown = descriptor;
    if (candidate !== null && typeof candidate === 'object' && 'dependencyEntries' in candidate) {
      const { dependencyEntries: _derived, ...rest } = candidate as Record<string, unknown>;
      candidate = rest;
    }
    let value: ProviderCatalogArtifact;
    try {
      value = ProviderCatalogArtifactSchema.parse(candidate);
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
    const dependencyEntries = resolveDependencyEntries(scope, value.dependencySha256);
    if (!dependencyEntries) return { ok: false, code: 'CATALOG_SCOPE_DRIFT' };
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
          dependencyEntries: Object.freeze(dependencyEntries),
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
