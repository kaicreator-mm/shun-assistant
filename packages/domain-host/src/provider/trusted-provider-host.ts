/**
 * T08 — signed trusted Host adapter over the v0.2 CuratedProviderVerifier.
 *
 * The pinned curator roots and trusted provider scopes are Shun-owned fixed
 * configuration (never a Planner/Recipe/HTTP input). They are snapshotted once
 * here: hostile getters are refused at construction and later mutation of the
 * caller's objects cannot retarget trust. The adapter exposes only bounded
 * verification methods; `describeTrust()` leaks key/binding identifiers, never
 * key material. It never downloads, executes, caches or grants anything.
 */
import {
  CuratedProviderVerifier,
  type ProviderVerificationRefusal,
  type ProviderVerificationResult,
  type TrustedProviderScope,
} from '../../../vertical-jit/src/curated-provider.ts';

/** One pinned curator trust root. PEM content never leaves this module. */
export type TrustedProviderRoot = Readonly<{ keyId: string; publicKeyPem: string }>;

/** Identifier-only trust description. No PEM, no scope field values. */
export type TrustedProviderTrustDescription = Readonly<{
  /** Pinned curator root keyIds. */
  readonly roots: readonly string[];
  /** Trusted scope bindingIds. */
  readonly bindings: readonly string[];
  /** Construction-time trust anchor snapshot (ISO 8601). */
  readonly anchoredAt: string;
}>;

export type TrustedProviderHostRefusal = ProviderVerificationRefusal;

export interface TrustedProviderHost {
  /** Exactly the four-class CuratedProviderVerifier admission verdict. */
  verifyProviderDescriptor(descriptor: unknown): ProviderVerificationResult;
  /** Byte binding against a result minted by THIS host's verifier instance. */
  verifyProviderBytes(verified: ProviderVerificationResult, bytes: Uint8Array): boolean;
  /** Identifier-only trust facts; safe to log, useless for impersonation. */
  describeTrust(): TrustedProviderTrustDescription;
}

export type TrustedProviderHostInput = Readonly<{
  readonly roots: readonly TrustedProviderRoot[];
  readonly scopes: readonly TrustedProviderScope[];
  /** Trusted clock read exactly once at construction; defaults to current time. */
  readonly now?: () => Date;
}>;

const CONFIG_REFUSED = 'TRUSTED_PROVIDER_HOST_CONFIGURATION_REFUSED';
const MAX_TEXT = 2048;

function isRecord(value: unknown): value is Record<string, unknown> {
  try {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  } catch {
    return false;
  }
}

function text(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_TEXT;
}

/**
 * Read each pinned field exactly once into a plain copy. A getter-backed root
 * or scope therefore cannot feed different values to validation and use, and
 * cannot retarget trust after construction. Any throwing or malformed read is
 * a configuration refusal, never a partial snapshot.
 */
function snapshotRoot(raw: unknown): TrustedProviderRoot {
  if (!isRecord(raw)) throw new Error(CONFIG_REFUSED);
  const keyId = raw.keyId;
  const publicKeyPem = raw.publicKeyPem;
  if (!text(keyId) || !text(publicKeyPem)) throw new Error(CONFIG_REFUSED);
  return { keyId, publicKeyPem };
}

function snapshotDependencyEntries(raw: unknown): ProviderDependencyEntryCopy[] | undefined {
  if (raw === undefined) return undefined;
  if (!Array.isArray(raw)) throw new Error(CONFIG_REFUSED);
  return raw.map((entry) => {
    if (!isRecord(entry)) throw new Error(CONFIG_REFUSED);
    const name = entry.name;
    const artifactSha256 = entry.artifactSha256;
    if (!text(name) || !text(artifactSha256)) throw new Error(CONFIG_REFUSED);
    return { name, artifactSha256 };
  });
}

type ProviderDependencyEntryCopy = Readonly<{ name: string; artifactSha256: string }>;

function snapshotScope(raw: unknown): TrustedProviderScope {
  if (!isRecord(raw)) throw new Error(CONFIG_REFUSED);
  const providerId = raw.providerId;
  const capabilityId = raw.capabilityId;
  const version = raw.version;
  const catalogRevision = raw.catalogRevision;
  const bindingId = raw.bindingId;
  const scopedVerifierId = raw.scopedVerifierId;
  const catalogManifestSha256 = raw.catalogManifestSha256;
  const bindingEvidenceSha256 = raw.bindingEvidenceSha256;
  const artifactSha256 = raw.artifactSha256;
  const origin = raw.origin;
  const platform = raw.platform;
  const artifactKind = raw.artifactKind;
  const abiRevision = raw.abiRevision;
  const dependencyEntries = snapshotDependencyEntries(raw.dependencyEntries);
  if (
    !text(providerId) ||
    !text(capabilityId) ||
    !text(version) ||
    !text(catalogRevision) ||
    !text(bindingId) ||
    !text(scopedVerifierId) ||
    !text(catalogManifestSha256) ||
    !text(bindingEvidenceSha256) ||
    !text(artifactSha256) ||
    !text(origin) ||
    platform !== 'windows-x64' ||
    (artifactKind !== 'CLI' && artifactKind !== 'NATIVE_ADDON') ||
    (abiRevision !== undefined && !text(abiRevision))
  ) {
    throw new Error(CONFIG_REFUSED);
  }
  const scope: TrustedProviderScope = {
    providerId,
    capabilityId,
    version,
    catalogRevision,
    bindingId,
    scopedVerifierId,
    catalogManifestSha256,
    bindingEvidenceSha256,
    artifactSha256,
    origin,
    platform,
    artifactKind,
    ...(abiRevision !== undefined ? { abiRevision } : {}),
    ...(dependencyEntries !== undefined ? { dependencyEntries } : {}),
  };
  return scope;
}

/**
 * Build the signed trusted Host adapter. Configuration is validated and
 * snapshotted exactly once; every later read flows through the frozen
 * snapshot, so mutating (or getter-swapping) the caller's objects afterwards
 * has no effect on admission decisions.
 */
export function createTrustedProviderHost(input: TrustedProviderHostInput): TrustedProviderHost {
  try {
    const rootsRaw = input?.roots;
    const scopesRaw = input?.scopes;
    if (!Array.isArray(rootsRaw) || !Array.isArray(scopesRaw)) throw new Error(CONFIG_REFUSED);
    if (rootsRaw.length === 0 || scopesRaw.length === 0) throw new Error(CONFIG_REFUSED);
    const roots = rootsRaw.map((root) => snapshotRoot(root));
    const scopes = scopesRaw.map((scope) => snapshotScope(scope));

    const now = input.now;
    let anchoredAt: string;
    if (now === undefined) {
      anchoredAt = new Date().toISOString();
    } else {
      if (typeof now !== 'function') throw new Error(CONFIG_REFUSED);
      const at = now();
      if (!(at instanceof Date) || Number.isNaN(at.getTime())) throw new Error(CONFIG_REFUSED);
      anchoredAt = at.toISOString();
    }

    let verifier: CuratedProviderVerifier;
    try {
      verifier = new CuratedProviderVerifier(roots, scopes);
    } catch {
      // Duplicate root keyIds / bindingIds, non-Ed25519 or unparseable PEM.
      throw new Error(CONFIG_REFUSED);
    }
    const verifyDescriptor = verifier.verify.bind(verifier);
    const verifyArtifactBytes = verifier.verifyBytes.bind(verifier);
    const trustDescription: TrustedProviderTrustDescription = Object.freeze({
      roots: Object.freeze(roots.map((root) => root.keyId)),
      bindings: Object.freeze(scopes.map((scope) => scope.bindingId)),
      anchoredAt,
    });

    return Object.freeze({
      verifyProviderDescriptor(descriptor: unknown): ProviderVerificationResult {
        // A hostile descriptor (e.g. a throwing Proxy) must surface as the
        // stable four-class refusal, exactly like the v0.2 stager boundary.
        try {
          return verifyDescriptor(descriptor);
        } catch {
          return { ok: false, code: 'CATALOG_UNTRUSTED' };
        }
      },
      verifyProviderBytes(verified: ProviderVerificationResult, bytes: Uint8Array): boolean {
        try {
          return verifyArtifactBytes(verified, bytes);
        } catch {
          return false;
        }
      },
      describeTrust(): TrustedProviderTrustDescription {
        return trustDescription;
      },
    });
  } catch {
    throw new Error(CONFIG_REFUSED);
  }
}
