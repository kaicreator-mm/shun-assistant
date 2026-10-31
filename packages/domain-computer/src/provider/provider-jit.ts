/**
 * T08 — Curated Provider JIT B: a bounded acquisition-lifecycle PROPOSAL.
 *
 * This adapter NEVER executes, downloads, installs, spawns or grants anything:
 * its only successful outcome is a frozen, deterministic proposal whose effect
 * route is `T11_WIRING_ONLY` (the composition root must independently wire any
 * later acquisition through the trusted stager/K path). Trust decisions are
 * delegated exclusively to the injected `TrustedProviderHostPort` (the T08
 * signed Host adapter or an equivalent T11 composition): no digest, signature
 * or cache presence is ever trusted from request input itself.
 */
import { ProviderCatalogArtifactSchema } from '../../../contracts/src/index.ts';
import type { ProviderVerificationResult } from '../../../vertical-jit/src/curated-provider.ts';

/**
 * Minimal structured trust port consumed by JIT B. Implemented by the T08
 * trusted Host adapter plus T11 composition-owned cache/offline policy. All
 * methods must come from trusted configuration, never per-request input.
 */
export interface TrustedProviderHostPort {
  /** Four-class CuratedProviderVerifier admission verdict. */
  verifyProviderDescriptor(descriptor: unknown): ProviderVerificationResult;
  /** Byte binding against a result minted by THIS port's verifier instance. */
  verifyProviderBytes(verified: ProviderVerificationResult, bytes: Uint8Array): boolean;
  /**
   * Presence-only peek into the trusted byte cache. Cache presence is never
   * trust: any real use re-hashes the bytes through the trusted stager.
   */
  cachePeek(artifactSha256: string): 'SEEDED' | 'MISS';
  /** OS/network policy from trusted host composition; caller cannot override. */
  isOffline(): boolean;
}

export type ProviderJitRefusal =
  | 'DESCRIPTOR_INVALID'
  | 'CATALOG_UNTRUSTED'
  | 'CATALOG_SCOPE_DRIFT'
  | 'CATALOG_SIGNATURE_INVALID'
  | 'ARTIFACT_HASH_MISMATCH'
  | 'OFFLINE_CACHE_MISS';

export type ProviderJitAcquisitionResult =
  | Readonly<{ status: 'REFUSED'; code: ProviderJitRefusal; modelCalls: 0 }>
  | Readonly<{
      status: 'PROPOSAL_ONLY';
      bindingId: string;
      artifactSha256: string;
      cacheState: 'SEEDED' | 'MISS';
      executionAuthorized: false;
      effectRoute: 'T11_WIRING_ONLY';
      modelCalls: 0;
      deterministic: true;
    }>;

export type ProviderJitOptions = Readonly<{
  /**
   * Optional additional capability pin enforced AFTER host admission. The
   * host scopes already pin capabilityId; this is a business-level second
   * gate for a composition that wants a narrower JIT surface.
   */
  readonly capabilityId?: string;
}>;

const CONFIG_REFUSED = 'PROVIDER_JIT_CONFIGURATION_REFUSED';
const MAX_TEXT = 2048;

function text(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_TEXT;
}

function refused(code: ProviderJitRefusal): ProviderJitAcquisitionResult {
  return deepFreeze({ status: 'REFUSED', code, modelCalls: 0 as const });
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/**
 * Host-only bounded adapter. Port methods are snapshotted exactly once so a
 * getter-backed or later-mutated host cannot swap trust between construction
 * and proposal. No execution-capability port is accepted by this factory.
 */
export function createProviderJitBusinessAdapter(
  host: TrustedProviderHostPort,
  options: ProviderJitOptions = {},
): {
  proposeProviderAcquisition(
    descriptor: unknown,
    artifactBytes?: Uint8Array,
  ): ProviderJitAcquisitionResult;
} {
  try {
    if (
      !host ||
      typeof host.verifyProviderDescriptor !== 'function' ||
      typeof host.verifyProviderBytes !== 'function' ||
      typeof host.cachePeek !== 'function' ||
      typeof host.isOffline !== 'function'
    ) {
      throw new Error(CONFIG_REFUSED);
    }
    const verifyDescriptor = host.verifyProviderDescriptor.bind(host);
    const verifyArtifactBytes = host.verifyProviderBytes.bind(host);
    const peekCache = host.cachePeek.bind(host);
    const offlinePolicy = host.isOffline.bind(host);
    const capabilityPin = options?.capabilityId;
    if (capabilityPin !== undefined && !text(capabilityPin)) {
      throw new Error(CONFIG_REFUSED);
    }

    return Object.freeze({
      proposeProviderAcquisition(
        descriptor: unknown,
        artifactBytes?: Uint8Array,
      ): ProviderJitAcquisitionResult {
        // 1. Wire-shape gate (contract concern, not trust): a structurally
        // invalid descriptor is DESCRIPTOR_INVALID and never reaches the
        // trust port as a "trust" question.
        try {
          if (!ProviderCatalogArtifactSchema.safeParse(descriptor).success) {
            return refused('DESCRIPTOR_INVALID');
          }
        } catch {
          // Hostile descriptor (throwing getter) or hostile schema input.
          return refused('DESCRIPTOR_INVALID');
        }

        // 2. Trust gate: only the injected port can mint admission.
        let verified: ProviderVerificationResult;
        try {
          verified = verifyDescriptor(descriptor);
        } catch {
          // Broken trusted component: the v0.2 stager maps verifier throws to
          // CATALOG_UNTRUSTED; keep the same stable vocabulary here.
          return refused('CATALOG_UNTRUSTED');
        }
        if (!verified.ok) return refused(verified.code);
        const { bindingId, artifactSha256, capabilityId } = verified.artifact;
        if (capabilityPin !== undefined && capabilityId !== capabilityPin) {
          return refused('CATALOG_SCOPE_DRIFT');
        }

        // 3. Optional caller-supplied bytes must hash-bind exactly.
        if (artifactBytes !== undefined) {
          let bytesOk = false;
          if (artifactBytes instanceof Uint8Array) {
            try {
              bytesOk = verifyArtifactBytes(verified, artifactBytes);
            } catch {
              bytesOk = false;
            }
          }
          if (!bytesOk) return refused('ARTIFACT_HASH_MISMATCH');
        }

        // 4. Cache presence peek (fail-closed: unknown peek state is MISS).
        let cacheState: 'SEEDED' | 'MISS' = 'MISS';
        try {
          const peeked = peekCache(artifactSha256);
          if (peeked === 'SEEDED') cacheState = 'SEEDED';
        } catch {
          cacheState = 'MISS';
        }

        // 5. Offline policy (fail-closed: unknown policy counts as offline).
        let offline: boolean;
        try {
          offline = offlinePolicy() !== false;
        } catch {
          offline = true;
        }
        if (offline && cacheState !== 'SEEDED') return refused('OFFLINE_CACHE_MISS');

        // 6. Frozen PROPOSAL_ONLY: zero authority, zero execution fields.
        return deepFreeze({
          status: 'PROPOSAL_ONLY' as const,
          bindingId,
          artifactSha256,
          cacheState,
          executionAuthorized: false as const,
          effectRoute: 'T11_WIRING_ONLY' as const,
          modelCalls: 0 as const,
          deterministic: true as const,
        });
      },
    });
  } catch {
    throw new Error(CONFIG_REFUSED);
  }
}
