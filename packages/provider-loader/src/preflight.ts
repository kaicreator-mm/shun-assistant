// T05 bounded, zero-effect admission preflight before optional Provider activation.
// This does NOT activate a CLI/native addon, grant privilege or load untrusted code.
import type { CuratedProviderVerifier } from '@shun/vertical-jit';
import type { CuratedProviderStager } from './staging.ts';

export type ProviderUseCurrentness = Readonly<{
  kind: 'CURRENT';
  taskId: string;
  providerId: string;
  bindingId: string;
  catalogRevision: string;
  artifactSha256: string;
  revocationEpoch: number;
  /** The trusted ActionController owns this claim, never the Planner/Recipe. */
  capability: 'PREPARE_PROVIDER';
}> | Readonly<{ kind: 'UNRESOLVABLE' }>;

export type ProviderPreflightRefusal =
  | 'CATALOG_UNTRUSTED'
  | 'AUTHORITY_UNAVAILABLE'
  | 'AUTHORITY_STALE'
  | 'DEPENDENCIES_UNVERIFIED'
  | 'ABI_MISMATCH'
  | 'ARTIFACT_NOT_VERIFIED'
  | 'HOST_UNSUPPORTED';

export type ProviderPreflightResult =
  | { ok: true; state: 'PREFLIGHT_ONLY'; bindingId: string; digest: string; byteLength: number }
  | { ok: false; code: ProviderPreflightRefusal };

export type TrustedPreflightHost = Readonly<{
  verifier: CuratedProviderVerifier;
  stager: Pick<CuratedProviderStager, 'readVerified'>;
  /** Unforgeable private port from ActionController, NOT a user/HTTP flag. */
  getAuthorizedCurrentness: (taskId: string, bindingId: string) => ProviderUseCurrentness;
  /** Host product policy owns the exact revoked epoch and never trusts a request. */
  requiredRevocationEpoch: (bindingId: string) => number;
  /** OS/runtime values come from the trusted executor, not request fields. */
  hostPlatform: () => string;
  hostArchitecture: () => string;
  hostNodeAbi: () => string;
}>;

export class CuratedProviderPreflight {
  private readonly host: TrustedPreflightHost;

  constructor(host: TrustedPreflightHost) {
    if (
      !host?.verifier ||
      typeof host.verifier.verify !== 'function' ||
      !host.stager ||
      typeof host.stager.readVerified !== 'function' ||
      typeof host.getAuthorizedCurrentness !== 'function' ||
      typeof host.requiredRevocationEpoch !== 'function' ||
      typeof host.hostPlatform !== 'function' ||
      typeof host.hostArchitecture !== 'function' ||
      typeof host.hostNodeAbi !== 'function'
    ) {
      throw new Error('PROVIDER_PREFLIGHT_CONFIGURATION_REFUSED');
    }
    this.host = host;
  }

  /**
   * Always fetch authority *from the trusted host* at this call boundary.
   * An unsigned descriptor, revoked catalog, missing staged bytes or ABI drift
   * results in a fixed denial. No executable path is ever returned.
   */
  async check(input: { taskId: string; descriptor: unknown }): Promise<ProviderPreflightResult> {
    if (!input || typeof input.taskId !== 'string' || input.taskId.length < 1) {
      return { ok: false, code: 'AUTHORITY_UNAVAILABLE' };
    }
    let proof: ReturnType<CuratedProviderVerifier['verify']>;
    try {
      proof = this.host.verifier.verify(input.descriptor);
    } catch {
      return { ok: false, code: 'CATALOG_UNTRUSTED' };
    }
    if (!proof.ok) return { ok: false, code: 'CATALOG_UNTRUSTED' };
    const artifact = proof.artifact;

    let snapshot: ProviderUseCurrentness;
    let revokedEpoch: number;
    let platform: string;
    let arch: string;
    let abi: string;
    try {
      snapshot = this.host.getAuthorizedCurrentness(input.taskId, artifact.bindingId);
      revokedEpoch = this.host.requiredRevocationEpoch(artifact.bindingId);
      platform = this.host.hostPlatform();
      arch = this.host.hostArchitecture();
      abi = this.host.hostNodeAbi();
    } catch {
      return { ok: false, code: 'AUTHORITY_UNAVAILABLE' };
    }
    if (
      snapshot.kind !== 'CURRENT' ||
      snapshot.capability !== 'PREPARE_PROVIDER' ||
      snapshot.taskId !== input.taskId ||
      snapshot.providerId !== artifact.providerId ||
      snapshot.bindingId !== artifact.bindingId ||
      snapshot.catalogRevision !== artifact.catalogRevision ||
      snapshot.artifactSha256 !== artifact.artifactSha256 ||
      !Number.isSafeInteger(revokedEpoch) ||
      revokedEpoch < 0 ||
      snapshot.revocationEpoch !== revokedEpoch
    ) {
      return { ok: false, code: 'AUTHORITY_STALE' };
    }
    if (platform !== 'win32' || arch !== 'x64' || artifact.platform !== 'windows-x64') {
      return { ok: false, code: 'HOST_UNSUPPORTED' };
    }
    if (artifact.artifactKind === 'NATIVE_ADDON' && artifact.abiRevision !== abi) {
      return { ok: false, code: 'ABI_MISMATCH' };
    }
    // Dependency closure requires independently signed transitive manifests.
    // This narrow slice deliberately refuses all nonempty sets until that
    // later host implementation exists. Never waive dependencies on "CLI".
    if (artifact.dependencySha256.length !== 0) {
      return { ok: false, code: 'DEPENDENCIES_UNVERIFIED' };
    }
    let bytes: Buffer | null;
    try {
      bytes = await this.host.stager.readVerified(input.descriptor);
    } catch {
      return { ok: false, code: 'ARTIFACT_NOT_VERIFIED' };
    }
    if (!bytes) return { ok: false, code: 'ARTIFACT_NOT_VERIFIED' };

    // This result is NOT an invocation authorization. The eventual native/CLI
    // worker MUST recheck trusted currentness, signature and bytes itself.
    return {
      ok: true,
      state: 'PREFLIGHT_ONLY',
      bindingId: artifact.bindingId,
      digest: artifact.artifactSha256,
      byteLength: bytes.byteLength,
    };
  }
}
