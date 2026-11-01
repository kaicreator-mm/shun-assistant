/**
 * R02-A production activation adapter over the PUBLIC DomainHarness v0.10.3
 * BUILD and host-seam functions. SDK implementations are injected by the
 * trusted process composition from installed public packages; there are NO
 * private src imports, bundled fake facades or test-only K substitutions.
 */
import type { DomainAppSendFacade } from '../api/gateway.ts';
import type { BuildV10AppOptions } from '../build/composition.ts';

export interface PublicV10SdkPort {
  buildV10App(options: BuildV10AppOptions): unknown;
  activateV10App(build: unknown, options: TrustedV10ActivationOptions): Promise<unknown>;
}

export interface TrustedV10ActivationOptions {
  readonly store: unknown;
  readonly tenantId: string;
  readonly now: () => number;
  readonly deploymentIdentity: Readonly<{
    deployedAppId: string;
    tenantId: string;
    appId: string;
  }>;
  /** Must be a *real* Host authority, never an unconditional fixture allow. */
  readonly queryAuthority: unknown;
  readonly deploymentRoot: string;
}

export interface ActivatedShunDomainApp {
  readonly facade: DomainAppSendFacade;
  readonly subjectDigest: string;
  dispose(): void;
}

const ID = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const DIGEST = /^[0-9a-f]{64}$/;

function record(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export async function activatePublicShunDomainApp(input: {
  readonly sdk: PublicV10SdkPort;
  readonly buildOptions: BuildV10AppOptions;
  readonly host: TrustedV10ActivationOptions;
}): Promise<ActivatedShunDomainApp> {
  const { sdk, buildOptions, host } = input;
  if (!sdk || typeof sdk.buildV10App !== 'function' ||
      typeof sdk.activateV10App !== 'function' || !host ||
      !ID.test(host.tenantId) || !ID.test(host.deploymentIdentity?.deployedAppId ?? '') ||
      host.deploymentIdentity.tenantId !== host.tenantId ||
      host.deploymentIdentity.appId !== buildOptions.appId ||
      typeof host.now !== 'function' ||
      !host.store || !host.queryAuthority || !host.deploymentRoot) {
    throw new TypeError('V03_PUBLIC_SDK_ACTIVATION_REFUSED');
  }
  let activation: unknown;
  try {
    const built = sdk.buildV10App(buildOptions);
    if (!record(built) || !DIGEST.test(built.subjectDigest as string) ||
        !Array.isArray(built.modules) || built.modules.length !== buildOptions.modules.length) {
      throw new TypeError('V03_PUBLIC_BUILD_INVALID');
    }
    // Verify SDK carried through each selected module package/digest. A stale
    // or substituted K/S/B/C must never activate under a changed identity.
    const material = new Map(
      buildOptions.modules.map((m) => [m.packageId, m.moduleSha256]),
    );
    for (const raw of built.modules) {
      if (!record(raw) || typeof raw.packageId !== 'string' ||
          material.get(raw.packageId) !== raw.moduleSha256) {
        throw new TypeError('V03_PUBLIC_BUILD_IDENTITY_MISMATCH');
      }
    }
    activation = await sdk.activateV10App(built, host);
    if (!record(activation) || !record(activation.facade) ||
        typeof activation.facade.send !== 'function' ||
        typeof activation.dispose !== 'function') {
      throw new TypeError('V03_ACTIVATED_FACADE_INVALID');
    }
    const facade = activation.facade as unknown as DomainAppSendFacade;
    const close = activation.dispose.bind(activation);
    return Object.freeze({
      facade: Object.freeze({ send: facade.send.bind(facade) }),
      subjectDigest: built.subjectDigest as string,
      dispose(): void { close(); },
    });
  } catch {
    if (record(activation) && typeof activation.dispose === 'function') {
      try { activation.dispose(); } catch { /* fail-closed cleanup */ }
    }
    throw new TypeError('V03_PUBLIC_SDK_ACTIVATION_REFUSED');
  }
}
