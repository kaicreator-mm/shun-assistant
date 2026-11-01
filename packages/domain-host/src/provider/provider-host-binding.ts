/**
 * R03-INT — trusted production install seam binding the selected K's sealed
 * Provider capability (`shun-provider-host`) to the REAL CuratedProvider
 * chain (OWNER_SHUN_V030_R03_F01F02Q01_REPAIR_APPROVE).
 *
 * The composing trusted process installs ONE binding over the operator's
 * pinned curator roots, catalog descriptor and provider cache root. Every
 * stage is the real production chain: CuratedProviderVerifier → Stager →
 * Activator with BoundedSpawnProcess and the scrubbed minimal environment;
 * the invocation-scoped authorizeRunEffect gate accepts ONLY the pinned
 * binding/artifact identity under the trusted cache root. No second kernel,
 * no unsigned bytes, no system-wide install.
 */
import { join } from 'node:path';
import {
  BoundedSpawnProcess,
  CuratedProviderActivator,
  minimalWindowsSpawnEnvironment,
  type ActivationResult,
  type ResolvedInvocation,
  type RunEffectDecision,
} from '../../../provider-loader/src/activation.ts';
import { CuratedProviderStager } from '../../../provider-loader/src/staging.ts';
import { CuratedProviderVerifier } from '../../../vertical-jit/src/curated-provider.ts';

export interface TrustedProviderBindingConfig {
  /** Operator-owned provider cache root (absolute); staging/active live under it. */
  readonly cacheRoot: string;
  /** Operator-pinned curator trust roots (production material, not test keys). */
  readonly roots: readonly { readonly keyId: string; readonly publicKeyPem: string }[];
  /** Operator-pinned provider scopes. */
  readonly scopes: readonly unknown[];
  /** The exact signed catalog descriptor admitted for first use. */
  readonly descriptor: unknown;
  /** Trusted task identity for PREPARE_PROVIDER currentness. */
  readonly taskId: string;
  /** Pinned revocation epoch the chain requires. */
  readonly revocationEpoch: number;
}

/** Capability envelope returned to the K (terminal receipts only). */
export type ProviderCapabilityEnvelope =
  | {
      readonly phase: 'terminal';
      readonly externalRef: string;
      readonly outcome:
        | { readonly ok: true; readonly output: Record<string, unknown> }
        | { readonly ok: false; readonly error: { readonly code: string; readonly message: string } };
    }
  | { readonly phase: 'running'; readonly externalRef: string };

let installed: {
  readonly activator: CuratedProviderActivator;
  readonly descriptor: unknown;
  readonly taskId: string;
  readonly bindingId: string;
  readonly artifactSha256: string;
  readonly cacheRoot: string;
} | undefined;

export function installTrustedProviderBinding(config: TrustedProviderBindingConfig): void {
  if (installed !== undefined) throw new Error('PROVIDER_HOST_ALREADY_INSTALLED');
  const verifier = new CuratedProviderVerifier(
    config.roots as never,
    config.scopes as never,
  );
  const proof = verifier.verify(config.descriptor);
  if (!proof.ok) throw new Error(`PROVIDER_HOST_DESCRIPTOR_UNTRUSTED:${proof.code}`);
  const artifact = proof.artifact;
  const stager = new CuratedProviderStager({
    cacheRoot: config.cacheRoot,
    verifier,
    isOffline: () => false,
  });
  const activeRoot = join(config.cacheRoot, 'active', artifact.bindingId, artifact.artifactSha256);
  const under = (value: string, root: string): boolean =>
    value.toLowerCase().startsWith(root.toLowerCase());
  const authorizeRunEffect = (invocation: ResolvedInvocation): Promise<RunEffectDecision> =>
    Promise.resolve(
      invocation.taskId === config.taskId &&
        invocation.bindingId === artifact.bindingId &&
        invocation.artifactSha256 === artifact.artifactSha256 &&
        under(invocation.executablePath, join(activeRoot, 'exec')) &&
        invocation.writeRoots.every((root) => under(root, join(activeRoot, 'sandbox')))
        ? { ok: true, leaseId: `lease-${config.taskId}` }
        : { ok: false, code: 'EFFECT_NOT_AUTHORIZED' },
    );
  const activator = new CuratedProviderActivator({
    verifier,
    stager,
    cacheRoot: config.cacheRoot,
    getAuthorizedCurrentness: () => ({
      kind: 'CURRENT' as const,
      taskId: config.taskId,
      providerId: artifact.providerId,
      bindingId: artifact.bindingId,
      catalogRevision: artifact.catalogRevision,
      artifactSha256: artifact.artifactSha256,
      revocationEpoch: config.revocationEpoch,
      capability: 'PREPARE_PROVIDER' as const,
    }),
    authorizeRunEffect,
    requiredRevocationEpoch: () => config.revocationEpoch,
    hostPlatform: () => process.platform,
    hostArchitecture: () => process.arch,
    hostNodeAbi: () => process.versions.modules,
    hostNativeChildRuntime: () => process.execPath,
    hostSpawnEnvironment: minimalWindowsSpawnEnvironment,
    process: new BoundedSpawnProcess(),
  });
  installed = {
    activator,
    descriptor: config.descriptor,
    taskId: config.taskId,
    bindingId: artifact.bindingId,
    artifactSha256: artifact.artifactSha256,
    cacheRoot: config.cacheRoot,
  };
}

function envelopeFrom(result: ActivationResult, externalRef: string): ProviderCapabilityEnvelope {
  if (result.ok) {
    return {
      phase: 'terminal',
      externalRef,
      outcome: {
        ok: true,
        output: {
          state: result.state,
          bindingId: result.bindingId,
          digest: result.digest,
          exitCode: result.exitCode,
          stdout: result.stdout.slice(0, 2048),
          stderr: result.stderr.slice(0, 512),
          timedOut: result.timedOut,
          durationMs: result.durationMs,
        },
      },
    };
  }
  if (result.code === 'ACTIVATION_INTERRUPTED') {
    // Ambiguous execution boundary: never close the K turn optimistically.
    return { phase: 'running', externalRef };
  }
  return {
    phase: 'terminal',
    externalRef,
    outcome: {
      ok: false,
      error: { code: result.code, message: 'trusted Provider Host refused the first use' },
    },
  };
}

/**
 * K→C callback: the pinned provider's genuine first use — identity probe
 * plus a real search canary over seeded sandbox input, both under the
 * invocation-scoped Host grant.
 */
export async function providerFirstUse(
  payload: unknown,
  _dispatchContext: unknown,
): Promise<ProviderCapabilityEnvelope> {
  if (installed === undefined) throw new Error('PROVIDER_HOST_NOT_INSTALLED');
  if (
    typeof payload !== 'object' ||
    payload === null ||
    Array.isArray(payload) ||
    Object.keys(payload).sort().join('|') !== 'taskId'.split('|').join('|') ||
    typeof (payload as { taskId: unknown }).taskId !== 'string' ||
    (payload as { taskId: string }).taskId !== installed.taskId
  ) {
    return {
      phase: 'terminal',
      externalRef: 'provider-first-use',
      outcome: {
        ok: false,
        error: { code: 'PROVIDER_INPUT_REFUSED', message: 'unexpected first-use payload' },
      },
    };
  }
  const probe = await installed.activator.runCli({
    taskId: installed.taskId,
    descriptor: installed.descriptor,
    run: { kind: 'VERSION_PROBE' },
  });
  const probeEnvelope = envelopeFrom(probe, 'provider-version-probe');
  if (probeEnvelope.phase !== 'terminal' || !probeEnvelope.outcome.ok) return probeEnvelope;
  const canary = await installed.activator.runCli({
    taskId: installed.taskId,
    descriptor: installed.descriptor,
    run: { kind: 'FILE_SEARCH', pattern: 'SHUN-PROVIDER-FIRST-USE', operands: ['canary.txt'] },
    sandboxFiles: [
      {
        name: 'canary.txt',
        bytes: new TextEncoder().encode('noise\nSHUN-PROVIDER-FIRST-USE matched\n'),
      },
    ],
  });
  const canaryEnvelope = envelopeFrom(canary, 'provider-first-use');
  if (canaryEnvelope.phase !== 'terminal' || !canaryEnvelope.outcome.ok) return canaryEnvelope;
  // One terminal receipt carrying BOTH real executions: the identity probe
  // version line and the search-canary match line.
  const probeOutput = probeEnvelope.outcome.output as Record<string, unknown>;
  const canaryOutput = canaryEnvelope.outcome.output as Record<string, unknown>;
  return {
    phase: 'terminal',
    externalRef: 'provider-first-use',
    outcome: {
      ok: true,
      output: {
        state: 'EXECUTED',
        bindingId: probeOutput.bindingId,
        digest: probeOutput.digest,
        exitCode: canaryOutput.exitCode,
        stdout:
          String(probeOutput.stdout ?? '').split(String.fromCharCode(10))[0] +
          String.fromCharCode(10) +
          String(canaryOutput.stdout ?? '').split(String.fromCharCode(10))[0],
        timedOut: canaryOutput.timedOut,
        durationMs:
          (typeof probeOutput.durationMs === 'number' ? probeOutput.durationMs : 0) +
          (typeof canaryOutput.durationMs === 'number' ? canaryOutput.durationMs : 0),
      },
    },
  };
}

/** Trusted-process evidence accessor. */
export function trustedProviderBindingStatus(): Readonly<{
  installed: boolean;
  bindingId: string | undefined;
  artifactSha256: string | undefined;
}> {
  return installed === undefined
    ? { installed: false, bindingId: undefined, artifactSha256: undefined }
    : {
        installed: true,
        bindingId: installed.bindingId,
        artifactSha256: installed.artifactSha256,
      };
}
