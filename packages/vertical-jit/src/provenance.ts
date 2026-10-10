// Provenance gate (Product C-002): trusted provenance is mandatory for JIT
// acquisition and is evaluated BEFORE any approval surface is consulted.
// A failed/unknown provenance cannot be overridden by user confirmation
// (frozen fail-closed rule), so this module never sees an approval port.
import type {
  ProviderAcquisition,
  ProviderDefinition,
  RESIDUE_CLASSIFICATIONS,
} from '@shun/contracts';
import { JitLifecycleError } from './failures.ts';
import type { AcquisitionCandidate } from './ports.ts';

/**
 * Decide whether a provider definition's declared acquisition is trusted for
 * JIT use: an official source on an official mechanism. Anything else —
 * `official: false`, mechanism OTHER/DIRECT_DOWNLOAD without an official
 * source, or a missing source — is UNKNOWN provenance and fails closed.
 */
export function evaluateProviderProvenance(provider: ProviderDefinition): {
  trusted: boolean;
  reason: string;
  classification: (typeof RESIDUE_CLASSIFICATIONS)[number] | 'UNKNOWN_PROVENANCE';
} {
  const acquisition: ProviderAcquisition = provider.acquisition;
  if (!acquisition.official) {
    return {
      trusted: false,
      reason: `provider ${provider.providerId} is not marked official`,
      classification: 'UNKNOWN_PROVENANCE',
    };
  }
  if (acquisition.mechanism === 'WINGET' || acquisition.mechanism === 'PACKAGE_MANAGER') {
    return {
      trusted: true,
      reason: `official ${acquisition.mechanism} source`,
      classification: 'PROGRAM_OWNED',
    };
  }
  if (acquisition.mechanism === 'PREINSTALLED') {
    return {
      trusted: true,
      reason: 'preinstalled on the managed host',
      classification: 'PROGRAM_OWNED',
    };
  }
  return {
    trusted: false,
    reason: `acquisition mechanism ${acquisition.mechanism} is not a verifiable official channel`,
    classification: 'UNKNOWN_PROVENANCE',
  };
}

/**
 * The hard provenance gate the orchestrator runs before selection. Unknown
 * provenance raises PROVENANCE_UNKNOWN; no approval can reach this module.
 */
export function requireTrustedProvider(
  providers: readonly ProviderDefinition[],
  providerId: string,
): ProviderDefinition {
  const provider = providers.find((candidate) => candidate.providerId === providerId);
  if (!provider) {
    throw new JitLifecycleError(
      'NO_TRUSTED_PROVIDER',
      `provider ${providerId} is not in the registry`,
    );
  }
  const verdict = evaluateProviderProvenance(provider);
  if (!verdict.trusted) {
    throw new JitLifecycleError(
      'PROVENANCE_UNKNOWN',
      `${verdict.reason} — trusted provenance is mandatory and cannot be overridden by user approval (C-002)`,
    );
  }
  return provider;
}

/**
 * Provenance record emitted into the lifecycle output. Exact version is
 * mandatory (C-002 precondition); hash/signature are recorded when the
 * official source exposes them.
 */
export function provenanceRecord(
  candidate: AcquisitionCandidate,
  licenseDisposition: string,
): {
  source: string;
  official: boolean;
  version: string;
  hash?: string;
  signature?: string;
  licenseDisposition: string;
} {
  if (!candidate.official) {
    throw new JitLifecycleError(
      'PROVENANCE_UNKNOWN',
      `candidate from ${candidate.source} is not official — refusing to record trusted provenance`,
    );
  }
  if (candidate.version.trim().length === 0) {
    throw new JitLifecycleError(
      'PROVENANCE_UNKNOWN',
      'candidate has no exact version — exact provenance/version is a C-002 precondition',
    );
  }
  return {
    source: candidate.source,
    official: candidate.official,
    version: candidate.version,
    ...(candidate.installerSha256 ? { hash: candidate.installerSha256 } : {}),
    ...(candidate.signature ? { signature: candidate.signature } : {}),
    licenseDisposition,
  };
}
