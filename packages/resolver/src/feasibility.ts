// Provider requirement derivation and Provider × Environment feasibility
// (L2 §7 resolver flow steps 4–5, Product resolver v0.1 hard gate 3).
//
// A Provider is discovered before environment binding: requirements are
// derived from the binding as data and evaluated against observed facts —
// requirements are never a verdict on the Provider itself, and environment
// feasibility never rejects a Provider whose requirements have not been
// resolved against the currently allowed environment candidates.
import {
  type BackendKind,
  BINDING_REJECTION_REASONS,
  type BindingRejectionReason,
  type EnvironmentFacts,
  type EnvironmentPolicy,
  type EnvironmentRequirements,
  type Feasibility,
  type PrivilegeMode,
  type ProviderCapabilityBinding,
  type ProviderDefinition,
} from '@shun/contracts';

const PRIVILEGE_RANK: Record<PrivilegeMode, number> = {
  STANDARD_USER: 0,
  FILTERED_ADMIN: 1,
  ELEVATED_ADMIN: 2,
  SERVICE: 3,
};

function osMatches(
  observed: string,
  required: NonNullable<EnvironmentRequirements['os']>,
): boolean {
  return observed.toUpperCase().includes(required);
}

function archMatches(
  observed: string,
  required: NonNullable<EnvironmentRequirements['arch']>,
): boolean {
  return observed.toUpperCase().includes(required);
}

/**
 * Derive the typed feasibility of one capability binding against one observed
 * environment under the goal's environment policy. Rejection reasons are the
 * frozen BINDING_REJECTION_REASONS enum, emitted in a fixed order so the
 * disposition evidence is deterministic.
 */
export function deriveFeasibility(input: {
  binding: ProviderCapabilityBinding;
  provider: ProviderDefinition;
  environment: EnvironmentFacts;
  environmentPolicy: EnvironmentPolicy;
}): Feasibility {
  const { binding, provider, environment, environmentPolicy } = input;
  const requirements = binding.environmentRequirements;
  const reasons: BindingRejectionReason[] = [];

  const backendEligible =
    requirements.backendKind === environment.backendKind &&
    environmentPolicy.allowedBackendKinds.includes(environment.backendKind as BackendKind);
  if (!backendEligible) {
    reasons.push('BACKEND_KIND_INELIGIBLE');
  }

  const platformDeclared = provider.supportedPlatforms.some(
    (platform) =>
      osMatches(environment.os, platform.os) &&
      (platform.arch === undefined || archMatches(environment.arch, platform.arch)),
  );
  if (!platformDeclared) {
    reasons.push('PLATFORM_UNSUPPORTED');
  }
  if (requirements.os !== undefined && !osMatches(environment.os, requirements.os)) {
    if (!reasons.includes('PLATFORM_UNSUPPORTED')) {
      reasons.push('PLATFORM_UNSUPPORTED');
    }
  }
  if (requirements.arch !== undefined && !archMatches(environment.arch, requirements.arch)) {
    reasons.push('ARCH_UNSUPPORTED');
  }

  if (requirements.privilegeMode !== undefined) {
    const observedRank = PRIVILEGE_RANK[environment.privilegeMode];
    const requiredRank = PRIVILEGE_RANK[requirements.privilegeMode];
    if (observedRank < requiredRank) {
      reasons.push('PRIVILEGE_INSUFFICIENT');
    }
  }

  if (requirements.guiSessionRequired === true && !environment.guiSession) {
    reasons.push('GUI_SESSION_UNAVAILABLE');
  }

  if (requirements.networkAccess === 'REQUIRED' && environment.networkPolicy === 'OFFLINE') {
    reasons.push('NETWORK_POLICY_FORBIDDEN');
  }

  if (
    requirements.minFreeDiskMb !== undefined &&
    environment.resources.freeDiskMb < requirements.minFreeDiskMb
  ) {
    reasons.push('RESOURCE_INSUFFICIENT');
  }

  const missingRuntimes = (requirements.runtimeCapabilities ?? []).filter(
    (capability) => !environment.runtimeCapabilities.includes(capability),
  );
  if (missingRuntimes.length > 0) {
    reasons.push('RUNTIME_CAPABILITY_MISSING');
  }

  const ordered = BINDING_REJECTION_REASONS.filter((reason) => reasons.includes(reason));
  return { feasible: ordered.length === 0, rejectionReasons: ordered };
}
