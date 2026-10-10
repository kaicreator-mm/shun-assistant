// Deterministic, policy-free binding ranking for the C-001 vertical.
//
// This is deliberately narrow: trust screening happens upstream (shared
// resolver/security tasks own it). The vertical only checks binding vs
// environment feasibility, format coverage, and applies a frozen
// interface-class preference with a lexicographic tiebreak so the same
// candidate list and facts always select the same binding.
import type { BindingRejectionReason, EnvironmentFacts, InterfaceClass } from '@shun/contracts';
import type { BindingView, ImageFormat } from './provider.ts';

export const RANKING_POLICY_REVISION = 'rank-pol-t05-v0.1';

const CLASS_PREFERENCE: readonly InterfaceClass[] = ['I0', 'I1', 'I2', 'I3', 'I4'];

export interface BindingCandidate {
  binding: BindingView;
  /** false = the provider is registered but not installed/available. */
  registered: boolean;
}

export type SelectionOutcome = 'SELECTED' | 'NO_TRUSTED_PROVIDER' | 'NO_FEASIBLE_BINDING';

export interface BindingSelection {
  selected: BindingView | null;
  outcome: SelectionOutcome;
  rankingEvidence: {
    rankingPolicyRevision: string;
    reasons: string[];
  };
}

/** Typed infeasibility reasons of one binding against observed machine facts. */
export function infeasibilityReasons(
  binding: BindingView,
  facts: EnvironmentFacts,
): BindingRejectionReason[] {
  const req = binding.environmentRequirements;
  const reasons: BindingRejectionReason[] = [];
  if (req.backendKind !== facts.backendKind) {
    reasons.push('BACKEND_KIND_INELIGIBLE');
  }
  if (req.os && !facts.os.toLowerCase().includes(req.os.toLowerCase())) {
    reasons.push('PLATFORM_UNSUPPORTED');
  }
  if (req.arch && !facts.arch.toLowerCase().includes(req.arch.toLowerCase())) {
    reasons.push('ARCH_UNSUPPORTED');
  }
  if (req.privilegeMode && facts.privilegeMode !== req.privilegeMode) {
    reasons.push('PRIVILEGE_INSUFFICIENT');
  }
  if (req.guiSessionRequired && !facts.guiSession) {
    reasons.push('GUI_SESSION_UNAVAILABLE');
  }
  if (req.networkAccess === 'FORBIDDEN' && facts.networkPolicy !== 'OFFLINE') {
    reasons.push('NETWORK_POLICY_FORBIDDEN');
  }
  if (req.networkAccess === 'REQUIRED' && facts.networkPolicy === 'OFFLINE') {
    reasons.push('NETWORK_POLICY_FORBIDDEN');
  }
  if (req.minFreeDiskMb !== undefined && facts.resources.freeDiskMb < req.minFreeDiskMb) {
    reasons.push('RESOURCE_INSUFFICIENT');
  }
  if (req.runtimeCapabilities?.some((c) => !facts.runtimeCapabilities.includes(c))) {
    reasons.push('RUNTIME_CAPABILITY_MISSING');
  }
  return reasons;
}

function coversAll(binding: BindingView, formats: readonly ImageFormat[]): boolean {
  return !formats.some((f) => binding.unsupportedFormats.includes(f));
}

function compareBindings(a: BindingView, b: BindingView): number {
  const ca = CLASS_PREFERENCE.indexOf(a.interfaceClass);
  const cb = CLASS_PREFERENCE.indexOf(b.interfaceClass);
  if (ca !== cb) {
    return ca - cb;
  }
  return a.bindingId.localeCompare(b.bindingId);
}

/**
 * Selects exactly one binding for the batch. `preferredBindingId` wins only
 * when it is registered and feasible; otherwise selection falls back to the
 * frozen ranking and the deviation is recorded in the reasons.
 */
export function selectBinding(
  candidates: readonly BindingCandidate[],
  facts: EnvironmentFacts,
  requiredFormats: readonly ImageFormat[],
  preferredBindingId?: string,
): BindingSelection {
  const reasons: string[] = [
    `policy ${RANKING_POLICY_REVISION}: I0>I1>I2 preference, bindingId tiebreak`,
  ];
  if (candidates.length === 0) {
    reasons.push('no provider candidate registered for this capability');
    return {
      selected: null,
      outcome: 'NO_TRUSTED_PROVIDER',
      rankingEvidence: { rankingPolicyRevision: RANKING_POLICY_REVISION, reasons },
    };
  }

  const registered = candidates.filter((c) => c.registered);
  const unregistered = candidates.length - registered.length;
  if (unregistered > 0) {
    reasons.push(`${unregistered} candidate(s) not registered/available`);
  }
  if (preferredBindingId && !registered.some((c) => c.binding.bindingId === preferredBindingId)) {
    reasons.push(`preferred binding ${preferredBindingId} missing; falling back to policy ranking`);
  }

  const feasible = registered
    .map((candidate) => ({ candidate, infeasible: infeasibilityReasons(candidate.binding, facts) }))
    .filter((entry) => {
      if (entry.infeasible.length > 0) {
        reasons.push(
          `binding ${entry.candidate.binding.bindingId} infeasible: ${entry.infeasible.join(', ')}`,
        );
        return false;
      }
      return true;
    });
  if (feasible.length === 0) {
    reasons.push('no feasible binding for the observed environment facts');
    return {
      selected: null,
      outcome: 'NO_FEASIBLE_BINDING',
      rankingEvidence: { rankingPolicyRevision: RANKING_POLICY_REVISION, reasons },
    };
  }

  const poolAll: BindingView[] = feasible.map((entry) => entry.candidate.binding);
  const fullCoverage = poolAll.filter((binding) => coversAll(binding, requiredFormats));
  let pool = poolAll;
  if (fullCoverage.length === 0) {
    reasons.push(
      `no candidate covers all batch formats [${requiredFormats.join(', ')}]; per-record fallback applies`,
    );
  } else {
    for (const binding of poolAll.filter((b) => !coversAll(b, requiredFormats))) {
      reasons.push(
        `binding ${binding.bindingId} lacks format(s) ${binding.unsupportedFormats.join(', ')}; demoted`,
      );
    }
    pool = fullCoverage;
  }

  const preferred = preferredBindingId
    ? pool.find((binding) => binding.bindingId === preferredBindingId)
    : undefined;
  const ranked = [...pool].sort(compareBindings);
  const selected = preferred ?? ranked[0];
  if (!selected) {
    reasons.push('feasible pool unexpectedly empty');
    return {
      selected: null,
      outcome: 'NO_FEASIBLE_BINDING',
      rankingEvidence: { rankingPolicyRevision: RANKING_POLICY_REVISION, reasons },
    };
  }
  if (preferred) {
    reasons.push(`selected preferred binding ${selected.bindingId}`);
  } else {
    reasons.push(`selected ${selected.bindingId}: best-ranked feasible candidate`);
  }
  return {
    selected,
    outcome: 'SELECTED',
    rankingEvidence: { rankingPolicyRevision: RANKING_POLICY_REVISION, reasons },
  };
}
