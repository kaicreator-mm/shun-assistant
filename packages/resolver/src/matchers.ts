// Deterministic objective → capability matchers (resolver-owned curated data).
//
// L2 §6.3: a structured/direct invocation of an already known Capability may
// bypass model use; free-form natural-language interpretation requires a
// PlannerPort backend. The P0 deterministic path therefore resolves a goal
// only when it names a registered capability id explicitly or matches a
// registered alias phrase. Matchers are versioned curated data — broadening
// them is a data revision, never silent behavior.
export const MATCHER_TABLE_REVISION = 'shun.resolver.objective-matchers/0.1';

export type ObjectiveMatcherTable = Readonly<Record<string, readonly RegExp[]>>;

export const OBJECTIVE_MATCHERS: ObjectiveMatcherTable = {
  'image.batch_process': [
    /\bimage\.batch_process\b/,
    /\bbatch[-\s]?(?:resize|process|convert)\s+(?:my\s+|the\s+)?(?:photos|images)\b/i,
  ],
  'software.jit_capability_lifecycle': [
    /\bsoftware\.jit_capability_lifecycle\b/,
    /\bjit\s+capability\s+lifecycle\b/i,
  ],
  'system.storage.diagnose_bounded_action': [
    /\bsystem\.storage\.diagnose_bounded_action\b/,
    /\bstorage\s+diagnos\w*\s+(?:and\s+)?(?:bounded\s+)?(?:action|clean\w*)\b/i,
  ],
};

/**
 * Distinct capability ids whose id or registered alias the objective names,
 * in table order (deterministic). Two or more matches make the goal ambiguous
 * and require clarification instead of a silent pick.
 */
export function matchCapabilityIds(
  objective: string,
  table: ObjectiveMatcherTable = OBJECTIVE_MATCHERS,
): string[] {
  const matched: string[] = [];
  for (const [capabilityId, patterns] of Object.entries(table)) {
    if (patterns.some((pattern) => pattern.test(objective))) {
      matched.push(capabilityId);
    }
  }
  return matched;
}
