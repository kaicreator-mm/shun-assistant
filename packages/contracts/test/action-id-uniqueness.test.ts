// Regression tests for review 5478548765 R2-02: one stable actionId must
// designate exactly one side effect (frozen L2 §9.4 stable identity). Covers
// the three interpretation surfaces a duplicate identity poisons:
//   - plan validation (ActionPlanSchema refuses duplicate actionIds);
//   - grant authorization (the reviewer counterexample: a self-consistent
//     duplicate-ID plan with a matching trusted grant must not pass by
//     "first match");
//   - receipt/recovery interpretation (resolvePlanAction fails closed on
//     ambiguity instead of returning the first match).
import { describe, expect, it } from 'vitest';
import {
  type AuthorizationGrant,
  type CurrentAuthorityState,
  type GrantIntegrityVerifier,
  type GrantValidationInput,
  validateGrantPresentation,
} from '../src/authorization.ts';
import {
  type ActionPlan,
  ActionPlanSchema,
  computePlanHash,
  type PlanAction,
  resolvePlanAction,
  validateActionPlanSemantics,
} from '../src/plan.ts';
import {
  parseActionPlan,
  parseAuthorizationGrant,
  parseAuthorizedAction,
} from '../src/registry.ts';
import { loadFixture } from './helpers.ts';

const NOW = '2026-10-10T08:10:00.000Z';

const plan = parseActionPlan(loadFixture('valid/action-plan/single-binding.json'));
const grant = parseAuthorizationGrant(loadFixture('valid/authorization-grant/automatic.json'));
const action = parseAuthorizedAction(loadFixture('valid/authorized-action/r1-automatic.json'));

const CURRENT: CurrentAuthorityState = {
  kind: 'CURRENT',
  authorityId: 'shun.action-controller',
  authorityRevision: 'auth-r5',
  policySnapshotRevision: 'pol-snap-2026-10-10-a',
  policyStatus: 'ACTIVE',
  revokedGrantIds: [],
};

/** Stand-in trusted substrate: accepts the presented envelope. */
const VERIFIER_ACCEPTS: GrantIntegrityVerifier = () => true;

function input(overrides: Partial<GrantValidationInput> = {}): GrantValidationInput {
  return {
    grant,
    plan,
    action,
    currentAuthority: CURRENT,
    now: NOW,
    verifyIntegrity: VERIFIER_ACCEPTS,
    ...overrides,
  };
}

function expectReject(code: string, overrides: Partial<GrantValidationInput> = {}): void {
  const result = validateGrantPresentation(input(overrides));
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.code).toBe(code);
  }
}

/**
 * The reviewer counterexample (R2-02): a second plan action reusing the SAME
 * actionId with a different op/parameters, under a freshly recomputed
 * self-consistent planHash — so plan-hash binding, grant scope and canonical
 * identity checks would all pass for the first action.
 */
function duplicateIdPlan(): ActionPlan {
  const first = plan.actions[0];
  if (!first) throw new Error('fixture plan must contain an action');
  const shadow: PlanAction = {
    ...first,
    op: 'image.delete',
    parameters: { recursive: true },
    expectedState: { outputsGone: true },
  };
  const withShadow: ActionPlan = { ...plan, actions: [first, shadow] };
  return { ...withShadow, planHash: computePlanHash(withShadow) };
}

function duplicateIdGrant(duplicated: ActionPlan): AuthorizationGrant {
  return { ...grant, planHash: duplicated.planHash };
}

describe('R2-02 plan validation: duplicate actionId is refused', () => {
  it('rejects a plan whose actions share one actionId even when the plan hash is self-consistent', () => {
    const duplicated = duplicateIdPlan();
    // Only the uniqueness rule can reject: the hash matches its own content.
    expect(computePlanHash(duplicated)).toBe(duplicated.planHash);
    const result = ActionPlanSchema.safeParse(duplicated);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(
        result.error.issues.some((issue) => /duplicate actionId "action-001"/.test(issue.message)),
      ).toBe(true);
    }
  });

  it('the shared semantic validator reports the duplicate identity for artifact consumers', () => {
    const issues = validateActionPlanSemantics(duplicateIdPlan());
    expect(issues.some((message) => /duplicate actionId "action-001"/.test(message))).toBe(true);
  });

  it('keeps accepting the unique valid plan (no regression)', () => {
    expect(ActionPlanSchema.safeParse(plan).success).toBe(true);
    expect(validateActionPlanSemantics(plan)).toEqual([]);
  });
});

describe('R2-02 grant authorization: the ambiguous plan cannot authorize anything', () => {
  it('refuses the reviewer counterexample even when the FIRST action is presented with a matching trusted grant', () => {
    const duplicated = duplicateIdPlan();
    const first = duplicated.actions[0];
    if (!first) throw new Error('fixture plan must contain an action');
    // Old behavior: actions.find(...) silently matched the first action, the
    // canonical identity comparison passed, and the grant authorized a plan
    // in which "action-001" ambiguously designated two different side
    // effects. The presentation below is otherwise fully consistent.
    expectReject('GRANT_MALFORMED', {
      plan: duplicated,
      grant: duplicateIdGrant(duplicated),
      action: { ...action, planHash: duplicated.planHash, action: first },
    });
  });

  it('refuses the same ambiguous plan when the shadow action is presented', () => {
    const duplicated = duplicateIdPlan();
    const shadow = duplicated.actions[1];
    if (!shadow) throw new Error('fixture plan must contain the shadow action');
    expectReject('GRANT_MALFORMED', {
      plan: duplicated,
      grant: duplicateIdGrant(duplicated),
      action: { ...action, planHash: duplicated.planHash, action: shadow },
    });
  });

  it('still authorizes the unique plan end to end (no regression)', () => {
    expect(validateGrantPresentation(input({})).ok).toBe(true);
  });
});

describe('R2-02 receipt/recovery interpretation: resolution fails closed on ambiguity', () => {
  it('resolves the unique action of a valid plan', () => {
    const first = plan.actions[0];
    if (!first) throw new Error('fixture plan must contain an action');
    expect(resolvePlanAction(plan, first.actionId)).toEqual(first);
  });

  it('returns undefined — never the first match — for an ambiguous plan (receipt/recovery refusal)', () => {
    const duplicated = duplicateIdPlan();
    // A receipt or recovery step naming "action-001" must not be attributed
    // to whichever action happens to sort first.
    expect(resolvePlanAction(duplicated, 'action-001')).toBeUndefined();
  });

  it('returns undefined for an actionId absent from the plan', () => {
    expect(resolvePlanAction(plan, 'action-absent')).toBeUndefined();
  });
});
