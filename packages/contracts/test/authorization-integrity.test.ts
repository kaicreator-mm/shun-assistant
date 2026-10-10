// Regression tests for the authorization-integrity review findings
// (review 5478384275), one describe block per finding:
//   P1-01 — the presented action must be exactly the action recorded in the
//           hashed plan (id, surface, policy revision, task);
//   P1-02 — an integrity envelope being present is not verification; the
//           caller-injected trusted verifier decides authenticity;
//   P1-03 — pathWithin fails closed on `..` segments (lexical check only);
//   P1-04 — expiry is decided on parsed instants (equal instants expire) and
//           the injected clock itself is validated.
import { describe, expect, it } from 'vitest';
import {
  type AuthorizationGrant,
  type CurrentAuthorityState,
  type GrantIntegrityVerifier,
  type GrantValidationInput,
  pathWithin,
  validateGrantPresentation,
} from '../src/authorization.ts';
import { type ActionPlan, type AuthorizedAction, computePlanHash } from '../src/plan.ts';
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

/** Stand-in trusted substrate (P1-02): accepts the presented envelope. */
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

describe('P1-01: the presented action must be exactly the action recorded in the hashed plan', () => {
  it('refuses an altered parameter under an unchanged actionId, plan and hash (reviewer counterexample)', () => {
    const tampered: AuthorizedAction = {
      ...action,
      action: {
        ...action.action,
        parameters: { ...action.action.parameters, maxLongEdgePx: 9999 },
      },
    };
    expectReject('GRANT_PLAN_MISMATCH', { action: tampered });
  });

  it('refuses an altered op under an unchanged actionId and hash', () => {
    const tampered: AuthorizedAction = {
      ...action,
      action: { ...action.action, op: 'image.delete' },
    };
    expectReject('GRANT_PLAN_MISMATCH', { action: tampered });
  });

  it('refuses an actionId the grant scope covers but the hashed plan does not contain', () => {
    const widenedGrant: AuthorizationGrant = {
      ...grant,
      actionScope: {
        ...grant.actionScope,
        actionIds: [...grant.actionScope.actionIds, 'action-999'],
      },
    };
    const rogue: AuthorizedAction = {
      ...action,
      actionId: 'action-999',
      action: { ...action.action, actionId: 'action-999' },
    };
    expectReject('GRANT_PLAN_MISMATCH', { grant: widenedGrant, action: rogue });
  });

  it('refuses a presented action whose top-level actionId does not match its embedded surface', () => {
    // Scope is widened so only the consistency rule can reject.
    const widenedGrant: AuthorizationGrant = {
      ...grant,
      actionScope: {
        ...grant.actionScope,
        actionIds: [...grant.actionScope.actionIds, 'action-999'],
      },
    };
    expectReject('GRANT_MALFORMED', {
      grant: widenedGrant,
      action: { ...action, actionId: 'action-999' },
    });
  });

  it('refuses a tampered action policySnapshotRevision', () => {
    expectReject('GRANT_PLAN_MISMATCH', {
      action: { ...action, policySnapshotRevision: 'pol-snap-9999' },
    });
  });

  it('refuses when the action/grant policy revision diverges from the revision hashed into the plan', () => {
    const divergentRevision = 'pol-snap-2026-10-09-z';
    const divergentPlan: ActionPlan = {
      ...plan,
      policySnapshotRevision: divergentRevision,
      planHash: computePlanHash({ ...plan, policySnapshotRevision: divergentRevision }),
    };
    const divergentGrant: AuthorizationGrant = { ...grant, planHash: divergentPlan.planHash };
    const divergentAction: AuthorizedAction = { ...action, planHash: divergentPlan.planHash };
    // The action still names the grant's revision, so only the plan-revision
    // binding rule can catch this internally-consistent triple.
    expectReject('GRANT_PLAN_MISMATCH', {
      grant: divergentGrant,
      plan: divergentPlan,
      action: divergentAction,
    });
  });

  it('refuses a presented action whose taskId is not the task of the hashed plan', () => {
    const otherTaskPlan: ActionPlan = {
      ...plan,
      taskId: 'task-other',
      planHash: computePlanHash({ ...plan, taskId: 'task-other' }),
    };
    const otherTaskGrant: AuthorizationGrant = { ...grant, planHash: otherTaskPlan.planHash };
    const otherTaskAction: AuthorizedAction = { ...action, planHash: otherTaskPlan.planHash };
    expectReject('GRANT_PLAN_MISMATCH', {
      grant: otherTaskGrant,
      plan: otherTaskPlan,
      action: otherTaskAction,
    });
  });
});

describe('P1-02: envelope presence is not verification — the trusted verifier decides', () => {
  it('refuses a structurally-present envelope that the trusted verifier rejects', () => {
    const result = validateGrantPresentation(input({ verifyIntegrity: () => false }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('GRANT_NOT_AUTHENTIC');
      expect(result.detail).toMatch(/present/);
      expect(result.detail).toMatch(/verif/);
    }
  });

  it('accepts only what the injected verifier accepts', () => {
    const seen: { grants: string[]; schemes: string[] } = { grants: [], schemes: [] };
    const recording: GrantIntegrityVerifier = (verified, envelope) => {
      seen.grants.push(verified.grantId);
      seen.schemes.push(envelope.scheme);
      return envelope.scheme === 'HMAC_SHA256' && verified.issuer.authorityId !== '';
    };
    const result = validateGrantPresentation(input({ verifyIntegrity: recording }));
    expect(result.ok).toBe(true);
    expect(seen.grants).toEqual([grant.grantId]);
    expect(seen.schemes).toEqual(['HMAC_SHA256']);
  });

  it('cannot even be invoked without a verifier — required at the type level (compile-time fail-closed)', () => {
    const missingVerifier = {
      grant,
      plan,
      action,
      currentAuthority: CURRENT,
      now: NOW,
    };
    // @ts-expect-error — `verifyIntegrity` is mandatory; omitting it must not typecheck.
    const broken: GrantValidationInput = missingVerifier;
    expect(broken.grant).toBeDefined();
  });
});

describe('P1-03: pathWithin fails closed on `..` segments (lexical check, not realpath)', () => {
  it('refuses the reviewer counterexample: `..` re-roots outside the authorized prefix', () => {
    // Win32-normalizes to C:\fixtures\protected\sensitive.txt — outside C:\fixtures\out.
    expect(pathWithin('C:\\fixtures\\out\\..\\protected\\sensitive.txt', 'C:\\fixtures\\out')).toBe(
      false,
    );
  });

  it('refuses a `..` segment on the prefix side', () => {
    expect(pathWithin('C:\\fixtures\\out\\a.png', 'C:\\fixtures\\out\\..\\out')).toBe(false);
    expect(pathWithin('C:\\fixtures\\out\\a.png', '..\\fixtures\\out')).toBe(false);
  });

  it('keeps ordinary containment semantics intact (no regression)', () => {
    expect(pathWithin('C:\\fixtures\\out\\a.png', 'C:\\fixtures\\out')).toBe(true);
    expect(pathWithin('c:/FIXTURES/out/deep/a.png', 'C:\\fixtures\\out')).toBe(true);
    expect(pathWithin('C:\\fixtures\\out', 'C:\\fixtures\\out')).toBe(true);
    expect(pathWithin('C:\\Users\\a', 'C:\\Users\\ab')).toBe(false);
    expect(pathWithin('C:\\fixtures\\outputs', 'C:\\fixtures\\out')).toBe(false);
  });
});

describe('P1-04: expiry on parsed instants, validated clock, action-level expiry', () => {
  it('treats equal instants written differently as expired (reviewer counterexample: lexical order passed)', () => {
    const expiringGrant: AuthorizationGrant = { ...grant, expiresAt: '2026-10-10T08:30:00Z' };
    expectReject('GRANT_EXPIRED', { grant: expiringGrant, now: '2026-10-10T08:30:00.000Z' });
    expectReject('GRANT_EXPIRED', { grant: expiringGrant, now: '2026-10-10T08:30:00Z' });
  });

  it('refuses an invalid injected clock instead of degrading expiry comparisons', () => {
    expectReject('GRANT_MALFORMED', { now: 'not-a-timestamp' });
    expectReject('GRANT_MALFORMED', { now: '2026-10-10 08:30:00' });
    expectReject('GRANT_MALFORMED', { now: '2026-10-10T08:30:00' });
  });

  it('keeps issuedAt/expiresAt ordering an instant comparison, not a string comparison', () => {
    // Same instant, different precision: lexicographically issuedAt sorts
    // before expiresAt ('.' < 'Z') and used to pass; as instants they are
    // equal, so the grant has zero validity and is malformed.
    const zeroLength: AuthorizationGrant = {
      ...grant,
      issuedAt: '2026-10-10T09:00:00.000Z',
      expiresAt: '2026-10-10T09:00:00Z',
    };
    expectReject('GRANT_MALFORMED', { grant: zeroLength });
  });

  it('refuses an action whose own expiresAt has passed even while the grant is still valid', () => {
    const longLivedGrant: AuthorizationGrant = { ...grant, expiresAt: '2026-10-10T09:00:00.000Z' };
    const shortLivedAction: AuthorizedAction = {
      ...action,
      expiresAt: '2026-10-10T08:05:00.000Z',
    };
    expectReject('GRANT_EXPIRED', { grant: longLivedGrant, action: shortLivedAction });
  });

  it('counts an action-level expiresAt equal to `now` as expired (fail-closed)', () => {
    const longLivedGrant: AuthorizationGrant = { ...grant, expiresAt: '2026-10-10T09:00:00.000Z' };
    const boundaryAction: AuthorizedAction = { ...action, expiresAt: '2026-10-10T08:10:00Z' };
    expectReject('GRANT_EXPIRED', { grant: longLivedGrant, action: boundaryAction });
  });

  it('accepts an action-level expiresAt still in the future', () => {
    const longLivedGrant: AuthorizationGrant = { ...grant, expiresAt: '2026-10-10T09:00:00.000Z' };
    const aliveAction: AuthorizedAction = { ...action, expiresAt: '2026-10-10T08:20:00Z' };
    const result = validateGrantPresentation(input({ grant: longLivedGrant, action: aliveAction }));
    expect(result.ok).toBe(true);
  });
});
