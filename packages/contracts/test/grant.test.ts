import { describe, expect, it } from 'vitest';
import {
  type AuthorizationGrant,
  assertGrantPresentation,
  type CurrentAuthorityState,
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
import { ShunContractError } from '../src/taxonomy.ts';
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

function input(overrides: Partial<GrantValidationInput> = {}): GrantValidationInput {
  return { grant, plan, action, currentAuthority: CURRENT, now: NOW, ...overrides };
}

function expectOk(overrides: Partial<GrantValidationInput> = {}): void {
  const result = validateGrantPresentation(input(overrides));
  expect(result.ok).toBe(true);
}

function expectReject(code: string, overrides: Partial<GrantValidationInput> = {}): void {
  const result = validateGrantPresentation(input(overrides));
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.code).toBe(code);
  }
}

describe('grant presentation: happy paths', () => {
  it('accepts an automatic grant under current authority and policy', () => {
    expectOk();
  });

  it('accepts an explicit-approval grant that references the durable approval record', () => {
    const explicitGrant: AuthorizationGrant = { ...grant, approvalRef: 'approval-2026-10-10-001' };
    const explicitAction: AuthorizedAction = { ...action, authorizationKind: 'EXPLICIT_APPROVAL' };
    expectOk({ grant: explicitGrant, action: explicitAction });
  });
});

describe('grant presentation: structural forgery and malformation fail closed', () => {
  it('refuses a self-declared grant with no integrity envelope before any side effect', () => {
    const { integrity: _stripped, ...forged } = grant;
    expectReject('GRANT_NOT_AUTHENTIC', { grant: forged });
  });

  it('refuses grants that do not parse as AuthorizationGrant', () => {
    expectReject('GRANT_MALFORMED', { grant: { ...grant, grantId: undefined } });
    expectReject('GRANT_MALFORMED', { grant: { hello: 'world' } });
    expectReject('GRANT_MALFORMED', { grant: null });
  });

  it('refuses a structurally invalid plan or action', () => {
    expectReject('GRANT_MALFORMED', { plan: { ...plan, planHash: 'nope' } });
    expectReject('GRANT_MALFORMED', { action: { ...action, planHash: 'nope' } });
  });

  it('refuses an action whose authorizationRef does not identify the presented grant', () => {
    expectReject('GRANT_MALFORMED', {
      action: { ...action, authorizationRef: 'grant-someone-else' },
    });
  });
});

describe('grant currentness: validated against current authority state, never self-claims', () => {
  it('refuses when the issuer is not the current authority revision', () => {
    expectReject('GRANT_AUTHORITY_STALE', {
      currentAuthority: { ...CURRENT, authorityRevision: 'auth-r4' },
    });
  });

  it('refuses when the issuer is not the current authority identity', () => {
    expectReject('GRANT_AUTHORITY_STALE', {
      currentAuthority: { ...CURRENT, authorityId: 'someone-else.controller' },
    });
  });

  it('refuses a grant issued under a superseded policy revision even though it is authentic and unexpired', () => {
    expectReject('GRANT_POLICY_STALE', {
      currentAuthority: { ...CURRENT, policyStatus: 'SUPERSEDED' },
    });
    expectReject('GRANT_POLICY_STALE', {
      currentAuthority: { ...CURRENT, policySnapshotRevision: 'pol-snap-2026-10-10-b' },
    });
  });

  it('refuses when the current policy revision is revoked', () => {
    expectReject('GRANT_POLICY_REVOKED', {
      currentAuthority: { ...CURRENT, policyStatus: 'REVOKED' },
    });
  });

  it('refuses a grant on the current revocation list', () => {
    expectReject('GRANT_REVOKED', {
      currentAuthority: { ...CURRENT, revokedGrantIds: [grant.grantId] },
    });
  });

  it('refuses an expired grant', () => {
    expectReject('GRANT_EXPIRED', { now: '2026-10-10T08:30:00.000Z' });
  });

  it('refuses when currentness cannot be resolved — no fallback to authentic-therefore-current', () => {
    expectReject('GRANT_CURRENTNESS_UNRESOLVABLE', {
      currentAuthority: { kind: 'UNRESOLVABLE', reason: 'currentness record unreadable' },
    });
    expectReject('GRANT_CURRENTNESS_UNRESOLVABLE', { currentAuthority: null });
    expectReject('GRANT_CURRENTNESS_UNRESOLVABLE', { currentAuthority: { kind: 'WRONG' } });
  });
});

describe('grant binding: exact plan identity re-derived by the privileged boundary', () => {
  it('refuses a tampered plan whose stored hash no longer matches the recomputed hash', () => {
    const first = plan.actions.at(0);
    if (!first) throw new Error('fixture plan must contain an action');
    const tampered: ActionPlan = {
      ...plan,
      actions: [{ ...first, parameters: { ...first.parameters, maxLongEdgePx: 9999 } }],
    };
    expectReject('GRANT_PLAN_MISMATCH', { plan: tampered });
  });

  it('refuses a self-consistent plan that differs from the approved plan identity', () => {
    const otherPlan: ActionPlan = {
      ...plan,
      taskId: 'task-other',
      planHash: computePlanHash({ ...plan, taskId: 'task-other' }),
    };
    expectReject('GRANT_PLAN_MISMATCH', { plan: otherPlan });
  });

  it('refuses an action carrying a different planHash than the grant', () => {
    expectReject('GRANT_PLAN_MISMATCH', { action: { ...action, planHash: 'a'.repeat(64) } });
  });
});

describe('grant scope: actionId, privilege, filesystem, network containment', () => {
  it('refuses an actionId outside the granted scope', () => {
    expectReject('GRANT_SCOPE_MISMATCH', { action: { ...action, actionId: 'action-999' } });
  });

  it('refuses privilege escalation beyond the granted level', () => {
    const escalated: AuthorizedAction = {
      ...action,
      action: { ...action.action, requiredPrivilege: 'ELEVATED' },
    };
    expectReject('GRANT_SCOPE_MISMATCH', { action: escalated });
  });

  it('refuses a taskId outside the grant', () => {
    expectReject('GRANT_SCOPE_MISMATCH', { action: { ...action, taskId: 'task-other' } });
  });

  it('refuses filesystem writes outside the granted prefixes, including segment-boundary tricks', () => {
    const outside: AuthorizedAction = {
      ...action,
      action: { ...action.action, filesystemScope: { read: [], write: ['C:\\fixtures\\other'] } },
    };
    expectReject('GRANT_SCOPE_MISMATCH', { action: outside });

    const boundary: AuthorizedAction = {
      ...action,
      action: {
        ...action.action,
        filesystemScope: { read: [], write: ['C:\\fixtures\\outputs\\x.png'] },
      },
    };
    expectReject('GRANT_SCOPE_MISMATCH', { action: boundary });
  });

  it('accepts writes inside the granted prefixes with windows casing and separator variations', () => {
    const inside: AuthorizedAction = {
      ...action,
      action: {
        ...action.action,
        filesystemScope: { read: [], write: ['c:/FIXTURES/out/sub/x.PNG'] },
      },
    };
    expectOk({ action: inside });
  });

  it('refuses undeclared network access', () => {
    const networked: AuthorizedAction = {
      ...action,
      action: { ...action.action, networkScope: { allowed: true } },
    };
    expectReject('GRANT_SCOPE_MISMATCH', { action: networked });
  });

  it('refuses an explicit-approval action whose grant lacks the approval reference', () => {
    const explicitAction: AuthorizedAction = { ...action, authorizationKind: 'EXPLICIT_APPROVAL' };
    expectReject('GRANT_APPROVAL_REF_MISSING', { action: explicitAction });
  });
});

describe('typed assertion wrapper', () => {
  it('throws ShunContractError with the typed rejection code', () => {
    const { integrity: _stripped, ...forged } = grant;
    expect(() => assertGrantPresentation(input({ grant: forged }))).toThrowError(ShunContractError);
    try {
      assertGrantPresentation(input({ grant: forged }));
    } catch (error) {
      expect((error as ShunContractError).code).toBe('GRANT_NOT_AUTHENTIC');
    }
  });
});

describe('path containment semantics', () => {
  it('matches whole segments only, case-insensitively, with either separator', () => {
    expect(pathWithin('C:\\fixtures\\out\\a.png', 'C:\\fixtures\\out')).toBe(true);
    expect(pathWithin('c:/fixtures/out/deep/a.png', 'C:\\FIXTURES\\OUT')).toBe(true);
    expect(pathWithin('C:\\fixtures\\out', 'C:\\fixtures\\out')).toBe(true);
    expect(pathWithin('C:\\fixtures\\outputs', 'C:\\fixtures\\out')).toBe(false);
    expect(pathWithin('C:\\fixtures\\other\\a.png', 'C:\\fixtures\\out')).toBe(false);
    expect(pathWithin('C:\\fixtures\\out-traversal', 'C:\\fixtures\\out')).toBe(false);
  });
});
