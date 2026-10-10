// Action Controller disposition, bounded approvals, and end-to-end
// authorize → grant → AuthorizedAction → boundary-pass (T02 scope:
// "approval or specific durable policy", R0-R3 routing).

import type { ApprovalPort } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { AuthorizationAuthority } from '../src/authority.ts';
import { ActionController } from '../src/controller.ts';
import {
  type DurablePolicyRule,
  DurablePolicyRuleSchema,
  type PolicyStateStore,
} from '../src/policy.ts';
import {
  AUTHORITY,
  activePolicy,
  approvingSurface,
  buildPlan,
  fixedClock,
  ISSUANCE_SECRET,
  memoryGrantStore,
  memoryPolicyState,
  secondPolicyReadReturns,
} from './helpers.ts';

const SECRET = 'controller-test-secret';

function makeWorld(options?: {
  policy?: ReturnType<typeof activePolicy>;
  approvals?: ApprovalPort;
  /** Wrap the shared policy state (both authority and controller see the wrapper). */
  stateWrapper?: (base: PolicyStateStore) => PolicyStateStore;
}) {
  const base = memoryPolicyState({
    authority: AUTHORITY,
    policy: options?.policy ?? activePolicy(),
  });
  const state = options?.stateWrapper ? options.stateWrapper(base) : base;
  const grants = memoryGrantStore();
  const clock = fixedClock();
  const authority = new AuthorizationAuthority({
    state,
    grants,
    integritySecret: SECRET,
    issuanceSecret: ISSUANCE_SECRET,
    clock: clock.now,
  });
  const approvals = approvingSurface();
  const controller = new ActionController({
    authority,
    policyState: state,
    approvals: options?.approvals ?? approvals.surface,
    issuanceSecret: ISSUANCE_SECRET,
    clock: clock.now,
  });
  return {
    /** The store both the authority and the controller see (possibly wrapped). */
    state,
    /** The underlying memory store, for direct slot injection in tests. */
    base,
    grants,
    clock,
    authority,
    approvals,
    controller,
  };
}

/** Rule authorizing the default plan action (image.resize @ NONE, R≤1, same paths). */
function defaultRule(overrides?: Partial<DurablePolicyRule>): DurablePolicyRule {
  return {
    ruleId: 'rule-image-resize-r1',
    capabilityId: 'image.batch_process',
    op: 'image.resize',
    maxRiskClass: 'R1',
    privilegeLevel: 'NONE',
    filesystem: { read: ['C:\\fixtures\\images'], write: ['C:\\fixtures\\out'] },
    ...overrides,
  };
}

describe('intake validation', () => {
  it('refuses a proposal that is not a valid ActionPlan', async () => {
    const { controller } = makeWorld();
    const result = await controller.authorizePlan({ plan: { hello: true } });
    expect(result).toMatchObject({ ok: false, code: 'PLAN_INVALID' });
  });

  it('refuses a proposal whose self-claimed planHash does not match the re-derived hash', async () => {
    const { controller } = makeWorld();
    const plan = buildPlan();
    const result = await controller.authorizePlan({ plan: { ...plan, planHash: '0'.repeat(64) } });
    expect(result).toMatchObject({ ok: false, code: 'PLAN_INVALID' });
  });

  it('refuses a proposal formed under a stale policy revision (re-plan, never downgrade)', async () => {
    const { controller } = makeWorld();
    const plan = buildPlan({ policySnapshotRevision: 'pol-snap-stale' });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({ ok: false, code: 'POLICY_BLOCKED' });
  });

  it('refuses to authorize under unresolvable or non-ACTIVE current policy', async () => {
    const unresolved = makeWorld({ policy: activePolicy() });
    unresolved.base.policySlot = undefined;
    const plan = buildPlan();
    expect(await unresolved.controller.authorizePlan({ plan })).toMatchObject({
      ok: false,
      code: 'AUTHORIZATION_STATE_UNRESOLVABLE',
    });

    const revoked = makeWorld({ policy: activePolicy({ status: 'REVOKED' }) });
    expect(await revoked.controller.authorizePlan({ plan })).toMatchObject({
      ok: false,
      code: 'POLICY_BLOCKED',
    });
  });
});

describe('R0-R3 disposition routing', () => {
  it('R0 under a covering rule is AUTOMATIC — no approval requested', async () => {
    const { controller, approvals } = makeWorld({
      policy: activePolicy({ rules: [defaultRule()] }),
    });
    const plan = buildPlan({
      actions: [
        {
          op: 'image.resize',
          sideEffectClass: 'R0',
          filesystemScope: { read: ['C:\\fixtures\\images'], write: [] },
        },
      ],
    });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'AUTOMATIC' } },
    });
    expect(approvals.requests).toHaveLength(0);
  });

  it('R0 without a covering rule is policy-blocked (default-deny, not approval)', async () => {
    const { controller } = makeWorld();
    const plan = buildPlan({
      actions: [
        {
          op: 'image.inspect',
          sideEffectClass: 'R0',
          filesystemScope: { read: ['C:\\fixtures\\images'], write: [] },
        },
      ],
    });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({ ok: false, code: 'POLICY_BLOCKED' });
  });

  it('R1 under a sufficiently specific rule is DURABLE_POLICY without approval', async () => {
    const { controller, approvals } = makeWorld({
      policy: activePolicy({ rules: [defaultRule()] }),
    });
    const result = await controller.authorizePlan({ plan: buildPlan() });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'DURABLE_POLICY', ruleIds: ['rule-image-resize-r1'] } },
    });
    expect(approvals.requests).toHaveLength(0);
  });

  it('R1 without a covering rule falls back to explicit approval', async () => {
    const { controller, approvals } = makeWorld();
    const result = await controller.authorizePlan({ plan: buildPlan() });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'EXPLICIT_APPROVAL' } },
    });
    expect(approvals.requests).toHaveLength(1);
  });

  it('R2 is never widened under an R1-bounded rule — it requires explicit approval', async () => {
    const { controller, approvals } = makeWorld({
      policy: activePolicy({ rules: [defaultRule()] }), // maxRiskClass R1
    });
    const plan = buildPlan({ actions: [{ op: 'image.resize', sideEffectClass: 'R2' }] });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'EXPLICIT_APPROVAL' } },
    });
    expect(approvals.requests).toHaveLength(1);
  });

  it('R2 under a rule bounded at R2 whose scope covers the action is DURABLE_POLICY ("sufficiently specific durable policy")', async () => {
    const { controller, approvals } = makeWorld({
      policy: activePolicy({
        rules: [
          defaultRule({
            ruleId: 'rule-bulk-rename-r2',
            op: 'files.bulk_rename',
            maxRiskClass: 'R2',
            filesystem: { read: [], write: ['C:\\fixtures\\out'] },
          }),
        ],
      }),
    });
    const plan = buildPlan({
      actions: [
        {
          op: 'files.bulk_rename',
          sideEffectClass: 'R2',
          filesystemScope: { read: [], write: ['C:\\fixtures\\out'] },
        },
      ],
    });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'DURABLE_POLICY', ruleIds: ['rule-bulk-rename-r2'] } },
    });
    expect(approvals.requests).toHaveLength(0);
  });

  it('a rule whose paths do not cover the declared scope cannot authorize (approval fallback)', async () => {
    const { controller, approvals } = makeWorld({
      policy: activePolicy({
        rules: [defaultRule({ filesystem: { read: [], write: ['C:\\elsewhere'] } })],
      }),
    });
    const result = await controller.authorizePlan({ plan: buildPlan() });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'EXPLICIT_APPROVAL' } },
    });
    expect(approvals.requests).toHaveLength(1);
  });

  it('R3 always requires explicit approval — a durable rule structurally cannot cover it', async () => {
    expect(() =>
      DurablePolicyRuleSchema.parse(defaultRule({ maxRiskClass: 'R3' as never })),
    ).toThrow();

    const { controller } = makeWorld({
      policy: activePolicy({ rules: [defaultRule({ maxRiskClass: 'R2' })] }),
    });
    const plan = buildPlan({ actions: [{ op: 'disk.wipe_free_space', sideEffectClass: 'R3' }] });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'EXPLICIT_APPROVAL' } },
    });
  });

  it('a policy risk guard RAISES the effective class: a rule-covered R1 write under a guarded prefix still requires approval', async () => {
    const { controller, approvals } = makeWorld({
      policy: activePolicy({
        rules: [defaultRule()],
        riskGuards: [
          {
            guardId: 'guard-contracts-dir',
            filesystemWritePrefix: 'C:\\fixtures\\out',
            minRiskClass: 'R2',
          },
        ],
      }),
    });
    const result = await controller.authorizePlan({ plan: buildPlan() });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'EXPLICIT_APPROVAL' } },
    });
    expect(approvals.requests).toHaveLength(1);
    expect(approvals.requests[0]?.summary).toContain('[R2]');
  });

  it('policy guards never lower a higher declared class', async () => {
    const { controller } = makeWorld({
      policy: activePolicy({
        rules: [defaultRule()],
        riskGuards: [{ guardId: 'guard-low', op: 'image.resize', minRiskClass: 'R0' }],
      }),
    });
    const plan = buildPlan({ actions: [{ op: 'image.resize', sideEffectClass: 'R2' }] });
    const result = await controller.authorizePlan({ plan });
    // Effective stays R2 → approval, never downgraded to the guard's R0.
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'EXPLICIT_APPROVAL' } },
    });
  });
});

describe('bounded approvals (exact plan/task binding)', () => {
  it('a rejected approval yields APPROVAL_REJECTED and persists no grant', async () => {
    const rejected = approvingSurface({ approved: false });
    const { controller, grants } = makeWorld({ approvals: rejected.surface });
    const result = await controller.authorizePlan({ plan: buildPlan() });
    expect(result).toMatchObject({ ok: false, code: 'APPROVAL_REJECTED' });
    expect(grants.snapshot()).toHaveLength(0);
  });

  it('a decision bound to a different planHash is invalid — approval never transfers across plans', async () => {
    const drifting = approvingSurface({ decidedPlanHash: 'a'.repeat(64) });
    const { controller, grants } = makeWorld({ approvals: drifting.surface });
    const result = await controller.authorizePlan({ plan: buildPlan() });
    expect(result).toMatchObject({ ok: false, code: 'APPROVAL_INVALID' });
    expect(grants.snapshot()).toHaveLength(0);
  });

  it('a decision bound to a different task is invalid', async () => {
    const drifting = approvingSurface({ decidedTaskId: 'task-other' });
    const { controller, grants } = makeWorld({ approvals: drifting.surface });
    const result = await controller.authorizePlan({ plan: buildPlan() });
    expect(result).toMatchObject({ ok: false, code: 'APPROVAL_INVALID' });
    expect(grants.snapshot()).toHaveLength(0);
  });

  it('a valid approval issues the grant with the durable approvalRef embedded', async () => {
    const { controller, grants } = makeWorld();
    const plan = buildPlan();
    const result = await controller.authorizePlan({ plan });
    if (!result.ok) throw new Error('expected authorization to succeed');
    expect(result.authorization.disposition.approvalRef).toBe('approval-001');
    expect(grants.snapshot()[0]?.grant.approvalRef).toBe('approval-001');
  });
});

describe('grant-backed AuthorizedActions', () => {
  it('produces AuthorizedActions whose presentation passes the boundary gate immediately', async () => {
    const { controller } = makeWorld({ policy: activePolicy({ rules: [defaultRule()] }) });
    const plan = buildPlan();
    const result = await controller.authorizePlan({ plan });
    if (!result.ok) throw new Error('expected authorization to succeed');
    const { authorization } = result;
    expect(authorization.actions).toHaveLength(1);
    const action = authorization.actions[0];
    const grant = authorization.grants[0];
    if (!action || !grant) throw new Error('authorization produced no action/grant');
    expect(action).toMatchObject({
      actionId: 'action-001',
      planHash: plan.planHash,
      authorizationKind: 'DURABLE_POLICY',
    });
    const effect = await controller.authorizeEffect({ plan, action, grant });
    expect(effect).toMatchObject({ ok: true });
  });

  it('bounds the action expiry by both the grant expiry and the configured action TTL', async () => {
    const { clock, controller } = makeWorld({ policy: activePolicy({ rules: [defaultRule()] }) });
    const plan = buildPlan();
    const result = await controller.authorizePlan({ plan });
    if (!result.ok) throw new Error('expected authorization to succeed');
    const action = result.authorization.actions[0];
    const grant = result.authorization.grants[0];
    expect(action?.expiresAt).toBe(new Date(Date.parse(clock.now()) + 5 * 60 * 1000).toISOString());
    expect(Date.parse(action?.expiresAt ?? '')).toBeLessThanOrEqual(
      Date.parse(grant?.expiresAt ?? ''),
    );
  });

  it('groups mixed-privilege plans into one grant per privilege level, each action bound to its own grant', async () => {
    const { controller } = makeWorld({
      policy: activePolicy({
        rules: [
          defaultRule(),
          defaultRule({
            ruleId: 'rule-elevated',
            op: 'service.restart',
            maxRiskClass: 'R2',
            privilegeLevel: 'ELEVATED',
            filesystem: { read: [], write: [] },
          }),
        ],
      }),
    });
    const plan = buildPlan({
      actions: [
        { op: 'image.resize', sideEffectClass: 'R1', requiredPrivilege: 'NONE' },
        { op: 'service.restart', sideEffectClass: 'R2', requiredPrivilege: 'ELEVATED' },
      ],
    });
    const result = await controller.authorizePlan({ plan });
    if (!result.ok) throw new Error('expected authorization to succeed');
    const { authorization } = result;
    expect(authorization.grants).toHaveLength(2);
    const privileges = authorization.grants.map((grant) => grant.actionScope.privilegeLevel).sort();
    expect(privileges).toEqual(['ELEVATED', 'NONE']);

    for (const action of authorization.actions) {
      const grant = authorization.grants.find(
        (candidate) => candidate.grantId === action?.authorizationRef,
      );
      expect(grant).toBeDefined();
      const effect = await controller.authorizeEffect({ plan, action: action, grant });
      expect(effect).toMatchObject({ ok: true });
    }
  });

  it('converts a typed issuance failure into a structured refusal preserving the grant code', async () => {
    // An authority whose clock breaks AFTER a first successful issuance:
    // intake still passes (no clock involved), issuance refuses typed, and the
    // controller surfaces the refusal instead of crashing or degrading.
    let broken = false;
    const flakyClock = fixedClock();
    const state = memoryPolicyState({
      authority: AUTHORITY,
      policy: activePolicy({ rules: [defaultRule()] }),
    });
    const grants = memoryGrantStore();
    const authority = new AuthorizationAuthority({
      state,
      grants,
      integritySecret: SECRET,
      issuanceSecret: ISSUANCE_SECRET,
      clock: () => (broken ? 'not-a-date' : flakyClock.now()),
    });
    const flakyController = new ActionController({
      authority,
      policyState: state,
      approvals: approvingSurface().surface,
      issuanceSecret: ISSUANCE_SECRET,
      clock: flakyClock.now,
    });
    const before = await flakyController.authorizePlan({ plan: buildPlan() });
    expect(before).toMatchObject({ ok: true });
    broken = true;
    const after = await flakyController.authorizePlan({ plan: buildPlan() });
    expect(after).toMatchObject({ ok: false, code: 'GRANT_MALFORMED' });
  });

  it('issues every grant through the protected issuance port with a per-request controller proof', async () => {
    const { controller, grants } = makeWorld({ policy: activePolicy({ rules: [defaultRule()] }) });
    const result = await controller.authorizePlan({ plan: buildPlan() });
    expect(result).toMatchObject({ ok: true });
    // The grant exists and carries the authority's own envelope (integration
    // evidence that the controller proof path issues exactly as before).
    expect(grants.snapshot()).toHaveLength(1);
    expect(grants.snapshot()[0]?.grant.integrity.scheme).toBe('HMAC_SHA256');
  });
});

describe('approval provenance — only explicit human approval completes the approval route (P1-01)', () => {
  it('an R3 plan whose approval decision records DURABLE_POLICY origin is refused — durable policy is not explicit approval', async () => {
    const { controller, grants } = makeWorld({
      approvals: approvingSurface({ approvedBy: 'DURABLE_POLICY' }).surface,
    });
    const plan = buildPlan({ actions: [{ op: 'disk.wipe_free_space', sideEffectClass: 'R3' }] });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: false,
      code: 'APPROVAL_INVALID',
      detail: expect.stringContaining('USER_APPROVAL'),
    });
    expect(grants.snapshot()).toHaveLength(0);
  });

  it('the provenance requirement is not R3-specific: an approval-requiring R1 with DURABLE_POLICY origin is refused too', async () => {
    const { controller, grants } = makeWorld({
      approvals: approvingSurface({ approvedBy: 'DURABLE_POLICY' }).surface,
    });
    const result = await controller.authorizePlan({ plan: buildPlan() });
    expect(result).toMatchObject({ ok: false, code: 'APPROVAL_INVALID' });
    expect(grants.snapshot()).toHaveLength(0);
  });

  it('a matching-hash, matching-task R3 decision of USER_APPROVAL origin still authorizes (positive control)', async () => {
    const { controller, grants } = makeWorld({
      approvals: approvingSurface({ approvedBy: 'USER_APPROVAL' }).surface,
    });
    const plan = buildPlan({ actions: [{ op: 'disk.wipe_free_space', sideEffectClass: 'R3' }] });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'EXPLICIT_APPROVAL' } },
    });
    expect(grants.snapshot()).toHaveLength(1);
  });
});

describe('network domain bounds — automatic policy never covers a domain-unbounded action (P1-03)', () => {
  const networkRule = (overrides?: Partial<DurablePolicyRule>): DurablePolicyRule =>
    defaultRule({
      ruleId: 'rule-image-fetch-r1',
      op: 'image.fetch',
      network: { allowed: true, domains: ['cdn.example.com'] },
      ...overrides,
    });

  it('an action declaring network access with an OMITTED domain list is not covered by a domain-limited rule — approval fallback', async () => {
    const { controller, approvals, grants } = makeWorld({
      policy: activePolicy({ rules: [networkRule()] }),
    });
    const plan = buildPlan({
      actions: [{ op: 'image.fetch', networkScope: { allowed: true } }],
    });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'EXPLICIT_APPROVAL' } },
    });
    expect(approvals.requests).toHaveLength(1);
    // Explicit approval keeps the presented (unbounded) representation; the
    // automatic-policy route is what may never cover it.
    expect(grants.snapshot()[0]?.grant.actionScope.network).toEqual({ allowed: true, domains: [] });
  });

  it('an action declaring an EMPTY domain list is domain-unbounded too and is not covered', async () => {
    const { controller, approvals } = makeWorld({
      policy: activePolicy({ rules: [networkRule()] }),
    });
    const plan = buildPlan({
      actions: [{ op: 'image.fetch', networkScope: { allowed: true, domains: [] } }],
    });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'EXPLICIT_APPROVAL' } },
    });
    expect(approvals.requests).toHaveLength(1);
  });

  it('a rule WITHOUT a domain allowlist cannot authorize any network action (its own bounds are unbounded)', async () => {
    const { controller, approvals } = makeWorld({
      policy: activePolicy({
        rules: [
          networkRule({
            network: { allowed: true },
          }),
        ],
      }),
    });
    const plan = buildPlan({
      actions: [
        { op: 'image.fetch', networkScope: { allowed: true, domains: ['cdn.example.com'] } },
      ],
    });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'EXPLICIT_APPROVAL' } },
    });
    expect(approvals.requests).toHaveLength(1);
  });

  it('a mixed domain list (one inside, one outside the rule) is not covered', async () => {
    const { controller, approvals } = makeWorld({
      policy: activePolicy({ rules: [networkRule()] }),
    });
    const plan = buildPlan({
      actions: [
        {
          op: 'image.fetch',
          networkScope: { allowed: true, domains: ['cdn.example.com', 'evil.example.com'] },
        },
      ],
    });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'EXPLICIT_APPROVAL' } },
    });
    expect(approvals.requests).toHaveLength(1);
  });

  it('an R0 network action outside explicit rule bounds is default-denied (POLICY_BLOCKED), never automatic', async () => {
    const { controller } = makeWorld({
      policy: activePolicy({ rules: [networkRule()] }),
    });
    const plan = buildPlan({
      actions: [
        {
          op: 'image.fetch',
          sideEffectClass: 'R0',
          networkScope: { allowed: true },
        },
      ],
    });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: false,
      code: 'POLICY_BLOCKED',
      actionIds: ['action-001'],
    });
  });

  it('a fully bounded network action inside the rule domains remains DURABLE_POLICY with an explicit grant domain list (positive control)', async () => {
    const { controller, approvals, grants } = makeWorld({
      policy: activePolicy({ rules: [networkRule()] }),
    });
    const plan = buildPlan({
      actions: [
        {
          op: 'image.fetch',
          networkScope: { allowed: true, domains: ['cdn.example.com'] },
        },
      ],
    });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: true,
      authorization: { disposition: { kind: 'DURABLE_POLICY', ruleIds: ['rule-image-fetch-r1'] } },
    });
    expect(approvals.requests).toHaveLength(0);
    expect(grants.snapshot()[0]?.grant.actionScope.network).toEqual({
      allowed: true,
      domains: ['cdn.example.com'],
    });
  });
});

describe('second policy read fails closed (P2-01 — race/coherence between the two reads)', () => {
  it('a failing second policy read is a structured refusal, never a thrown error', async () => {
    const { controller } = makeWorld({
      stateWrapper: (base) =>
        secondPolicyReadReturns(base, () => {
          throw new Error('simulated racing policy read failure');
        }),
    });
    const result = await controller.authorizePlan({ plan: buildPlan() });
    expect(result).toMatchObject({
      ok: false,
      code: 'AUTHORIZATION_STATE_UNRESOLVABLE',
      detail: expect.stringContaining('racing policy read failure'),
    });
  });

  it('a corrupt successor snapshot on the second read is a structured refusal', async () => {
    const { controller } = makeWorld({
      stateWrapper: (base) => secondPolicyReadReturns(base, () => ({ garbage: true })),
    });
    const result = await controller.authorizePlan({ plan: buildPlan() });
    expect(result).toMatchObject({ ok: false, code: 'AUTHORIZATION_STATE_UNRESOLVABLE' });
  });

  it('a successor policy revision read between the two reads refuses the plan as incoherent state (no authorization under a phantom snapshot)', async () => {
    const { controller, grants } = makeWorld({
      stateWrapper: (base) =>
        secondPolicyReadReturns(base, () => activePolicy({ policySnapshotRevision: 'pol-snap-2' })),
    });
    const plan = buildPlan({ policySnapshotRevision: 'pol-snap-1' });
    const result = await controller.authorizePlan({ plan });
    expect(result).toMatchObject({
      ok: false,
      code: 'AUTHORIZATION_STATE_UNRESOLVABLE',
      detail: expect.stringContaining('moved between reads'),
    });
    expect(grants.snapshot()).toHaveLength(0);
  });
});
