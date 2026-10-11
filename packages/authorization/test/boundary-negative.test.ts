// Privileged-side fail-closed boundary evidence (T02 required test evidence):
// forged/self-declared grants, authentic-but-stale A1/P1 after A2/P2,
// UNKNOWN/unresolvable revocation/currentness, expiry (incl. equal instants),
// over-scope presentations, and post-approval plan tamper — every branch
// refuses before any side effect. Presentations are authority-issued and
// validated through the authority's own verifier + freshly resolved current
// state, exactly as a privileged executor consumes them.

import {
  type ActionPlan,
  type AuthorizedAction,
  type GrantIntegrityVerifier,
  validateGrantPresentation,
} from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { AuthorizationAuthority } from '../src/authority.ts';
import { createHmacGrantVerifier } from '../src/integrity.ts';
import {
  AUTHORITY,
  activePolicy,
  buildPlan,
  fixedClock,
  grantOf,
  ISSUANCE_SECRET,
  memoryGrantStore,
  memoryPolicyState,
} from './helpers.ts';

const SECRET = 'boundary-test-secret';
const VERIFIER: GrantIntegrityVerifier = createHmacGrantVerifier(SECRET);

function makeWorld() {
  const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
  const grants = memoryGrantStore();
  const clock = fixedClock();
  const authority = new AuthorizationAuthority({
    state,
    grants,
    integritySecret: SECRET,
    issuanceSecret: ISSUANCE_SECRET,
    clock: clock.now,
  });
  return { state, grants, clock, authority };
}

/** The grant scope a plain issuance covers for a plan (mirrors issueRequestFor). */
function firstScope(p: ActionPlan) {
  const first = p.actions[0];
  if (!first) throw new Error('plan has no actions');
  return {
    actionIds: p.actions.map((a) => a.actionId),
    privilegeLevel: first.requiredPrivilege,
  };
}

function actionFor(p: ActionPlan, grant: { grantId: string }): AuthorizedAction {
  const first = p.actions[0];
  if (!first) throw new Error('plan has no actions');
  return {
    taskId: p.taskId,
    actionId: first.actionId,
    planHash: p.planHash,
    policySnapshotRevision: p.policySnapshotRevision,
    authorizationKind: 'DURABLE_POLICY',
    authorizationRef: grant.grantId,
    action: first,
  };
}

/** Present one (grant, plan, action) triple to the boundary the way an executor does. */
async function present(
  w: ReturnType<typeof makeWorld>,
  args: {
    grant: unknown;
    plan?: ActionPlan;
    action?: AuthorizedAction;
    now?: string;
    currentAuthority?: unknown;
    verifyIntegrity?: GrantIntegrityVerifier;
  },
) {
  const plan = args.plan ?? buildPlan();
  const grantId =
    typeof (args.grant as { grantId?: unknown })?.grantId === 'string'
      ? (args.grant as { grantId: string }).grantId
      : 'unknown-grant';
  return validateGrantPresentation({
    grant: args.grant,
    plan,
    action: args.action ?? actionFor(plan, { grantId }),
    currentAuthority: args.currentAuthority ?? (await w.authority.currentAuthority()),
    now: args.now ?? w.clock.now(),
    verifyIntegrity: args.verifyIntegrity ?? VERIFIER,
  });
}

describe('baseline: authentic current presentation passes', () => {
  it('an authority-issued grant bound to the exact plan validates', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: true, grant: { grantId: grant.grantId } });
  });
});

describe('forged / self-declared grants', () => {
  it('a grant stripped of its integrity envelope is structurally refused', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    const { integrity: _omitted, ...bare } = grant;
    const result = await present(w, { grant: bare, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_NOT_AUTHENTIC' });
  });

  it('a tampered grant carrying the original envelope is refused — presence is not verification', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    const tampered = {
      ...grant,
      actionScope: {
        ...grant.actionScope,
        filesystem: { read: [], write: ['C:\\Users\\victim\\Documents'] },
      },
    };
    const result = await present(w, { grant: tampered, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_NOT_AUTHENTIC' });
  });

  it('a structurally valid envelope from a foreign secret fails trusted verification', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    // Re-sign the (untampered) grant with an attacker secret: the trusted
    // verifier — holding the authority secret — refuses it.
    const { signGrantIntegrity } = await import('../src/integrity.ts');
    const reSigned = { ...grant, integrity: signGrantIntegrity('attacker-secret', grant) };
    const result = await present(w, { grant: reSigned, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_NOT_AUTHENTIC' });
  });

  it('an envelope of a scheme without a P0 substrate fails closed', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    const foreignScheme = {
      ...grant,
      integrity: { scheme: 'SIGNATURE_ED25519' as const, value: 'dHJ1c3RlZA==' },
    };
    const result = await present(w, { grant: foreignScheme, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_NOT_AUTHENTIC' });
  });

  it('a structurally invalid grant is refused as malformed before the envelope is even consulted', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    const invalid = { ...grant, issuedAt: 'yesterday', integrity: undefined };

    const result = await present(w, { grant: invalid, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_MALFORMED' });
  });
});

describe('authentic-but-stale: A1/P1 grant after A2/P2', () => {
  it('the same authentic, unexpired grant becomes void after authority rotation A1→A2 plus policy adoption P2', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);

    const before = await present(w, { grant, plan });
    expect(before).toMatchObject({ ok: true });

    await w.authority.rotateAuthority({ authorityRevision: 'auth-rev-2' });
    await w.authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });

    const after = await present(w, { grant, plan });
    expect(after).toMatchObject({ ok: false, code: 'GRANT_AUTHORITY_STALE' });
  });

  it('a grant issued under policy P1 is refused after the policy moves to P2 under the same authority', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    await w.authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_POLICY_STALE' });
  });

  it('a grant is refused when the current policy revision is revoked in place', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    await w.authority.revokePolicy();

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_POLICY_REVOKED' });
  });

  it('a grant on the current revocation list is refused', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    await w.authority.revokeGrant(grant.grantId);

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_REVOKED' });
  });
});

describe('UNKNOWN / unresolvable currentness', () => {
  it('a missing current policy record resolves UNRESOLVABLE and the boundary refuses', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    w.state.policySlot = undefined;

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_CURRENTNESS_UNRESOLVABLE' });
  });

  it('a corrupt policy record fails closed exactly like negative currentness', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    w.state.policySlot = Buffer.from('not-json');

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_CURRENTNESS_UNRESOLVABLE' });
  });

  it('a failing state read fails closed — the boundary never falls back to "authentic therefore current"', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    w.state.authorityReadsFail = true;

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_CURRENTNESS_UNRESOLVABLE' });
  });

  it('an unparseable currentness input to the boundary is refused, never guessed', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);

    const result = await present(w, { grant, plan, currentAuthority: { kind: 'SOMEHOW' } });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_CURRENTNESS_UNRESOLVABLE' });
  });
});

describe('expiry — decided on parsed instants (P1-04)', () => {
  it('an expired grant is refused', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    w.clock.advanceMs(16 * 60 * 1000);

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_EXPIRED' });
  });

  it('expiry exactly equal to now counts as expired (fail closed)', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    w.clock.advanceMs(15 * 60 * 1000); // now == grant.expiresAt

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_EXPIRED' });
  });

  it('equal instants written differently (no millis vs millis) are the same moment and count as expired', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    // '…T12:15:00Z' sorts lexicographically AFTER '…T12:15:00.000Z' ('Z' > '.'),
    // so naive string order would wrongly report "not yet expired"; the same
    // parsed instant must count as expired.
    const nowNoMillis = grant.expiresAt.replace('.000Z', 'Z');
    expect(nowNoMillis > grant.expiresAt).toBe(true);

    const result = await present(w, { grant, plan, now: nowNoMillis });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_EXPIRED' });
  });

  it('a grant whose issuedAt is not before expiresAt is refused as malformed (envelope re-signed by the trusted side)', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    // Tamper + re-sign with the authority secret: authenticity passes, the
    // internal instant ordering must still refuse.
    const { signGrantIntegrity } = await import('../src/integrity.ts');
    const malformed = { ...grant, issuedAt: grant.expiresAt };
    const reSigned = { ...malformed, integrity: signGrantIntegrity(SECRET, malformed) };

    const result = await present(w, { grant: reSigned, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_MALFORMED' });
  });

  it('an action-level expiry in the past is refused once the action is proven plan-bound', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    const action = {
      ...actionFor(plan, grant),
      expiresAt: '2026-10-10T11:59:59.000Z', // before the frozen now (12:00)
    };

    const result = await present(w, { grant, plan, action });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_EXPIRED' });
  });
});

describe('over-scope presentations (grant scope deliberately narrowed at issuance)', () => {
  it('a declared write path outside the grant prefixes is refused — sibling-prefix confusion included', async () => {
    const w = makeWorld();
    const plan = buildPlan({
      actions: [
        { filesystemScope: { read: ['C:\\fixtures\\images'], write: ['C:\\fixtures\\out2'] } },
      ],
    });
    const grant = await grantOf(w.authority, plan, {
      actionScope: {
        actionIds: plan.actions.map((a) => a.actionId),
        privilegeLevel: 'NONE',
        filesystem: { read: ['C:\\fixtures\\images'], write: ['C:\\fixtures\\out'] },
      },
    });

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_SCOPE_MISMATCH' });
  });

  it('a traversal segment fails closed even against an identical declared prefix', async () => {
    const w = makeWorld();
    const traversal = 'C:\\fixtures\\out\\..\\windows';
    const plan = buildPlan({
      actions: [{ filesystemScope: { read: [], write: [traversal] } }],
    });
    const grant = await grantOf(w.authority, plan);

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_SCOPE_MISMATCH' });
  });

  it('an actionId outside the grant scope is refused even when the plan and hash are consistent', async () => {
    const w = makeWorld();
    const plan = buildPlan({
      actions: [{ op: 'image.resize' }, { op: 'image.annotate', sideEffectClass: 'R1' }],
    });
    const grant = await grantOf(w.authority, plan, {
      actionScope: { actionIds: ['action-001'], privilegeLevel: 'NONE' },
    });
    const second = plan.actions[1];
    if (!second) throw new Error('missing second action');
    const action: AuthorizedAction = {
      taskId: plan.taskId,
      actionId: 'action-002',
      planHash: plan.planHash,
      policySnapshotRevision: plan.policySnapshotRevision,
      authorizationKind: 'DURABLE_POLICY',
      authorizationRef: grant.grantId,
      action: second,
    };

    const result = await present(w, { grant, plan, action });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_SCOPE_MISMATCH' });
  });

  it('a privilege level outside the granted privilege is refused', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan, {
      actionScope: { ...firstScope(plan), privilegeLevel: 'ELEVATED' },
    });

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_SCOPE_MISMATCH' });
  });

  it('a network domain outside the granted domains is refused', async () => {
    const w = makeWorld();
    const plan = buildPlan({
      actions: [{ networkScope: { allowed: true, domains: ['cdn.example.com'] } }],
    });
    const grant = await grantOf(w.authority, plan, {
      actionScope: {
        actionIds: plan.actions.map((a) => a.actionId),
        privilegeLevel: 'NONE',
        network: { allowed: true, domains: ['api.example.com'] },
      },
    });

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_SCOPE_MISMATCH' });
  });

  it('a registry write outside the granted keys is refused', async () => {
    const w = makeWorld();
    const plan = buildPlan({
      actions: [{ registryScope: { write: ['HKCU\\Software\\Shun'] } }],
    });
    const grant = await grantOf(w.authority, plan, {
      actionScope: {
        actionIds: plan.actions.map((a) => a.actionId),
        privilegeLevel: 'NONE',
        registry: { write: ['HKCU\\Software\\Other'] },
      },
    });

    const result = await present(w, { grant, plan });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_SCOPE_MISMATCH' });
  });

  it('an action naming a different task than the grant is refused', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    const action = { ...actionFor(plan, grant), taskId: 'task-something-else' };

    const result = await present(w, { grant, plan, action });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_SCOPE_MISMATCH' });
  });
});

describe('post-approval plan tamper (U-06 D2-b) and exact action↔plan binding', () => {
  it('a plan whose content changed but whose claimed planHash did not is refused at the hash gate', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    const tampered = { ...plan, actions: [tamperedFirstAction(plan)], planHash: plan.planHash }; // stale hash claim

    const result = await present(w, { grant, plan: tampered });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_PLAN_MISMATCH' });
  });

  function tamperedFirstAction(plan: ActionPlan): ActionPlan['actions'][number] {
    const first = plan.actions[0];
    if (!first) throw new Error('plan has no actions');
    return { ...first, filesystemScope: { read: [], write: ['C:\\Windows\\System32'] } };
  }

  it('a presented action surface that differs from the hashed plan action is refused even under a matching planHash', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    const first = plan.actions[0];
    if (!first) throw new Error('plan has no actions');
    const action = {
      ...actionFor(plan, grant),
      action: { ...first, parameters: { format: 'PNG', exif: 'strip-all' } }, // same actionId, different surface
    };

    const result = await present(w, { grant, plan, action });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_PLAN_MISMATCH' });
  });

  it('an authorizationRef naming a different grant than the presented one is refused', async () => {
    const w = makeWorld();
    const plan = buildPlan();
    const grant = await grantOf(w.authority, plan);
    const action = { ...actionFor(plan, grant), authorizationRef: 'forged-grant-id' };

    const result = await present(w, { grant, plan, action });
    expect(result).toMatchObject({ ok: false, code: 'GRANT_MALFORMED' });
  });
});
