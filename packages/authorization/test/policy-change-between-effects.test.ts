// Policy changes between multiple effects (T02 required test evidence):
// a multi-action plan authorized once must re-establish CURRENT
// authority/policy state before EVERY effect — an authority rotation, policy
// supersede/revocation, grant revocation or unresolvable currentness record
// appearing between effect 1 and effect 2 voids the remaining effects
// (fail-closed, L2 §4.6.1 + §11.2).

import type { AuthorizedAction } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { AuthorizationAuthority } from '../src/authority.ts';
import { ActionController } from '../src/controller.ts';
import {
  AUTHORITY,
  activePolicy,
  approvingSurface,
  buildPlan,
  fixedClock,
  memoryGrantStore,
  memoryPolicyState,
} from './helpers.ts';

const SECRET = 'midplan-secret';

/** World with a two-action plan authorized up front (explicit approval). */
async function makeAuthorizedWorld() {
  const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
  const grants = memoryGrantStore();
  const clock = fixedClock();
  const authority = new AuthorizationAuthority({
    state,
    grants,
    integritySecret: SECRET,
    clock: clock.now,
  });
  const controller = new ActionController({
    authority,
    policyState: state,
    approvals: approvingSurface().surface,
    clock: clock.now,
  });
  const plan = buildPlan({
    actions: [
      { op: 'files.stage', sideEffectClass: 'R1' },
      { op: 'files.commit', sideEffectClass: 'R2' },
    ],
  });
  const authorized = await controller.authorizePlan({ plan });
  if (!authorized.ok) throw new Error(`world setup failed: ${authorized.code}`);
  return { state, grants, clock, authority, controller, plan, authorized };
}

function effectInputs(world: Awaited<ReturnType<typeof makeAuthorizedWorld>>, index: number) {
  if (!world.authorized.ok) throw new Error('world was not authorized');
  const action: AuthorizedAction | undefined = world.authorized.authorization.actions[index];
  if (!action) throw new Error(`no action at index ${index}`);
  const grant = world.authorized.authorization.grants.find(
    (c) => c.grantId === action.authorizationRef,
  );
  if (!grant) throw new Error('no grant for action');
  return { action, grant };
}

describe('policy changes between multiple effects', () => {
  it('effect 1 passes, the policy moves P1→P2, effect 2 is refused and the plan stops', async () => {
    const w = await makeAuthorizedWorld();
    const first = effectInputs(w, 0);
    const second = effectInputs(w, 1);

    const gate1 = await w.controller.authorizeEffect({
      plan: w.plan,
      action: first.action,
      grant: first.grant,
    });
    expect(gate1).toMatchObject({ ok: true });

    await w.authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });

    const gate2 = await w.controller.authorizeEffect({
      plan: w.plan,
      action: second.action,
      grant: second.grant,
    });
    expect(gate2).toMatchObject({ ok: false, code: 'GRANT_POLICY_STALE' });

    // The already-passed first effect must not be re-runnable against the new state either.
    const gate1Again = await w.controller.authorizeEffect({
      plan: w.plan,
      action: first.action,
      grant: first.grant,
    });
    expect(gate1Again).toMatchObject({ ok: false, code: 'GRANT_POLICY_STALE' });
  });

  it('a grant revoked between effects is refused at the next gate', async () => {
    const w = await makeAuthorizedWorld();
    const second = effectInputs(w, 1);
    await w.authority.revokeGrant(second.grant.grantId);

    const gate = await w.controller.authorizeEffect({
      plan: w.plan,
      action: second.action,
      grant: second.grant,
    });
    expect(gate).toMatchObject({ ok: false, code: 'GRANT_REVOKED' });
  });

  it('a policy revocation between effects refuses the remaining effects', async () => {
    const w = await makeAuthorizedWorld();
    const second = effectInputs(w, 1);
    await w.authority.revokePolicy();

    const gate = await w.controller.authorizeEffect({
      plan: w.plan,
      action: second.action,
      grant: second.grant,
    });
    expect(gate).toMatchObject({ ok: false, code: 'GRANT_POLICY_REVOKED' });
  });

  it('an authority rotation A1→A2 between effects makes currentness UNRESOLVABLE until adoption, then AUTHORITY_STALE', async () => {
    const w = await makeAuthorizedWorld();
    const second = effectInputs(w, 1);

    await w.authority.rotateAuthority({ authorityRevision: 'auth-rev-2' });
    const midRotation = await w.controller.authorizeEffect({
      plan: w.plan,
      action: second.action,
      grant: second.grant,
    });
    expect(midRotation).toMatchObject({ ok: false, code: 'GRANT_CURRENTNESS_UNRESOLVABLE' });

    await w.authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });
    const afterAdoption = await w.controller.authorizeEffect({
      plan: w.plan,
      action: second.action,
      grant: second.grant,
    });
    expect(afterAdoption).toMatchObject({ ok: false, code: 'GRANT_AUTHORITY_STALE' });
  });

  it('an unreadable currentness record between effects refuses the remaining effects (never "authentic therefore current")', async () => {
    const w = await makeAuthorizedWorld();
    const first = effectInputs(w, 0);
    const second = effectInputs(w, 1);

    expect(
      await w.controller.authorizeEffect({
        plan: w.plan,
        action: first.action,
        grant: first.grant,
      }),
    ).toMatchObject({ ok: true });

    w.state.policyReadsFail = true;
    const gate = await w.controller.authorizeEffect({
      plan: w.plan,
      action: second.action,
      grant: second.grant,
    });
    expect(gate).toMatchObject({ ok: false, code: 'GRANT_CURRENTNESS_UNRESOLVABLE' });
  });

  it('after a mid-plan policy move, NEW plans formed under the old revision are refused at intake', async () => {
    const w = await makeAuthorizedWorld();
    await w.authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });

    const result = await w.controller.authorizePlan({
      plan: buildPlan({ policySnapshotRevision: 'pol-snap-1' }),
    });
    expect(result).toMatchObject({ ok: false, code: 'POLICY_BLOCKED' });
  });

  it('expiry that passes between effects refuses the later effect', async () => {
    const w = await makeAuthorizedWorld();
    const first = effectInputs(w, 0);
    const second = effectInputs(w, 1);

    expect(
      await w.controller.authorizeEffect({
        plan: w.plan,
        action: first.action,
        grant: first.grant,
      }),
    ).toMatchObject({ ok: true });

    w.clock.advanceMs(16 * 60 * 1000); // beyond grant + action TTLs
    const gate = await w.controller.authorizeEffect({
      plan: w.plan,
      action: second.action,
      grant: second.grant,
    });
    expect(gate).toMatchObject({ ok: false, code: 'GRANT_EXPIRED' });
  });
});
