// AuthorizationAuthority issuance + currentness resolution (T02 evidence:
// issuance is fail-closed and only ever authoritative-signed).

import { ShunContractError } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { AuthorizationAuthority } from '../src/authority.ts';
import { createHmacGrantVerifier } from '../src/integrity.ts';
import { resolveCurrentAuthorityState } from '../src/policy.ts';
import {
  AUTHORITY,
  activePolicy,
  buildPlan,
  fixedClock,
  grantOf,
  memoryGrantStore,
  memoryPolicyState,
  POLICY_REVISION,
} from './helpers.ts';

function makeAuthority(
  state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() }),
  clock = fixedClock(),
) {
  const grants = memoryGrantStore();
  const authority = new AuthorizationAuthority({
    state,
    grants,
    integritySecret: 'test-authority-secret',
    clock: clock.now,
  });
  return { authority, grants, state, clock };
}

describe('AuthorizationAuthority issuance', () => {
  it('issues a durable, integrity-protected grant bound to the CURRENT authority/policy state', async () => {
    const { authority, grants, clock } = makeAuthority();
    const plan = buildPlan();
    const grant = await grantOf(authority, plan);

    expect(grant.issuer).toEqual({
      authorityId: AUTHORITY.authorityId,
      authorityRevision: AUTHORITY.authorityRevision,
    });
    expect(grant.policySnapshotRevision).toBe(POLICY_REVISION);
    expect(grant.taskId).toBe(plan.taskId);
    expect(grant.planHash).toBe(plan.planHash);
    expect(grant.integrity.scheme).toBe('HMAC_SHA256');
    expect(grant.integrity.value).not.toBe('');
    expect(grant.expiresAt).toBe(new Date(Date.parse(clock.now()) + 15 * 60 * 1000).toISOString());

    // Durable record exists before the grant is returned.
    expect(grants.has(grant.grantId)).toBe(true);
  });

  it('signs with the trusted substrate only: a caller cannot obtain a valid envelope with a foreign secret', async () => {
    const { authority } = makeAuthority();
    const plan = buildPlan();
    const grant = await grantOf(authority, plan);

    expect(createHmacGrantVerifier('test-authority-secret')(grant, grant.integrity)).toBe(true);
    expect(createHmacGrantVerifier('attacker-secret')(grant, grant.integrity)).toBe(false);
  });

  it('never issues under unresolvable currentness (missing state)', async () => {
    const { authority } = makeAuthority(memoryPolicyState());
    await expect(grantOf(authority, buildPlan())).rejects.toMatchObject({
      name: 'ShunContractError',
      code: 'GRANT_CURRENTNESS_UNRESOLVABLE',
    });
  });

  it('never issues under corrupt state', async () => {
    const state = memoryPolicyState();
    state.authoritySlot = { authorityId: 'x' }; // missing revision/updatedAt → schema-invalid
    state.policySlot = { garbage: true };
    const { authority } = makeAuthority(state);
    await expect(grantOf(authority, buildPlan())).rejects.toMatchObject({
      name: 'ShunContractError',
      code: 'GRANT_CURRENTNESS_UNRESOLVABLE',
    });
  });

  it('never issues under a non-ACTIVE policy', async () => {
    const revoked = makeAuthority(
      memoryPolicyState({ authority: AUTHORITY, policy: activePolicy({ status: 'REVOKED' }) }),
    );
    await expect(grantOf(revoked.authority, buildPlan())).rejects.toMatchObject({
      code: 'GRANT_POLICY_REVOKED',
    });
    const superseded = makeAuthority(
      memoryPolicyState({ authority: AUTHORITY, policy: activePolicy({ status: 'SUPERSEDED' }) }),
    );
    await expect(grantOf(superseded.authority, buildPlan())).rejects.toMatchObject({
      code: 'GRANT_POLICY_STALE',
    });
  });

  it('refuses a request classified under a stale policy revision', async () => {
    const { authority } = makeAuthority();
    const plan = buildPlan();
    await expect(
      grantOf(authority, plan, { policySnapshotRevision: 'pol-snap-old' }),
    ).rejects.toMatchObject({ code: 'GRANT_POLICY_STALE' });
  });

  it('refuses explicit-approval issuance without the durable approval reference', async () => {
    const { authority } = makeAuthority();
    const plan = buildPlan();
    await expect(
      grantOf(authority, plan, { authorizationKind: 'EXPLICIT_APPROVAL' }),
    ).rejects.toMatchObject({ code: 'GRANT_APPROVAL_REF_MISSING' });
  });

  it('refuses a malformed issue request and a malformed clock', async () => {
    const { authority } = makeAuthority();
    const bogus: unknown = { bogus: true };
    await expect(authority.issue(bogus as never)).rejects.toMatchObject({
      code: 'SCHEMA_VIOLATION',
    });

    const brokenClock = makeAuthority(undefined, { now: () => 'not-a-date', advanceMs: () => {} });
    await expect(grantOf(brokenClock.authority, buildPlan())).rejects.toMatchObject({
      code: 'GRANT_MALFORMED',
    });
  });
});

describe('authority events move the current state', () => {
  it('revokeGrant places the grant on the current revocation list', async () => {
    const { authority } = makeAuthority();
    const grant = await grantOf(authority, buildPlan());
    await authority.revokeGrant(grant.grantId);

    const current = await authority.currentAuthority();
    expect(current).toMatchObject({ kind: 'CURRENT', revokedGrantIds: [grant.grantId] });
  });

  it('revokePolicy flips the current policy status to REVOKED', async () => {
    const { authority } = makeAuthority();
    await authority.revokePolicy();
    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      policyStatus: 'REVOKED',
    });
  });

  it('adoptPolicy supersedes by revision: the new revision is current, old grants compare stale', async () => {
    const { authority } = makeAuthority();
    await authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });
    const current = await authority.currentAuthority();
    expect(current).toMatchObject({
      kind: 'CURRENT',
      policySnapshotRevision: 'pol-snap-2',
      policyStatus: 'ACTIVE',
    });
  });

  it('rotating the authority alone makes currentness deliberately UNRESOLVABLE (incoherent pairing fails closed)', async () => {
    const { authority } = makeAuthority();
    await authority.rotateAuthority({ authorityRevision: 'auth-rev-2' });
    const current = await authority.currentAuthority();
    expect(current).toMatchObject({ kind: 'UNRESOLVABLE' });
    expect(current.kind === 'UNRESOLVABLE' && current.reason).toContain('bound to authority');
  });

  it('after rotation + policy adoption under the new revision, currentness is CURRENT again', async () => {
    const { authority } = makeAuthority();
    await authority.rotateAuthority({ authorityRevision: 'auth-rev-2' });
    await authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });
    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      authorityRevision: 'auth-rev-2',
      policySnapshotRevision: 'pol-snap-2',
    });
  });

  it('authority events fail closed on corrupt state instead of crashing untyped', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY });
    const { authority } = makeAuthority(state);
    await expect(authority.revokePolicy()).rejects.toBeInstanceOf(ShunContractError);
    await expect(authority.revokeGrant('g-1')).rejects.toBeInstanceOf(ShunContractError);
    await expect(authority.rotateAuthority({ authorityRevision: 'x' })).rejects.toBeInstanceOf(
      ShunContractError,
    );
  });
});

describe('resolveCurrentAuthorityState fail-closed resolution', () => {
  it('resolves CURRENT only for well-formed coherent records', async () => {
    const state = memoryPolicyState({
      authority: AUTHORITY,
      policy: activePolicy({ revokedGrantIds: ['g-9'] }),
    });
    expect(await resolveCurrentAuthorityState(state)).toEqual({
      kind: 'CURRENT',
      authorityId: AUTHORITY.authorityId,
      authorityRevision: AUTHORITY.authorityRevision,
      policySnapshotRevision: POLICY_REVISION,
      policyStatus: 'ACTIVE',
      revokedGrantIds: ['g-9'],
    });
  });

  it('returns UNRESOLVABLE when a read throws', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    state.policyReadsFail = true;
    const resolved = await resolveCurrentAuthorityState(state);
    expect(resolved).toMatchObject({ kind: 'UNRESOLVABLE' });
    expect(resolved.kind === 'UNRESOLVABLE' && resolved.reason).toContain('read failed');
  });
});
