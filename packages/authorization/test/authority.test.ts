// AuthorizationAuthority issuance + currentness resolution (T02 evidence:
// issuance is fail-closed and only ever authoritative-signed).

import { ShunContractError } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { AuthorizationAuthority } from '../src/authority.ts';
import { createHmacGrantVerifier } from '../src/integrity.ts';
import { computeIssuanceProof } from '../src/issuance-proof.ts';
import { resolveCurrentAuthorityState } from '../src/policy.ts';
import {
  AUTHORITY,
  activePolicy,
  buildPlan,
  fixedClock,
  grantOf,
  ISSUANCE_SECRET,
  issueRequestFor,
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
    issuanceSecret: ISSUANCE_SECRET,
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

describe('the issuance port is protected — grants are issued only through the Action Controller (P1-04)', () => {
  it('a direct issuer call carrying no controller issuance proof is refused with a structured error and persists nothing', async () => {
    const { authority, grants } = makeAuthority();
    const plan = buildPlan();
    await expect(authority.issue(issueRequestFor(plan))).rejects.toMatchObject({
      name: 'ShunContractError',
      code: 'GRANT_NOT_AUTHENTIC',
      message: expect.stringContaining('issuance proof'),
    });
    expect(grants.snapshot()).toHaveLength(0);
  });

  it('a direct issuer call with a forged proof string is refused', async () => {
    const { authority, grants } = makeAuthority();
    const plan = buildPlan();
    await expect(
      authority.issue(issueRequestFor(plan), 'forged-issuance-proof'),
    ).rejects.toMatchObject({ name: 'ShunContractError', code: 'GRANT_NOT_AUTHENTIC' });
    expect(grants.snapshot()).toHaveLength(0);
  });

  it('a proof minted under a foreign secret does not authorize issuance', async () => {
    const { authority, grants } = makeAuthority();
    const plan = buildPlan();
    const request = issueRequestFor(plan);
    const foreignProof = computeIssuanceProof('attacker-issuance-secret', request);
    await expect(authority.issue(request, foreignProof)).rejects.toMatchObject({
      name: 'ShunContractError',
      code: 'GRANT_NOT_AUTHENTIC',
    });
    expect(grants.snapshot()).toHaveLength(0);
  });

  it('a valid proof does not transfer across requests — the proof binds the exact issuance request', async () => {
    const { authority, grants } = makeAuthority();
    const plan = buildPlan();
    const request = issueRequestFor(plan);
    const proof = computeIssuanceProof(ISSUANCE_SECRET, request);
    // A different request (different privilege) presented under the first request's proof.
    const other = issueRequestFor(plan, {
      actionScope: {
        actionIds: plan.actions.map((a) => a.actionId),
        privilegeLevel: 'ELEVATED',
      },
    });
    await expect(authority.issue(other, proof)).rejects.toMatchObject({
      code: 'GRANT_NOT_AUTHENTIC',
    });
    // And the exact bound pair still issues.
    await expect(authority.issue(request, proof)).resolves.toMatchObject({
      planHash: plan.planHash,
    });
    expect(grants.snapshot()).toHaveLength(1);
  });

  it('the controller-issued route still mints valid grants bound to the exact request (positive control)', async () => {
    const { authority } = makeAuthority();
    const plan = buildPlan();
    const request = issueRequestFor(plan);
    const grant = await authority.issue(request, computeIssuanceProof(ISSUANCE_SECRET, request));
    expect(grant.planHash).toBe(plan.planHash);
    expect(grant.integrity.scheme).toBe('HMAC_SHA256');
    expect(grant.integrity.value).not.toBe('');
  });
});

describe('policy revision non-reuse and durable revocation (P1-02)', () => {
  it('a revoked grant cannot be resurrected by re-adopting the revision that revoked it (P1→revoke→P1)', async () => {
    const { authority } = makeAuthority();
    const plan = buildPlan();
    const grant = await grantOf(authority, plan);
    await authority.revokeGrant(grant.grantId);

    await expect(
      authority.adoptPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] }),
    ).rejects.toBeInstanceOf(ShunContractError);

    // The current state is untouched: the revision stays, the revocation stays.
    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      policySnapshotRevision: POLICY_REVISION,
      policyStatus: 'ACTIVE',
      revokedGrantIds: [grant.grantId],
    });
  });

  it('a superseded revision cannot be re-adopted to resurrect its grants (P1→P2→P1)', async () => {
    const { authority } = makeAuthority();
    const grant = await grantOf(authority, buildPlan());
    await authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });

    await expect(
      authority.adoptPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] }),
    ).rejects.toBeInstanceOf(ShunContractError);

    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      policySnapshotRevision: 'pol-snap-2',
    });
    // The P1 grant's durable record is untouched — and it must stay void.
    const stored = await authority.storedGrant(grant.grantId);
    expect(stored?.grant.policySnapshotRevision).toBe(POLICY_REVISION);
  });

  it('the currently active revision is itself non-reusable (re-adoption would reset its revocations)', async () => {
    const { authority } = makeAuthority();
    await expect(
      authority.adoptPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] }),
    ).rejects.toBeInstanceOf(ShunContractError);
  });

  it('revision non-reuse holds across a chain: P1→P2→P3, then P2 is refused', async () => {
    const { authority } = makeAuthority();
    await authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });
    await authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-3', rules: [] });
    await expect(
      authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] }),
    ).rejects.toBeInstanceOf(ShunContractError);
    expect(await authority.currentAuthority()).toMatchObject({
      policySnapshotRevision: 'pol-snap-3',
    });
  });

  it('revocation history is durable: grants revoked under a predecessor stay revoked under the successor', async () => {
    const { authority } = makeAuthority();
    const grant = await grantOf(authority, buildPlan());
    await authority.revokeGrant(grant.grantId);
    await authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });

    expect(await authority.currentAuthority()).toMatchObject({
      policySnapshotRevision: 'pol-snap-2',
      revokedGrantIds: [grant.grantId],
    });
  });

  it('re-adoption refusal is fail-closed on a corrupt current policy record', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const { authority } = makeAuthority(state);
    state.policySlot = { garbage: true };
    await expect(
      authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] }),
    ).rejects.toMatchObject({ code: 'GRANT_CURRENTNESS_UNRESOLVABLE' });
  });

  it('first-ever adoption still bootstraps an empty store (positive control)', async () => {
    const { authority } = makeAuthority(memoryPolicyState({ authority: AUTHORITY }));
    await expect(
      authority.adoptPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] }),
    ).resolves.toBeUndefined();
    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      policySnapshotRevision: POLICY_REVISION,
      policyStatus: 'ACTIVE',
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
