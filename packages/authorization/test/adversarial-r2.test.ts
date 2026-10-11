// R2 adversarial regressions (Issue #34 — fresh independent security review
// R1 of PR #43 at exact HEAD 349569f, claim
// SHUN_T02_PR43_349569F_FRESH_INDEPENDENT_SECURITY_REVIEW_R1, RESULT
// CHANGES_REQUESTED P1×4).
//
// Every test reproduces one of the reviewer's deterministic counterexamples
// against the public seams BEFORE the repair (each fails on 349569f) and pins
// the repaired fail-closed behavior:
//   P1-A — a previously-initialized but UNMARKED legacy state (valid policy,
//          issued/revoked grants, no policyInitialized marker) must never be
//          treated as a virgin bootstrap when its policy slot is lost: grant
//          records prove prior policy existence, so adoption refuses.
//   P1-B — atomic durable mutation is MANDATORY: a store without
//          compare-and-save primitives is rejected at construction (no
//          optional unsafe adapter), authority-record writes (initialization
//          marker, rotation) are CAS-protected, and a second Authority
//          instance can never roll currentness back.
//   P1-C — issuance-proof consumption lives in the SHARED durable state, not
//          an instance-local ledger: a reconstructed issuer (second instance
//          / restart) cannot replay an already-consumed proof.
//   P1-D — authority revisions are non-reusable (A1→A2→A1 refuses): a stale
//          grant can never be re-currented by revision rollback.

import { describe, expect, it } from 'vitest';
import { AuthorizationAuthority } from '../src/authority.ts';
import { computeIssuanceProof } from '../src/issuance-proof.ts';
import type { AuthorityRecord, PolicySnapshotRecord } from '../src/policy.ts';
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

function authorityOn(
  state: ReturnType<typeof memoryPolicyState>,
  grants = memoryGrantStore(),
  clock = fixedClock(),
) {
  const authority = new AuthorizationAuthority({
    state,
    grants,
    integritySecret: 'test-authority-secret',
    issuanceSecret: ISSUANCE_SECRET,
    bootstrapAuthorizer: ({ proof }) => proof === 'trusted-one-shot-bootstrap',
    clock: clock.now,
  });
  return { authority, grants, clock };
}

/**
 * Deterministic store barrier (same pattern as adversarial-r1): parks the
 * FIRST authority-record mutation the store receives — whichever write shape
 * the authority emits (plain save pre-fix, compare-and-save post-fix) — so a
 * concurrent event on a SECOND Authority instance interleaves at an exact,
 * reproducible point.
 */
function gateFirstAuthorityRecordSave(state: ReturnType<typeof memoryPolicyState>) {
  let releaseBarrier!: () => void;
  const gate = new Promise<void>((resolve) => {
    releaseBarrier = resolve;
  });
  let markEntered!: () => void;
  const entered = new Promise<void>((resolve) => {
    markEntered = resolve;
  });
  let parked = false;
  const park = async <T>(run: () => Promise<T>): Promise<T> => {
    if (!parked) {
      parked = true;
      markEntered();
      await gate;
    }
    return run();
  };
  const baseSave = state.saveAuthorityRecord.bind(state);
  const baseCas = state.compareAndSaveAuthorityRecord.bind(state);
  state.saveAuthorityRecord = async (record: AuthorityRecord) => park(() => baseSave(record));
  state.compareAndSaveAuthorityRecord = async (record: AuthorityRecord, expectedPrior: unknown) =>
    park(() => baseCas(record, expectedPrior));
  return { entered, release: releaseBarrier };
}

describe('P1-A: grant records prove prior policy existence — unmarked loss is never a bootstrap', () => {
  it('a legacy unmarked authority whose policy slot is lost refuses adoption and never resurrects revoked grants', async () => {
    // The reviewer's counterexample: a pre-marker-era valid state
    // {authority: A1 (no marker), policy: P1}; issue an unexpired grant,
    // revoke it, lose the policy slot, then adopt P1 again. Grant records
    // exist, so this provably was NOT a virgin store.
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const { authority, grants } = authorityOn(state);
    const grant = await grantOf(authority, buildPlan());
    await authority.revokeGrant(grant.grantId);

    state.policySlot = undefined;

    await expect(
      authority.adoptPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] }),
    ).rejects.toMatchObject({ name: 'ShunContractError' });
    await expect(
      authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] }),
    ).rejects.toMatchObject({ name: 'ShunContractError' });

    // The revoked grant was never revalidated or re-minted: exactly the
    // original durable record remains, currentness stays unresolvable.
    expect(grants.snapshot()).toHaveLength(1);
    expect(grants.snapshot()[0]?.grantId).toBe(grant.grantId);
    expect(await authority.currentAuthority()).toMatchObject({ kind: 'UNRESOLVABLE' });
    expect((state.policySlot as PolicySnapshotRecord | undefined) ?? null).toBeNull();
  });

  it('a virgin store bootstraps only through the explicit trusted ceremony (positive control)', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY });
    const { authority } = authorityOn(state);
    await authority.bootstrapPolicy(
      { policySnapshotRevision: POLICY_REVISION, rules: [] },
      'trusted-one-shot-bootstrap',
    );
    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      policySnapshotRevision: POLICY_REVISION,
      policyStatus: 'ACTIVE',
    });
  });
});

describe('R3: missing policy is never implicit proof of a virgin authority', () => {
  it('an unmarked REVOKED legacy policy with zero grant history cannot reactivate after slot loss', async () => {
    const state = memoryPolicyState({
      authority: AUTHORITY,
      policy: activePolicy({ status: 'REVOKED' }),
    });
    const { authority } = authorityOn(state);
    // Exact R2 independent-review counterexample: no grants ever existed,
    // so grant-history evidence is empty. Losing the policy slot still must
    // not transform a previously revoked authority into a virgin bootstrap.
    state.policySlot = undefined;
    await expect(
      authority.adoptPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] }),
    ).rejects.toMatchObject({
      name: 'ShunContractError',
      code: 'GRANT_CURRENTNESS_UNRESOLVABLE',
    });
    expect(state.policySlot).toBeUndefined();
  });

  it('ordinary adoptPolicy refuses an actually empty policy slot too — bootstrap must be explicit', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY });
    const { authority } = authorityOn(state);
    await expect(
      authority.adoptPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] }),
    ).rejects.toMatchObject({
      name: 'ShunContractError',
      code: 'GRANT_CURRENTNESS_UNRESOLVABLE',
    });
    expect(state.policySlot).toBeUndefined();
    expect(state.authoritySlot).toEqual(AUTHORITY);
  });

  it('a trusted explicit bootstrap ceremony can establish the first policy on a virgin store', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY });
    const grants = memoryGrantStore();
    const authority = new AuthorizationAuthority({
      state,
      grants,
      integritySecret: 'test-authority-secret',
      issuanceSecret: ISSUANCE_SECRET,
      clock: fixedClock().now,
      bootstrapAuthorizer: ({ proof, authorityRecord, snapshot }) =>
        proof === 'trusted-one-shot-bootstrap' &&
        authorityRecord.authorityRevision === AUTHORITY.authorityRevision &&
        snapshot.policySnapshotRevision === POLICY_REVISION,
    });

    await authority.bootstrapPolicy(
      { policySnapshotRevision: POLICY_REVISION, rules: [] },
      'trusted-one-shot-bootstrap',
    );

    expect(state.authoritySlot).toMatchObject({ policyInitialized: true });
    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      policySnapshotRevision: POLICY_REVISION,
      policyStatus: 'ACTIVE',
    });
  });

  it('R4: async bootstrap authorization cannot persist caller-mutated or authorizer-mutated policy rules', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY });
    let releaseAuthorization!: () => void;
    const pause = new Promise<void>((resolve) => {
      releaseAuthorization = resolve;
    });
    let reachedAuthorizer!: () => void;
    const entered = new Promise<void>((resolve) => {
      reachedAuthorizer = resolve;
    });
    const authority = new AuthorizationAuthority({
      state,
      grants: memoryGrantStore(),
      integritySecret: 'test-authority-secret',
      issuanceSecret: ISSUANCE_SECRET,
      clock: fixedClock().now,
      bootstrapAuthorizer: async ({ proof, snapshot }) => {
        expect(proof).toBe('trusted-one-shot-bootstrap');
        expect(snapshot.policySnapshotRevision).toBe(POLICY_REVISION);
        expect(snapshot.rules).toEqual([]);
        reachedAuthorizer();
        await pause;
        // A callback must not be able to mutate the candidate persisted by
        // the authority, even if it changes the snapshot it was shown.
        snapshot.rules.push({
          ruleId: 'rule-authorizer-injected',
          capabilityId: 'software.remove',
          op: 'software.uninstall',
          maxRiskClass: 'R2',
          privilegeLevel: 'ELEVATED',
        });
        return true;
      },
    });
    const candidate = { policySnapshotRevision: POLICY_REVISION, rules: [] as PolicySnapshotRecord['rules'] };
    const pending = authority.bootstrapPolicy(candidate, 'trusted-one-shot-bootstrap');
    await entered;
    // Independent review R3 P1: mutate the caller-owned object while the
    // trusted authorizer is parked, AFTER it inspected benign S1.
    candidate.policySnapshotRevision = 'policy-broadened-after-approval';
    candidate.rules.push({
      ruleId: 'rule-caller-injected',
      capabilityId: 'software.remove',
      op: 'software.uninstall',
      maxRiskClass: 'R2',
      privilegeLevel: 'ELEVATED',
    });
    releaseAuthorization();
    await pending;
    expect(state.policySlot).toMatchObject({
      policySnapshotRevision: POLICY_REVISION,
      rules: [],
      riskGuards: [],
      status: 'ACTIVE',
    });
    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      policySnapshotRevision: POLICY_REVISION,
    });
  });

  it('an absent or rejected bootstrap proof leaves the virgin store byte-state untouched', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY });
    const grants = memoryGrantStore();
    const authority = new AuthorizationAuthority({
      state,
      grants,
      integritySecret: 'test-authority-secret',
      issuanceSecret: ISSUANCE_SECRET,
      clock: fixedClock().now,
      bootstrapAuthorizer: () => false,
    });

    const beforeAuthority = structuredClone(state.authoritySlot);
    await expect(
      authority.bootstrapPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] }, 'forged'),
    ).rejects.toMatchObject({ name: 'ShunContractError', code: 'GRANT_NOT_AUTHENTIC' });
    expect(state.authoritySlot).toEqual(beforeAuthority);
    expect(state.policySlot).toBeUndefined();
  });
});

describe('P1-B: shared-durable atomicity is mandatory, not optional or per-instance', () => {
  it('an authority refuses a store without the mandatory compare-and-save primitives', () => {
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    // The reviewer's supported-but-unsafe store shape: no CAS method. The
    // authority used to fall back to unconditional saves — the exact hole a
    // second instance could drive a rollback through. Construction must
    // reject it instead of degrading.
    const unsafe = state as unknown as Record<string, unknown>;
    delete unsafe.compareAndSavePolicySnapshot;
    delete unsafe.compareAndSaveAuthorityRecord;
    delete unsafe.consumeIssuanceNonce;
    expect(() => authorityOn(unsafe as unknown as ReturnType<typeof memoryPolicyState>)).toThrow(
      /compare-and-save|atomic/i,
    );
  });

  it('a parked initialization-marker write cannot overwrite an intervening rotation from another instance', async () => {
    // The reviewer's interleaving: an unmarked A1 adoption parks inside its
    // authority-record (marker) write; a second instance rotates A1→A2; the
    // resumed plain save overwrote A2 with A1 again — the rotation vanished.
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const x = authorityOn(state);
    const y = authorityOn(state);

    const barrier = gateFirstAuthorityRecordSave(state);
    const adopt = x.authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });
    await barrier.entered; // X's marker write is parked, state read as A1

    await y.authority.rotateAuthority({ authorityRevision: 'auth-rev-2' });
    barrier.release();
    await adopt;

    // The rotation must survive: the marker write may never resurrect A1.
    expect(state.authoritySlot).toMatchObject({
      authorityRevision: 'auth-rev-2',
      policyInitialized: true,
    });
    expect(await x.authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      authorityRevision: 'auth-rev-2',
      policySnapshotRevision: 'pol-snap-2',
    });
  });

  it('two concurrent rotations from distinct instances preserve a durable revision lineage', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const x = authorityOn(state);
    const y = authorityOn(state);

    const barrier = gateFirstAuthorityRecordSave(state);
    const rotateX = x.authority.rotateAuthority({ authorityRevision: 'auth-rev-2' });
    await barrier.entered; // X's rotation write is parked (read A1)

    await y.authority.rotateAuthority({ authorityRevision: 'auth-rev-3' });
    barrier.release();
    await rotateX;

    // X's rotation loses the CAS race against Y's A3 write and must retry
    // from the FRESH record: A2 lands on top of A3 with BOTH prior revisions
    // retained durably — a revision dropped from the lineage would become
    // re-adoptable.
    const record = state.authoritySlot as AuthorityRecord;
    expect(record.authorityRevision).toBe('auth-rev-2');
    expect(record.priorAuthorityRevisions).toEqual(
      expect.arrayContaining(['auth-rev-1', 'auth-rev-3']),
    );
  });
});

describe('P1-C: proof consumption is shared durable state, not an instance ledger', () => {
  it('a reconstructed issuer cannot replay an already-consumed proof (second instance / restart)', async () => {
    // The reviewer's counterexample: issue G1 with the proof, revoke G1,
    // construct a SECOND authority over the same durable state (a restart of
    // the issuer), and replay the same (request, proof) pair inside its
    // validity window. The instance-local nonce ledger used to reset, minting
    // a fresh unrevoked grant without new controller approval.
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const sharedGrants = memoryGrantStore();
    const first = authorityOn(state, sharedGrants);
    const request = issueRequestFor(buildPlan());
    const proof = computeIssuanceProof(ISSUANCE_SECRET, request);
    const g1 = await first.authority.issue(request, proof);
    await first.authority.revokeGrant(g1.grantId);

    const restarted = authorityOn(state, sharedGrants, fixedClock('2026-10-10T12:01:00.000Z'));
    await expect(restarted.authority.issue(request, proof)).rejects.toMatchObject({
      name: 'ShunContractError',
      code: 'GRANT_NOT_AUTHENTIC',
    });
    // No second grant ever existed.
    expect(sharedGrants.snapshot()).toHaveLength(1);
    expect(sharedGrants.snapshot()[0]?.grantId).toBe(g1.grantId);
  });

  it('a fresh proof from a second authority still issues (positive control)', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const sharedGrants = memoryGrantStore();
    const first = authorityOn(state, sharedGrants);
    const second = authorityOn(state, sharedGrants, fixedClock('2026-10-10T12:01:00.000Z'));
    const request = issueRequestFor(buildPlan());
    await first.authority.issue(request, computeIssuanceProof(ISSUANCE_SECRET, request));
    // A separately minted proof is its own consumable approval.
    const g2 = await second.authority.issue(
      request,
      computeIssuanceProof(ISSUANCE_SECRET, request),
    );
    expect(g2.grantId).not.toBeUndefined();
    expect(sharedGrants.snapshot()).toHaveLength(2);
  });
});

describe('P1-D: authority revisions are non-reusable — rollback re-currents stale grants', () => {
  it('rotateAuthority refuses A1→A2→A1 and the formerly stale grant stays stale', async () => {
    // The reviewer's single-instance counterexample: mint an unexpired grant
    // under A1/P1, rotate to A2 (currentness correctly UNRESOLVABLE), then
    // rotate BACK to A1 — the still-ACTIVE P1 policy re-cohered and the stale
    // grant passed currentness again without any race.
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const { authority, grants } = authorityOn(state);
    // The grant record must exist under A1/P1 so the reuse attempt has a
    // stale grant it could resurrect.
    await grantOf(authority, buildPlan());

    await authority.rotateAuthority({ authorityRevision: 'auth-rev-2' });
    expect(await authority.currentAuthority()).toMatchObject({ kind: 'UNRESOLVABLE' });

    await expect(
      authority.rotateAuthority({ authorityRevision: 'auth-rev-1' }),
    ).rejects.toMatchObject({ name: 'ShunContractError', code: 'GRANT_AUTHORITY_STALE' });

    // A2 stays current: P1 remains incoherent and the A1/P1 grant stays stale.
    expect(await authority.currentAuthority()).toMatchObject({ kind: 'UNRESOLVABLE' });
    expect(grants.snapshot()).toHaveLength(1);
  });

  it('rotating to a genuinely fresh revision still works, and reuse of the CURRENT revision refuses too', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const { authority } = authorityOn(state);
    await authority.rotateAuthority({ authorityRevision: 'auth-rev-2' });
    await authority.rotateAuthority({ authorityRevision: 'auth-rev-3' });
    expect(state.authoritySlot).toMatchObject({ authorityRevision: 'auth-rev-3' });
    expect(state.authoritySlot).toMatchObject({
      priorAuthorityRevisions: expect.arrayContaining(['auth-rev-1', 'auth-rev-2']),
    });
    await expect(
      authority.rotateAuthority({ authorityRevision: 'auth-rev-3' }),
    ).rejects.toMatchObject({ name: 'ShunContractError', code: 'GRANT_AUTHORITY_STALE' });
  });
});
