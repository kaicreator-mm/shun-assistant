// R1 adversarial regressions (Issue #34 — fresh independent security review of
// PR #43 at exact HEAD 9872ce1, claim
// SHUN_T02_POSTMERGE_PR43_FRESH_INDEPENDENT_REVIEW_R0, RESULT CHANGES_REQUESTED).
//
// Every test here reproduces one of the reviewer's deterministic
// counterexamples against the public seams BEFORE the repair (each fails on
// 9872ce1) and pins the repaired fail-closed behavior:
//   P1-A — a missing policy row in an authority whose record proves an earlier
//          policy adoption is durable-state loss, never a first bootstrap;
//          adoption over the absent predecessor refuses and no revoked grant
//          is resurrected or revalidated.
//   P1-B — concurrent authority events stay serializable: store-side barriers
//          park one mutation at an exact point so another event (or an
//          out-of-band writer on the shared store) interleaves
//          deterministically; a stale write may never roll back revision or
//          revocation currentness.
//   P1-C — a controller issuance proof is a single-use, expiring capability:
//          the same (request, proof) pair cannot re-mint a grant after the
//          first grant's revocation, after the proof's validity window, or in
//          its legacy reusable bare-HMAC shape.

import { createHmac } from 'node:crypto';
import { canonicalJson, ShunContractError } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { AuthorizationAuthority } from '../src/authority.ts';
import { computeIssuanceProof } from '../src/issuance-proof.ts';
import type { PolicySnapshotRecord } from '../src/policy.ts';
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

/**
 * Deterministic store barrier: the test parks the authority INSIDE one store
 * call and resumes it on demand, so a concurrent event interleaves at an
 * exact, reproducible point — no polling, no sleeps, no reliance on
 * cooperative scheduling luck.
 */
function storeBarrier() {
  let releaseBarrier!: () => void;
  const gate = new Promise<void>((resolve) => {
    releaseBarrier = resolve;
  });
  let markEntered!: () => void;
  const entered = new Promise<void>((resolve) => {
    markEntered = resolve;
  });
  let markedOnce = false;
  return {
    gate,
    entered,
    release: releaseBarrier,
    enter: () => {
      if (!markedOnce) {
        markedOnce = true;
        markEntered();
      }
    },
  };
}

/**
 * Park the FIRST policy WRITE the store receives (compare-and-save when the
 * authority uses it, plain save otherwise) behind a barrier. Whichever write
 * shape the authority emits, the test observes exactly the reviewer's pause
 * point: state read, mutation computed, write not yet landed.
 */
function gateFirstPolicyWrite(
  state: ReturnType<typeof memoryPolicyState>,
  barrier: ReturnType<typeof storeBarrier>,
) {
  const baseSave = state.savePolicySnapshot.bind(state);
  const baseCas = state.compareAndSavePolicySnapshot?.bind(state);
  state.savePolicySnapshot = async (snapshot: PolicySnapshotRecord) => {
    barrier.enter();
    await barrier.gate;
    return baseSave(snapshot);
  };
  if (baseCas) {
    state.compareAndSavePolicySnapshot = async (
      snapshot: PolicySnapshotRecord,
      expectedPrior: unknown,
    ) => {
      barrier.enter();
      await barrier.gate;
      return baseCas(snapshot, expectedPrior);
    };
  }
}

/**
 * One macrotask turn: flushes every pending microtask of an UNLOCKED
 * interleaving, so a second authority event that is free to run drives to
 * completion while the first event's write stays parked. Under the repaired
 * single-writer serialization the second event makes no store progress at all
 * here — it is queued — so the very same script is deterministic in both the
 * vulnerable and the repaired mode.
 */
async function settleUnlockedInterleaving(): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, 0);
  });
}

describe('P1-A: a missing policy row in an initialized authority is storage loss, never a bootstrap', () => {
  it('P1→issue→revoke→policy-slot loss→adopt(P1) refuses and the revoked grant is not resurrected or revalidated', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY });
    const { authority, grants } = makeAuthority(state);
    await authority.adoptPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] });
    const grant = await grantOf(authority, buildPlan());
    await authority.revokeGrant(grant.grantId);

    // Storage loss: the policy row disappears while the authority record and
    // the issued grant records survive.
    state.policySlot = undefined;

    await expect(
      authority.adoptPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] }),
    ).rejects.toBeInstanceOf(ShunContractError);
    // Even a FRESH successor revision refuses: an absent predecessor can never
    // be sealed over, or loss would reset revocation and lineage wholesale.
    await expect(
      authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] }),
    ).rejects.toBeInstanceOf(ShunContractError);

    // G was never revalidated or re-minted: exactly the original durable
    // record remains, and currentness stays unresolvable (fail-closed).
    expect(grants.snapshot()).toHaveLength(1);
    expect(grants.snapshot()[0]?.grantId).toBe(grant.grantId);
    expect(await authority.currentAuthority()).toMatchObject({ kind: 'UNRESOLVABLE' });
  });

  it('the first bootstrap adoption records a durable initialization marker outside the policy slot', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY });
    const { authority } = makeAuthority(state);
    await authority.adoptPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] });

    // The marker must live OUTSIDE the slot it guards: it survives exactly
    // the loss it makes detectable.
    expect(state.authoritySlot).toMatchObject({ policyInitialized: true });
    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      policySnapshotRevision: POLICY_REVISION,
      policyStatus: 'ACTIVE',
    });
  });

  it('the initialization marker survives an authority rotation', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY });
    const { authority } = makeAuthority(state);
    await authority.adoptPolicy({ policySnapshotRevision: POLICY_REVISION, rules: [] });
    await authority.rotateAuthority({ authorityRevision: 'auth-rev-2' });

    expect(state.authoritySlot).toMatchObject({
      authorityRevision: 'auth-rev-2',
      policyInitialized: true,
    });
    // Loss after rotation must stay adoption-hostile too.
    state.policySlot = undefined;
    await expect(
      authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] }),
    ).rejects.toBeInstanceOf(ShunContractError);
  });
});

describe('P1-B: concurrent authority events stay serializable (deterministic store barriers)', () => {
  it('a revocation parked before its write cannot roll back a concurrent adoption (revoke↔adopt)', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const { authority } = makeAuthority(state);
    const grant = await grantOf(authority, buildPlan());

    // revokeGrant reads P1 and parks immediately before its write; the
    // reviewer's interleaving then lets a full adoption land before the
    // parked revocation write resumes.
    const barrier = storeBarrier();
    gateFirstPolicyWrite(state, barrier);

    const revoke = authority.revokeGrant(grant.grantId);
    await barrier.entered;
    // The reviewer's interleaving: a FULL adoption lands while the revocation
    // write is parked. Unlocked (pre-fix) the adoption completes here and its
    // stale-safe state never saw the parked revocation; repaired, it is
    // queued behind the single-writer lock instead.
    const adopt = authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });
    await settleUnlockedInterleaving();
    barrier.release();
    await revoke;
    await adopt;

    // The revocation must stay applied AND the adoption must stay current.
    // Pre-fix, the parked revocation write rolled the revision back to P1
    // (or dropped the revocation), re-currenting unrevoked P1 grants.
    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      policySnapshotRevision: 'pol-snap-2',
      policyStatus: 'ACTIVE',
      revokedGrantIds: [grant.grantId],
    });
  });

  it('two concurrent adoptions of different successors preserve the lineage (adopt↔adopt)', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const { authority } = makeAuthority(state);

    const barrier = storeBarrier();
    gateFirstPolicyWrite(state, barrier);

    const adoptP2 = authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] });
    await barrier.entered; // P2 computed, its write parked
    // Pre-fix the second adoption reads the STILL-CURRENT P1 (P2's write is
    // parked) and lands P3 with P1-only lineage; repaired, it is queued.
    const adoptP3 = authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-3', rules: [] });
    await settleUnlockedInterleaving();
    barrier.release();
    await adoptP2;
    await adoptP3;

    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      policySnapshotRevision: 'pol-snap-3',
      policyStatus: 'ACTIVE',
    });
    // P2 must be part of the durable lineage: a revision dropped by a lost
    // update becomes adoptable again, resetting its revocation list.
    expect((state.policySlot as PolicySnapshotRecord).priorRevisions).toEqual([
      'pol-snap-1',
      'pol-snap-2',
    ]);
    await expect(
      authority.adoptPolicy({ policySnapshotRevision: 'pol-snap-2', rules: [] }),
    ).rejects.toBeInstanceOf(ShunContractError);
  });

  it('a policy write that lost a race against an out-of-band writer retries from fresh state (CAS)', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const { authority } = makeAuthority(state);
    const grant = await grantOf(authority, buildPlan());

    const barrier = storeBarrier();
    gateFirstPolicyWrite(state, barrier);

    const revoke = authority.revokeGrant(grant.grantId);
    await barrier.entered;
    // A writer outside this authority instance (second process on the shared
    // store) moves the current policy to P2 while the revocation is parked.
    state.policySlot = activePolicy({ policySnapshotRevision: 'pol-snap-2' });
    barrier.release();
    await revoke;

    // The revocation must land on the FRESH current revision; the stale P1
    // write may never overwrite it (last-write-wins rolled P2 back to P1).
    expect(await authority.currentAuthority()).toMatchObject({
      kind: 'CURRENT',
      policySnapshotRevision: 'pol-snap-2',
      policyStatus: 'ACTIVE',
      revokedGrantIds: [grant.grantId],
    });
  });

  it('a policy mutation that cannot win its compare-and-save refuses typed, leaving the store untouched', async () => {
    const state = memoryPolicyState({ authority: AUTHORITY, policy: activePolicy() });
    const { authority } = makeAuthority(state);
    await grantOf(authority, buildPlan());

    let attempts = 0;
    state.compareAndSavePolicySnapshot = async () => {
      attempts += 1;
      return false; // a persistent concurrent writer wins every generation
    };

    await expect(authority.revokeGrant('g-external')).rejects.toMatchObject({
      name: 'ShunContractError',
      code: 'GRANT_CURRENTNESS_UNRESOLVABLE',
    });
    // Bounded retries, then a typed refusal — and the stale write never landed.
    expect(attempts).toBeGreaterThanOrEqual(2);
    expect((state.policySlot as PolicySnapshotRecord).revokedGrantIds).toEqual([]);
  });
});

describe('P1-C: issuance proofs are single-use, expiring capabilities', () => {
  it('the same (request, proof) pair cannot re-mint a grant after the granted revocation (replay)', async () => {
    const { authority, grants } = makeAuthority();
    const request = issueRequestFor(buildPlan());
    const proof = computeIssuanceProof(ISSUANCE_SECRET, request);
    const first = await authority.issue(request, proof);
    await authority.revokeGrant(first.grantId);

    // Replay of the observed pair: the pre-fix deterministic HMAC re-minted a
    // fresh grant that escaped G1's revocation without a new controller
    // decision.
    await expect(authority.issue(request, proof)).rejects.toMatchObject({
      name: 'ShunContractError',
      code: 'GRANT_NOT_AUTHENTIC',
    });
    expect(grants.snapshot()).toHaveLength(1);
    expect(grants.snapshot()[0]?.grantId).toBe(first.grantId);
  });

  it('an issuance proof presented after its validity window is refused (approval expired)', async () => {
    const { authority, grants, clock } = makeAuthority();
    const request = issueRequestFor(buildPlan());
    const proof = computeIssuanceProof(ISSUANCE_SECRET, request);
    clock.advanceMs(30 * 24 * 60 * 60 * 1000); // far beyond any proof validity window

    await expect(authority.issue(request, proof)).rejects.toMatchObject({
      name: 'ShunContractError',
      code: 'GRANT_NOT_AUTHENTIC',
    });
    expect(grants.snapshot()).toHaveLength(0);
  });

  it('the legacy bare request-HMAC proof shape is no longer a valid capability', async () => {
    const { authority, grants } = makeAuthority();
    const request = issueRequestFor(buildPlan());
    // Exactly what the pre-fix computeIssuanceProof minted: a reusable MAC
    // over the bare request, with no nonce, expiry or one-shot consumption.
    const bareHmac = createHmac('sha256', ISSUANCE_SECRET)
      .update(canonicalJson(request), 'utf8')
      .digest('base64');

    await expect(authority.issue(request, bareHmac)).rejects.toMatchObject({
      name: 'ShunContractError',
      code: 'GRANT_NOT_AUTHENTIC',
    });
    expect(grants.snapshot()).toHaveLength(0);
  });
});
