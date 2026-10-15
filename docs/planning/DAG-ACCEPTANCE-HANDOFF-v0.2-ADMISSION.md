# Shun v0.2 — Scoped Task DAG Acceptance Handoff Admission

**Controller admission:** `T01_SOURCE_GATE=ADMITTED`. This record accepts
the *non-relaxing, reviewed* execution handoff from PR #129 / Issue #128,
without rewriting the frozen Product, L2 or DAG source.

## Exact reviewed authority

- Product successor: PR #96, record `46d35708688663943868b556c0b8b298f609488a`.
- L2 Freeze: PR #101, record `cf8bc227366ea8f07f9e853158f3e9e568691126`.
- Task DAG Freeze: PR #102, record `57658c628fa01d9cd12343d81c8311b286dd1ffb`.
- Frozen 11-node / 26-edge design: `31574f9767a4e8a8a5f413f02064d52de079f601`.
- Reviewed handoff candidate: `docs/planning/DAG-ACCEPTANCE-HANDOFF-v0.2-CANDIDATE.md` blob
  `f13c8e1bd7573df7186122ca1f9d001cb9497414`.
- Independent read-only security/architecture review: Issue #128 comment
  `6194564704` at PR #129 HEAD `dbf9ff785472cb304b2972eb3724af87ed948e61`,
  source tree `829c1142a1d849ceab5255820e25088193338a51`;
  `PASS P0=0 P1=0 P2=0`, `MERGE_ELIGIBLE=YES`.
- Merged reviewed candidate: PR #129 → version commit
  `4e19cb0c11572aa9bce3138249fc5a378f793d9b`.

## Admitted execution semantics

**T01** may be accepted for downstream Task DAG *source-readiness* after its
real adapter code, Proposal schema normalization handoff, privacy/issuer
verification port, atomic budget and exact HTTP-body verification have passed
CI **and required independent security review**. Fake broker tests do not
demonstrate a real authenticated human consent.

**T04** may begin only after this admitted T01 source gate and already
accepted T03. T04 must never mint grants or touch T01-owned planner-seam.

**T08** remains the sole implementation owner of the real authenticated
private-IPC user-gesture issuer; it cannot be treated as finished by a
public localhost API, test broker, simulated UI or unsigned approval.

**T10 and T11** retain all original **real** Chinese and English DeepSeek
end-to-end acceptance, actual issuer, privacy zero-send negatives,
durable cost accounting, supported Windows Home/Pro qualified journeys,
hidden/full regression, portable installation, recovery and Release
qualification. T01 source-ready alone is NOT end-to-end or Release PASS.

All other frozen P0 requirements, 11 DAG nodes, 26 dependency edges,
exclusive write sets, optional T02 posture and per-PR CI/review gates remain
unchanged. This scoped *controller sequencing clarification* is not
new Product Feature Scope or a waiver of security/Windows evidence.

## Explicit execution boundary

This document becomes operative only upon its own merge to
`version/v0.2.0` after CI checks; do not backdate authority or pretend an
independent reviewer signed the controller admission. Existing parent
Issue #104 cannot be closed until its own source-ready acceptance evidence
is recorded separately; Issue #128 may then close.

```ini
CHANGE=SCOPED_NONRELAXING_ACCEPTANCE_HANDOFF
REVIEWED_CANDIDATE_PR=#129
INDEPENDENT_REVIEW=#128_PASS_AT_EXACT_SHA
FROZEN_PRODUCT_L2_DAG_CHANGED=NO
TASK_COUNT=11
EDGE_COUNT=26
T01_SOURCE_READINESS=ADMITTED_ON_MERGE
T04_UNBLOCK=ONLY_AFTER_T01_SOURCE_GATE_PASS
T08_AUTHENTIC_CONSENT=MANDATORY
T10_CN_EN_LIVE=MANDATORY
T11_RELEASE_QUALIFICATION=MANDATORY
T02_LOCAL=DEFERRED
RELEASE_PASS=NO
```
