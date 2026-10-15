# Shun v0.2 — Task DAG acceptance handoff correction (candidate)

> **Status: CANDIDATE / INDEPENDENT_REVIEW_REQUIRED / NOT YET OPERATIVE**.
> Source: Issue #128. Additive execution-gate clarification of the reviewed and
> frozen authority; no destructive edit to the original frozen DAG bytes.

## 1. Authoritative inputs and unchanged contract

- Product re-freeze: PR #96 / Product record blob `46d35708688663943868b556c0b8b298f609488a`.
- L2 freeze: PR #101 / record blob `cf8bc227366ea8f07f9e853158f3e9e568691126`.
- Task DAG freeze: PR #102 / record blob `57658c628fa01d9cd12343d81c8311b286dd1ffb`.
- Frozen design blob `31574f9767a4e8a8a5f413f02064d52de079f601` is preserved unchanged.
- **Exactly 11 P0 tasks, 26 graph edges, all exclusive write-set owners and optional T02 posture are unchanged.** No new risk, release shortcut, simulated consent or LOCAL fallback is authorized.

## 2. Finding: acceptance cycle despite acyclic graph

The graph edges are `T01 -> T04 -> T07 -> T08` and T08 also
depends on T01. However, the older T01 criterion includes live authenticated
user consent and bilingual end-to-end DeepSeek calls, while the only real
private-IPC issuer is explicitly owned by **T08**. If live T08 broker proof
is interpreted as a *precondition for T01 source closure*, T04/T07/T08 cannot
begin under the frozen edge graph. Mocking a broker would hide the problem
and violate the privacy requirement.

## 3. Candidate execution gate mapping

| Gate | Earliest owner | Acceptance for this gate | What this gate explicitly does **not** prove |
| --- | --- | --- | --- |
| T01 source-ready | T01 (#104) | Source/CI/independent security review of actual DeepSeek HTTPS composer, closed-field approved disclosure, backend key isolation, trusted issuer **verification port**, fresh scope/currentness/nonce checks, durable call+worst-case budget reservations, zero-call privacy negatives, fixed redacted failures, PlannerPort normalized proposal integration | **Not** real user gesture issuer, UI or live full journey |
| T04 and T07 | Existing DAG edges after source-ready T01 and accepted T03 | Typed Recipe mediation/revalidation; scoped file effects with R2 preview, rollback and refusal | Not an actual consent UI or release verification |
| T08 | T08 (#110) | Authentic Shun-owned private IPC consent issuer, physical user confirmation, nonce binding, browser forbidden from minting authority, truthfully labeled remote model and bounded feedback | Not cross-component Release PASS |
| T10 | T10 (#112) | Genuine Chinese and English DeepSeek end-to-end goals through T08 issuer; schema→deterministic normalization→R2 decision; forged localhost user/nonce, changed actual body, concurrent maxCalls=1, UNKNOWN_COST, zero remote calls on forbidden/offline; provider and file cross-boundary proofs | Not portability/hidden release closure |
| T11 | T11 (#113) | Independent real Windows host acceptance, full regression/hidden, cost/accounting evidence, portable core and supported edition matrix, honest Release qualification | No inferred PASS from partial CI, mocked broker or earlier pilot |

**Gate transfer is not deletion.** All actual CN+EN and privacy tests remain
mandatory. Earlier T01 text stays historical evidence of product intent; T10/T11
are the integration owners for the *real* end-to-end acceptance. T01 must
still meet its **own** source/security acceptance and cannot be called full
live production qualified. A first-party broker **verifier port** with test
fakes is not a first-party real issuer.

## 4. Safe admission conditions

1. Preserve frozen DAG blob and dependency edges without reissuing old freezes.
2. Run **one bounded independent security/architecture review** on this exact
   additive handoff (Issue #128). It must verify that no original acceptance
   requirement is lost and no write-set ownership changes.
3. The authority owner admits the correction as a scoped successor on an exact
   reviewed SHA/blob. **Until then T01 hard closure / T04 dispatch remains
   controlled by the existing freeze; this file is NOT admission.**
4. Following admission, T01 source gate may close when its own independent
   source review and CI pass; T08/T10/T11 remain open until real host/issuer
   evidence, never waived.

```ini
CANDIDATE_KIND=NON_RELAXING_DAG_EXECUTION_HANDOFF
FROZEN_DAG_BLOB=31574f9767a4e8a8a5f413f02064d52de079f601
P0_TASKS=11
P0_EDGES=26
T02_LOCAL=DEFERRED
T01_SOURCE_GATE=PROPOSED
T08_PRIVATE_BROKER=MANDATORY
T10_BILINGUAL_REAL_E2E=MANDATORY
T11_RELEASE_PROOF=MANDATORY
INDEPENDENT_REVIEW=PENDING
OWNER_ADMISSION=PENDING
SUCCESSOR_EFFECTIVE=NO
```
