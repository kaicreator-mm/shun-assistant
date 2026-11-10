# shun-assistant — DKE Preparation R4 Reviewer Packet

> [devkit #5](https://github.com/kaicreator-mm/devkit/issues/5), 2026-11-11. **REVIEWABLE RESEARCH INPUT, NOT VERIFIED DOMAIN KNOWLEDGE, NOT OFFICIALLY ACCEPTED.** Research base pinned to `91420edca44009aa2c984c876104b40814a7c265`; corrected active version must be checked separately.

## G1 Project Intent / authoritative goal

- **User/product outcome:** Windows Goal→Capability/Provider→approval→Kernel permit→trusted Host effect→receipt.
- Product document `docs/product/PRODUCT_FREEZE-v0.3.md` is pinned to Git Blob `0f8a67c2f06364d58a842502d3dee11bfeeedba4` (see R3 global Product authority checks).
- The product goal and knowledge preparation are different from an active release or completed professional field test. Out-of-scope platform/general-expert claims remain explicitly excluded.

## G2 Complete Business System — bounded current delivery

- [R2 Business and Domain Preparation](PROJECT_BUSINESS_DOMAIN_PREPARATION_R2.md) describes actors, responsibilities, objects, states, primary positive and failure/recovery journeys, external dependencies and acceptance candidates.
- [R4 Business Evidence Matrix](BUSINESS_EVIDENCE_MATRIX_R4.json) pins 3 central source/test obligations with positive/negative cases, exact Product/source/test Blob identities.
- Key failure and recovery boundary: **Current PR #272 materially differs from R2 pinned source; actual Windows effect and per-user identity need real independent review**.
- **Not asserted:** every business path read, every test executed, every real environment effect proven.

## G3 Domain System / bounded contexts and owners

- The R2 report identifies business contexts, domain source authority, relation owners, knowledge vs implementation boundaries.
- The [devkit cross-product Domain Authority Map](https://github.com/kaicreator-mm/devkit/blob/docs/dke-14-preparation-r2-index/docs/portfolio/DKE_14_CROSS_PRODUCT_DOMAIN_MAP_R2.md) cross-checks overlapping semantics.
- A source provider, external professional truth, project business system and DIS runtime authority are distinct. Semantic edges may refer to another repository but do not equate to Element/Package execution edges.

## G4 Domain Knowledge Scope / independent falsification plan

- [R4 Claim/Relation/CQ Candidate Pack](DKE_HANDOFF_CANDIDATE_R4.json): 3 source-pinned candidates, 1 cross-Context relation/owner, 3 competence questions, paired positive/negative/UNKNOWN validation plans.
- Every Claim must carry context, source provenance/Blob, version applicability, counterexample, invalidation trigger and external Oracle requirement.
- Project policy or observed implementation is **not** automatically a transferable external industry/domain truth. External data permission and domain expertise remain NOT_REVIEWED.

## G5 Preparation-to-DKE input and limits

- **SC01** Research authority version pinned; see source inventory and any R3 Product/active version correction. 
- **SC02** [R2 full tracked Git path inventory](SOURCE_PATH_INVENTORY_R2.json) and [R3 source relevance shortlist](SOURCE_RELEVANCE_SHORTLIST_R3.json) are available; shortlist needs manual source relevance and external-license review, not falsely claimed exhaustive.
- **SC03** [R4 Product/DOC/CODE/TEST evidence matrix](BUSINESS_EVIDENCE_MATRIX_R4.json) has 3 concrete source anchors; test code is defined, not executed by this preparation audit.
- **SC04** Source-backed Claim, CQ and deliberate counterexample/UNKNOWN plan available. Independent external and DKE critic verdicts NOT_RUN.
- **SC05** Context owner, Global/recursive Element and scoped stale-change candidates ready as questions; [domain-forge #209](https://github.com/kaicreator-mm/domain-forge/issues/209) owns final evaluation/SAP, not this Issue.

## Requested PR Review / source acceptance decision

The project source reviewer must check against current Product and available domain facts, especially `shun-assistant` authority boundaries and negative paths: `Current PR #272 materially differs from R2 pinned source; actual Windows effect and per-user identity need real independent review`. Each reviewer verdict must be attached to exact commit and reviewed source spans, with decision **PASS_PREPARATION / REWORK / BLOCKED_WITH_OWNER_DISPOSITION**. Reject any false label such as `DOMAIN_TRUTH_PROVEN`, `TESTS_EXECUTED`, `SAP_QUALIFIED`, `REAL_EFFECT_VERIFIED` without independent receipts.

**State:** `PREPARATION_INPUT_DELIVERED`; `G1–G5_INDEPENDENT_REVIEW=NOT_RUN`; `EXTRACTION_READY_FORMAL=NO`; `SOURCE_LICENSE_OR_EXTERNAL_ORACLE=UNKNOWN_OR_PENDING`; `NO_PRODUCT_CODE_CHANGE`.