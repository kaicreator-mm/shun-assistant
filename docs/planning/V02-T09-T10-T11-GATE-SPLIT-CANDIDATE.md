# v0.2 T09 → T10 / T11 acceptance gate split — proposed amendment

> **Status: CANDIDATE / NOT EFFECTIVE.** This document is a one-file review subject for [Issue #205](https://github.com/kaicreator-mm/shun-assistant/issues/205). It is **not** permission to close T09, dispatch T10 implementation, qualify T11 or merge `main`. No Product/L2 scope waiver is claimed. Effective only after independent exact-SHA review, controller acceptance and version-line merge.

## Frozen authority

- Product scoped refreeze PR #96, blob `46d35708688663943868b556c0b8b298f609488a`.
- L2 freeze PR #101, blob `cf8bc227366ea8f07f9e853158f3e9e568691126`; reviewed L2 candidate `f23a6c44374ab49d84e608693d7793d294c88258`.
- Task DAG freeze blob `57658c628fa01d9cd12343d81c8311b286dd1ffb`; operative reviewed draft blob `31574f9767a4e8a8a5f413f02064d52de079f601`. T09→T10→T11 ordering remains; only the location of physical release-matrix evidence is proposed for explicit review.
- Implementation baseline: `version/v0.2.0@18cae14293d4c488ff7a641a77b426bbfbd82148`. The branch is version-only; `main` is HOLD.

## Observed baseline (never convert UNKNOWN to PASS)

| Evidence | Current acceptance |
| --- | --- |
| T09 P01 manifest PR #202 / P02 portable PR #203 / P03 lifecycle PR #204 | Independently PASS; merged into version branch |
| Node24 Windows P03 lifecycle tests | 6/6 PASS, EXIT 0; dual CI SUCCESS |
| Windows 11 Pro signed install/upgrade/uninstall, state canaries, unsigned/tampered/refused, UNC and fixed-disk SQLite WAL | Physically PASS in non-elevated filtered-admin session, [#111 receipts](https://github.com/kaicreator-mm/shun-assistant/issues/111#issuecomment-6466004886) |
| Installed portable Core real-storage bounded Recipe | 14/14 PASS, model calls 0 on same Pro host |
| Account group/privilege classification | Owner **WAIVED verification**, not a PASS; operator-run 30 PASS / 1 identity FAIL, literal EXIT 1 is preserved, [#111](https://github.com/kaicreator-mm/shun-assistant/issues/111#issuecomment-6467786655) |
| Windows 11 Home physical compatibility | **UNKNOWN**, no Home host |
| OS-authenticated trusted distribution entrypoint / publisher identity | **UNSATISFIED**, P01 Ed25519 signed *payload* is not code-signing provenance |

## Proposed acceptance split, subject to independent review

1. **T09 source and Windows build acceptance:** Require exact reviewed+merged portable P01/P02/P03, signed payload, offline/no user pnpm, Pro representative physical lifecycle, user-owned state preservation and local-fixed-disk SQLite WAL. Existing proofs satisfy those specific checks. Record account privilege verification as explicitly owner-waived, not executed-pass. Windows Home remains UNKNOWN, and full supported-edition **release** qualification must remain outstanding. **T09 closure under this amended criterion is a separate controller action only after independent approval; no automatic close.**
2. **T10 integration source readiness:** After independently accepted T09 source evidence, allow integration implementation only in `tests/integration/v02/**`. All real DeepSeek Chinese+English positive journeys, forged localhost consent and GoalRequest zero-send, `maxCalls=1` atomic concurrency, exact payload drift denial, UNKNOWN_COST non-refund, all outward path redaction, generated source/graph tamper refusal, signed Provider reuse/offline, and immutable zero-LLM Recipe replay remain mandatory. No T10 completion without its own exact-SHA review/CI and real required evidence.
3. **T11 supported Windows edition *release matrix*:** Retain **hard no-release** for missing Windows 11 Home x64 physical qualification. Verify actual Home and Pro native critical journeys, not merely an artifact compiled on a Windows hosted runner. Reuse accepted T09 Pro evidence and perform only edition-specific missing checks. If no Home host, `RELEASE_READY=NO`.
4. **T11 distribution trust / publisher gate:** Windows OS-trusted launcher/installer identity (where required for approved distribution), verified issuer/provenance and secure bootstrapping of the manifest verifier are **release channel obligations**. A signed Ed25519 manifest is valuable but does not make an unsigned `.cmd` or `.mjs` entrypoint trusted. Prefer mature Windows SDK SignTool/OS distribution and operator-controlled publisher identity; do not create a bespoke code-signing system. No publisher identity → `PUBLISHABLE_DISTRIBUTION=NO`.
5. **No silent scope changes:** Windows Home support remains a frozen product requirement; account-privilege verification is the *only* owner-waived check. This proposal reallocates when supported-edition proof blocks work. Should the independent reviewer find T09 Home/Pro acceptance is itself an indivisible frozen L1/L2 promise, return **BLOCK** and require a separate authorized scope amendment rather than treating this file as authority.
6. **Merge and review discipline:** Before this becomes effective, reviewer must anchor exact PR SHA/tree, read both frozen DAG blobs and the live #111/#112/#113 issue-level contracts, and record P0/P1/P2, `PASS/BLOCK`, `DAG_GATE_REALLOCATION_READY`, and the exact conditions that unlock T10. Even if approved, never merge into `main` without T11 independent RQ.

## Explicit failure containment

No new Windows account, account-token check, model installation, encrypted signature scheme, build architecture or speculative filesystem hardening is added here. No full regression/Hidden run is shifted into T10; that stays T11. A Home test failure is a genuine blocker for v0.2 release and must be routed back to its owning implementation concern with exact evidence, not hidden or globally waived.
