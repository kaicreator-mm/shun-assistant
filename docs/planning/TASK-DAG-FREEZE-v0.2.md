# Shun Assistant v0.2 — Frozen P0 Implementation Task DAG

> **TASK_DAG_FREEZE=PASS** (explicit controller terminal). This authorizes materializing the **11 mandatory Issue-level tasks** below **after this record is merged and CI PASS**. It is not implementation, actual Windows validation or Release PASS. 2026-10-14.

## 1. Normative pins and scope

- Version target: `kaicreator-mm/shun-assistant@version/v0.2.0`.
- Product scope: DeepSeek Flash API-first Product re-freeze #96 (`PRODUCT-REFREEZE-v0.2-DEEPSEEK-FIRST.md` blob `46d35708688663943868b556c0b8b298f609488a`); historical v0.2 PRD unchanged.
- **L2 Freeze:** PR #101, baseline `version/v0.2.0@c2f520fc28c83379ef38eb5b09a72e7e1414bbbb`, freeze record `docs/architecture/L2-FREEZE-v0.2-DEEPSEEK-FIRST.md` blob `cf8bc227366ea8f07f9e853158f3e9e568691126`. Reviewed L2 candidate blob `f23a6c44374ab49d84e608693d7793d294c88258`; contract blob `c286e48441089ddafd9b6aecaae86ad667a5ba8b`. Independent #98 R2 exact-source PASS and all 2×P1/2×P2 CLOSED.
- **Normative frozen DAG bytes:** `docs/planning/task-dag-v0.2-DRAFT.md` blob `31574f9767a4e8a8a5f413f02064d52de079f601`, reviewed #98 R2 source PR #100 HEAD `c33357bef6b22cb13ccd8692c05cd64f4c8cf635`, tree `8ae5c4e1b8be97af3e837b9b9a6b6a4f7103cd65`. The historical `DRAFT` filename and `NOT FROZEN` header describe its pre-freeze snapshot; **this separate terminal** declares the exact reviewed bytes operative without mutating them.

## 2. Mandatory dependency DAG and primary write-set ownership

| Task | Dependencies | Primary write-set (exclusive except sequential integration) |
| --- | --- | --- |
| **T00** | L2 Freeze | `packages/contracts/**` |
| **T01** | T00 | `packages/llm-remote/**`, `packages/resolver/src/planner-seam.ts` |
| **T03** | T00 | `packages/store/**`, `packages/workflow/src/recipe-seam.ts` |
| **T04** | T00,T01,T03 | new `packages/resolver/src/recipe-resolver.ts` and recipe-only subpaths, `packages/recipe-runtime/**`; must not edit T01 planner-seam |
| **T05** | T00 | `packages/vertical-jit/**`, `packages/provider-loader/**` |
| **T06** | T00 | `packages/vertical-system/**` |
| **T07** | T00,T04 | `packages/vertical-files/**` |
| **T08** | T01,T03,T04,T05,T06,T07 | `apps/control-api/**`, `apps/control-ui/**` |
| **T09** | T08 | `packaging/**`, `scripts/package-v02/**` |
| **T10** | T00,T01,T03,T04,T05,T06,T07,T08,T09 | `tests/integration/v02/**` |
| **T11** | T10 | `docs/implementation/v0.2/**`, `tests/closure/v02/**` |

**Exactly 11 P0 tasks** and **26 dependency edges**, no missing nodes/cycles confirmed by independent #98 R2. **T02 is NOT dispatchable**: old LOCAL/Ollama research #85 remains optional and technically unproven; no LOCAL runtime download, model installation or fake LOCAL inference PASS. A historical candidate sentence referencing `T02`'s *future own qualification* has no present v0.2 P0 force. All existing #85/#86/#87 host research is adopted only within its actual evidentiary limits.

No concurrent edit to `packages/resolver/src/index.ts`: choose safe subpath exports, otherwise reserve it for one sequential integrator after T01/T04. No downstream task mutates T00 schema except through a new formally reviewed contract successor. If DAG node write ownership changes, HIGH_ASSURANCE/architecture change gate applies. Split overly large implementation concern into bounded Contract → Core → Integration subissues only where actual risk/review/write-set requires, and preserve parent DAG.

## 3. Dispatch and acceptance rules

- Every implementation Issue cites exact Product + L2 + DAG freeze identity, direct predecessor Issue/PR, and one **concern / PR**.
- T00 begins immediately. **After T00's reviewed merge** dispatch T01, T03, T05, T06 **in parallel** (disjoint owners); then T04, T07; then T08, T09, T10, T11. Issue creation does not equate to dispatch/merge authorization before predecessors pass.
- Tests are authored with implementation: schema/positive/negative, concurrent consent maxCalls=1, forged localhost issuer, no egress for forbidden/expired/stale/privacy mismatch, exact outbound bytes digest, UNKNOWN_COST no blind refund, redaction in thrown+nonthrow responses; immutable Recipe zero-model replay; signed Provider JIT, actual scoped Windows, UI CN+EN and real DeepSeek goal journeys; portable Standard User / Windows Home+Pro critical paths.
- Required reviews on security/privacy/mutation/supply chain, CI gates before merge; collect exact commit SHA + environment and honest risk residuals. Native Build Host/Windows prompts ONLY for genuine local verification and packaging where GitHub CI can't prove supported environment; no new Ollama/local-model pilot.
- Can close an Issue only after all its scoped contract/implementation+CI+required review accepted; **PR PASS ≠ Release PASS**. Final T11 requires full regression, hidden/negative journeys, recovery, packaging and independent Release Qualification.

## 4. Frozen terminal

```ini
PRODUCT_RE_FREEZE=PASS_PR96
L2_ARCHITECTURE_FREEZE=PASS_PR101
L2_FREEZE_RECORD_BLOB=cf8bc227366ea8f07f9e853158f3e9e568691126
TASK_DAG_FREEZE=PASS
FROZEN_DAG_BLOB=31574f9767a4e8a8a5f413f02064d52de079f601
P0_TASKS=11
P0_EDGES=26
DEFERRED_OPTIONAL=T02_LOCAL
IMPLEMENTATION_ISSUES=TO_BE_MATERIALIZED_AFTER_RECORD_MERGE
IMPLEMENTATION_COMPLETE=0_OF_11
RELEASE_QUALIFICATION=NO
```
