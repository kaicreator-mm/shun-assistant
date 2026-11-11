# Shun Assistant v0.2 — Revised Product Freeze (DeepSeek Flash API-first)

> **PRODUCT_RE_FREEZE=PASS — scoped successor only.** The Product Owner directly authorized replacing required LOCAL model inference with default DeepSeek API Flash on 2026-10-14. This authority terminal is recorded **only after independent exact-SHA Product review #92 PASS**. The old PRD remains immutable; this successor is authoritative for **only** the LLM strategy/acceptance changes set out below. No L2/implementation/Release PASS is implied.

## 1. Authority identity and exact verification

| Item | Frozen identity |
| --- | --- |
| Repository/version | `kaicreator-mm/shun-assistant` / `v0.2.0` |
| Product Owner decision | Direct user instruction 2026-10-14: existing DeepSeek API key; `deepseek-flash`; do **not** mandate Ollama/local model on end-user devices |
| Historical Product Freeze | `docs/product/PRODUCT-FREEZE-v0.2.md`, candidate commit `79f47be5ff08a54588790e8abdacffd8697ac4d8` tree `10c0ad768fee849ada952b038b0b1a653fd9a6d7` |
| Historical PRD blob (immutable) | `docs/product/PRD-v0.2.md@68cf2fcec919dedd9ce61339b81f60855404fb12` |
| Scoped successor source | `docs/product/PRODUCT-SCOPE-CHANGE-v0.2-DEEPSEEK-FIRST.md`, PR #91 reviewed source commit `6259852416fa88da63910577d788ccc9f5e8d0cc`, blob `1ee97babb0a1308525842a24f7585c775ee91687` |
| Independent adversarial review | [#92](https://github.com/kaicreator-mm/shun-assistant/issues/92) comment `6167747780`; `PASS`, `P0=0 P1=0 P2=3`, `PRODUCT_RE_FREEZE_ELIGIBLE=YES` at **exact** successor source/blobs |
| Successor metadata chain | Candidate PR #91 squash merged; L2/DAG propagation PRs #93/#94/#95 were **conditional draft**, not independent product review or Product Freeze |
| Freeze authorization | Existing direct Product Owner change decision + separate independent #92 PASS; this file is the explicit Product authority terminal, **not a claim the reviewer/CI exercised Product Owner authority** |

## 2. Effective normative precedence (bounded)

1. **This freeze record** authorizes `docs/product/PRODUCT-SCOPE-CHANGE-v0.2-DEEPSEEK-FIRST.md` as the **v0.2 LLM strategy and acceptance successor**: **P0 DeepSeek cloud/API `deepseek-flash`**, key from `DEEPSEEK_API_KEY` inside trusted backend, separate disclosure consent, limited disclosure/cost, strict **zero API call** on LOCAL_ONLY/offline/forbidden disclosure/stale authority/no consent/missing key/exceeded budget. Actual API response is **untrusted proposal only**.
2. **No P0 LOCAL model runtime, model weights, AppContainer model execution or two genuine offline-local inferences.** Optional local remains explicitly **UNAVAILABLE until independently proven**, with `LOCAL_ONLY` failing closed instead of silently routing to DeepSeek. Keep bounded #85 research source as optional evidence only; its technical LOCAL verdict remains BLOCKED, not retroactively PASS.
3. **Everything else** in historical PRD and v0.1 security contracts remains **normative and unchanged**: Windows native read-only observations/single reversible optimization, user-file scope/R2 approval/reconciliation, immutable hash-bound Recipe/verified zero-model replay, signed curated on-demand Provider, real bilingual UI, safe portable packaging, independent tests/Release Qualification. No general raw LLM-authored shell or weak credential handling.
4. Conditional architecture candidates `docs/architecture/L2-v0.2-CANDIDATE.md` and `docs/architecture/L2-v0.2-CONTRACT-DECISIONS.md` must now be independently reviewed **at their subsequent exact freeze revision**. Draft `docs/planning/task-dag-v0.2-DRAFT.md` has **11 mandatory P0 nodes** (T00,T01,T03–T11) and **T02 optional/deferred**. **Neither L2 nor DAG is frozen by this act.**
5. Avoid re-opening the historical 188-line PRD or claim #84 reviewed changed scope. Later material Product changes require their own scoped review/authority.

## 3. Carry forward independent #92 P2 findings (nonblocking)

- **P2-01 bilingual proof:** `one real DeepSeek call` is the **minimum endpoint reality check**, **not** the whole bilingual journey test. T01/T10/T11 must separately exercise real **Chinese and English** goal→typed proposal→deterministic validation/approval journeys, plus forbidden zero-call cases.
- **P2-02 reuse precision:** Existing source `packages/resolver/src/planner-seam.ts` provides a policy/proposal **PlannerPort seam** only; the DeepSeek **HTTP adapter remains to be implemented** in T01 and requires actual live API proof and privacy/security testing. Do not call a hypothetical existing adapter shipped.
- **P2-03 revision honesty:** DeepSeek response `model`, optional `system_fingerprint`, request endpoint, local receipt time, usage, response/request ID where available are observed evidence; no API-published immutable underlying weight/build SHA is guaranteed for floating `deepseek-flash`. **Do not invent or claim a frozen model binary revision.**

These P2s are **specific T01/T10/T11 implementation tests/requirements**, not excuses for extra L1 exploration or #85 Ollama installation.

## 4. Gate terminal and handoff

```ini
PRODUCT_RE_FREEZE=PASS
SCOPE=ONLY_LLM_STRATEGY_P0_AND_LOCAL_OPTIONAL_ACCEPTANCE
OLD_PRODUCT_FROZEN_SHA=79f47be5ff08a54588790e8abdacffd8697ac4d8
OLD_PRD_BLOB=68cf2fcec919dedd9ce61339b81f60855404fb12
SCOPED_SUCCESSOR_SOURCE_SHA=6259852416fa88da63910577d788ccc9f5e8d0cc
SCOPED_SUCCESSOR_BLOB=1ee97babb0a1308525842a24f7585c775ee91687
INDEPENDENT_PRODUCT_REVIEW=#92_PASS_P0_0_P1_0_P2_3
DEEPSEEK_P0=REQUIRED_NOT_YET_IMPLEMENTED
LOCAL_MODEL_P0=NOT_REQUIRED
LOCAL_TECHNICAL_INFERENCE=BLOCKED_OPTIONAL_NOT_SHIPPED
L2_FREEZE=NO
TASK_DAG_FREEZE=NO
IMPLEMENTATION_COMPLETE=0
RELEASE_QUALIFICATION=NO
```

**Next:** record #92 as terminal and #85 as completed bounded optional research without technical LOCAL PASS; review exact successor L2 security architecture (separate independent reviewer), then explicit L2 Freeze → DAG Freeze/11 GitHub implementation Issues → dependency-directed one-concern PRs → Windows/DeepSeek actual integrations and full release validation. CI PASS for this docs-only record cannot substitute for any downstream gate.
