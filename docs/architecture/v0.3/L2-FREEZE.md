# Shun Assistant v0.3 — L2 Architecture Freeze (Owner-authorized)

**State:** `L2_FROZEN_EXACT_SOURCE` / `PRODUCT_FROZEN`. **Task DAG/Scaffold remain NOT frozen**. This is an authority/evidence checkpoint, not new L2 design. It changes no Product/L2 code or reviewed L2 document content.

## Frozen subject and authority

| Gate | Exact evidence |
|---|---|
| Product Owner Freeze | [#214 Owner approval](https://github.com/kaicreator-mm/shun-assistant/issues/214#issuecomment-6477255283); Product version checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95` |
| L2 independently reviewed PR | [#219](https://github.com/kaicreator-mm/shun-assistant/pull/219), reviewed HEAD `ce6846021056ef5f89f8009ceeccec58c359d745`, five docs only |
| Frozen L2 content | `docs/architecture/v0.3/L2-DOMAIN-HARNESS-R0.md` Git **blob** `8c555aff66d3006a1dbd4fb523e350f70c5db490` (unchanged) |
| Independent L2 R2 | [#217 R2 exact-source PASS](https://github.com/kaicreator-mm/shun-assistant/issues/217#issuecomment-6478302812); `P0/P1/P2=0/0/2`, `L2_FREEZE_READY=YES`; previous R1 BLOCK was remedied |
| Architecture Owner decision | [#217 exact-SHA Owner authorization](https://github.com/kaicreator-mm/shun-assistant/issues/217#issuecomment-6478493811): **explicit user approval** of only this L2 blob/HEAD, retaining both P2 |
| Source integration | [PR #219](https://github.com/kaicreator-mm/shun-assistant/pull/219) into **`version/v0.3.0` only**, GitHub merge `7a4d498d166eb3dc4dc0b9a23c5b53e7fad6e704`; parents `c8334c7723eecf7fbbb6895b1defd6439edc6b95` and `ce6846021056ef5f89f8009ceeccec58c359d745`. Exact reviewed L2 blob preserved in actual version readback. |
| Source SDK | DomainHarness v0.10.3 **CONDITIONAL Git-only** release tag `061376f4a023070f215f9feffad5c24d96d503cb`, tree `099cdc831aef63befd62aaede7e7a853d1be468f`; no public npm v0.10.3. |

## Frozen architecture decisions

1. One selected DomainHarness Kernel K owns **migrated** Case/effect orchestration, Permit, Journal and UNKNOWN. Preserve ShunStore business records and `apply(effectId)` idempotent transaction receipts; old `WorkflowEffectJournal` must not dispatch the same migrated Case/effect.
2. Actual physical Windows effect requires **both** current K-issued authority and independent fresh Shun `ActionController.authorizeEffect` Host grant/policy/OS-currentness. Untrusted model, UI, StepOutcome and raw messages cannot mint either.
3. DeepSeek through selected `llm.openai.generate` C and static trusted `domain-harness-openai-host.generate`, bound to Shun original `TrustedCloudInterpreter` / one `TrustedDeepSeekTransport.invoke` network sender. Same canonical body Buffer is used for signed consent/ledger reservation, final `MAY_HAVE_SENT` and `fetch`; preserve `thinking:disabled`, financial `UNKNOWN_COST`, K UNKNOWN fence. No parallel SDK OpenAI reserialization path.
4. Actual remote goal proposal is **untrusted data**. Strict one-goal neutral DTO; private approved scope cannot be widened by model/provider. Preserve B-040 local-only/zero external disclosure, actual CN/EN operator approval/UI parity, bounded Guided forms, Meta feedback as candidate/Shadow with separately authorized future BUILD promotion.
5. DomainHarness v0.10.3 published [#1437 raw-send/poisoned Case limitation](https://github.com/kaicreator-mm/domain-harness/issues/1437) remains open: T09 Control API source gateway validates untrusted Case/goal/currentness **before calling public `DomainApp.send`**. T11 exposes only trusted route; V01 validates denied malformed→valid same-Case with zero send and zero Effect Journal for initial denial. Do not claim generic poisoned-Case recovery.

## Retained R2 P2 — binding downstream hard acceptance (not waived)

- **P2-01**: T04/T11 zero-paid real selected C/Host bridge with exact per-call neutral request ceiling/deadline, single sender, complete status/refusal/UNKNOWN mapping and signed consent/budget replay/duplicate negative tests.
- **P2-02**: T09/T11/V01 pre-send source/Case gateway rejects malformed/forged/stale untrusted input with **zero** public facade sends and K Effect Journal rows, then allows a valid follow-up for the **same stable Case** under real selected packed SDK without bypass; raw facade and already-poisoned recovery remain unqualified.

Existing CI of source planning docs is not implementation E2E. Shun-specific Node>=24 packed Git-tag SDK consumer, actual Windows Host and any real model invocation **NOT_RUN**.

## Strict stage limits

- **`L2_FREEZE=YES`**: only the above exact L2 blob is frozen. Changes require new owner/source-bound amendment and independent review.
- **`DAG_FREEZE=NO`**, **`SCAFFOLD_FREEZE=NO`**: `TASK-DAG-v0.3-R0.md`, `TASK-PACKS-R0.json`, `SCAFFOLD-LAYOUT.md` and handoff integrated with PR #219 are proposals only. DAG R1/Owner Freeze separate; native GitHub Task Issues, `blocked_by` edges and accepted CAS Builder Claims do not exist.
- **`ADS_V418_PROJECT_ADOPTION=NO`**: current effective version-branch `.dev-standard/VERSION` remains `4.13.1@f35fcdb153ff171aaa0027b6e1b9c7592f28d3cd`, independent #216 adoption PR/review/currentness required.
- **`SOURCE_IMPLEMENTATION=NOT_AUTHORIZED`**: no actual three-package scaffold, protected source code, paid LLM/Windows effect, main or v0.2 modification or release authorized by this freeze.

```ini
PRODUCT_FREEZE=YES
ARCHITECTURE_OWNER_FREEZE=YES_EXACT_SOURCE
L2_FROZEN_BLOB=8c555aff66d3006a1dbd4fb523e350f70c5db490
INDEPENDENT_R2=PASS_P0_0_P1_0_P2_2
VERSION_L2_INTEGRATION=7a4d498d166eb3dc4dc0b9a23c5b53e7fad6e704
DAG_FREEZE=NO
SCAFFOLD_SOURCE=NOT_CREATED
ADS_V418_EFFECTIVE=NO
NATIVE_TASK_ISSUES=0
NATIVE_BLOCKED_BY=0
BUILDER_CLAIMS=NONE
```
