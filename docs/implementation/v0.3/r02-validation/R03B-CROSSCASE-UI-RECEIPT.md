# R03B receipt — cross-Case binding, real CN/EN UI loop, composite evidence

**Authority**: `OWNER_SHUN_V030_R03B_CROSSCASE_UI_COMPOSITE_APPROVE` ([#259]), extending the standing R03-INT authorization. Base SHA `6e9f880231d37032a2e351b0505daf67c8037605`. Factual execution record; not an R03 PASS and not a release approval.

## 1. Cross-Case binding (production enforcement, not a test-only property)

`packages/domain-host/src/windows/effect-host-binding.ts` now binds the effect authority to the **live K turn instance** before any Host dispatch: the instance key is parsed from the K-minted permit's `durableControlTurnId` (`turn:{workflow}:{instance}…`, the grammar the selected Kernel derives), and a plan/grant whose `taskId` belongs to any OTHER task/case refuses terminally (`CROSS_CASE_AUTHORITY_REFUSED`) with zero ActionController calls and zero effect. Malformed payloads/unparseable permits still fall through to the effect-host grammar (unchanged refusals).

Evidence: `j02-production-chain.test.ts` now mints every plan/grant with `taskId = caseId` (8/8 green, including the new negative "plan minted for ANOTHER task refuses with zero effect"); the composite suite carries the same negative.

## 2. Real CN/EN UI→API→K→Host user loop

The shipped v03 UI gains a Production-Journeys panel (`apps/control-ui/public/v03/`: index.html + app.js + strings.js + styles.css; 37 new string keys in strict en/zh parity with polarity markers; `stringsAudit` unchanged and passing):

- The UI stays a pure relay: the operator pastes the Host-issued reference pair (printed at the trusted boot console, never HTTP-minted); **caseId is read exclusively from the live guided state** (`currentStep.taskId`), never free-typed; empty references or a missing live case refuse locally with no request.
- Each panel maps the truthful receipt vocabulary: COMPLETED (with actionRef / provider stdout first line / candidateRef) vs REFUSED·KERNEL_REFUSED (with code) vs UNKNOWN/ADMITTED — never rendering a non-COMPLETED outcome as success.

`ui-journeys-loop.test.ts` (3/3, physical-gated) drives the **REAL shipped app.js/view-model/strings modules** (imported unmodified; the only substituted layer is a minimal DOM shim implementing exactly the DOM surface app.js uses — browser infrastructure, not a product double; the UI's fetch is the real global fetch with relative same-origin resolution against the live loopback origin) through **both locales**: each locale completes the effect family (real scoped write, canary bytes verified on disk), the provider family (real signed `ripgrep 14.1.1` execution surfaced through the UI status), and the meta family (real durable `FUTURE_BUILD_SHADOW` candidate) — UI → API → selected K → trusted Host, end to end.

## 3. Composite evidence (all families, one App, permits per family)

`journeys-composite.test.ts` (5/5, physical-gated): ONE selected DomainApp carrying goal + windows + provider + meta route families, with a REAL submit per family (scoped write; signed provider execution with version line in the HTTP receipt; durable Shadow candidate), the cross-Case negative, and **per-family K-minted permit evidence** asserted in the durable k-docs store (`effect-permit:turn:windows-journey:…`, `turn:shun-provider:…`, `turn:shun-meta:…`).

## Command / exit-code record (Windows Node v24.21.0)

```text
vitest ... j02-production (SHUN_R02V_PHYSICAL=1)         EXIT=0 (8/8)
vitest ... journeys-composite (SHUN_R02V_PHYSICAL=1)     EXIT=0 (5/5)
vitest ... ui-journeys-loop (SHUN_R02V_PHYSICAL=1)       EXIT=0 (3/3, en+zh)
vitest ... full r02-v default gates                      EXIT=0 (19 passed / 38 skipped)
vitest ... full r02-v physical gates                     EXIT=0 (51 passed / 6 skipped)
t10-ui authority suite (unchanged UI contracts)          35/35; control-ui package 20/20
```

## Non-waivers

No paid DeepSeek call; no merge/tag/release; no `main`/`version/v0.2.0` change. UNKNOWN is never PASS. The parallel-lane admission and write sets are recorded in `.agent/execution/R03-INT/MANIFEST.yaml` (R03B extension) under the #259 authorization events.

[#259]: https://github.com/kaicreator-mm/shun-assistant/issues/259
