# Shun v0.2 — Product/L1 Evidence and ROI Adoption

> **Stage 1 candidate evidence, not a Release/implementation claim.** Input PR #81; review subject must be exact current PR HEAD after this artifact is written. Standard pinned in project: `kaicreator-mm/ai-development-standard@7929012f36a2202dcc2edc7a414b8163adc7afbd`, v4.9.0. User authorized product direction and asked for final PRD review/freeze on 2026-10-14; technical/reviewer gates remain applicable.

## 1. User/job and real problem

User is a non-developer on Windows Home or Pro and wants to describe an outcome, not choose a package, run a test harness or troubleshoot commands. Success means use of **real LLM** to interpret/request clarification, reliable read-only system diagnostics and a few safe bounded actions, **verified repeatable saved routines**, and simple user-facing UI/portable onboarding.

The v0.1 test/reference system established source-backed patterns and narrow executable proofs. It did NOT establish v0.2 local/remote LLM, arbitrary generated script confinement, startup mutation, universal Windows optimization, a native optional-module loader or first-run UX.

## 2. Existing evidence — directly adopted, exact source pin

| Source | Grounded assertion | Decision relevance | What it does NOT establish |
| --- | --- | --- | --- |
| [v0.1 L1](../product/L1-product-evidence.md) at [frozen tag](https://github.com/kaicreator-mm/shun-assistant/tree/v0.1.0) @ `2313ba2773dac7aa535570e22760147d9b383b65` | Purposefully stratified source records: user asks by goals/symptoms, system maintenance and software lifecycle matter; descriptive not population-representative | Windows steward, goal-first and minimal provider lifecycle rather than universal GUI | True population frequency, ranking of v0.2 tasks or measurable retention |
| [v0.1 PRD](https://github.com/kaicreator-mm/shun-assistant/blob/v0.1.0/docs/product/PRD-v0.1.md) and provider resolver | Capability/provider × environment hard gates and risk/authorization separation are already product foundations | Preserve v0.1 semantic and security model, reuse before introducing code | Shun users automatically trust any LLM script or arbitrary download |
| [B-037/B-038/B-039/B-040 v0.1 evidence](https://github.com/kaicreator-mm/shun-assistant/tree/v0.1.0) | Narrow real Windows image/sharp, JIT WinGet, bounded storage and support collector were exercised; regression and hidden release evidence exists at frozen v0.1 source | Reuse three verticals, trusted acquisition and journal safety | Generic module import/hotload, broad WinGet uninstall, full-disk optimization or user-grade UI |
| [Current v0.2 source gap](https://github.com/kaicreator-mm/shun-assistant/tree/v0.1.0/apps/control-api) | v0.1 actual local UI is storage-focused, image/JIT UI are not all real-backed; `PlannerPort` has deliberately strict LOCAL boundary | Real LLM+real UI wiring are release blockers, not cosmetic P1 | Model call or UI journey success without new implementation |

**Research selection:** `EXISTING_EVIDENCE_ADOPTED + TARGETED_PRODUCT_CHALLENGE`. No new broad online market study or model-generated ROI score invented. Targeted verification is needed for Windows startup changes and safe on-demand local code installation, but that is primarily **L2 Architecture/real-host** proof after Product Freeze; L1 prevents unstable implementation claims by narrowing P0.

## 3. Ranked product jobs (qualitative, not invented frequency)

| Rank | Job | Why first | Minimum user-visible outcome |
| --- | --- | --- | --- |
| 1 | Explain local PC state and current storage pressure | Default native APIs, low installation cost, read-only | Evidence-backed per-scope report without excessive data disclosure |
| 2 | Perform safe bounded space cleanup | Existing verified v0.1 vertical | Exact preview/permission and measured reclaimed bytes, protected files intact |
| 3 | Find and organize selected files | Repeatable deterministic operations with predictable verification | Dry-run diff and accurate post-state, reversible when feasible |
| 4 | Turn a repeated job into saved Recipe | User explicit product objective; reduce model latency/cost over repeated uses | First real LLM proposal; second matched replay with zero new LLM calls, fresh target consent |
| 5 | Use image/software vertical from one readable UI | Reuse core already built | Real vs demo status, actual verified results and issue recovery |
| 6 | Diagnose startup/background pressure | Useful user pain but unsafe to over-claim causal improvement | Read-only evidence; **startup writes P1 conditional** on exact host evidence |
| 7 | Fetch small, allowlisted optional tools only when needed | Avoids installer bloat; existing WinGet JIT partial precedent | Core-only offline diagnosis, first-use explicitly consented acquisition, verified cache and no trusted-origin bypass |

No numerical ROI ranking is claimed. A P0-only native report may be more useful than adding media/complex PDF providers before an actual LLM UX.

## 4. Falsification and unsafe alternatives

- “Automatically optimize Windows” can be marketing-only or actively harmful: memory/boot figures vary with time and background processes. **Counter:** only measured bounded cleanup is a mandatory P0 optimizing effect; P0 startup outputs are diagnostic, P1 modification gated by proved rollback and comparable evidence.
- “LLM-generated JS/TS script” can become arbitrary full-user-power JavaScript. **Counter:** only typed mediated `SystemCapability` actions execute; raw script execution requires independently proven OS isolation; no permission model/PowerShell ExecutionPolicy/AST scan by itself can grant authority.
- “Provider loads when necessary” can become arbitrary remote-code execution, ABI breakage, DLL hijack or untrusted dependencies. **Counter:** a trusted preapproved manifest, exact artifact hash/signature, consent, staged install, guarded invocation, journal/reconcile, cache currentness and idempotent removal. No generated URLs or unsigned manifest authority.
- “Local LLM with small core-only installer” can incorrectly promise model availability out of box. **Counter:** offline native tasks work immediately, model configuration explicitly allows user-provisioned local runtime/weights, remote inference only by opt-in; actual model tests are Version Closure-owned.
- Model generated recommendations may claim causal performance improvement without a measured before/after. **Counter:** separate `CONFIG_CHANGED_VERIFIED`, `BYTES_RECLAIMED_VERIFIED`, `PERF_IMPROVEMENT_UNPROVEN`.

## 5. Decisive Stage 1 acceptance decisions

| ID | Decision | User/product authority | Product Review sensitive? |
| --- | --- | --- | --- |
| PD-01 | Real local + remote LLM are required integrations; no fake-only LLM | explicit 2026-10-14 user decisions | YES privacy/auth/network |
| PD-02 | High-ROI Windows stewardship; P0 bounded cleanup + read-only startup analysis; higher-impact tuning deferred | user approved system optimization, narrowed for truthful safety | YES boundaries/claims |
| PD-03 | JS/TS dominant Recipe, model-free exact replay, scoped effect regrant | user requested repeated scripts | YES execution safety/currentness |
| PD-04 | Two implementation layers: Node+reviewed PowerShell/CIM and conditional Rust/napi-rs/windows-rs with scoped external FFI/performance | user explicit direction | YES native trust boundary |
| PD-05 | Lean core-only Windows delivery, optional signed allowlisted Provider payloads acquired lazily; reuse v0.1 JIT | user explicit direction | YES supply chain/code loading |
| PD-06 | UI should serve non-developer with real preview, choice, progress, Recipes, failures; no dev tooling | user explicit direction | YES consent usability |
| PD-07 | Defer app8 Provider Factory, arbitrary Windows tweaks, provider marketplace, unbounded scripts and unattended automation | user scope narrowing | YES negative acceptance |

**Release posture:** Must-pass real Windows installation/runtime + same-SHA/host privacy and script safety evidence, negative file/outcome canaries, guarded JIT activation, UI and repeat Recipe. Product Freeze alone does not claim any of these passed.

**Exact owner basis:** in-conversation user authorized these directions and requested final Product Review/Freeze. Reviewer evidence must remain independent per project override. The controller must bind an exact candidate SHA/tree and explicit owner act when a later Product Freeze is lawful.
