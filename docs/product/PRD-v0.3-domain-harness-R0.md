# Shun Assistant v0.3 — DomainHarness Domain App 重构（Product R0 / REVIEW CANDIDATE）

> **STATUS: PRODUCT_R0_DRAFT / NOT_FROZEN / NO_IMPLEMENTATION_AUTHORITY**  
> Controller: [#214](https://github.com/kaicreator-mm/shun-assistant/issues/214)  
> Standard planning authority: ADS v4.18.0 **qualified main source** `2c395c55569fe2edf3f4135f12d3d069e526d0b7` (not v4.19 intake).  
> Shun **planning-only** snapshot: `version/v0.2.0@f01233a002f65b9bfea04828f6e56914666a160a`. v0.2 is not a qualified v0.3 final baseline; #112/#113/#212 remain independent v0.2 delivery gates.  
> DomainHarness v0.10.3 Product / data Contract / L2 **have passed independent review and are frozen**: selected design baseline `version/v0.10.3@7d571858bd6524ffd13a7985227183dbecb2924a` (moving branch, snapshot not final package identity). **Contract choice is confirmed for v0.3 development**; final SDK implementation/package hash, installed-consumer verification, and Release/RQ remain pending. No v0.10.2 fallback or speculative ABI redesign.  
> Related L1: [L1 parity and risk inventory](./L1-v0.3-domain-harness-parity-R0.md).  
> This draft is a Product decision request, not L2 Freeze, Task DAG, code permission, approval grant, Windows evidence, or release.

## 1. User problem / product outcome

Shun remains a **Windows-first AI computer assistant**: the user describes a goal, the assistant resolves bounded, registered capabilities, shows truthful scope/cost/risk, obtains any required independent human approval, performs a permitted real action and verifies the observable outcome. Deterministic actions and verified Recipes must function without cloud inference when the local journey permits.

v0.2 achieved substantive Windows, authorization, privacy, provider and Recipe components but maintains its own execution orchestration, durable effect tracking and domain integrations. v0.3 proposes **consolidating reusable orchestration under DomainHarness Package-first** while retaining Shun's real Windows host implementation and product-level trust boundary.

**Definition of success:** existing supported v0.2 business journeys demonstrably remain operational on the **actual selected public DomainHarness SDK path**, with less duplicated orchestration state, truthful recovery, and no new automatic privileges. No numerical ROI is claimed before measured evidence.

### Explicitly not in this refactor
- Autonomous general desktop interaction, generic agent browser/operator, arbitrary LLM-generated shell/PowerShell/CMD/JS/Python execution, unknown Provider marketplace.
- Replacing mature Windows native execution, private consent broker, grant currentness or JIT signature checks with a mock/LLM assertion.
- Adopting unqualified DomainHarness private `src/` imports, pinning a pending SDK as production-ready, new Kernel/Host CAS engines or separate Meta database.
- Retrofitting v0.2 release requirements with v0.3 implementation status, or broadening #212 to generated arbitrary effects.
- Unattended scheduling or expanding into unrelated PC management features to make a rewrite worthwhile.

## 2. Scope and compatibility contract

**P0 parity** (a feature is accepted only at its real supported v0.2 scope; if v0.2 acceptance remains incomplete, carry an explicit GAP/UNKNOWN until proved on the final v0.3 source):

1. **Goal / semantic normalization.** Reuse strict GoalRequest, GoalProposal, registry-selected capability and environment facts. Remote output is always untrusted proposal data; unsupported target/path/privacy/command/authority is rejected or clarified.
2. **User-facing diagnostics and local support context (frozen B-040).** Retain genuine native Windows system inventory, scope-bounded folder diagnosis and the existing `packages/vertical-support/**` `collectWindowsSupportContext` → `minimizeSupportContext` path. Preserve report schema `shun.support-context.v1`, `localOnly:true`, `externalDisclosures:[]`, and deterministic minimization of environment/process names/command lines, unrelated document content, secrets and absolute paths. No network, LLM, Meta feedback, external error report or SDK issue upload receives these local-only reports automatically; any separately authorized support-sharing flow requires an independently scoped consent, explicit redaction and distinct source data, not silent B-040 reclassification. Offline read-only functions must not require model access.
3. **Scoped effects.** Selected-folder preview/manifest → separate R2 human plan approval → exact-scope Windows effect → independently checked poststate and protected canaries; policy drift, aliases, moved targets, UAC refusal, insufficient rights and stale grants fail closed.
4. **Reproducible Recipes.** Immutable source+graph+parameter identity and revalidation; user-selected deterministic replay generates zero LLM requests; no unbounded script execution.
5. **DeepSeek/LLM integration.** Host-configured OpenAI-compatible DeepSeek with independently authenticated user disclosure/cost consent; at-most-once-send reservations, no blind retry/refund for `MAY_HAVE_SENT/UNKNOWN_COST`; CN/EN real provider and privacy zero-call evidence at the release gate.
6. **Provider lifecycle.** Curated, signed/pinned, JIT acquired Provider artifacts; trusted deployment and native ABI binding; no user file reclassified as Provider-owned, safe offline reuse and uninstall.
7. **Lifecycle & recovery.** SQLite WAL local fixed disk, authoritative state/recovery history, idempotence and UNC/mapped-path limitations stated honestly; no duplicated physical effects across restart, concurrent requests or replay.
8. **User packaging and bilingual UI.** The v0.2 selected Windows Home/Pro x64, ordinary-user constraints, trusted release origin and native portable requirements remain inherited obligations. Preserve actual nondeveloper **Chinese and English** Control UI journeys for selected-root input, user-understandable independent approvals, scope/risk, truthful progress/history and refusal/UNKNOWN explanations; not merely CN/EN model responses. Source and mocks are not real Windows acceptance substitutes.

9. **Guided user interaction (v0.10.3 contract adoption).** Reuse approved `StepTemplate`, `FormSchema`, `ChoiceCatalog`, `StepSpec`, `StepOutcome` and bounded advisory for missing path/scope, clarification, privacy disclosure and explicit plan confirmation. Offline and zero-model paths must work. Shun UI renders the selected step; Host supplies current facts; template/catalog choices are fixed and versioned. Dynamic step selection **does not create approval, grant or K Permit**. Scope this to one meaningful Windows critical journey, not a generic auto-generated UI platform.
10. **Feedback and experience reuse.** Reuse selected DomainHarness `meta-feedback`/candidate-validation and public Host `runMetaFeedbackWorkflow` to capture user feedback plus verified task outcomes (with redaction and opt-in). Create bounded candidate → independent validation → shadow evidence → explicit operator acceptance → future immutable BUILD; no automatic self-improving production permissions, unapproved telemetry, or raw user data in feedback. Keep `task-meta` optional for execution metadata, not an invented hard product dependency.

**P1 beyond minimum reuse:** improve more advanced UI/Recipe authoring and additional guided journeys after completing the first real integrated user loop. Do not build a new form renderer/meta-learning engine merely because an SDK example exists.

## 3. Domain App direction and owner boundaries (L2 design inputs, not pre-approved source contract)

Proposed composition: external selected DomainHarness BUILD → one selected K/Microkernel → S (semantic) + B (Shun task workflows/registered computer abilities) + C (declared Tool operations) → trusted Shun Windows/LLM/Provider Host.

- **K**: one authoritative durable effect Permit, operation Journal, replay and UNKNOWN for migrated workflows. Existing ShunStore data survives via explicit migration/read-only compatibility policy; no two simultaneously writable authorities for the same effect identity.
- **S**: parse/normalize user intent and semantic context; never infer authority from LLM recommendation.
- **B**: typed system-diagnosis, storage, file, Provider lifecycle and Recipe operations; own human-visible business states and selected tool intent.
- **C**: declared operations that execute only after K Permit; split internal deterministic calculation from externally observable Windows, cloud and Provider effects.
- **Windows Host**: retain existing executor, physical file identity/path constraints, ActionController/private consent/UAC/OS account/permissions. **A valid K Permit alone never authorizes Windows writes.** A Shun grant alone likewise never bypasses K admission.
- **LLM Host**: real DeepSeek endpoint/model/key and independent budget/disclosure checks, not model-selected endpoint; reuse the confirmed v0.10.3 neutral `dh.llm.generate/1` with explicit `llm.openai.generate` C/Host binding for Shun's DeepSeek. Anthropic C remains selectable by SDK but **is not an extra Shun P0 service dependency**. No model-name implicit routing, keys in B/Prompt, or automatic retry on uncertain post-send state.
- **Guided Journey / form**: B chooses exactly one next approved step from Host-observed current context; UI displays bounded form and captures `StepOutcome`. Optional `LLMAdvisory` is untrusted, not a new template, change to approval authority or execution permit. Real UI/authorization integration is Shun-owned beyond the SDK's offline example.
- **Feedback / Meta**: reuse selected S `meta-feedback`, candidate-validation, Host shadow/feedback workflow; Shun owns feedback provenance, privacy, and user/operator acceptance. Candidate promotion creates a **new** approved BUILD, never mutates the current active workflow or its K state.
- **Control UI/API**: preserve user gestures, separate approved plan, refusal and recoverable evidence, avoid UI-as-authority.

**Key architecture unknowns needing falsification before L2 Freeze**:
A. Are K Permit / Shun authorization / side-effect commit order composable without TOCTOU, dual decision or deadlock?  
B. Can public selected SDK handle Windows and cloud UNKNOWN without replaying an already-sent / already-executed effect?  
C. Can existing ShunStore data/journal/Recipe IDs map to K stable identities without loss, ambiguity or a dual-writer period?  
D. Can native NAPI-RS/UAC/helper and signed Provider be bound through public C/Host ABI without bypassing selected public API?  
E. Can Shun private consent and budget reservation guarantee no forbidden DeepSeek request under SDK LLM effect scheduling?  
F. The v0.10.3 Contract/L2 is frozen; which exact public package/export set and source SHA will be used for development, and which installed-consumer/Release checks remain before shipping? This is a packaging/evidence question, **not a reason to reopen frozen contract selection**.
G. Can Shun Guided Journey advance/recover across actual UI, changing Host observations and human approval without treating an LLM advisory/StepOutcome as K authority?
H. Can redacted feedback + observed outcome enter public Meta workflow and remain candidate-only until explicit future-BUILD operator approval, including negative forged/cross-user feedback cases?

Keep UNKNOWN explicit. A `NOT_RUN` real host or public-consumer journey is **not** an architecture PASS.

## 4. Options and minimum total delivery cost

| Option | Benefit | Cost/risk | Product R0 decision |
| --- | --- | --- | --- |
| A — Keep existing v0.2 stack | Lowest immediate migration cost | Two evolving orchestration designs across projects | **Fallback** if actual SDK gap, parity regression or higher total cost |
| B — Wrap whole ShunStore/ActionController inside one C | Quick demo | Creates shadow Kernel, dual Journal, misleading effect authority | **Reject** as target architecture |
| C — Selective DomainHarness Package-first migration | SDK reuse, one K, domain workflows remain Shun-specific | One-time adapter, state migration & Windows trust proof | **Preferred hypothesis, requires L2 evidence** |
| D — Full rewrite of Windows executor, consent, provider and Recipes | Superficially uniform | High security regression/host revalidation cost | **Reject** without demonstrated defect/owner decision |

Evaluate actual source reuse, count of removed duplicated orchestration responsibilities, adapter burden, validation/review/risk and installed user journey before choosing C irrevocably. Avoid local patches that conceal an unresolved K/Host trust conflict.

## 5. Product acceptance / negative matrix

| ID | Required journey | Essential negative falsifiers | Evidence owner |
| --- | --- | --- | --- |
| J01 | Windows real read-only system/folder diagnosis via selected App **plus frozen B-040** `collectWindowsSupportContext` → `minimizeSupportContext`, exact `shun.support-context.v1` / `localOnly:true` / `externalDisclosures:[]` | No LLM; no auto network/Meta/LLM/SDK issue forwarding of support report; secret words, environment values/keys, process names/args, unrelated document bodies, sensitive paths must be minimized; unsupported facts → honest no-effect | Windows Host + CI |
| J02 | Folder plan, separate human R2, scope-locked effect, independently verified bytes/canary | forged/stale grant, path alias, UI assertion, mutation between preview and effect → 0 effect | Windows Host + independent Review |
| J03 | CN & EN genuine DeepSeek advice → strict typed proposal → **separate** plan acceptance → verified real effect | private content without consent, stale cost permit, hallucinated operation, model grant spoofing → 0 forbidden calls/effects | Local Windows + genuine controlled cloud |
| J04 | Immutable Recipe replay without LLM call | script/graph/param drift, stale approvals → refuse | CI + Windows |
| J05 | Curated Provider genuine first-use JIT signature, cache/offline reuse | changed binary, wrong signature, stolen user assets, unknown ABI → refuse | Windows Host |
| J06 | CAS/replay/crash recovery with real selected SDK | duplicate effect, dropped ACK, UNKNOWN remote timeout, poisoned DTO before send → no unsafe replay | SDK external consumer + Host |
| J07 | Portable Windows Home/Pro product journeys, trusted first entrypoint and **CN/EN nondeveloper UI** for selected root, approval, progress/history and clear refusal/UNKNOWN in same supported workflow | unsupported OS/launcher provenance, missing rights or package tamper → hold; either locale must not hide scope, consent or refusal | Physical Windows + independent RQ |
| J08 | Current Windows facts → one approved guided StepSpec → user choices/StepOutcome → correct resumed step, rendered in Chinese and English with equivalent risk/approval semantics | stale case, forged outcome, unapproved choice, missing locale-bound consent or model advisory override → refuse; model absent still works | UI/Business + Windows Host |
| J09 | User feedback + verified task receipt → bounded Meta candidate → validation/Shadow → explicit operator-approved future BUILD | fabricated feedback/provenance, secret in telemetry, unapproved self-promotion, current-build mutation → refuse | Host/Meta + independent Review |

Carry forward genuine unproved v0.2 evidence as `UNKNOWN`, **not** migrated PASS. v0.3 only claims a user journey when the real chosen public SDK, Shun Host and bounded user-facing path are wired end-to-end.

## 6. ADS v4.18 lifecycle and version independence

1. **Stage 0 / Product R0 now:** issue #214, proposal docs and exact frozen-input references on `planning/v0.3-domain-harness-product-r0`; risk-based Product independent Review **required** because authority/migration sensitive. `version/v0.3.0` is only a staging branch; neither a new frozen base nor a runtime permission.
2. **Product R1:** selected independent exact-HEAD review; Product owner explicitly authorizes any Product Freeze. Reviewer judgement alone cannot freeze.
3. **Stage 2:** L2 derives from frozen Product, **reuses confirmed DomainHarness v0.10.3 Product/Contract/L2**, maps the existing public K/S/B/C/Host interfaces and resolves Shun-specific UNKNOWNs through bounded tests; independent Shun architecture review and explicit Shun L2 Freeze. Do **not** re-specify the already-frozen SDK ABI.
4. **Task DAG:** concern-first, source owners and non-conflicting parallel lanes. At least separated lanes for host Windows, domain business workflows, semantic/LLM, guided forms/UI, feedback/Meta, state/Recipe migration and real integration; shared exports & composition owned by one integrator. Dependencies are materialized as **native GitHub Issue Dependencies** and read back. No L3 dispatch from a prose DAG alone.
5. **Implementation:** legal actual Task Claim, exact SHA, allowed write sets, independent review where required; WEB+CI first, LOCAL only for physical missing proof. No double writers. Correct branch and exact-SHA validation. SDK gaps raised to `kaicreator-mm/domain-harness`, with minimal repro and no private data.
6. **Version closeout:** full regression/selected real Windows/DeepSeek/Provider/Hidden/packaging and independent RQ. Keep `main`, v0.2 frozen scope, public tags and real user secrets untouched until qualified authorization.

**Critical baseline gate:** v0.3 planning snapshot is v0.2 source `f01233a...`, NOT final v0.2 release. **After Shun Product/L2/DAG/Claim authorization, independent v0.3 implementation lanes may develop against an explicitly pinned v0.2 source snapshot in isolation while v0.2 T10/T11 finish.** Each impacted component must rebase/reconcile v0.2 accepted successor before final v0.3 integration, with currentness/CI and independent review. No v0.3 implementation may overwrite v0.2 source, re-use unqualified v0.2 release receipts, or claim shipped parity from unresolved v0.2 cases.

**ADS adoption:** shun v0.2 currently pins `.dev-standard/VERSION = 4.13.1@f35fcdb...`; changing that historical pin is forbidden here. For v0.3, request an explicit qualified ADS v4.18 source-revision adoption with compatibility/role/Claim review; do not silently edit the pin in Product R0.

## 7. Product decisions requested

- Approve **functional parity plus bounded v0.10.3 LLM/Guided Journey/Meta integration** as the v0.3 baseline, and selective DomainHarness migration as the preferred, reversible hypothesis.
- Preserve existing private consent + ActionController / Windows authorization for physical effects, subject to L2 proof of composition with single K.
- Approve independent Product R1 for this security-sensitive rewrite; do **not** infer Product Freeze from this document.
- Keep v0.2 release path separate; no v0.3 source implementation until qualified baseline, L2 and native Task admissions exist.

```ini
PRODUCT_R0=REVIEW_CANDIDATE
PRODUCT_FREEZE=NO
L2_FREEZE=NO
SDK_CONTRACT=v0.10.3_PRODUCT_DATA_L2_FROZEN
SDK_DEV_SOURCE_SNAPSHOT=7d571858bd6524ffd13a7985227183dbecb2924a
SDK_PUBLIC_PACKED_CONSUMER=NOT_RUN
SDK_RELEASE_PIN=PENDING_RQ
ISOLATED_SOURCE_WORK_ALLOWED_AFTER_V03_L2_DAG_CLAIM=YES
V02_ACCEPTED_DELTA_RECONCILIATION=REQUIRED_BEFORE_V03_FINAL_INTEGRATION
NATIVE_TASK_DAG=NOT_CREATED
IMPLEMENTATION_AUTHORIZED=NO
RELEASE_READY=NO
```
