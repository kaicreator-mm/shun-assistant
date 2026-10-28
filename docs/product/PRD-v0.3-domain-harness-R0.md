# Shun Assistant v0.3 — DomainHarness Domain App 重构（Product R0 / REVIEW CANDIDATE）

> **STATUS: PRODUCT_R0_DRAFT / NOT_FROZEN / NO_IMPLEMENTATION_AUTHORITY**  
> Controller: [#214](https://github.com/kaicreator-mm/shun-assistant/issues/214)  
> Standard planning authority: ADS v4.18.0 **qualified main source** `2c395c55569fe2edf3f4135f12d3d069e526d0b7` (not v4.19 intake).  
> Shun **planning-only** snapshot: `version/v0.2.0@f01233a002f65b9bfea04828f6e56914666a160a`. v0.2 is not a qualified v0.3 final baseline; #112/#113/#212 remain independent v0.2 delivery gates.  
> DomainHarness v0.10.3 `version/v0.10.3@7d571858bd6524ffd13a7985227183dbecb2924a` observed as **candidate**. Final exact SDK release/packaging/API/ABI selection is explicitly pending.  
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
2. **User-facing diagnostics.** Genuine native Windows system inventory, scope-bounded folder diagnosis, evidence and uncertainty; no model dependency for deterministic read-only functions; user interface remains functional.
3. **Scoped effects.** Selected-folder preview/manifest → separate R2 human plan approval → exact-scope Windows effect → independently checked poststate and protected canaries; policy drift, aliases, moved targets, UAC refusal, insufficient rights and stale grants fail closed.
4. **Reproducible Recipes.** Immutable source+graph+parameter identity and revalidation; user-selected deterministic replay generates zero LLM requests; no unbounded script execution.
5. **DeepSeek/LLM integration.** Host-configured OpenAI-compatible DeepSeek with independently authenticated user disclosure/cost consent; at-most-once-send reservations, no blind retry/refund for `MAY_HAVE_SENT/UNKNOWN_COST`; CN/EN real provider and privacy zero-call evidence at the release gate.
6. **Provider lifecycle.** Curated, signed/pinned, JIT acquired Provider artifacts; trusted deployment and native ABI binding; no user file reclassified as Provider-owned, safe offline reuse and uninstall.
7. **Lifecycle & recovery.** SQLite WAL local fixed disk, authoritative state/recovery history, idempotence and UNC/mapped-path limitations stated honestly; no duplicated physical effects across restart, concurrent requests or replay.
8. **User packaging.** The v0.2 selected Windows Home/Pro x64, ordinary-user constraints, trusted release origin and native portable requirements remain in scope as inherited product obligations. Source and mock tests are not a real Windows acceptance substitute.

**P1 (only when independently justified)**: improve plugin/recipe authoring UX and optional guided-step UI *after parity*. No new feature may be treated as a P0 migration prerequisite unless an explicit Product review amendment makes it so.

## 3. Domain App direction and owner boundaries (L2 design inputs, not pre-approved source contract)

Proposed composition: external selected DomainHarness BUILD → one selected K/Microkernel → S (semantic) + B (Shun task workflows/registered computer abilities) + C (declared Tool operations) → trusted Shun Windows/LLM/Provider Host.

- **K**: one authoritative durable effect Permit, operation Journal, replay and UNKNOWN for migrated workflows. Existing ShunStore data survives via explicit migration/read-only compatibility policy; no two simultaneously writable authorities for the same effect identity.
- **S**: parse/normalize user intent and semantic context; never infer authority from LLM recommendation.
- **B**: typed system-diagnosis, storage, file, Provider lifecycle and Recipe operations; own human-visible business states and selected tool intent.
- **C**: declared operations that execute only after K Permit; split internal deterministic calculation from externally observable Windows, cloud and Provider effects.
- **Windows Host**: retain existing executor, physical file identity/path constraints, ActionController/private consent/UAC/OS account/permissions. **A valid K Permit alone never authorizes Windows writes.** A Shun grant alone likewise never bypasses K admission.
- **LLM Host**: real DeepSeek endpoint/model/key and independent budget/disclosure checks, not model-selected endpoint; selected DomainHarness LLM C only where its observed public contract fits these existing safeguards.
- **Control UI/API**: preserve user gestures, separate approved plan, refusal and recoverable evidence, avoid UI-as-authority.

**Key architecture unknowns needing falsification before L2 Freeze**:
A. Are K Permit / Shun authorization / side-effect commit order composable without TOCTOU, dual decision or deadlock?  
B. Can public selected SDK handle Windows and cloud UNKNOWN without replaying an already-sent / already-executed effect?  
C. Can existing ShunStore data/journal/Recipe IDs map to K stable identities without loss, ambiguity or a dual-writer period?  
D. Can native NAPI-RS/UAC/helper and signed Provider be bound through public C/Host ABI without bypassing selected public API?  
E. Can Shun private consent and budget reservation guarantee no forbidden DeepSeek request under SDK LLM effect scheduling?  
F. Is SDK v0.10.3 a qualified/public consumable baseline, and what is the minimal compatible adaptation otherwise?

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
| J01 | Windows real read-only system/folder diagnosis via selected App | No LLM, unsupported facts → honest no-effect | Windows Host + CI |
| J02 | Folder plan, separate human R2, scope-locked effect, independently verified bytes/canary | forged/stale grant, path alias, UI assertion, mutation between preview and effect → 0 effect | Windows Host + independent Review |
| J03 | CN & EN genuine DeepSeek advice → strict typed proposal → **separate** plan acceptance → verified real effect | private content without consent, stale cost permit, hallucinated operation, model grant spoofing → 0 forbidden calls/effects | Local Windows + genuine controlled cloud |
| J04 | Immutable Recipe replay without LLM call | script/graph/param drift, stale approvals → refuse | CI + Windows |
| J05 | Curated Provider genuine first-use JIT signature, cache/offline reuse | changed binary, wrong signature, stolen user assets, unknown ABI → refuse | Windows Host |
| J06 | CAS/replay/crash recovery with real selected SDK | duplicate effect, dropped ACK, UNKNOWN remote timeout, poisoned DTO before send → no unsafe replay | SDK external consumer + Host |
| J07 | Portable Windows Home/Pro product journeys and trusted first entrypoint | unsupported OS/launcher provenance, missing native permissions, package tamper → hold | Physical Windows + independent RQ |

Carry forward genuine unproved v0.2 evidence as `UNKNOWN`, **not** migrated PASS. v0.3 only claims a user journey when the real chosen public SDK, Shun Host and bounded user-facing path are wired end-to-end.

## 6. ADS v4.18 lifecycle and version independence

1. **Stage 0 / Product R0 now:** issue #214, proposal docs and exact frozen-input references on `planning/v0.3-domain-harness-product-r0`; risk-based Product independent Review **required** because authority/migration sensitive. `version/v0.3.0` is only a staging branch; neither a new frozen base nor a runtime permission.
2. **Product R1:** selected independent exact-HEAD review; Product owner explicitly authorizes any Product Freeze. Reviewer judgement alone cannot freeze.
3. **Stage 2:** L2 derives from frozen Product, selects exact SDK and K/S/B/C/Host ABI, answers high-impact UNKNOWNs with bounded real tests; independent architecture review and explicit L2 Freeze.
4. **Task DAG:** concern-first, source owners and non-conflicting parallel lanes. At least separated lanes for host Windows, domain business workflows, semantic/LLM, state/Recipe migration, API/UI composition and real integration; shared exports & composition owned by one integrator. Dependencies are materialized as **native GitHub Issue Dependencies** and read back. No L3 dispatch from a prose DAG alone.
5. **Implementation:** legal actual Task Claim, exact SHA, allowed write sets, independent review where required; WEB+CI first, LOCAL only for physical missing proof. No double writers. Correct branch and exact-SHA validation. SDK gaps raised to `kaicreator-mm/domain-harness`, with minimal repro and no private data.
6. **Version closeout:** full regression/selected real Windows/DeepSeek/Provider/Hidden/packaging and independent RQ. Keep `main`, v0.2 frozen scope, public tags and real user secrets untouched until qualified authorization.

**Critical baseline gate:** v0.3 planning snapshot is v0.2 source `f01233a...`, NOT v0.2 finished code. Before v0.3 source implementation dispatch, owner must adopt an exact eligible successor from completed v0.2 and revalidate all migration assumptions. A v0.2 Release HOLD cannot be bypassed by invoking new v0.3 architecture; parity claims against missing v0.2 cases remain UNKNOWN.

**ADS adoption:** shun v0.2 currently pins `.dev-standard/VERSION = 4.13.1@f35fcdb...`; changing that historical pin is forbidden here. For v0.3, request an explicit qualified ADS v4.18 source-revision adoption with compatibility/role/Claim review; do not silently edit the pin in Product R0.

## 7. Product decisions requested

- Approve **functional parity before new features** and the selective DomainHarness migration as the preferred, reversible hypothesis.
- Preserve existing private consent + ActionController / Windows authorization for physical effects, subject to L2 proof of composition with single K.
- Approve independent Product R1 for this security-sensitive rewrite; do **not** infer Product Freeze from this document.
- Keep v0.2 release path separate; no v0.3 source implementation until qualified baseline, L2 and native Task admissions exist.

```ini
PRODUCT_R0=REVIEW_CANDIDATE
PRODUCT_FREEZE=NO
L2_FREEZE=NO
SDK_ABI_PIN=NOT_SELECTED
REBASE_V02_RELEASE=REQUIRED_BEFORE_IMPLEMENTATION
NATIVE_TASK_DAG=NOT_CREATED
IMPLEMENTATION_AUTHORIZED=NO
RELEASE_READY=NO
```
