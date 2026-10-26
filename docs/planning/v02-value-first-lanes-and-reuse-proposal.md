# Shun Assistant v0.2 — value-first Product/L2/DAG prospective correction

> **Status: PROPOSED; NOT FROZEN OR EXECUTION AUTHORITY.** This is one bounded planning subject, not a permission to bypass the existing native GitHub Issue dependencies, review policy, write-set ownership or release gates. Owner-approved Product/L2/DAG amendment is required for material scope/dependency changes. Source: ADS [#1337](https://github.com/kaicreator-mm/ai-development-standard/issues/1337), [#1241](https://github.com/kaicreator-mm/ai-development-standard/issues/1241), [#1320](https://github.com/kaicreator-mm/ai-development-standard/issues/1320); Shun [#109](https://github.com/kaicreator-mm/shun-assistant/issues/109)–[#113](https://github.com/kaicreator-mm/shun-assistant/issues/113).

## 1. Verified incident and immediate correction

During 2026-10-25/26, nine T07 PRs #179–#187 were produced around previews, native no-overwrite effects, file identity, durable recovery and physical kill canaries, while the eleven-Task DAG remained at **6/11 closed** and no complete new installed Windows v0.2 user journey was independently proven. The work is real but was over-optimized for internal review/CI outputs. Later real Windows P1–P4 kill evidence was delivered via #188 and integrated at `version/v0.2.0@b6dbf572a7dadbf7c5304f10a9a660bb1075247b`; **do not request another crash matrix by default**. As of this planning snapshot PR #187 P0 still needs independent R1 and integration, and #109 needs a final accepted acceptance check before closure.

The frozen DAG `T07 → T08 → T09 → T10 → T11` has excessive **full-Task** dependency edges: DeepSeek/cloud UX and build/packaging preparations do not inherently require five crash scenarios to finish. The frozen Task issues still enforce their stated predecessors today. This proposal makes no early T08/T09 implementation admissible by itself.

## 2. One supported product journey first

**J0 (minimal diagnosis, reusable Recipe)**: Standard User starts packaged portable Core without pnpm or local Ollama → enters ordinary non-destructive Windows diagnosis → sees **explicit** REMOTE DeepSeek Flash posture and cloud/privacy/cost opt-in → real model returns a bounded proposed plan → user sees preview → read-only Windows diagnosis runs with truthful receipt, or safely refuses/UNKNOWN → user sees results and may save/replay approved Recipe with zero LLM calls. A no-key/offline path must remain truthful and useful (local read-only diagnosis, provider-unavailable instead of fake LOCAL/REMOTE). R2 file mutation, if offered, requires a separately authentic Shun-owned IPC user gesture + ActionController effect authorization; J0 does not need a destructive file effect merely to qualify.

**Success proof**: actual Windows Standard User screenshot/terminal trace + network metadata (no secrets) + real DeepSeek call with visible explicit consent, and a zero-model Recipe replay; packaging smoke from a clean runtime lacking dev dependencies. Simulation/demos/PR counts do not count as J0 PASS. Product authority must choose minimum J0 scope; no silent change to existing frozen critical journeys.

## 3. Proposed independent lanes (minimal ownership, no shadow scheduler)

| Lane | Smallest coherent work | Source owner | Needed integrated inputs | Independent work now | Join condition |
| --- | --- | --- | --- | --- | --- |
| A — actual user/API | truthful REMOTE posture, provider opt-in, safe diagnostics, preview, receipt and Recipe UX; secure OS-bound consent only for R2 | `apps/control-api/**`, `apps/control-ui/**` | T01/T03/T04/T05/T06 published contracts; T07 **effect adapter** only for actual R2 file actions | Product/L2/UI contract design and read-only diagnosis can be split and admitted **after** authorized DAG edit | real J0 Windows gesture→response→receipt |
| B — file operations | preserve already integrated R2 no-overwrite and durable STARTED/no-auto-replay; unreadable crash poststate → UNKNOWN/manual reconciliation | `packages/vertical-files/**` plus nominated private Host seam | T00/T04; F03/F04B2 already merged; #187 independent R1 pending | close #109 on accepted scope without inventing further positive causality requirements | current P0–P4 evidence correctly classified, no false success/overwrite |
| C — portable delivery | minimal Core launcher, bundled runtime, local fixed-disk state, no secrets in artifact, start/upgrade/uninstall basic checks | `packaging/**`, `scripts/package-v02/**` | package/export/asset contract can freeze before UI completion | minimal package manifest/bootstrap preparation can run disjoint from Lane A **only after a lawful split/admission** | clean Standard User boot and upgrade smoke |
| D — integration/RQ | per-journey tests and final contract/security release convergence, not another product feature | `tests/integration/v02/**`, `tests/closure/v02/**` | accepted lane baselines | design fixtures and read-only evidence inventory early | final frozen feature set, CI+review+real Windows; full Release Qualification |

**Proposed revised dependencies** (requires native Issue Dependency amendment): `A(UI read-only/cloud)` and `C(packager scaffolding)` can begin from **accepted shared contracts**, not T07 final crash proofs. `B(R2 file path)` remains a prerequisite only to A's file-mutation feature and the relevant R2 integration tests. The final D version convergence still depends on A/B/C accepted baselines. A's Shun-owned authenticated consent broker can evaluate `@kai-tools/win-ipc` only **after** a qualified Windows library build; its release and J0 must not depend on experimental extraction.

Treat `PREP_ALLOWED` (research/design/read-only tests) differently from `SOURCE_WRITE_ADMISSIBLE` and `MERGE_ELIGIBLE`. This proposal does not change frozen native GitHub blocked_by until approval.

## 4. Build-vs-reuse decision for T07 — no rewrite-for-rewrite

| Need | First candidate | Exact gap/safety check | Decision now |
| --- | --- | --- | --- |
| Copy fail-if-target-exists | Node 24 `fs.copyFile(src,dst,COPYFILE_EXCL)` or Win32 `CopyFile2` with `COPY_FILE_FAIL_IF_EXISTS` | path/reparse anchoring, no wrong target, cancellation/partial artifact, independent verified result | **EVALUATE** against retained trusted F03; not an immediate replacement |
| Rename/move, no replacement | Win32 `MoveFileExW` without replace flag, or retained native no-replace handle-relative rename | `fs.rename` may overwrite, source/dest actor races, same-volume identity; test anchored scope | **KEEP** existing working native implementation until candidate passes identical key canaries |
| Scope-relative filesystem | Rust `cap-std` (`Dir` capability semantics) | verify Windows behavior, junction/no-follow, destination no-overwrite and Node/Rust boundary | **EVALUATE** narrow prototype only; no new dependency by default |
| Durable operation admission/recovery | existing local SQLite WAL/FULL plus two-state STARTED / verified-or-UNKNOWN outcome | current policy and exact intent, no auto-replay, wrong-success prevention | **KEEP**, stop expanding forensic positive causality |
| File duplicate preview | existing F01/F02 candidate report, standard hashing | UI selection, confirmed duplicate bytes, false delete/overwrite risk | **DEFER** further sophistication unless chosen user journey needs it |
| User-authenticated consent | evaluate qualified Win32 pipe token facts (`@kai-tools/win-ipc` experimental) | true OS/UI gesture, actual process token/session, revocation/no browser self-sign | **CONDITIONAL REUSE**; do not import unqualified library to satisfy T08 gate |

A custom security primitive is justified only by a specific gap under the **actual supported exposure**. A high-level Shell API is not automatically safe under untrusted LLM-originated file paths; a copy convenience method does not waive current R2 authority. Retain valid native evidence; prefer an adapter/interface test to a wholesale rewrite.

## 5. Risk acceptance and anti-gold-plating decisions

**Non-negotiable:** no unauthorized R2 effect, no wrong target, no overwrite/data loss, no false terminal success, no automatic replay after uncertain effect, no provider-key leak or fake cloud consent. An unknown crash result is **UNKNOWN** and user-mediated; never cast CONSISTENT to PROVEN. A P2/P3 is not automatically an extra release blocker. Product/L2 can prospectively classify truly unsupported edge cases, but cannot turn an already required frozen FAIL into PASS without approved change and new exact review subject.

Before commissioning another new utility/edge subtask, controller records briefly: (1) enabled/shipped path? (2) proven mature alternative? (3) concrete missing critical-journey edge? (4) safe refusal possible? (5) independent lane blocked? Decision `KEEP_SECURITY_FIX | REUSE | DEFER | MINIMAL_SHIP | REQUEST_PRODUCT_L2_DAG_CHANGE`. No new global schema, mandatory review gate, artificial PR limit or repeated all-suite CI. Reuse exact-head existing verification whenever source/assumption remains current.

## 6. Requested approval / immediate next actions

1. T07 controller: consume integrated #188 Windows real-effect P1–P4 evidence, independent R1 of #187 P0, and prior F01–F04 evidence; close #109 if its **actual frozen** acceptance is met. If not, state a single real missing acceptance edge; do not create another multi-phase campaign by default.
2. Product/L2 owner: review J0 diagnosis-first product choice, `UNKNOWN/manual` on unrecoverable state, DeepSeek remote opt-in/actual consent and the build-vs-reuse table. Approve/reject narrowly with an exact versioned subject; existing requirements are unchanged before approval.
3. DAG owner: upon Product/L2 acceptance, split T08 and T09 into truthful lane requirements, revise **canonical GitHub Issue Dependencies** and relevant frozen authority, not just a Markdown diagram. Preserve merge-integrated baseline requirements and the final join.
4. Builder: after lawful updated readiness, prioritize real Control UI/DeepSeek J0, optional Shun-owned secure consent, and parallel independent package bootstrap; use required targeted CI/security review. Report `closed_tasks` **and** `new_installed_journeys_passed` every iteration.
5. kai-tools: extract only proven stable cross-project low-level API with a real consumer; file journal/reconciler and grant policy remain in Shun. Library migration never blocks v0.2.

```ini
PLAN_STATUS=PROPOSED_ONLY
BASE_VERSION_SHA=b6dbf572a7dadbf7c5304f10a9a660bb1075247b
FROZEN_DEPENDENCIES_CHANGED=NO
MAIN_MERGED=NO
DAG_CLOSED_AT_SNAPSHOT=6/11
INSTALLED_V02_J0=NOT_PROVEN
T07_F04B3B_WIN32_EFFECT_KILL=MERGED_PR188
T07_F04B3A_P0=PR187_R1_PENDING
REQUIRED_DECISION=AUTHORIZED_PRODUCT_L2_DAG_PROSPECTIVE_AMENDMENT
```
