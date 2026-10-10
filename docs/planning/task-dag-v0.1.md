# Shun v0.1 — Frozen Initial Implementation Task DAG

Status: FROZEN_INITIAL_DAG / no implementation PASS claimed.
Standard: kaicreator-mm/ai-development-standard v4.9.0 @ `7929012f36a2202dcc2edc7a414b8163adc7afbd`
Frozen Product: `19d19b519bab322a731592009dcf1a4a0db9b308`
Frozen L2: `7273095804f662de430b78a365b35ddab86a76ae` (tree `794ebe50853c971114c50505bd69eff527a12f24`)
Integrated main checkpoint: `458b05424828c184b04f035114d660eb0ce873b3`
L2 review: Issue #9 PASS, 0 P0 / 0 P1 / 0 UNKNOWN; U-06 real Windows evidence Issue #5.
Validation support: Issue #4 WEB-PRE01 and WEB-PRE02 non-blocking design terminals.
Integration mode: `main` + one-concern short PR branches, JIT off current main when dependencies are satisfied.

## Scope rule

Implement ONLY the **first executable P0 reference proof**: shared Goal/Capability/Provider×local Environment authority spine, image.batch_process, software.jit_capability_lifecycle, system.storage.diagnose_bounded_action, safety/authorization/recovery, semantic verification, and minimal control surface. Other P0 capability-map rows are staged expansion, not parallel foundational projects. Recipe automatic promotion, remote runx/ECF, dynamic glue and creative workflows remain P1+ and are NOT required in this first proof.

## Frozen planning DAG

| ID | Concern / exclusive primary write set | Depends | Review policy | Execution | Required task validation | Priority |
| --- | --- | --- | --- | --- | --- | --- |
| T00 | Runtime contracts, schemas and test/validation interfaces; `packages/contracts/**` | none | required (public schemas) | Local or WEB coding-capable Builder | schema/parser contract tests; negative and exact-identity examples | CRITICAL ROOT |
| T01 | Goal normalization, Capability Registry, Provider×local Environment resolver, deterministic policy-free ranking, PlannerPort seam; `packages/resolver/**` | T00 | required (resolution hard gates) | Local Builder | fixture gold vs resolver; no-feasible-binding and privacy constraints | parallel wave 1 |
| T02 | Trust/Policy/Action Controller, AuthorizationAuthority/Grant, current policy+revocation checks, bounded approvals; `packages/authorization/**` | T00 | required (security) | Local Builder | forged/self-declared, stale, revoked, UNKNOWN, policy-change-between-effects fail-closed | parallel wave 1 |
| T03 | WorkflowKernelPort, ShunStore SQLite records, durable effectId/receipt journal/reconcile, RecipeResolverPort interfaces only; `packages/workflow/**`, `packages/store/**` | T00 | required (transaction/data integrity) | Local Builder | restart/idempotence, partial/torn journal, uncertain destructive same-actionId no blind retry | parallel wave 1 |
| T04 | LocalWindowsBackend and one-shot elevated allowlisted helper; `packages/executor-windows/**` | T00 | required (privileged actions) | LOCAL_WINDOWS_BUILD_HOST | Windows UAC real positive/negative, typed argv, helper pin/current grant, timeout/cancel, uncertain receipt; demo code evidence-only | parallel wave 1 |
| T05 | Loop A `image.batch_process` real adapter + verifier; `packages/vertical-image/**` | T00 | recommended (bounded deterministic) | Local Builder | B-037 200 mixed images, EXIF, 1600px + precommitted SSIM, missing Provider, corrupt input | parallel wave 1 |
| T06 | Loop B trusted software JIT acquisition/use/retain/remove adapter; `packages/vertical-jit/**` | T00 | required (supply chain/destructive lifecycle) | LOCAL_WINDOWS_BUILD_HOST | official provenance + exact version, user assets untouched, R2 removal gate, residue classification, interrupted uninstall | parallel wave 1 (mock seams first) |
| T07 | Loop C scoped Windows storage observation / attribution / bounded cleanup adapter; `packages/vertical-storage/**` | T00 | required (destructive cleanup/privacy) | LOCAL_WINDOWS_BUILD_HOST | B-039 protected asset and hidden growth, no deletion by size, R2 gate, reclaimed-byte verification | parallel wave 1 (mock seams first) |
| T08 | Minimal local Control Surface, preview/approval/progress/recovery; `apps/control-ui/**` and `apps/control-api/**` | T00 | recommended (no authority) | Local Builder | approval readability, override forbidden, local-only disclosure, predictable fallback | parallel wave 1 |
| T09 | Deterministic benchmark fixture/oracle and clean-run harness; `tests/fixtures/**`, `tests/oracles/**`, `tests/harness/**` | T00 | recommended (test trust) | Local/WEB Builder | independent gold oracle, negative data/SSIM/VMAF distinction, no fixture truth leakage | parallel wave 1 |
| T10 | End-to-end integration + real Windows and privacy/semantic validation; `tests/integration/**`, `tests/e2e/**` | T01–T09 | required (integration/critical journeys) | LOCAL_WINDOWS_BUILD_HOST + independent Validator | B-037/38/39/40, provider + lifecycle + risk + journal crash, real Win+UAC, 3 closed loops; no fake PASS | integration wave |
| T11 | Version Closure evidence/critical journeys/full regression/hidden/package/release decision; `docs/validation/closeout/**` | T10 | required (release) | Controller + independent Validator | full integrated exact-SHA gates, Hidden as applicable, packaging and release qualification | closeout wave |

## Dispatch discipline

- T00 alone is initially executable. Its merge releases the maximum independent wave T01–T09.
- A task may author unit tests/mocks within its own write set while shared providers are pending, but must not mutate sibling packages or assert end-to-end PASS.
- When T00 is merged, issue-based execution may dispatch T01–T09 concurrently in separate worktrees **with no overlapping authoritative write set**. Each task gets a JIT branch from then-current main and its own PR.
- Do not create nine long-lived implementation branches now. Issue creation is queue materialization, not implementation dispatch.
- If native GitHub Issue Dependencies cannot be written through this connector, the `Depends` column and Task Issue `BLOCKED_BY` fields record planning links; a GitHub-capable Local Controller must materialize/check native Issue Dependencies before automated dispatch. Never pretend the native edges were added.
- Per concern: tests → contract/interface → implementation → failure handling → examples; local validation mandatory; independent review according to explicit risk-based policy. Documentation/precompute is not execution evidence.
- No CI/check runs exist for the L2 docs-only PR. Implementation tasks must configure minimal clean-checkout CI or record a policy-compliant CI waiver/alternate validation; absent checks do not imply PASS.
- Integration/closure only after prerequisites really merge; PR PASS != Release PASS.
- Do not silently reopen frozen Product for implementation design choices. Architecture contradictions require deliberate amendment with evidence.
- After Task DAG freeze, controller should avoid gratuitous DAG expansion, new gates, duplicate reviews or polling stalls.