# Shun v0.2 — Implementation Task DAG planning draft (NOT FROZEN, NOT AUTHORIZED)

**Stage:** `TASK_DAG_DESIGN_ONLY`. This draft is an L2 preparation convenience and **is not a live GitHub execution DAG**, not a Task DAG Freeze and not permission for implementation. Historical frozen Product: `79f47be5ff08a54588790e8abdacffd8697ac4d8`, tree `10c0ad768fee849ada952b038b0b1a653fd9a6d7`. **Conditional DeepSeek-first Product successor:** `docs/product/PRODUCT-SCOPE-CHANGE-v0.2-DEEPSEEK-FIRST.md` (PR #91, review #92/re-freeze PENDING). Architecture candidates: [L2 v0.2](../architecture/L2-v0.2-CANDIDATE.md) and [L2 trust/contract decisions](../architecture/L2-v0.2-CONTRACT-DECISIONS.md). Controller #83. Windows pilot #85 is optional future LOCAL research after Product re-freeze, not a P0 gate; #86/#87 bounded evidence is adopted. Product successor review and explicit Product re-freeze, then exact L2 review/freeze, precede implementation.

## 1. Bounded nodes and file-level ownership

| ID | Concern / primary write owner | Depends on | Review policy | Must-pass concern proof | Location |
| --- | --- | --- | --- | --- | --- |
| **T00** | New typed v0.2 contracts, LLM proposal, Recipe immutable identity, ProviderCatalog/Acquisition contracts; `packages/contracts/**` ONLY | Frozen L2 | **required** (API/schema/security) | positive JSON/schema fixtures, graph-only/source-only tamper RCP-01, unknown ops deny, backwards compatibility | Web coding agent; local tests via CI |
| **T01** | **DeepSeek Flash `deepseek-flash` API P0** remote HTTPS adapter, `DEEPSEEK_API_KEY` backend credential, trusted pre-planner privacy/currentness/consent/budget gate; `packages/llm-remote/**`, `packages/resolver/src/planner-seam.ts` ONLY | T00 | **required** (privacy) | real CN/EN Flash API calls, 0 calls on LOCAL_ONLY/OFFLINE/stale/no consent/key/budget, no key/PII leakage, malformed/model-hallucination refusal | Web+Windows integration |
<!-- T02 former required LOCAL implementation is DEFERRED optional and excluded from the 11-node P0 DAG after Product re-freeze; no mandatory model installation; #85 research preserved. -->
| **T03** | Durable immutable Recipe persistence/revision migrations and currentness; `packages/store/**` + `packages/workflow/src/recipe-seam.ts` | T00 | **required** (data integrity) | restart replay, immutable identity, all representations hashed, schema migration rollback, tamper `BLOCK`, no old enablement inheritance | Web coding + CI/host |
| **T04** | Closed-world JS/TS-to-typed-action mediation/RecipeResolver, planner join + secure ActionController reentry; **new** `packages/resolver/src/recipe-resolver.ts` (and recipe-only new files) + `packages/recipe-runtime/**`; **must not edit T01-owned `planner-seam.ts`** | T00,T01,T03 | **required** (execution safety) | no JS code execution for untrusted source, imports/FFI/shell bypass denied, per-run plan/approval, zero LLM exact replay | Web coding + Windows negatives |
| **T05** | Minimal signed catalog and on-demand Provider artifact staging/activation/cache; `packages/vertical-jit/**` + `packages/provider-loader/**` | T00, **#86 architecture proof adopted** | **required** (supply chain) | unsigned/wrong-hash/redirect/ABI/downgrade/refused consent/offline fail closed; restart/canaries; CLI and native addon separate | Web coding + **Windows Build Host** |
| **T06** | Real read-only Windows inventory and bounded optimization report; `packages/vertical-system/**` | T00 | **recommended**, required if adding privilege-bearing changes | CPU/disk/RAM/process/startup facts; rate/scopes/PII; reuse C003 cleanup oracle (no false startup-speed claim) | Web coding + **Windows observation** |
| **T07** | Real scoped file search/copy/move/rename/duplicate previews via typed effect graph; `packages/vertical-files/**` | T00,T04 | **required** (file effects, recovery) | junction/symlink/UNC/collision canaries, dry-run vs committed proof, no overwrite, reconciliation after crash | Web coding + Windows host |
| **T08** | Unified user-facing Control API/UI real backend (DeepSeek Flash config, cloud consent/cost/privacy, progress, verified result, image/JIT/storage/diagnosis, Recipe library); `apps/control-api/**` + `apps/control-ui/**` | T01,T03,T04,T05,T06,T07; **NOT T02** | **recommended**, required for consent/privacy seam | no DEMO claims under REAL label, locale/keyboard/consent, actual R2 state from ActionController, no UI-origin grant signing, model/prov offline UX | Web coding + browser/Windows E2E |
| **T09** | Portable Core-only Windows distribution/startup/owned-state cleanup; `packaging/**`, `scripts/package-v02/**` | T08, **#87 narrow architecture evidence adopted** | **required** (distribution/supply chain) | end user no pnpm, offline no provider/model, exact bundle manifest/signature, upgrades/uninstall user-canaries, **genuine Standard User** run, ShunStore/keys local fixed disk, UNC/network state fail-closed (SQLite WAL), product inventory UI is not C003 pilot | **Windows Build Host** |
| **T10** | Cross-component integration + schema/live acceptance binding (no feature expansion); `tests/integration/v02/**` | T00,T01,T03–T09 | **required** (cross-boundary) | real LLM→diagnose→plan/approve→verify; generated source/graph tamper denied; lazy Provider acquired/cache/reused; zero-LLM Recipe replay | Web/CI+Windows |
| **T11** | Version Closure & independent full Windows negative/hidden/packaging qualification; `docs/implementation/v0.2/**`, `tests/closure/v02/**` | T10 | **required** | all Frozen Product Critical Journeys on actual supported Windows editions; hidden malicious prompts; installer/user-state, recovery, local egress, privacy, full regression, Release Qualification inputs | **Windows Build Host + independent reviewer** |

**Source ownership invariant:** T01 alone owns `packages/resolver/src/planner-seam.ts` (pre-model currentness/privacy gate). T04 owns newly introduced Recipe resolver sources, consumes T01's exported guarded PlannerPort interface, and must not add a competing direct model-call path. Shared `packages/resolver/src/index.ts`, if it needs simultaneous edits, is deferred to a single integration owner after T01/T04; otherwise expose a safe subpath API. No concurrent PRs may write the same path. Deferred **T02** is NOT dispatchable in v0.2 P0 and cannot block T08/T10/T11; a later independently authorized LOCAL implementation requires genuine model/egress proof. Treat shared API signature drift as a dependency update, not a reason for co-owned source writes.

**Do not split further without an actual write-set/review/runtime need.** If a task exceeds a reasonable review or Build Host window, split within its owner concern into bounded Contract→Core→Integration or reviewable sub-issues, preserving one ownership point. No mandatory L3/demos for every leaf; add focused L3 only for security/negative/complex changes.

### 1.1 Immediate parallelism

```text
After L2 Freeze:
                  T00 (contracts)
                   │
   ┌────────┬──────┼─────────┬──────────┐
   T01           T03       T05        T06
   DeepSeek API   store     JIT        inventory
    └───────┐       │
            └────── T04 (typed Recipe+Resolver; after T01,T03)
                     └── T07 (files)
   T01,T03,T04,T05,T06,T07
                    ↓
                T08 (real user UI)
                    ↓
                T09 (portable)
                    ↓
                T10 (integration)
                    ↓
                T11 (version closure)
```

L2 pilots #85–#87 are **not duplicated** as implementation DAG nodes: consume their exact evidence/decisions in T02/T05/T09. **#85 technically remains BLOCKED for optional real LOCAL model inference**; bounded rt1f isolation evidence remains at `task/i85-rt1-zc@3cc6733ccfd3e3da8c6704e3f5e6941852a1f16c`. After revised Product Freeze, #85 is deferred optional research, not a P0 dependency. **#86 is CLOSED** with bounded ripgrep/Sharp ABI architecture evidence, **not** a production loader PASS. **#87 is CLOSED** with a narrow C003 portable local-disk core result, **not** standard-user/inventory-UI or UNC-state qualification. Their release obligations remain in T02/T05/T09/T10/T11. A pilot FAIL changes architecture, and `BLOCKED` stays blocked, never a fake PASS.

## 2. Inputs, outputs and task handoff contract

For every future GitHub Task Issue after Task DAG Freeze:

- **Input**: current frozen Product SHA+tree; exact frozen L2 SHA/tree; contracts/spec revisions; predecessor Issue/PR exact identity, v0.1 reuse references.
- **Expected output**: one concern's bounded code/tests/fixture/evidence with one PR; no unexplained `packages/contracts/**` edits from downstream tasks and no writing another concern's files.
- **Test-first**: at least one real positive and one failure/abuse/rollback case where effectful; record exact SHA×environment×toolchain×profile. Failing/blocked real Windows tests cannot be replaced by mocks.
- **Review policy**: exactly one `required|recommended|not-required` per issue; required security/privacy/mutation/supply chain cannot be skipped. On no actual risk, avoid mandatory fresh independent review rituals.
- **Integration**: PR concerns merge promptly into `version/v0.2.0` after required local gates. Integration/version closure tests remain distinct; CI green is not Release PASS.
- **Failure handling**: always include typed error, interrupted/retry behavior, persistent evidence and independent verifier ownership. No automatic remote fallback for LOCAL_ONLY, no continuing a destructive action after unverified drift.
- **Task metadata**: output both deliverable and compact metadata (inputs/pins, changed file list, test matrix, issues encountered/lessons with reusability, follow-on flags). Only high-ROI reusable lessons become future standards; no mandatory knowledge factory.
- **Dispatch**: Web implements what connected GitHub tools permit; delegate Windows host tests/native package only where actual user environment is required. Independent security review cannot be self-attested by author.

## 3. Architecture acceptance status

```ini
PRODUCT_FREEZE=FROZEN
L2_FREEZE=NO
TASK_DAG_FREEZE=NO
EXECUTION_DAG_ISSUES=NOT_CREATED
PLANNED_P0_TASK_COUNT_AFTER_PRODUCT_RE_FREEZE=11
DEFERRED_OPTIONAL_TASK=T02_LOCAL_LLM
COMPLETED_V02_IMPLEMENTATION_TASKS=0
HOST_L2_HYPOTHESES=#85_OPTIONAL_LOCAL_DEFERRED_ISOLATION_PASS,#86_ARCH_EVIDENCE_COMPLETE,#87_PARTIAL_FEASIBILITY_CLOSED
```

**Next:** independent scoped Product review #92 and explicit re-freeze → adopt DeepSeek-first L2, fresh independent security review and explicit L2 Freeze → freeze **11 P0 DAG nodes** and materialize GitHub Issues. Actual DeepSeek calls belong in T01/T10/T11, not a mandatory L2 local-model pilot. Nothing in this draft authorizes implementation.
