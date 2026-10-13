# Shun Assistant v0.2 — Product L1 / PRD DRAFT (LLM-First Usable Windows Steward)

> **UNFROZEN / PROPOSAL.** Parent #80, draft PR #81. Six user-approved product direction changes captured 2026-10-14. This supersedes the earlier v0.2 Provider-ecosystem-first draft **within this draft branch**, not the frozen v0.1 source/tag. L1 evidence/adversarial review and acceptance remain required before Product Freeze, L2 or Task DAG.
>
> Immutable source baseline v0.1.0 @ `2313ba2773dac7aa535570e22760147d9b383b65`. Reuse v0.1 Resolver, ActionController, authorization, ShunStore, Windows Executor, three business verticals and Control UI.

## 1. Product definition and release outcome

v0.2 is a **usable Windows AI computer steward**, not a universal Provider ecosystem or generalized autonomous desktop agent. A non-developer should install/start it, say what they need in Chinese or English, review bounded scope and risk when necessary, get a **real verified result**, and reuse a previously verified script/Recipe without full LLM regeneration every time.

The six v0.2 product pillars:

1. **Real LLM integration**, both explicitly configured remote OpenAI-compatible and attested local on-device endpoints; no mock-only proof.
2. **High-ROI computer stewardship** based primarily on built-in Windows/Node functionality and carefully reviewed OSS libraries, not new general Provider breadth.
3. **LLM script creation + safe approval + reusable parameterized Recipes**; verified replay should be deterministic and generally model-free.
4. **A narrow, explicit multi-language script policy**; not arbitrary executable text running with the user's full rights.
5. **User-friendly Windows-first UI**, simple onboarding, real progress, explanations and recoverable task history.
6. **Minimal fixed OSS Provider set only**, reused from v0.1 and a few mature libraries; deep app8 Provider Factory, automatic multi-Provider discovery/benchmarking and marketplace deferred.

## 2. MVP task catalog (candidate P0)

Order by reuse of v0.1 kernel, repeat frequency and independently checkable outcome; no unsourced numeric ROI claims.

| Stage | User job | Execution path | Safety/verification contract |
| --- | --- | --- | --- |
| P0-A | **System overview and diagnosis**: CPU, RAM, disk usage, OS, uptime, top resource-consuming processes, installed software, startup entries (read-only) | Windows native APIs/PowerShell read-only commands, Node fs/os | Selectively gathered data with PII minimization; never infer a root cause from one snapshot; show evidence and uncertainty |
| P0-A | **Storage explanation and conservative cleanup**: which approved folder uses space, cache/temp classification, bounded cleanup | Reuse `vertical-storage`; typed native actions | Operator-approved roots; protected assets immutable; R2 preview+consent; verify bytes and canaries |
| P0-A | **File search / bulk organization**: find by name/type/content, report duplicates (read-only), group/copy/move/rename selected files | Native fs/approved `fd`/`ripgrep`, parameterized Recipe and typed I/O | First preview actual manifest; input untouched when copy-only; no overwrite/alias; R2 explicit approval for destructive/move/rename; crash recovery |
| P0-A | **Maintenance report**: disk/temporary files/software install state, relevant update and Windows Event data **read-only summaries** | native Windows diagnostics and curated read-only PowerShell; no direct OS repair | Privacy and volume boundaries; evidence citations; no unsupported “fixed your PC” claims |
| P0-B | **Re-use proven image batch and bounded software lifecycle** through the same UI | Reuse `sharp` and `WinGet` verticals | User selects scope/provider; preserve originals and managed user assets; maintain v0.1 authorization/verification |
| P0-B | **Scripted routine**: user says “every time I download invoices, organize them by month” → propose preview-able parameterized Recipe and perform **manual replay** when asked | LLM proposes script/typed plan, Recipe verifier/store, constrained host | No unattended background schedule; execution on selected root only, diff+parameter display, cached script rechecked before each replay |

P0-A are the indispensable initial user journeys; P0-B limited to reuse existing v0.1 capabilities and demonstrate explicit replay. If delivery time is constrained, postpone PDF/archive breadth, not LLM trust or safe script reuse.

**P1 if evidence and packaging are inexpensive:** PDF page merge/split via `pdf-lib` (one library), archive ZIP inspect/create/extract (one library), simple network connectivity diagnostic (read-only), Python generated-script run mode with pinned embedded runtime, explicit user-approved scheduling. OCR, FFmpeg video, software-driver manipulation, background autonomous maintenance and deep app8 integration **defer**.

## 3. Real LLM system (P0)

- One real **remote OpenAI-compatible endpoint** with user permission, URL/model/API-key onboarding, settings stored using OS credential mechanism; timeout, tokens/budget, model health, disclosure preview.
- One real **local** Ollama/llama.cpp-compatible endpoint with proven local model and **enforceable LOCAL identity/egress**. `localhost` and caller-provided `transport=LOCAL` labels alone do not qualify. v0.1 `planner-seam` intentionally refuses unprovable local, so design a host-controlled origin/egress boundary and falsification on real Windows; if unavailable, explicitly BLOCK local-mode release gate, never fake a pass.
- LLM jobs: user intent → structured `GoalProposal`, clarification, bounded maintenance diagnosis hypotheses, **script proposal**, script repair suggestion after observed failures, human-readable preview/reports. Reuse existing registered capability names and verified host facts; no unsupervised network/download or shell privileges.
- Only Shun deterministic verifier validates proposed capability, file refs, allowed action classes, script language and exact parameters. Model-proposed CLI args, URLs, commands, sources and trust claims are **untrusted content**, not authority.
- R0/R1/R2 risk gates and policy currentness remain with ActionController, not model confidence or UI. Remote request never silently receives file contents, process args, tokens, Windows user identity or unrelated directory metadata.
- Must pass actual-call tests with Chinese+English goals, hallucinated tools, prompt injection in filenames/documents, model outage, malformed JSON, budget exhausted, provider drift, disclosure refusal and zero egress under local-only.

## 4. Script support and reuse (P0)

The v0.2 definition is in [Script Recipe v0.2 draft](./script-recipe-v0.2-DRAFT.md). **Scripts are untrusted work products, not substitute Provider/authorization infrastructure.** All effects still pass Shun authorization and independent outcome verification.

| Language | Priority | P0 execution policy |
| --- | --- | --- |
| **JavaScript (Node, JS)** | **P0 primary** | Host-bundled pinned Node; generated JS may compute plans and read bounded facts via a mediated capability interface; no unrestricted `fs` write/child process/network. OS isolation required if raw JS would run outside mediation. TS is a developer language and may be compiled to JS but not an independent end-user runtime. |
| **PowerShell** | **P0 Windows specialist** | Windows-native read-only inventory and bounded diagnostics through **approved cmdlets/functions**, with structured JSON result. Arbitrary generated `.ps1`, `Invoke-Expression`, COM/WMI mutation, registry/service edits and elevation are NOT automatically executable. Require a proven host isolation/application-control policy for general PowerShell script execution; otherwise limited templates or proposal-only. |
| **Python** | **P1 optional v0.2** | Strong general scripting option, but pinned/embedded Python runtime, packages, sandbox and offline installation increase footprint. Allow import/export of Python source in UI and extend full execution only after Windows packaging, isolation and semantics pass; do not silently invoke host Python. |
| **CMD/.bat** | **legacy compatibility/read-only import** | No LLM-generated CMD execution in P0. `cmd.exe` syntax, quoting and batch redirection introduce disproportionate ambient authority/escaping risk. Parse known safe commands into structured operations or preview/deny. |
| **PowerShell admin / unrestricted arbitrary script** | **OUT OF SCOPE** | v0.1 privileged helper supports typed allowlist operations, not free-form model-authored elevated scripts. Consent alone never turns unknown commands into trusted authority. |

- **Two-layer model:** `ScriptProposal` is an editable/auditable implementation candidate, whereas `Recipe` stores approved intent, parameter schema, script/body hash, runtime identity, declared effects, risk, verifier and observed version/currentness. Replaying with new parameter values always recomputes scope and required approval. A script body edit = new revision and loses previous validation authority.
- **Process:** `Goal → structured proposal/script → syntax/schema/static checks → preflight in non-production scratch/isolation → dry-run manifest/diff → grant/risk preview → mediated effect call → semantic verifier → immutable run receipt → user-approved Recipe promotion → replay with revalidation`. Static analysis is a safety aid, never the sole proof of benign arbitrary code.
- Repeat recognition: goal/capability + normalized parameter schema, required object types and policy bound; choose `EXACT_REUSE` only if script hash/version/host/provider/policy/effects/verifier/currentness match; else `PARAMETER_REBIND_AND_RECHECK`, `REVALIDATE`, `REGENERATE` or `BLOCK`. **No “similarity ≈ permission”**.
- **Performance success** = lower measured model calls/latency/cost on a repeated journey, with equivalent independent task result. Track hits, false reuse, policy changes and reasons for misses; no made-up percentage target.
- Never persist credentials, private document content or model conversation in a reusable script by default. No automatic cloud/shell access from stored scripts, and no background recurring execution in v0.2.

## 5. Minimal Provider set and app8 boundary

- **REUSE** existing v0.1 `sharp` and `WinGet` only on already supported scope, and built-in Node/Windows APIs. **Add** `fd` + `ripgrep` for bounded search if needed; `pdf-lib` / one archival utility are P1 opt-ins only after ROI and Windows deployment review. No obligation to integrate qpdf+pdfcpu+libarchive+7-Zip simultaneously.
- v0.2 runtime remains capable of running typed Provider adapters, but **does not** deepen Provider discovery, automatic Provider generation, multi-Provider substitution benchmarks or catalog marketplace.
- **app8 remains independent, deferred.** Reserve schema import/admission compatibility only; no dependency on app8 v0.4 empirical release, no App8CapabilityImportAdapter required for v0.2 P0 and no automatic export-ready assertion. See candidate archive at `docs/research/v0.2/open-source-provider-candidates.md`.
- No mature library functionality reinvented gratuitously. Windows native tools are still runtime capabilities even if not branded an external Provider.

## 6. UI, delivery and safety UX

- One local Windows UI, plain Chinese and English, **real LLM chat/task input** with clarification and selected-root file picker, task intent explanation, bounded scope, preview of script/effects (non-expert view first), manual approval/decline, status, independent verification details, recoverable history.
- **Recipe library**: “Saved tasks” with human labels, parameter fields and scope, last verified date, last model use/cost, run/edit/delete/disable, policy-drift warning, script inspection as advanced disclosure. A script run must clearly state `SIMULATED`, `DRY_RUN`, `EXECUTED`, `VERIFIED`, `BLOCKED` without conflating.
- Real Windows portable delivery with bundled pinned JS runtime or documented checked OS dependency and one-step bootstrap. First run checks model endpoints, permission profile, allowed folders, network and bundled library hashes. No development checkout/pnpm, no mandatory administrator login. A full MSI not needed if portable route is actual end-user usable.
- Elevated actions remain explicit pre-existing *typed* executor flows with authentic UAC; generated scripts are not a new privilege boundary. LLM configuration/external data permission must be visible at request time.

## 7. P0 must-pass journeys / acceptance

1. **Real LLM:** Chinese and English “what is filling my selected disk?” becomes valid bounded plan; remote endpoint authentic call passes with explicit disclosure opt-in; actual local inference passes with attested no-external-host path. Malicious planner output cannot escape registered capabilities, and no planner configured preserves deterministic read-only use.
2. **Inventory:** native Windows process/disk/startup/software report matches independently measured host facts (no unsupported root cause claim); unintended reads of secrets denied.
3. **Files:** find selected files and generate rename/organize Recipe; dry-run contains real before/after manifest; controlled move under explicit R2 approval preserves sources when declined, no collision overwrite or symlink/junction escape.
4. **Script creation:** real model generates structured JS and a PowerShell diagnostic proposal from a user instruction; Python and CMD modes correctly preview/defer. Safe sandbox/mediation rejects file deletion, network egress, child spawn, encoded obfuscation, COM and credential access; any script requiring direct unverified host mutation is NOT_RUN/BLOCKED.
5. **Repeated Recipe:** two manual executions of same approved parametric script, second with **zero LLM calls**, equivalent verified output, exact hash/runtime/policy/scope checks; body tamper, policy drift, endpoint change, new destination outside grant or fixture mismatch causes revalidation or BLOCKED, no silent reuse.
6. **Existing vertical:** image and managed software lifecycle real UI integration without changing v0.1 product safety/ownership; bounded storage R2 approval, crash/uncertain-recovery and protected canaries.
7. **UI/package:** fresh Windows 11 end-user user-profile install/start without dev toolchain; distinct simulated and real labels, understandable consent, recipe history and clean removal. Support Windows Home and Pro or explicitly limit/downgrade features when isolation unavailable; don't silently assume Windows Sandbox is present.
8. **Release:** independent Windows negative/adversarial validation and full regression/hidden; install/run/restore, LLM privacy and actual model/cost evidence, script output and user-file invariant, release notes honest about safety proof bounds. CI/PR PASS never substituted for Release PASS.

## 8. Research / L2 decision list

- Windows Home/Pro **OS-supported sandbox and token isolation** per script class; PowerShell application-control policy; network egress controls; Node Permission Model only defense in depth (not kernel sandbox); Python runtime footprint. If no enforceable isolation for raw generated scripts, **run typed mediated actions only**, not unrestricted scripts.
- Whether `Recipe` may contain declarative action graphs, source text, or both, and what per-step signer/approval owns; prevent confused-deputy bypass.
- Which Windows inventory evidence is safe for remote summarization; minimum telemetry needed for local diagnostics; signed currentness of host context between proposal and effect.
- Minimum bundled LLM types/model sizes and onboarding, optional cloud, fallback; RAM/VRAM/cost bench on actual host.
- P0 user acceptance denominator based on repeatable 8–12 real Windows journeys; no unsupported “works on all PCs” claim.

## 9. Development process

L1 Product Evidence and draft product review → scope/risk closure and freeze → L2 Architecture and environment feasibility → bounded Task DAG (LLM integration, host script security and Recipe identity before UI workflows) → L3 tests/contracts/implementation → exact-SHA independent security review → full Windows build-host qualification, hidden and packaging → Release qualification/tag. No new demo factory when v0.1 evidence can be reused; don't freeze a misleading acceptance before Windows script isolation feasibility is proven.

## 10. Windows System API sourcing decision (Owner direction, 2026-10-14)

**Explicitly EXCLUDE `Koffi` and `node-win32-api` from v0.2 runtime dependencies, experiments and default architecture.** This is a scope/risk/maintenance decision, not a blanket claim that the projects are broken. Do not reintroduce a general-purpose JS FFI surface or a model-selected native DLL/function gateway as a substitute.

**Preferred three tier capability-adapter stack** (call these **tiers A/B/C**, distinct from project lifecycle L1 Product / L2 Architecture / L3 Implementation):

| Tier | Technology | Responsibility | v0.2 adoption |
| --- | --- | --- | --- |
| **A — foundational** | Native Node.js `fs/os`, trusted Windows PowerShell/CIM **fixed audited functions** | file-safe operations, storage/system info, service/event/startup inventory, bounded troubleshooting | **P0 actual host implementation.** Start here; avoid dynamic PowerShell assembled from a model. |
| **B — native platform interop** | **dynwinrt** (WinRT) and **node-api-dotnet** (.NET) | modern Windows notifications, pickers/device/app APIs; richer .NET management APIs when native/PowerShell contracts are insufficient | **P0 interface seam only; P1/conditional implementation per proven P0 user journey.** Both projects currently have preview-status surfaces; exact version and target API must pass native Windows host smoke/packaging. |
| **C — reviewed native module** | **napi-rs + windows-rs** | narrowly implemented Win32/COM/WinRT calls requiring precise lifetime, handle, memory, system service or special Windows access | **Only when A/B cannot support a specific high-ROI task safely; no generic native API gateway.** Pin Rust/Node-API/target architecture; test crashes, disposal and Node runtime versions. |

Select the narrowest supported binding per Capability. Multiple tiers are complementary, **not mandatory sequential dependencies**. A product that meets all P0 tasks using Tier A is allowed to ship without building Tier B or Tier C. If UI requires Windows native pickers/notifications, assess Tier B without forcing A/B/C everywhere.

**Maturity and trust caveats:**
- `dynwinrt` internally relies on a native Rust/libffi runtime; avoiding Koffi does **not** eliminate FFI/memory hazards. Its WinRT projection is the main candidate; experimental Classic COM/Flat Win32 projections cannot be assumed production-stable. Assess version/API-level support and Windows packaged/unpackaged identity.
- `node-api-dotnet` is a Microsoft-maintained public preview and can dynamically host .NET in process; Native AOT removes client .NET dependency **only for statically exported compatible APIs** and does not permit arbitrary reflection/dynamic assembly loading. Verify runtime footprint and installer identity.
- `napi-rs/windows-rs` isolates pointer/COM/Win32 complexity into a **reviewed native module**, but in-process native faults can still terminate Shun; where risk warrants, run sensitive native operations in a separate bounded helper process. Node-API ABI stability does not prove Shun's C/Rust/Windows calls are memory safe or security sandboxes.
- **LLM-authored JS/TS Recipes may call only Shun's approved typed SystemCapability interface.** Raw `powershell.exe`, `dotnet`, generated WinRT binding loading, `require('*.node')`, DLL names, pointer values, registry/service mutation, network and elevation are never model-provided authority. The same authorization, R2, scope,currentness and verifier gates apply whichever adapter tier executes the trusted tool.
- Do not use vendor identity as substitute for tests. Each admitted adapter requires exact package/dependency pin and supply-chain/license review, Win11 Home+Pro host observations, Unicode/locale cases, installation/upgrade/uninstall proof, failures and concurrency/resource-release tests.

**Validation before L2 freeze:** Tier A must demonstrate disk/memory/process/startup read-only diagnostics and bounded file plan; Tier B needs an API-specific independent smoke only if an accepted task truly needs its feature; Tier C is excluded until a named, demonstrable gap. This decision replaces any prior broad adoption advice for Koffi+node-win32-api. Relevant research and version verification: https://github.com/microsoft/dynwinrt , https://github.com/microsoft/node-api-dotnet , https://github.com/napi-rs/napi-rs , https://github.com/microsoft/windows-rs .
