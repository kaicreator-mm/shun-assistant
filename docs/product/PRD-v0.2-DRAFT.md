# Shun Assistant v0.2 — Product L1 / PRD DRAFT (LLM-First Usable Windows Steward)

> **UNFROZEN / PROPOSAL.** Parent #80, draft PR #81. Six user-approved product direction changes captured 2026-10-14. This supersedes the earlier v0.2 Provider-ecosystem-first draft **within this draft branch**, not the frozen v0.1 source/tag. L1 evidence/adversarial review and acceptance remain required before Product Freeze, L2 or Task DAG.
>
> Immutable source baseline v0.1.0 @ `2313ba2773dac7aa535570e22760147d9b383b65`. Reuse v0.1 Resolver, ActionController, authorization, ShunStore, Windows Executor, three business verticals and Control UI.

## 1. Product definition and release outcome

v0.2 is a **usable Windows AI computer steward**, not a universal Provider ecosystem or generalized autonomous desktop agent. A non-developer should install/start it, say what they need in Chinese or English, review bounded scope and risk when necessary, get a **real verified result**, and reuse a previously verified script/Recipe without full LLM regeneration every time.

The six v0.2 product pillars:

1. **Real LLM integration**, both explicitly configured remote OpenAI-compatible and attested local on-device endpoints; no mock-only proof.
2. **High-ROI Windows diagnosis and bounded system optimization**: identify evidence-supported performance problems, propose reversible optimizations, execute only admitted typed operations and measure before/after changes. Use Node/Windows built-ins first.
3. **LLM script creation + safe approval + reusable parameterized Recipes**; verified replay should be deterministic and generally model-free.
4. **A narrow, explicit multi-language script policy**; not arbitrary executable text running with the user's full rights.
5. **User-friendly Windows-first UI**, simple onboarding, real progress, explanations and recoverable task history.
6. **Minimal allowlisted Provider set, distributed on demand**: lean core installer with provider catalog/loader metadata, acquire optional signed/version-pinned Provider payloads only when a user-approved capability is needed; reuse v0.1 JIT lifecycle. Deep app8 Provider Factory, dynamic untrusted tool discovery and marketplace are deferred.

## 2. MVP task catalog (candidate P0)

Order by reuse of v0.1 kernel, repeat frequency and independently checkable outcome; no unsourced numeric ROI claims.

| Stage | User job | Execution path | Safety/verification contract |
| --- | --- | --- | --- |
| P0-A | **System overview and diagnosis**: CPU, RAM, disk usage, OS, uptime, top resource-consuming processes, installed software, startup entries (read-only) | Windows native APIs/PowerShell read-only commands, Node fs/os | Selectively gathered data with PII minimization; never infer a root cause from one snapshot; show evidence and uncertainty |
| P0-A | **Storage explanation and conservative cleanup**: which approved folder uses space, cache/temp classification, bounded cleanup | Reuse `vertical-storage`; typed native actions | Operator-approved roots; protected assets immutable; R2 preview+consent; verify bytes and canaries |
| P0-A | **File search / bulk organization**: find by name/type/content, report duplicates (read-only), group/copy/move/rename selected files | Native fs/approved `fd`/`ripgrep`, parameterized Recipe and typed I/O | First preview actual manifest; input untouched when copy-only; no overwrite/alias; R2 explicit approval for destructive/move/rename; crash recovery |
| P0-A | **Maintenance report**: disk/temporary files/software install state, relevant update and Windows Event data **read-only summaries** | native Windows diagnostics and curated read-only PowerShell | Privacy and volume boundaries; no unsupported root-cause or fix claim |
| P0-A | **System optimization**: execute one real verifiable improvement via already proven scoped cache/storage cleanup, plus startup/background pressure analysis (read-only) | Existing vertical-storage and typed executor, Node/CIM diagnosis | Baseline → exact-target preview/R2 approval → independently verify reclaimed bytes/protected canaries; startup toggle is P1 until a specific reversible method has host evidence |
| P0-B | **Re-use proven image batch and bounded software lifecycle** through the same UI | Reuse `sharp` and `WinGet` verticals; optional Provider payloads loaded only after curated JIT acquire | User selects scope/provider; preserve originals and managed user assets; maintain v0.1 authorization/verification |
| P0-B | **Scripted routine**: user says “every time I download invoices, organize them by month” → propose preview-able parameterized Recipe and perform **manual replay** when asked | LLM proposes script/typed plan, Recipe verifier/store, constrained host | No unattended background schedule; execution on selected root only, diff+parameter display, cached script rechecked before each replay |

P0-A are the indispensable initial user journeys; P0-B limited to reuse existing v0.1 capabilities and demonstrate explicit replay. If delivery time is constrained, postpone PDF/archive breadth, not LLM trust or safe script reuse.

**P1 if evidence and packaging are inexpensive:** PDF page merge/split via on-demand `pdf-lib` (one library), archive ZIP inspect/create/extract (one on-demand library), simple network connectivity diagnostic (read-only), power mode recommendation/explicit reversible configuration, limited startup-task/service optimization after independent safety proof, Python generated-script run mode with pinned embedded runtime. OCR, FFmpeg video, driver/firmware changes, invasive registry cleaners, unsupported service tweaks, unattended scheduling and deep app8 integration **defer**.

## 3. Real LLM system (P0)

- One real **remote OpenAI-compatible endpoint** with user permission, URL/model/API-key onboarding, settings stored using OS credential mechanism; timeout, tokens/budget, model health, disclosure preview.
- One real **local** Ollama/llama.cpp-compatible endpoint with proven local model and **enforceable LOCAL identity/egress**, evaluated against a user-provisioned runtime/model. Bundling a model in the core installer is not required. `localhost` and caller-provided `transport=LOCAL` labels alone do not qualify. v0.1 `planner-seam` intentionally refuses unprovable local, so design a host-controlled origin/egress boundary and falsification on real Windows; if unavailable, explicitly BLOCK local-mode release gate, never fake a pass.
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

- **REUSE** existing v0.1 `sharp` and `WinGet` only on already supported scope, and built-in Node/Windows APIs. **Add** `fd` + `ripgrep` for bounded search only if needed; `pdf-lib` / one archival utility remain P1 options. Except platform-provided native APIs and the trusted Shun bootstrap/executor, external Provider payloads are **not required to ship inside the core installer**. They are cached and activated from approved manifests on demand; no obligation to integrate qpdf+pdfcpu+libarchive+7-Zip simultaneously.
- v0.2 adds a **bounded lazy Provider acquisition/activation lifecycle** atop the v0.1 JIT, not deep Provider discovery: `CATALOG_APPROVED → ABSENT → DOWNLOAD_REQUESTED → VERIFIED → INSTALLED → READY → RETAINED/REMOVED`, with `BLOCKED/OFFLINE/DRIFT` typed states. Trust comes from a previously approved signed/pinned catalog, not the LLM or download result. No automatic Provider generation, multi-Provider substitution benchmarks or catalog marketplace.
- **app8 remains independent, deferred.** Reserve schema import/admission compatibility only; no dependency on app8 v0.4 empirical release, no App8CapabilityImportAdapter required for v0.2 P0 and no automatic export-ready assertion. See candidate archive at `docs/research/v0.2/open-source-provider-candidates.md`.
- No mature library functionality reinvented gratuitously. Windows native tools are still runtime capabilities even if not branded an external Provider.

## 6. UI, delivery and safety UX

- One local Windows UI, plain Chinese and English, **real LLM chat/task input** with clarification and selected-root file picker, task intent explanation, bounded scope, preview of script/effects (non-expert view first), manual approval/decline, status, independent verification details, recoverable history.
- **Recipe library**: “Saved tasks” with human labels, parameter fields and scope, last verified date, last model use/cost, run/edit/delete/disable, policy-drift warning, script inspection as advanced disclosure. A script run must clearly state `SIMULATED`, `DRY_RUN`, `EXECUTED`, `VERIFIED`, `BLOCKED` without conflating.
- Real Windows portable delivery with pinned Shun **core** JS runtime or documented checked OS dependency and one-step bootstrap, **without bundling optional external Provider binaries/libraries/models**. First run checks model endpoints, permission profile, allowed folders, catalog trust/signing metadata and core library hashes. A needed Provider is clearly described (size, source, permission, license and offline alternatives), downloaded only after suitable user consent, then independently verified and loaded. No development checkout/pnpm or mandatory administrator login. A full MSI is not required if portable route is usable.
- Elevated actions remain explicit pre-existing *typed* executor flows with authentic UAC; generated scripts are not a new privilege boundary. LLM configuration/external data permission must be visible at request time.

## 7. P0 must-pass journeys / acceptance

1. **Real LLM:** Chinese and English “what is filling my selected disk?” becomes valid bounded plan; remote endpoint authentic call passes with explicit disclosure opt-in; actual local inference passes with attested no-external-host path. Malicious planner output cannot escape registered capabilities, and no planner configured preserves deterministic read-only use.
2. **Inventory:** native Windows process/disk/startup/software report matches independently measured host facts (no unsupported root cause claim); unintended reads of secrets denied.
3. **Files:** find selected files and generate rename/organize Recipe; dry-run contains real before/after manifest; controlled move under explicit R2 approval preserves sources when declined, no collision overwrite or symlink/junction escape.
4. **Script creation:** real model generates structured JS and a PowerShell diagnostic proposal from a user instruction; Python and CMD modes correctly preview/defer. Safe sandbox/mediation rejects file deletion, network egress, child spawn, encoded obfuscation, COM and credential access; any script requiring direct unverified host mutation is NOT_RUN/BLOCKED.
5. **Repeated Recipe:** two manual executions of same approved parametric script, second with **zero LLM calls**, equivalent verified output, exact hash/runtime/policy/scope checks; body tamper, policy drift, endpoint change, new destination outside grant or fixture mismatch causes revalidation or BLOCKED, no silent reuse.
6. **Existing vertical:** image and managed software lifecycle real UI integration without changing v0.1 product safety/ownership; bounded storage R2 approval, crash/uncertain-recovery and protected canaries.
7. **UI/package:** fresh Windows 11 end-user user-profile install/start without dev toolchain or preinstalled optional providers; distinct simulated/real and provider-missing/offline/download labels, understandable consent, recipe history and clean removal. Support Windows Home and Pro or explicitly limit/downgrade features when isolation unavailable; don't silently assume Windows Sandbox is present.
8. **Optimization:** baseline → bounded signed-plan storage cleanup → independent reclaimed-bytes/protected-file oracle; read-only startup pressure summary. P1 startup mutation only with exact before/after/restore evidence. No invented speedup percentage. Negative cases: security/driver target, unknown startup mechanism, policy drift and boot-pending effects.
9. **On-demand Provider:** fresh package starts without external Provider payload; user-approved first-use acquisition from exact pinned trusted source, binary/package hash verified, no duplicate concurrent downloads, cache reuse after restart, corrupt/signature/architecture mismatch BLOCKED, offline absence yields actionable error without breaking core; user-owned assets not deleted on Provider removal.
10. **Release:** independent Windows negative/adversarial validation and full regression/hidden; install/run/restore, LLM privacy and actual model/cost evidence, script output and user-file invariant, release notes honest about safety proof bounds. CI/PR PASS never substituted for Release PASS.

## 8. Research / L2 decision list

- Windows Home/Pro **OS-supported sandbox and token isolation** per script class; PowerShell application-control policy; network egress controls; Node Permission Model only defense in depth (not kernel sandbox); Python runtime footprint. If no enforceable isolation for raw generated scripts, **run typed mediated actions only**, not unrestricted scripts.
- Whether `Recipe` may contain declarative action graphs, source text, or both, and what per-step signer/approval owns; prevent confused-deputy bypass.
- Which Windows inventory evidence is safe for remote summarization; minimum telemetry needed for local diagnostics; signed currentness of host context between proposal and effect.
- Minimum bundled LLM types/model sizes and onboarding, optional cloud, fallback; RAM/VRAM/cost bench on actual host.
- P0 user acceptance denominator based on repeatable 8–12 real Windows journeys; no unsupported “works on all PCs” claim.

## 9. Development process

L1 Product Evidence and draft product review → scope/risk closure and freeze → L2 Architecture and environment feasibility → bounded Task DAG (LLM integration, host script security and Recipe identity before UI workflows) → L3 tests/contracts/implementation → exact-SHA independent security review → full Windows build-host qualification, hidden and packaging → Release qualification/tag. No new demo factory when v0.1 evidence can be reused; don't freeze a misleading acceptance before Windows script isolation feasibility is proven.

## 10. Windows system access and Rust FFI/performance module — **two implementation layers** (Owner direction, 2026-10-14)

**Decision:** Retain exactly TWO trusted implementation layers. The second layer is **not just a Win32 API adapter**: it is Shun's **native Rust module for external FFI interoperability, performance-intensive algorithms and operations cumbersome/unsafe/unreliable to implement directly in JS**. It is conditional on demonstrated requirements; it must not become a universal foreign-function execution gateway.

**Exclude v0.2 dependencies:** `dynwinrt`, `node-api-dotnet`, `Koffi`, `node-win32-api`. No third managed interop layer or model-selected native symbol/DLL invocation. These are **implementation layers**, different from development gates Product L1 / Architecture L2 / Implementation L3.

| Layer | Technology | Role | Delivery gate |
| --- | --- | --- | --- |
| **Layer 1 — TypeScript/Node + Windows built-ins** | Node.js native `fs/os/process` and bounded built-in Windows interfaces; **reviewed, fixed-function** PowerShell/CIM | All ordinary business orchestration, file operations, machine diagnostics and bounded system actions through existing Shun ActionController. The primary and default v0.2 implementation. | **P0 mandatory.** Confirm real Windows support (including Home, Pro), end-user packaging, source/file scope, privacy, verifier and recovery. |
| **Layer 2 — trusted Rust Native/FFI** | **Rust + napi-rs** for Node-API bindings; **windows-rs** when Win32/COM/WinRT is needed; reviewed Rust `extern "C"`/library bindings to third-party native APIs as needed | **(a)** wrap approved external FFI libraries / native C ABI / OS API, **(b)** accelerate measured CPU/memory intensive workloads, **(c)** implement features awkward in JS (complex handles, unsafe buffer lifetimes, highly concurrent native state, typed low-level OS APIs). | **Conditional** — no forced Rust work or binary dependency if Layer 1 suffices. Each Rust addition names user value, unmet Layer 1 constraint, FFI/library provenance or measured benchmark, semantic tests and security ownership. |

### Direction of FFI and ownership

```text
  LLM Goal / vetted JS-TS Recipe
               ↓ (only typed, mediated SystemCapability calls)
  Shun Resolver / ActionController / verifier
       ├── Layer 1: Node.js + fixed-function PowerShell/CIM
       └── Layer 2: trusted Rust module
                      ↑ Node.js ↔ Rust: N-API via napi-rs
                      ↓ Rust → Windows: Win32/COM/WinRT via windows-rs
                      ↓ Rust → approved native libraries: typed FFI/C ABI
                      ↔ optional Rust → external clients: explicit versioned C ABI
                          (ONLY if a real independent consumer requires one)
```

- The **primary external-facing boundary for Shun's Node host** is the **typed N-API interface** exposed by `napi-rs`. Rust may **consume** foreign FFI from pinned/trusted native libraries and Windows OS interfaces. If later other languages/processes must **call into** Rust, a separate narrowly defined, versioned `extern "C"` API is allowed after demonstrated demand; it is **not** mandatory for v0.2 and must not expose generic invocation by symbol name.
- **Performance is evidence-led.** First compare a representative Node.js implementation against Rust on real host workloads (time, p95 latency, CPU, memory, data-transfer/copy overhead, packaging cost and failure modes). Include Rust only when correctness, system API coverage or measured benefit justifies native maintenance; no arbitrary performance PASS threshold asserted before benchmarking.
- **Strict native boundary:** small typed input/output contracts; validate lengths, encodings, ownership, overflow, handles, nulls, thread/apartment affinity and cancellation; bound memory/CPU/timeout. Catch/contain Rust panics at FFI boundaries where feasible; never unwind across a C ABI. A crash in an in-process native module can still take down Node; use a separate signed bounded helper with structured IPC for high-risk or unstable native operations, not just wishful try/catch.
- **Supply-chain:** pin exact Rust module/target architecture and external library versions/hashes, licenses and distribution obligations; verify Windows 11 Home/Pro and native packaging/uninstall. No unreviewed dynamically loaded DLL paths, arbitrary `GetProcAddress`, or user/LLM-selected FFI entrypoints. Revocation or drift makes binding unavailable.
- **Permissions unchanged:** Rust/native FFI does **not** carry independent execution authority. A JS/TS Recipe can call only Shun's approved `SystemCapability` tools; it cannot import `.node` modules, pass raw DLL pointers, spawn arbitrary PowerShell, perform network activity or elevate. All mutating effects still require v0.1 policy/currentness, bounded target, R0/R1/R2, independent oracle and journal.
- **Keep Layer 1 generic but controlled:** audited PowerShell/CIM commands must never be assembled from model-generated raw text; fixed functions with validated parameters only. The Windows shell/GUI framework may supply its own supported file pickers and notifications without creating a new native bridge; only make Layer 2 when a concrete missing functionality requires it.

### L2 entry and test requirements

- **Layer 1** delivers a real host-observed Windows inventory, user-selected scoped file plan, real LLM proposal and at least one repeatable validated Recipe with no LLM call on exact replay.
- **Layer 2** is triggered ONLY for one documented capability gap, an approved external FFI library integration, or a measured performance bottleneck. For each use record `WHY_NOT_NODE`, `WHY_RUST`, `FFI_BOUNDARY`, exact native dependency provenance, risk/OS permissions, benchmark methodology (if speed is the reason), separate tests/rollback and run receipts. If no such use case exists in v0.2, `RUST_NATIVE_MODULE=NOT_REQUIRED`.
- Avoid creating a generic cross-language/plugin framework, compiler, scripting VM or provider-discovery layer just to accommodate Rust; defer broad Provider/app8 integration and retain two-layer simplicity.

**Product direction tags**:
```ini
WINDOWS_IMPL_LAYERS=TWO
LAYER_1=NODE_NATIVE_PLUS_FIXED_POWERSHELL_CIM
LAYER_2=RUST_NAPI_FFI_PERFORMANCE_OPTIONAL
RUST_EXTERNAL_NATIVE_LIB_FFI=SCOPED_PINNED_BINDINGS
RUST_EXPORT_C_ABI=ONLY_ON_DEMONSTRATED_EXTERNAL_CONSUMER
DYNWINRT=EXCLUDED_V02
NODE_API_DOTNET=EXCLUDED_V02
KOFFI=EXCLUDED_V02
NODE_WIN32_API=EXCLUDED_V02
LLM_RECIPE_RAW_FFI=FORBIDDEN
```

## 11. Windows optimization and on-demand Provider delivery (owner additions, 2026-10-14)

### 11.1 Optimization is a verified effect, not a performance marketing claim

- **P0 user outcomes**: explain significant storage consumers (within approved roots), perform already proven scope-bounded temp/cache cleanup and verify reclaimed bytes, identify startup and background app pressure from factual observations. A read-only recommendation is a valid result when unsafe or unsupported. **Startup disable/restore is P1**, admitted only after a specific user-level mechanism has observed reversibility and a post-state oracle.
- Workflow: `OBSERVE baseline → RECOMMEND alternatives + likely impact + evidence confidence → PLAN typed concrete target → R2 preview/authorize for user-state mutations → APPLY limited change → VERIFY actual Windows state → RECORD before/after + RESTORE handle`. Verification of a disabled startup entry can confirm a configuration change immediately; reduced boot delay is **NOT proven** until a comparable subsequent boot is observed. CPU/memory readings are noisy and must not be misrepresented as causal improvement.
- Do **not** conflate Windows built-in Storage Sense, Shun's existing private workspace cleanup and full system-drive cleaning. Storage Sense has documented scope and user-specific Downloads/Recycle Bin policies; Shun must not imply its C003 workspace cleaner can cleanse all of `C:\` or delete user Downloads.
- Protected system/AV/security software, core services, drivers, registry "optimization" bundles, event log clearing, prefetch deletion, pagefile edits, bcdedit, disk partition operations, forced service disable, hidden Defender/Windows Update downgrade, and arbitrary LLM-authored elevated PowerShell **OUT OF SCOPE** for P0. Prefer offering a safe native Windows Settings deep-link instead of pretending Shun did a privileged change.
- P1 may consider user-level startup toggles, narrowly defined power policy or per-user scheduled-task configurations only with machine-specific reversible evidence and explicit permissions. A recommendation and safe official-UI handoff remains available without claiming automatic repair.

### 11.2 Tiny core, fixed approved catalog, lazy Provider payloads

- **Core package** includes UI/LLM mediation, trusted download verifier, pinned Provider **catalog metadata**, typed adapters (or minimal trusted adapter bootstrap), ActionController/Resolver/ShunStore/Recipe runtime and its startable JS runtime. Optional OSS binaries/native `sharp` payloads and local model weights are **not bundled**. Offline core diagnostics require no provider/model download; actual local LLM needs a user-provisioned trusted model endpoint or an independently approved later on-demand model acquisition. If an adapter requires native Node ABI or dynamic JS module files, L2 must design a reviewed compatible signed module artifact and verify it before import; code loading is a privileged boundary.
- **On-demand path:** goal resolves an already registered capability → core checks user/host environment and existing installed binding → if absent and network allowed, show exact package, size, version, license/source, required permissions and optional retention → user consents to acquisition if required → download from catalog-owned pinned origin to staging without executing → SHA256/signature and dependency/architecture checks against a trust root that **preceded** the download → atomic install/activation, controlled typed adapter execution, independent output verification → cache/retain or provenance-safe removal. Catalog updates are a separate authenticated, reviewable process, not a task-time LLM suggestion.
- **Failure paths:** absent provider + offline/network denied `PROVIDER_NOT_AVAILABLE` with download-once/manual-install alternatives; tamper or bad signature `PROVIDER_TRUST_FAILED`; unexpected artifact/version/OS `PROVIDER_BINDING_MISMATCH`; interrupted download `ACQUIRE_INCOMPLETE`; install / effect uncertainty → journal-first reconcile, never blind retry. Respect metered networks and disk quotas, and never depend on a remote endpoint to fulfill LOCAL_ONLY execution.
- **Cache and Recipe semantics:** each Recipe pins a logical capability + provider compatibility/version bounds and exact approved runtime/binary evidence; provider absent on replay leads to explicit reacquisition and revalidation (not auto-autorun from untrusted state). Provider removed only if not in active use; known user-owned assets/config are preserved. Module hot reload inside a busy Node process is **not** an acceptance requirement; on-demand availability across tasks or bounded worker process restarts is sufficient.
- **Out of scope:** provider marketplace, arbitrary GitHub URL downloads, self-authored manifest trust, LLM-generated installation commands, every task scanning the internet for tools, enterprise auto-update orchestration and full app8 factory integration. The minimal allowlisted collection remains the v0.2 boundary.

### 11.3 L2 / release questions

- `CORE_VS_OPTIONAL_ARTIFACT` manifest; build/runtime compatibility for `sharp` and any optional native modules; pinned catalog signature keys and update policy; offline-first-run behavior; provider cache/GC rules; resolver waiting vs approval UX; separation of acquire permission from target write permission; measured installer footprint/download speed. These are implementation decisions, **not preconditions for making the product-scope decision**.
- Real Windows Home/Pro release qualification must include initial core-only launch, native optimization with no external Provider download, one on-demand external Provider install/use/reuse/remove, tamper/error negatives, and no protected file loss. No unverified `WINDOWS_OPTIMIZATION_PASS` or `DYNAMIC_PROVIDER_PASS` claims in L1.

```ini
WINDOWS_OPTIMIZATION=V02_P0_BOUNDED_REVERSIBLE
PROVIDER_DELIVERY=V02_P0_MINIMAL_ALLOWLIST_JIT
OPTIONAL_PROVIDER_BINARIES_IN_CORE=NO
PROVIDER_MARKETPLACE=DEFERRED
APP8_DEEP_INTEGRATION=DEFERRED
PRODUCT_FREEZE=NOT_YET
```
