# Shun Assistant v0.2 — Product L1 / PRD draft

> STATE: **PRODUCT_L1_DRAFT_UNFROZEN**. Work item: #80. This is a proposal based on the three v0.2 objectives, not approved Product Freeze, L2, task DAG or implemented functionality.
>
> Source baseline: [v0.1.0](https://github.com/kaicreator-mm/shun-assistant/tree/v0.1.0) @ `2313ba2773dac7aa535570e22760147d9b383b65`. Reuse security/authorization/recovery/provider seams and existing three real reference verticals; do not modify frozen v0.1 artifacts.

## 1. Product outcome

Shun v0.2 is a usable, local-first **Windows AI task assistant**: user describes a file/document/software/storage task in natural language, Shun identifies a registered capability and its feasible trusted provider, shows a bounded plan, performs the task under policy and approvals, independently verifies results, and can explain or recover failures. Users should **not** need to learn the provider's CLI, install Node/pnpm, or manipulate test fixtures.

No general-purpose unrestricted desktop agent. Provider and execution policies, not LLM confidence, bound what is possible.

## 2. Scope prioritized by benefit and integration effort

All rows are PROPOSED until evidence/acceptance review. Reuse existing Loops A/B/C first, then grow the capability surface.

| Stage | User job and minimum observable result | Provider direction | Explicit boundary |
| --- | --- | --- | --- |
| P0 Core | Through ONE real UI submit and execute **image batch resize**; verify outputs/EXIF/quality and source untouched | Existing sharp/vertical-image | Current v0.1 control UI image route is demo only; wire real vertical |
| P0 Core | Through same UI **trusted software acquire/use/retain or safe remove**; show provenance/version and R2 gate | Existing vertical-jit and WinGet; controlled portable | Not arbitrary package-manager uninstall, no unproven residue removal |
| P0 Core | Through same UI **bounded storage diagnosis/cache cleanup**; show scope, approval and reclaimed bytes | Existing vertical-storage | Restricted operator-issued scope and protected assets |
| P0 High ROI | **Find files** by name/type/content and **batch rename/copy/move** with preview, collisions, source verification, no overwrites | Native fs + fd/ripgrep; tool-call adapters | No broad destructive dedup or arbitrary recursive deletion |
| P0 High ROI | **Merge/split/extract PDF pages** and verify page order/count + source preservation | pdf-lib (TS I0), qpdf/pdfcpu (I1 alternatives) | OCR and arbitrary PDF repair not required for first usable tranche |
| P0 High ROI | **Create/extract ZIP/TAR/7z**, inspect entries before extracting, verify expected hashes, reject traversal/symlink/zip bombs | libarchive or 7-Zip (licensed/pinned) | Never extract into an unapproved/protected tree; no arbitrary executables |
| P0 Cross-cut | Trusted **real LLM**, common Provider registry, usable Windows packaging/onboarding, progress/results/failures, DEMO visibly separate from REAL | v0.1 contracts, resolver, authority, store and UI | No free-form model-generated shell/PowerShell or hidden data upload |
| P1 Optional | OCR/scanned PDF, simple video/audio convert, explicit user-reviewed Recipe save/replay | Tesseract/OCRmyPDF, FFmpeg | Include only after P0 acceptance; dependencies/licensing reviewed |
| Defer | Broad system repair/drivers/firmware, remote RunX/legacy, universal GUI Computer Use, unattended background automation, automatic Recipe promotion | Later versions | No accidental expansion of Product Freeze |

**ROI scoring before freeze:** observable weekly demand/job frequency, saved manual steps, reuse of v0.1 core, Provider availability/license, risk of damaging user data, install friction, independent semantic verification feasibility. Numeric score must be based on actual sample journeys, not invented usage data. If P0 overloads capacity, remove optional feature *families*, never weaken safety gates.

## 3. Real LLM is a product P0, not a stub

- Support at least one **real external OpenAI-compatible** inference endpoint and one **real local** Ollama/llama.cpp-compatible endpoint in the Windows reference host matrix. User selects model/provider and sees LOCAL vs REMOTE + costs and disclosure scope; timeout, cancellation, budget and rate limit controls.
- API surface `GoalRequest → PlannerPort → strict GoalProposal schema → normalizeGoal → Registry/Resolver → ActionPlan`. A planner may suggest known capability IDs, object references and task constraints, but may not emit executable commands or grants. Unknown/missing Providers, paths, permissions, hallucinated operations, ambiguous goals and low-confidence tool choices stay NOT_READY or ask clarification. Deterministic path remains functional without LLM.
- **Repair v0.1 LOCAL planner trust posture without weakening it.** `packages/resolver/src/planner-seam.ts` currently rejects ALL caller-labeled LOCAL Planner execution as unverifiable transport. v0.2 L2 must define an OS-enforced host-origin/no-network boundary, tested by malicious remote-backed-local adapter, egress denial and cross-account spoof. A loopback URL or declaration alone is not sufficient evidence of local inference.
- Remote LLM: explicit opt-in per model/goal, deny by default for local-only, redact paths/tokens/private content, structured data-minimization audit, no task evidence/files in remote prompt unless separately approved, reproducible request and token cost metadata (without sensitive raw payload).
- Prove real API calls and model output, schema-negative cases, model outages/fallback, deterministic replay tests, provider and tool-hallucination rejection, and R2 approval invariants. Do not accept a mocked LLM as the sole integration proof.

## 4. Open-source Provider ecosystem (real implementations)

- Use a **capability-first registry**, not a giant list of installable packages. `CapabilityDefinition → ProviderDefinition → ProviderEnvironmentBinding` with per-binding probe and exactly typed inputs/outputs.
- Every accepted Provider record: upstream URL, license + transitive/distribution review, exact version/checksum/signature if available, Windows x64 support, interface (`I0` library / `I1` CLI / `I2` structured IPC/MCP), executable pin, input/output contract, scope+effects, process sandbox/no-shell spawning, output semantic verifier, expected performance ceilings, cancellation, fail-closed error handling, acquisition/retention/removal. Do not silently auto-download arbitrary binaries on plan suggestion.
- Benchmark ≥2 different Providers for **one identical capability contract** (PDF merge, for example) to prove true substitutability and deterministic fallback. This is a design acceptance target, not a current claim.
- Minimum credible approved P0 set: existing sharp + WinGet + native filesystem, new fd/ripgrep + pdf-lib/qpdf/pdfcpu + a vetted archive tool. See `docs/research/v0.2/open-source-provider-candidates.md`.
- Deny zip-slip, decompression bombs, reparse-point/junction and output-to-input aliases; output creation is O_EXCL or verified atomic staging; grant only bounded root paths; provide independent before/after file manifest and observable risk gate. Store Provider lifecycle state and receipts in ShunStore.

## 5. Usable packaging and UI

- End user can launch a Windows 11 x64 **portable** package or bounded installer without configuring Node/pnpm, Python test harness or admin ownership manually. One secure onboarding: workspace roots, exclusions, available Provider probes, LLM setup/test, privacy choice, restore/backup policy. Non-admin default.
- UI provides actual file/folder picker, previews with side effects and exact planHash, human-readable risk, approval/decline, task queue, live progress, verification report and history, clear DEMO/REAL indicator, actionable failure/recovery. Existing real-storage UI currently has a narrow C003-only scope; it is not the v0.2 complete application.
- A portable archive may satisfy P0 if fully offline-startable with bundled/pinned runtime and clean uninstall. MSI is not automatic requirement. The package/security/license evaluation chooses the least complex reliable Windows delivery.
- Localization: Chinese and English intent and key approval UI, with no reliance on English-only `storage|cache` regex recognition. Open unsafe arbitrary paths only with explicit operator-approved workspace grant.

## 6. User acceptance examples (to be turned into hidden cases)

- Chinese goal: resize selected 100 JPG/PNG images, max 1600 px, preserve original; output count/format/originals verified; empty provider → safe error.
- Find documents with a text phrase under selected scope; preview 50 rename operations; collisions and invalid paths refused; no source lost when cancellation/crash occurs.
- Merge three PDFs into one; verify page count/order, all sources unchanged; malformed/encrypted input surfaces typed error.
- Extract ZIP with `../` entry or reparse-point escape into selected root → reject and prove no protected write. Valid archive produces manifest and checked output.
- Real UI JIT Provider lifecycle with official provenance and safe retain/remove; rejected untrusted source does not prompt for dangerous approval.
- Real local storage cache classification and R2 approval; protected document under a cache-named tree remains untouched.
- LLM success from **actual local and actual remote** backend (separate privacy profiles); injected prompt/tool-name/source content cannot bypass registered schemas; offline task makes remote call count zero.

## 7. Evidence and release bar

P0 family must-pass Windows host tests; independent semantic gold and negative/falsification suites; no user/protected data loss; no remote upload under LOCAL_ONLY (network-level proof or explicitly bounded release condition); full regression; complete package clean-install/run/remove; model latency/cost/availability telemetry; Provider version/provenance/license manifests. PR PASS ≠ v0.2 release PASS.

Start by L1 Product Evidence/PRD and Provider candidate risk scoring → Fresh Product Adversarial Review → Product Freeze → L2 Architecture and environment/preflight → Task DAG with bounded scopes → L3/PR/CI → full Windows E2E, hidden and release qualification. No demo loops solely to prove old v0.1 seams. All new source must be introduced after decisions are frozen.

## 8. Open decisions for Product Freeze

Final P0 tranche size (especially Archive vs PDF/Files), local host network enforcement design, minimum supported model classes and memory footprint, packaging delivery class, OCR admission and licenses, success-metric denominators, product onboarding risk class. None of these is silently decided by this draft.
