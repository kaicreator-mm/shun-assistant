# Shun v0.2 — Minimal open-source Provider shortlist (L1 RESEARCH DRAFT)

> **v0.2 product scope updated 2026-10-14:** Real LLM + high-ROI Windows stewardship/verified optimization + generated script/Recipe reuse + usable UI. **Minimal curated, ON-DEMAND downloadable Provider payloads; no optional Provider binaries bundled in Shun Core.** Not a deep Provider platform or app8 integration release. All new OSS binaries must pass exact-version, Windows packaging, provenance, runtime ABI, license and safe-recovery checks. See #80, `docs/product/PRD-v0.2.md` and `docs/product/script-recipe-v0.2-DRAFT.md`.

## 1. Rule: minimum Provider breadth

Most system-management functions should be supplied by **native Windows APIs and built-in audited host tools**, requiring no extra Provider download. In Shun's architecture those remain trusted capability bindings; no new third-party platform is needed. Optional external Provider **payloads** are acquired lazily from a *small pre-approved manifest catalog* when the user first uses their capability, and cached/revalidated thereafter. A generated script is not a trusted Provider, installer or substitute for a capability contract; mutation is handled by Shun's typed effect executor.

| Tier | Capability | Provider / OSS asset | Role in v0.2 | Evidence or admission |
| --- | --- | --- | --- | --- |
| **P0 REUSE** | Image batch | [sharp](https://github.com/lovell/sharp) and `@shun/vertical-image` | Keep logical capability/approved adapter in catalog; first-use **lazy-download** optional Sharp native payload only with exact Node ABI/arch checks; wire production UI | Frozen v0.1 B037 oracle; lazy acquisition itself still requires Windows E2E, not currently proven |
| **P0 REUSE** | Managed software/JIT | [WinGet](https://github.com/microsoft/winget-cli) and `@shun/vertical-jit` | Extend v0.1 trusted JIT acquisition/journals for approved optional tool payloads, keep typed WinGet operations; Windows system WinGet presence must be probed | Frozen v0.1 B038 scoped lifecycle evidence; **new generic payload loader not yet implemented** |
| **P0 REUSE** | Storage cleanup | Windows filesystems and `@shun/vertical-storage` | Keep user-approved bounded cache cleanup | Frozen v0.1 C003 actual Control UI |
| **P0 NATIVE** | Windows diagnostics, inventory, safe file operations | Node `fs/os`, PowerShell audited read-only functions, Windows native APIs | **Main new product features**; script plan and typed effect API | Independent host observation, privacy/scope, high-risk authorization |
| **P0 LIMITED** | File name/content search | [fd](https://github.com/sharkdp/fd) and [ripgrep](https://github.com/BurntSushi/ripgrep) | Download only when native fs search falls short and user accepts; no core installer inclusion | Same bounded root/facts, shell-free argv, result redaction, exact exe identity |
| **P0 INFERENCE** | Local model | [llama.cpp](https://github.com/ggml-org/llama.cpp) **or** [Ollama](https://github.com/ollama/ollama) | User-configured/installed real local model/runtime; **model weights excluded from Core**; optional future curated download | Independently prove true local inference and no remote origin masquerade |
| **P0 INFERENCE** | Remote model | Configured OpenAI-compatible endpoint | One real remote model path | Per-task user disclosure decision, privacy minimization and cost/budget |
| **P1 OPTIONAL** | Basic PDF split/merge | [pdf-lib](https://github.com/Hopding/pdf-lib) | One low-footprint TS module if LLM/Recipe P0 gates complete | PDF page/order/source semantic oracle |
| **P1 OPTIONAL** | Archive ZIP/7z/TAR | [libarchive](https://github.com/libarchive/libarchive) **or** [7-Zip](https://www.7-zip.org/) | One vetted option only after safe extraction evaluation | Deny traversal, zip bombs, NTFS junctions and foreign file overwrite |
| **LATER** | Advanced PDF alternatives | [qpdf](https://github.com/qpdf/qpdf), [pdfcpu](https://github.com/pdfcpu/pdfcpu) | No P0 multi-Provider benchmark/substitutability milestone | Candidate notes only |
| **LATER** | OCR and scanned PDF | [Tesseract](https://github.com/tesseract-ocr/tesseract), [OCRmyPDF](https://github.com/ocrmypdf/OCRmyPDF) | Defer Windows dependency/packaging burden | Pin language packs; OCRmyPDF/ghostscript dependency/license review |
| **LATER** | A/V operations | [FFmpeg](https://ffmpeg.org/) | Defer until LLM/Recipe product is independently useful | Correct LGPL/GPL build and output-quality verification |
| **LATER** | Duplicates | [jdupes](https://github.com/jbruchon/jdupes) | Report-only candidate; no v0.2 bulk deletion | Source-preserving hash report |
| **LATER** | Advanced JSON transform | [jq](https://github.com/jqlang/jq) | Native JS preferred if simpler | Pinned binary only if justified by measured ROI |

### License / installer traps

- Official [7-Zip](https://www.7-zip.org/license.txt) licensing spans LGPL/BSD and unRAR restrictions; pin actual build/distributed components before packaging.
- [FFmpeg legal](https://ffmpeg.org/legal.html) describes LGPL vs GPL build variations; installation claims must be build-specific.
- [OCRmyPDF Windows installation](https://ocrmypdf.readthedocs.io/en/latest/installation.html) includes several runtime dependencies; not free in product onboarding cost.
- Local model runtimes have different packaging/runtime requirements; host attestations and network behavior matter more than HTTP interface compatibility.
- No license statement above is a final distribution opinion or exact-version certification. Pin selected upstream tag/artifact, verify SPDX+transitives, cryptographic hash, Windows x64 behavior and removal obligations.

## 2. Lightweight fixed Provider record in Shun

For **each tool actually admitted** keep a minimal stable record:

`capabilityId`; `bindingId`; `origin+version+binaryHash`; `licenseDecision`; `WindowsHostRequirements`; `interface I0/I1`; typed input/output/error; observed allowed roots + read/write/network/privilege budget; no shell string; independent verifier; retained result and updated status; **catalog signature, download URL allowlist, artifact size/dependency hashes, disk quota, permission-to-acquire, native ABI compatibility and cache identity**.

This is **not** authorization. LLM-created `ScriptProposal` may refer to a registered capability but cannot install, trust, sign, grant or execute a new arbitrary Provider. **Acquisition authorization is separate from action execution authorization**; already-verified payloads still require task-level grants. Keep first-run probes quick and local. Don't introduce automated global marketplace browsing or mass wrapper generation to ship v0.2.

## 3. app8 deferred deliberately

[kaicreator-mm/app8](https://github.com/kaicreator-mm/app8) is an attractive **future Provider Factory/Evidence producer**, NOT a runtime tool executor and NOT a v0.2 P0 prerequisite. When examined at `app8/main@7803594b38a959c3c5d8cf2ca2a7d8149a08db1a`, app8 supplied source discovery, Evidence, readiness, search and CLI/MCP/Skill projection **metadata**, plus a scoped real CPython JSON test. It expressly reported Product Release **NO** and full SE10/SE11 benchmark not yet proven. CLI previews are `ILLUSTRATIVE_UNVERIFIED`, not executable production exports.

Do not build `App8CapabilityImportAdapter`, a signing bridge, auto-projection runner, tool-marketplace or a general-purpose Provider registry refresh in v0.2. **Only reserve the compatibility seam** conceptually: future app8 `Capability/Evidence/Binding` snapshots would be mapped into Shun Registry *after separate version/source/currentness/trust admission*, never directly into `AuthorizedAction`. Revisit on app8's meaningful scoped release progress, outside the v0.2 P0 DAG.

## 4. Provider-related v0.2 gates

1. Reuse existing v0.1 sharp, WinGet, storage and Windows Executor behavior with no regressions and a real end-user UI.
2. A **native-only** Windows “system inventory + file plan” job succeeds with an actual LLM proposal and independent host data without third-party program installation.
3. Optional fd/ripgrep must improve measured usability or speed on one real file search over the native implementation; otherwise keep native implementation alone. Do not demand eight Providers for a simple task.
4. Imported PDF/archive/OCR/media adapter work **never** blocks P0 LLM, Script Recipe or UI gates; new libraries remain independently bounded work.
5. No false Product claim: a script body plus shell interpreter is *not* sufficient proof of safe native OS access. Preserve ActionController gates and journal semantics for every host mutation.

**Freeze decision to seek:** `PROVIDER_SCOPE=MINIMAL_FIXED`, `APP8_INTEGRATION=DEFERRED`, `SCRIPTED_STEWARDSHIP=V02_CORE`, `REAL_LLM=V02_CORE`. This document is a proposed evidence input, not a Product Freeze terminal.


## 5. v0.2 optional Provider on-demand distribution contract (P0)

The **small Shun Core installer starts and runs its native diagnostics without any external Provider payload**. A signed/version-pinned catalog of *approved* optional Provider identities/typed adapters is in the trusted base. The Provider engine, executable or optional native Node module is **downloaded only on demand** when required by the selected, approved user task. No code is loaded merely because an LLM suggested a package name, arbitrary URL, DLL or script.

```text
resolve trusted capability
  → built-in capability available? use built-in
  → optional Provider installed with correct hash/ABI? reuse
  → not present? show catalog-origin, exact version, size, license, permissions
  → consent/network/budget → download to isolated staging → verify signature/hash
  → atomic activation / host-env check → typed ActionController execution + oracle
  → retained cache or checked, provenance-safe removal
```

**Minimal lifecycle:** `CATALOG_APPROVED | ABSENT | ACQUIRING | VERIFIED | INSTALLED | READY | BLOCKED | STALE | REMOVED`; persisted download/resume/reconcile journal; serialise acquisitions for same `providerId@version@arch`, allow multiple tasks to share one valid cache. No automatic model-driven catalog mutation.

**No-bypass safety / failure cases:**
- Offline-first core must function; absent optional Provider returns typed `PROVIDER_NOT_AVAILABLE` and an explicit “download later” action. Never auto-switch privacy from LOCAL_ONLY.
- Manifest trust is pinned independently of downloaded content; metadata and download itself cannot redefine root keys. Verify exact SHA-256 or trusted signature, source/provenance, license/distribution acceptability, expected file set, dependencies, node ABI, Windows OS/arch and required permissions; rollback incomplete activation.
- A corrupt archive, zip-slip, dependency DLL substitution, symlink/reparse escape, unsigned executable, expired trust, redirected origin or wrong architecture is `BLOCKED`; do not allow approval to override this.
- Only approved provider-owned files under Shun-managed install roots may be removed automatically. Existing user executables, PATH binaries, provider output, personal config and user-created files are not Shun-owned merely because names match.
- Download/probe (software acquisition permission), execution against user resources (effect authorization) and optional removal (R2/retention policy) are **separate** grants. Validate currentness of all three, and preserve crash/restart reconciliation.
- A cached Provider is not automatically safe forever: recheck hash, catalog revocation, version/runtime compatibility and active Recipe pins on every use. Updating a Provider invalidates dependent Recipe executability until their semantic assumptions are revalidated.
- **Do not require true in-process hot reload** of Node native modules. Loading on subsequent bounded worker task/startup meets v0.2 “dynamic load”; native code ABI loading and code-signing should be more deterministic than hot swapping code in a running Node process.

**Acceptance on a real clean Windows install:** no preinstalled third-party providers, successful read-only system optimization diagnosis offline, first-use approved external `fd/ripgrep` or `sharp` acquisition, actual verified task result, second use from cache without network, unsupported offline case, hash tamper and revoked manifest blocking, no user-file loss during removal. Do not count v0.1 WinGet JIT proof as passing every new v0.2 plugin-loading path.

**Not included:** app8 factory, general marketplace, automatic search for unknown provider, autonomous software update policy, untrusted dynamic package imports or LLM-generated installer scripts.
