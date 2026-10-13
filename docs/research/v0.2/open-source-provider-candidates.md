# Shun v0.2 — Minimal open-source Provider shortlist (L1 RESEARCH DRAFT)

> **v0.2 product focus changed 2026-10-14:** Real LLM + high-ROI Windows stewardship + generated script/Recipe reuse + usable UI. Not a deep Provider platform or app8 integration release. All new OSS binaries must still pass exact-version, Windows packaging, provenance and license checks. See #80, `docs/product/PRD-v0.2-DRAFT.md` and `docs/product/script-recipe-v0.2-DRAFT.md`.

## 1. Rule: minimum Provider breadth

Most proposed system-management functions are enabled by **native Windows APIs and built-in safe host tools**. In Shun's architectural terms these are still capability bindings/Provider functions; they do **not** require building or discovering an ecosystem of third-party Providers. A generated script is not a trusted Provider or a substitute for a capability contract; mutation is handled by Shun's typed effect executor.

| Tier | Capability | Provider / OSS asset | Role in v0.2 | Evidence or admission |
| --- | --- | --- | --- | --- |
| **P0 REUSE** | Image batch | [sharp](https://github.com/lovell/sharp) and `@shun/vertical-image` | Already implemented real resize/verifier; wire production UI only | Frozen v0.1 real B037 oracle; expanding formats needs separate contract |
| **P0 REUSE** | Managed software/JIT | [WinGet](https://github.com/microsoft/winget-cli) and `@shun/vertical-jit` | Reuse allowlisted versions only; no arbitrary auto-uninstall | Frozen v0.1 B038/real-host safety and lifetime evidence |
| **P0 REUSE** | Storage cleanup | Windows filesystems and `@shun/vertical-storage` | Keep user-approved bounded cache cleanup | Frozen v0.1 C003 actual Control UI |
| **P0 NATIVE** | Windows diagnostics, inventory, safe file operations | Node `fs/os`, PowerShell audited read-only functions, Windows native APIs | **Main new product features**; script plan and typed effect API | Independent host observation, privacy/scope, high-risk authorization |
| **P0 LIMITED** | File name/content search | [fd](https://github.com/sharkdp/fd) and [ripgrep](https://github.com/BurntSushi/ripgrep) | Optional pinned CLI adapters for searches too slow/complex for native fs | Same bounded root/facts, shell-free argv, result redaction, exact exe identity |
| **P0 INFERENCE** | Local model | [llama.cpp](https://github.com/ggml-org/llama.cpp) **or** [Ollama](https://github.com/ollama/ollama) | One real local model backend, not both mandatory packaging | Independently prove true local inference and no remote origin masquerade |
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

`capabilityId`; `bindingId`; `origin+version+binaryHash`; `licenseDecision`; `WindowsHostRequirements`; `interface I0/I1`; typed input/output/error; observed allowed roots + read/write/network/privilege budget; no shell string; independent verifier; retained result and updated status.

This is **not** authorization. LLM-created `ScriptProposal` may refer to a registered capability but cannot install, trust, sign, grant or execute a new arbitrary Provider. Keep first-run probes quick and local. Don't introduce automated global marketplace browsing or mass wrapper generation to ship v0.2.

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
