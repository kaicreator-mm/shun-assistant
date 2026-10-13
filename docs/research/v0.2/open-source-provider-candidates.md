# Shun v0.2 — Open-source Provider candidate inventory (Research DRAFT)

> Status **RESEARCH_CANDIDATES_ONLY**; none of the new binaries listed below is approved, bundled, installed or qualified for Shun v0.2. Link to Product kickoff #80 and `docs/product/PRD-v0.2-DRAFT.md`. License text and dependencies must be verified against a pinned upstream tag/build before incorporation/distribution.
>
> Existing v0.1 capabilities are already implemented for `sharp`, WinGet software lifecycle and native Windows storage. Do not rebuild those engines.

## Selection rules

Prefer I0 native TS/Node library with structured I/O, then I1 pinned CLI, then scoped structured IPC/MCP; vision/GUI automation only if no stable provider and explicitly in scope. A Provider is **not** an execution authority: each proposed call must be narrowed into one registered typed capability and routed through ActionController (plan hash, policy/currentness, risk gate). For no-state read-only operations, still bind roots/privacy/provenance. Compare total functionality *and install costs*, not GitHub popularity.

## Provider shortlist (verify exact releases/licenses before implementation)

| Family / candidate | Upstream | Interface & provisional license | v0.2 role | Reason / limitation |
| --- | --- | --- | --- | --- |
| Existing image: **sharp** | https://github.com/lovell/sharp | I0 Node; already pinned in v0.1 | **Reuse P0** | Image resizing, decoder and SSIM verification already proven; expand safe conversion/compression only after new oracle |
| Existing package: **WinGet** | https://github.com/microsoft/winget-cli | I1 Windows package manager; distribution/manifest licensing to verify | **Reuse P0** | Official provenance and controlled managed lifecycle; disallow broad arbitrary uninstall |
| File search: **fd** | https://github.com/sharkdp/fd | I1; MIT OR Apache-2.0 | **Primary P0** | Fast name/path enumeration; do not follow links outside bounded roots; enumerate from observed filesystem facts |
| Content search: **ripgrep** | https://github.com/BurntSushi/ripgrep | I1; MIT OR Unlicense | **Primary P0** | Windows fast text search; redact results and limit scanned scopes, file size and binary content |
| File mutation: **Node fs** | https://nodejs.org/api/fs.html | I0 standard library; Node runtime terms to verify for bundle | **Primary P0** | Atomic staging/rename/copy/manifest; existing `executor-windows` safety/recovery owns effect semantics |
| Document: **pdf-lib** | https://github.com/Hopding/pdf-lib | I0 TS/JS; MIT | **Primary P0** | PDF merge/split/page copy within same Node runtime; validate corrupt/encrypted behavior with adversarial corpus |
| Document: **qpdf** | https://github.com/qpdf/qpdf | I1 CLI; Apache-2.0 | **Alternative P0** | Content-preserving PDF transformation, split, merge and structural validation; signed official release + executable pin required |
| Document: **pdfcpu** | https://github.com/pdfcpu/pdfcpu | I1 CLI/Go; Apache-2.0 | **Alternative P0** | PDF validate/merge/split/optimize; benchmark Windows build and semantics vs pdf-lib/qpdf; do not integrate all three without reason |
| Archive: **libarchive / bsdtar** | https://github.com/libarchive/libarchive | I1/C library; BSD-family (pin+dependency review) | **Primary candidate P0** | ZIP/TAR handling with controlled entry inspection and safe extraction; compile/distribution complexity must be assessed |
| Archive: **7-Zip** | https://www.7-zip.org/ | I1 CLI; mostly LGPL, some BSD and unRAR restrictions | **Alternative P0** | Widely supported formats including 7z; inspect exact build/features/license; extraction requires separate Shun path checks |
| Optional duplicates: **jdupes** | https://github.com/jbruchon/jdupes | I1 CLI; license to verify | **P1 candidate** | Duplicate **report-only** by hashes first; no mass delete until distinct safe approval and recovery contract |
| OCR engine: **Tesseract** | https://github.com/tesseract-ocr/tesseract | I1; Apache-2.0 | **P1** | Text extraction from images; language-pack/version and unicode OCR-quality oracle required |
| Scanned PDF: **OCRmyPDF** | https://github.com/ocrmypdf/OCRmyPDF | I1/Python; MPL-2.0 (dependency licenses separate) | **P1** | Creates searchable scans; current Windows install requires separate Tesseract, uv/Python and sometimes Ghostscript, which complicates user onboarding |
| Media: **FFmpeg** | https://ffmpeg.org/ | I1; LGPL 2.1+, GPL modules/build flags possible | **P1** | Conversion/compression; pin exact Windows distribution configuration, LGPL/GPL obligations, semantic A/V verification and resource quotas |
| JSON/CSV utility: **jq** | https://github.com/jqlang/jq | I1; MIT (auxiliary dependencies have own terms) | **P1 / internal** | Typed JSON transformations; prefer native JS for simple operations |
| Local LLM runtime: **llama.cpp** | https://github.com/ggml-org/llama.cpp | local OpenAI-like HTTP, schema and tool modes; license to pin | **P0 inference backend** | Useful for GPU/CPU models and constrained JSON; host must prove no remote-backed LOCAL spoof |
| Local LLM runtime: **Ollama** | https://github.com/ollama/ollama | local OpenAI-compatible HTTP, model management; MIT | **P0 inference alternative** | Easier onboarding, may support model downloads/cloud choice; local/offline provenance must be explicitly enforced |
| Remote LLM: **OpenAI-compatible endpoint** | https://github.com/openai/openai-openapi | HTTP API contract; endpoint terms vary | **P0 inference backend** | Real remote path only with explicit disclosure permission, timeout/budget/cost logging; never raw process/file/secret dump |

### Provenance references consulted (2026-10-14)

- https://github.com/sharkdp/fd : Windows CLI, dual MIT/Apache-2.0.
- https://github.com/BurntSushi/ripgrep : CLI Windows; FAQ MIT/Unlicense.
- https://github.com/Hopding/pdf-lib : TS/JS, MIT.
- https://github.com/qpdf/qpdf : PDF transform, Apache-2.0.
- https://github.com/pdfcpu/pdfcpu : PDF CLI, Apache-2.0.
- https://www.7-zip.org/ : LGPL/BSD/unRAR component restrictions.
- https://github.com/tesseract-ocr/tesseract : Apache-2.0 OCR.
- https://ocrmypdf.readthedocs.io/en/latest/installation.html : current Windows multi-dependency setup.
- https://github.com/ocrmypdf/OCRmyPDF : MPL-2.0.
- https://www.ffmpeg.org/legal.html : LGPL vs GPL build-feature distinction.
- https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md : OpenAI-compatible schema/tool support.
- https://docs.ollama.com/api/openai-compatibility : local OpenAI-compatible runtime.
- https://docs.ollama.com/capabilities/structured-outputs : structured output API.

## Provider registry record and acceptance pack

Each **approved** Provider version gets:
- Identity `providerId`, upstream org/URL, release/tag, license/SPDX + transitive SBOM + packaging policy, source hash/signature, download/install channel, architecture/platform.
- Capability bindings `capabilityId`, exact schema revision, interface class (I0/I1/I2), tool-call name, input/output JSON Schema, preconditions, observed environment features, network/side-effect/privilege declarations, risk class.
- Execution `argv` array (never arbitrary shell), executable identity and timestamp/hash pins, workspace/read/write scopes, symlink/junction checks, max file count/size/runtime/memory, cancellation, stdout/stderr redaction, typed status+errors, idempotence/reconcile.
- Independent verification sample corpus and oracle, attribution of output files, source immutability, proper output collision and partial-output cleanup. Provider exit code 0 is **not** user-task PASS.
- Lifecycle `PROBE → PRESENT/TRUSTED? → ACQUIRE (explicit) → CONFIGURE → RUN → VERIFY → RETAIN/REMOVE`, signed evidence and observed re-checks, explicit package removal limitation.

**Keep a small curated registry**: 8–12 vetted entries with 1 primary and alternatives for one or two hot capabilities. A thousand unvetted marketplace entries would make v0.2 less safe and less useful.

## Research decisions before Product/L2 freeze

1. Perform native Windows x64 smoke: installation footprint, clean one-call results, startup latency, file format support, safety, resource and distribution license for fd/ripgrep/pdf-lib/qpdf/pdfcpu/libarchive/7-Zip. Benchmark same PDF merge contract across pdf-lib vs qpdf (and pdfcpu optionally); select primary/fallback rather than shipping all.
2. Confirm **native Windows** OCRmyPDF/Tesseract/Ghostscript dependency cost and associated distribution terms; accept OCR only if it fits zero-developer-setup onboarding; otherwise P1.
3. For LLM, benchmark actual schema-valid GoalProposal, adversarial tool injection, Chinese commands, short/long requests, privacy and network behavior on at least one local runtime and one authorized remote endpoint; capture latency/total tokens/cost/VRAM on the actual host. Local `BASE_URL=127.0.0.1` alone does not prove local model/no egress.
4. Ensure capability register and package acquisition never trust model-generated URLs, unsigned provider metadata or `winget search` results as authority. Freeze approved catalog and verify update process.
5. Confirm distribution obligations, executable signing and security advisories against exact selected version before source integration. These rows are **research hypotheses**, not compliance certifications.

### Narrow initial Provider milestone

Use existing sharp/WinGet/Windows fs/store and integrate **fd, ripgrep, pdf-lib, one archive tool**, plus one real local inference runtime and one remote connector. `qpdf` is the first alternate Provider to benchmark; OCRmyPDF/FFmpeg are not needed to establish v0.2 Usable MVP. Product review may prune by actual evidence.
