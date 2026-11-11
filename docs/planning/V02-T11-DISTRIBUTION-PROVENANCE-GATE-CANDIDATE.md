# v0.2 T11 distribution entrypoint trust — scope-alignment candidate

> **CANDIDATE / NOT EFFECTIVE.** ADS v4.18 #1241 Issue [#209](https://github.com/kaicreator-mm/shun-assistant/issues/209). Independent exact-SHA review, controller acceptance, merge to `version/v0.2.0` and formal #113 acceptance successor are required. No T11 release PASS or `main` merge follows from this document.

## Authority and specific mismatch

- Original Product `docs/product/PRD-v0.2.md` blob `68cf2fcec919dedd9ce61339b81f60855404fb12` requires safe Windows portable one-step startup, checked runtime/core hashes and trusted Shun bootstrap/executor, but does **not** mandate Authenticode, a purchased publisher certificate, Store publishing or MSIX.
- Scoped Product successor blob `46d35708688663943868b556c0b8b298f609488a` retains packaging and signed curated Provider policy.
- Frozen L2 reviewed candidate blob `f23a6c44374ab49d84e608693d7793d294c88258` §packaging requires exact runtime/installer/manifest digest, OS and architecture proof, no dev-toolchain or elevated-account dependency; signed curated Provider keys remain pinned independently.
- Frozen Task DAG source blob `31574f9767a4e8a8a5f413f02064d52de079f601` T09 specifies the complete portable manifest/signature, lifecycle/SQLite WAL, and T11 specifies real full Windows packaging/negative/hidden qualifications. Neither mandates one particular OS publisher service.
- T09 P01/#202, P02/#203 and P03/#204 have passed independent source/Host validation; reviewed/merged governance PR #206 and the subsequently adopted #113 acceptance addendum described an **OS-trusted publisher/launcher** as a mandatory release gate. That adds a specific distribution mechanism beyond the frozen Product/L2 text, and may unduly hold v0.2 delivery.

## Proposed correction (only acceptance method, not authenticity)

The T11 launch/distribution origin must be independently verifiable **before accepting any untrusted mutable executable script or verifier**. An authenticated publisher/channel plus independently pinned complete first-stage artifact/verifier identity, exact SHA and signed payload manifest can satisfy this gate, subject to concrete evidence. Windows Authenticode/SignTool or OS Store/MSIX identity is **one option, not automatically mandatory**.

For a verified portable distribution, the operator must demonstrate a trustworthy, auditable origin for the release root and verifier itself (e.g. an independently authenticated maintainer release record with exact immutable artifact digest, checked via a trusted verification mechanism), validate exact release entrypoint bytes **before execution**, then validate the existing pinned Ed25519 bundle manifest and supported OS/architecture. Merely displaying a SHA on the same unverified download page, accepting a filename, following an unsigned launcher, or verifying a manifest only *after* running arbitrary unverified bootstrap code is **insufficient**. Do not claim an unsigned `.cmd` has Authenticode or that code-signing warnings/SmartScreen are cleared.

**Hard no-release remains** for unknown verifier provenance, modified bootstrap or signed payload, absent trusted release-root identity, missing independent first-stage verification mechanism, and any failed Home/Pro physical native/portable critical journey. Genuine DeepSeek CN/EN consent/cost/zero-send, full/hidden/packaging, provider signature and R2 action-safety checks remain intact; user waived *only* account privilege testing. No new installer system, certificate account purchase or bespoke cryptography is authorized by this candidate.

## Review and effectiveness

Reviewer must compare exact PR SHA and single-file diff, Product/L2/frozen DAG blobs, #111/#112/#113 effective addenda, T09 signed-manifest P01 receipts, and distinguish (a) source proven, (b) chosen release channel authenticated, (c) actual OS-supported Home/Pro, (d) publisher reputation optional. Return P0/P1/P2, PASS/BLOCK, `T11_PROVENANCE_GATE_ALIGNMENT_READY`, whether additional Product/L2 approval is needed, and **specific evidence needed to certify the chosen channel**. On BLOCK the current #113 stricter gate remains effective. Only after approved version merge and an exact-source-bounded #113 task acceptance successor may the new choice be applied. No T10 dependency/writeset change; no main integration/tag before full T11 RQ.
