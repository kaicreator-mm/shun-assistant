# T04 — koffi → windows-rs + napi-rs native replacement (technology-constraint repair)

PR #162 · ADS #1241 · v0.2 T04 #108. Repair of the TECHNOLOGY_CONSTRAINT_HOLD
recorded at controller level on `deae06bd1ca6dcf9a6859483bb49cfeea2e9811a`:
the project architecture rejects `koffi`/node-win32-api; Windows FFI must go
through Rust `windows-rs` behind `napi-rs`.

## Exact SHAs

| item | SHA |
|---|---|
| Pre-repair reviewed head (source identity `ee52bdba`) | `deae06bd1ca6dcf9a6859483bb49cfeea2e9811a` |
| This repair source commit | `c96a43269b769ba74216ae8d4e4c4d3f272f0e62` |
| This evidence commit | direct child of the source commit (self-reference impossible); exact HEAD pinned in the independent-review request on PR #162 |
| Base (unchanged) | `version/v0.2.0@3a5cfb6864b190469e5588a10dc597f38409173a` |

## Scope adjustment (auditable)

Write set expands from the R2-reviewed two-file concern to:

- `packages/recipe-runtime/src/scoped-file-search.ts` (koffi loader → napi addon loader; walk/parse/refusal logic unchanged)
- `packages/recipe-runtime/test/scoped-file-search.test.ts` (canary koffi declarations → separate canary addon; soak-test over-strict assertion corrected, see "Test-assertion correction" below)
- `packages/recipe-runtime/package.json` + `pnpm-lock.yaml` (koffi removed; 0 references remain in the lockfile)
- `packages/recipe-runtime/native/**` (NEW: two-crate cargo workspace + committed built artifacts, see native/README.md)
- `docs/validation/v0.2/t04-napi-native-replacement-canary.md` (this file)

Disjoint from #161 (`src/index.ts`, `test/host.test.ts` in
@shun/recipe-runtime — note: those files exist on this branch from the base
and are NOT touched) and #163 (journal files). `src/index.ts` does not export
the scoped search; the module stays unexported from the package root.

## Design: what moved, what stayed

Two **separately compiled** Windows-only napi addons (crates.io `napi` 3.x +
`napi-derive`, Microsoft `windows` 0.62.2):

- `native/impl` → `shun_win32_impl.node` — production surface used by the
  walk: ntdll `NtOpenFile` / `NtQueryDirectoryFile` / `NtClose`, kernel32
  `GetFileInformationByHandle` / `GetFinalPathNameByHandleW`. Contains **no
  parsing, no bounds policy, no refusal logic**; raw statuses, attribute
  masks and byte counts are returned verbatim. All validation stays in the
  TypeScript layer exactly as reviewed at R2 (`ee52bdba`): handle-anchored
  child opens via `RootDirectory` + single name component +
  `FILE_OPEN_REPARSE_POINT`, reparse refusal from enumeration metadata alone,
  final-path root anchoring with UNC/subst provenance refusal, chain-stride
  and returned-size bounds, fixed `R0_FILE_SEARCH_REFUSED` envelope.
- `native/canary` → `shun_win32_canary.node` — test-only instrument for the
  physical canaries, built from a **separate crate on disjoint
  declarations** (kernel32 `CreateFileW` flag semantics), so the canary
  remains an independent instrument that cannot be satisfied by the
  implementation's ntdll code path.

The koffi-era shared mutable enumeration buffer is gone: each
`NtQueryDirectoryFile` round trip gets a fresh buffer from the addon.

## Fail-closed contract (proven, not claimed)

- Addon missing/unloadable → `loadNativeImplAddon()` returns null →
  `walkWin32` refuses → fixed `R0_FILE_SEARCH_REFUSED` envelope. There is no
  path-based JS fallback on Windows.
- Physical proof on this host (same run): with
  `native/impl/shun_win32_impl.node` present the harness returns
  `RESULT=OK paths=["nested\\second.txt","note.txt"]`; with the artifact
  renamed away the identical harness returns
  `RESULT=REFUSED message=R0_FILE_SEARCH_REFUSED`. (Fail-closed on stale or
  unusable handles is enforced inside the addon: an invalid `HANDLE` bigInt —
  negative or truncated — maps to null/refusal via `get_u64()` losslessness.)

## Toolchain and build recipe (Build Host, pinned)

- Host: Windows 11 Pro, `10.0.26300.9711`, user `15549`, **non-elevated**
  token (`net session` denied) — same host and same UAC-filtered
  (Administrators-group-member, non-elevated) token as the P1-01 canaries.
- Node.js `v24.21.0` (fnm; `.node-version`), pnpm `10.34.5`, N-API 8
  (`napi8` crate feature).
- Rust: `stable-x86_64-pc-windows-gnu` — `rustc 1.99.1 (58cf8f9c3
  2026-10-13)`, `cargo 1.99.1 (5f94df478 2026-08-27)`. The MSVC toolchain and
  Windows SDK are **not installed** on this host, so the self-contained GNU
  host toolchain (bundled rust-lld + MinGW import libraries) is used and
  pinned here; the produced cdylibs import only `ntdll.dll`/`kernel32.dll`
  system exports plus the node N-API surface.
- Import library for the node N-API exports (GNU-style `libnode.dll`,
  machine-local build aid, not committed): generated from the exact runtime
  binary `node.exe v24.21.0`
  SHA256 `ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32`
  with msys2 ucrt64 `gendef` + `dlltool` (GNU Binutils 2.46):
  `gendef node.exe && dlltool -d node.def -D node.exe -l libnode.dll -m i386:x86-64`,
  located at `C:\xDev\runtimes\libnode-import\v24.21.0\` and selected by
  `LIBNODE_PATH` (napi-build's documented GNU lookup).
- Full build recipe: `packages/recipe-runtime/native/README.md` (committed).
- `Cargo.lock` committed; crate graph pinned.

## Committed artifact hashes (SHA256)

- `packages/recipe-runtime/native/impl/shun_win32_impl.node`
  `592eb1f743e810083494f3453a9a5cef444ae05f12165278824750ebb3b55ede`
- `packages/recipe-runtime/native/canary/shun_win32_canary.node`
  `b5f8d1bf5b4a3927ff7c259f751b50ee63fc5dfab99c85b66ca148985a87d5a0`

Rebuild note: byte-identity of a rebuilt artifact is only expected under the
pinned toolchain above; functional equivalence is proven by the full canary
suite regardless of toolchain.

## Physical canaries re-run (all against the new native binary)

`npx vitest run test/scoped-file-search.test.ts` at this head —
**13 passed | 1 skipped (14), exit 0** (5 consecutive runs, exit 0 each), on
the real host above. The skip is the honest one: `refuses a directory symlink
when the host can create one` (EPERM — no `SeCreateSymbolicLinkPrivilege`
under the non-elevated token; junctions cover the reparse surface), same as
the R2-qualified runs.

Covered, per test name: OS-primitive no-follow junction proof (independent
canary addon); in-scope junction→outside refusal with zero outside opens
(instrumented); junction nested one level deep refused only after opening its
verified parent (`opened == ['nested']`); junction with exclusively pinned
outside target refused without resolving; deterministic mid-traversal
rename+delete+junction-replacement attack; renamed-ancestor soak
(object-anchored); junction/device-form/UNC roots refused before any open
(`opened == []`); subst drive-letter alias root refused (mapped-volume
provenance negative, 129 ms); **1.5 s real worker-thread rename soak**
(1549 ms this run) — five walks, every outcome exact-expected or fixed
refusal, zero outside-scope paths.

Mutation-style sensitivity (this repair): during repair, an interim build
with a wiring bug (missing `\??\` namespace prefix on the absolute bootstrap
open) failed exactly the four tests that require the walk to succeed and
passed only the vacuous refusal tests (log retained at build host:
`t162-vitest-1.log`); the corrected build is fully green. The instrumentation
hooks therefore still measure handle-anchored traversal on the new binary.

## Test-assertion correction (disclosed for reviewer attention)

`task-check.sh` under full workspace load exposed a pre-existing flaky
assertion in the worker-thread soak test: a successful walk that enumerates
the root in the attacker's renamed instant legitimately observes the
transient `nested__atk` name of the **same in-scope directory object** and
returns `nested__atk\second.txt`; the old assertion
`not.toContain('__atk')` treats that accurate observation as failure. The
exposure window is identical in the koffi implementation (same enumerate →
handle-anchored open logic; the R2 pass was timing luck under lighter load).
The assertion is corrected to the actual security invariant: every returned
path must be one of the fixture's real names under either spelling
(`note.txt`, `nested\second.txt`, `nested__atk\second.txt`) and must never
contain outside-scope content (`outside`, `secret`) — unchanged in strength
for the property the test title claims ("without ever returning outside-scope
paths"). The walk source is unchanged by this correction. Five consecutive
full-suite runs pass at this head.

## Install / build / packaging verification

- `pnpm install --frozen-lockfile` — exit 0 (lockfile koffi-free).
- `pnpm pack --dry-run` (recipe-runtime) — tarball
  `shun-recipe-runtime-0.2.0.tgz` includes `native/impl/shun_win32_impl.node`,
  `native/canary/shun_win32_canary.node`, all Rust sources and `Cargo.lock`.
- `npx biome check` on both TS files — exit 0; `npx tsc --noEmit` — exit 0.
- `tools/task-check.sh` (workspace gate, lint + typecheck + test over all
  packages) — exit 0 at this head (log retained at build host).

CI note: `contracts` CI (ubuntu) runs recipe-runtime's tests through the
non-Windows legacy walk (win32 canaries are `describe.skipIf`-gated and the
native addon is never loaded off-Windows); `executor-windows` CI runs only
`@shun/contracts` + `@shun/executor-windows`. Neither workflow needs the
native addon; both must pass at this head before review.

## Honest NOT_RUN / residuals

- Real SMB-backed mapped-drive root canary: **NOT_RUN** (a standard user
  cannot create a local SMB share) — unchanged from R2; covered by the subst
  alias canary, junction→UNC refusals and `\??\UNC\` provenance refusal.
  Stays in the T04 qualification backlog.
- Root-acquisition residual window (first absolute open, attributes-only,
  detected by final-path equality) — unchanged by this repair (same access
  mask, same single bootstrap open as the reviewed `ee52bdba` logic);
  hardening (P2-04) remains backlog.
- Non-Windows hosts keep the legacy walk (out of T04 slice; deployment gate
  is the Windows host). The native addon is never loaded off-Windows.
- The addon artifact is committed so exact-head review can run the canaries
  without a Rust toolchain; provenance is pinned by source + `Cargo.lock` +
  toolchain record above, and the reviewer is expected to review the Rust
  source as the security surface (the binary is a build product of it).

## Merge policy

Unchanged: do not merge until a fresh independent delta review (architecture
conformance + path-security re-check on the new binary) returns non-BLOCK at
this exact head; T04_DONE and T07 unlock remain blocked; no release claim.
