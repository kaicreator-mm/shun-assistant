# native/ — T04 Windows napi-rs addons (windows-rs)

Replaces the `koffi` FFI dependency for the scoped file search per the v0.2
technology constraint (koffi/node-win32-api rejected; Windows FFI goes through
Rust `windows-rs` behind `napi-rs`).

Two **separately compiled** addons on disjoint declarations:

| crate | artifact | surface | consumer |
|---|---|---|---|
| `impl/` (`shun-win32-impl`) | `impl/shun_win32_impl.node` | ntdll `NtOpenFile` / `NtQueryDirectoryFile` / `NtReadFile` / `NtClose`, kernel32 `GetFileInformationByHandle` / `GetFinalPathNameByHandleW` / `QueryDosDeviceW` / `GetDriveTypeW` | `src/scoped-file-search.ts` (native walker) and `src/r0-independent-poststate-oracle.ts` (independent post-state oracle; raw adapter only — parsing, traversal, matching, fingerprinting and refusal logic are per-consumer) |
| `canary/` (`shun-win32-canary`) | `canary/shun_win32_canary.node` | kernel32 `CreateFileW` flag semantics, `CloseHandle`, `GetFileInformationByHandle`, `GetFinalPathNameByHandleW` | `test/scoped-file-search.test.ts` only (physical canaries) |

The canary addon is the physical canaries' **independent instrument**: it is
built from a separate crate and proves OS primitives through a different API
surface than the implementation uses, so no canary result can be produced by
the implementation's own code path. Neither addon contains parsing, bounds
policy or refusal logic — every raw status/attribute/byte-count is returned
verbatim to the reviewed TypeScript layer, which owns all validation.

## Build (Windows x64, Build Host)

Toolchain used for the committed artifacts (pinned in the validation evidence):

- rustc/cargo `stable-x86_64-pc-windows-gnu` (self-contained; no MSVC/VS Build
  Tools or Windows SDK present on the Build Host — the GNU target bundles
  rust-lld and the MinGW import libraries)
- msys2 ucrt64 `gendef` + `dlltool` (import-library generation only)
- Node.js v24.21.0 (`.node-version`), N-API 8 (`napi8` feature)

```bash
# 1. Generate the GNU import library for node.exe exports (napi-build looks
#    for a file literally named libnode.dll; this is machine-local tooling,
#    not committed — regenerate from your own node.exe and record its SHA256):
mkdir -p /c/xDev/runtimes/libnode-import/v24.21.0
cp "$(node -p process.execPath)" /c/xDev/runtimes/libnode-import/v24.21.0/node.exe
cd /c/xDev/runtimes/libnode-import/v24.21.0
gendef node.exe
dlltool -d node.def -D node.exe -l libnode.dll -m i386:x86-64

# 2. Build the workspace (CARGO_TARGET_DIR outside the repo, per workspace rules):
cd <repo>/packages/recipe-runtime/native
export CARGO_TARGET_DIR=<repo-root>/.target CARGO_INCREMENTAL=0
export LIBNODE_PATH=/c/xDev/runtimes/libnode-import/v24.21.0
rustup run stable-x86_64-pc-windows-gnu cargo build --release

# 3. Publish the cdylibs into the package (the committed artifacts):
cp "$CARGO_TARGET_DIR/release/shun_win32_impl.dll"   impl/shun_win32_impl.node
cp "$CARGO_TARGET_DIR/release/shun_win32_canary.dll" canary/shun_win32_canary.node
```

### Byte-identical native provenance check (independent validator)

The independent Windows Node 24 validator reproduced both committed binaries from
the frozen `Cargo.lock` and exact Rust sources using rustc/cargo 1.99.1
`stable-x86_64-pc-windows-gnu`. A normal fresh build differed only in PE
COFF TimeDateStamp and derived CheckSum; rebuilding each independently with
its original linker epoch produced SHA256-identical committed binaries:

```sh
# Build from a fresh, exact-SHA source checkout with the documented Node
# import library, pinned toolchain and external CARGO_TARGET_DIR.
# Keep the builds separate: the binaries were linked at different times.
SOURCE_DATE_EPOCH=1792785077 \
  rustup run stable-x86_64-pc-windows-gnu cargo build --release --locked -p shun-win32-impl
# Force the canary to relink under its distinct, independently derived epoch.
rustup run stable-x86_64-pc-windows-gnu cargo clean -p shun-win32-canary
SOURCE_DATE_EPOCH=1792785321 \
  rustup run stable-x86_64-pc-windows-gnu cargo build --release --locked -p shun-win32-canary
```

Before treating the result as provenance evidence, verify actual GitHub blob
bytes against the checkout, compare each rebuilt `.dll` to the committed
`.node` byte-for-byte, record the SHA256s, toolchain/Node executable identities
and command exit codes, then run the Windows Standard User canary suite on the
**committed** artifacts. A differing binary is not proof about the shipped
binary even when its own tests pass. The epochs were independently recovered
from the committed PE headers, not accepted solely from the original builder.

Production packaging is restricted by the package `files` allowlist: publish
`src/` and `native/impl/shun_win32_impl.node` only, never the test-only
`native/canary/` addon or Rust build source. The `test/pack-contents.test.ts`
negative test checks real `npm pack --dry-run` output; no source or native
rebuild is performed by the packaging test.

The built `.node` artifacts are committed so the exact-head CI/review host can
run the physical canaries without a Rust toolchain; their SHA256 and the exact
toolchain are pinned in `docs/validation/v0.2/`. A rebuilt artifact must pass
the full canary suite; byte-identity is only expected with the pinned
toolchain. `Cargo.lock` pins the crate graph.

## Fail-closed contract

- If `shun_win32_impl.node` is missing, unloadable, or exposes an unexpected
  surface, `loadNativeImplAddon()` returns null and the Windows walk **refuses
  the whole action** (`R0_FILE_SEARCH_REFUSED`). There is no path-based JS
  fallback on Windows.
- Non-Windows hosts never load the addon; they keep the legacy walk (out of
  T04 scope, deployment gate is the Windows host).
