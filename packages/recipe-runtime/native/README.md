# native/ — T04 Windows napi-rs addons (windows-rs)

Replaces the `koffi` FFI dependency for the scoped file search per the v0.2
technology constraint (koffi/node-win32-api rejected; Windows FFI goes through
Rust `windows-rs` behind `napi-rs`).

Two **separately compiled** addons on disjoint declarations:

| crate | artifact | surface | consumer |
|---|---|---|---|
| `impl/` (`shun-win32-impl`) | `impl/shun_win32_impl.node` | ntdll `NtOpenFile` / `NtQueryDirectoryFile` / `NtClose`, kernel32 `GetFileInformationByHandle` / `GetFinalPathNameByHandleW` | `src/scoped-file-search.ts` (production, behind the SQLite grant gate) |
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
