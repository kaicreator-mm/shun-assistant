# T04 P1-01 repair — handle-anchored no-follow directory traversal: physical canary evidence

- **PR / branch:** #162 `task/v02-t04-private-file-search`
- **Pre-fix reviewed source (R1 BLOCK subject):** `0273709e76a23eab027df07271a3d7f8af559962` (base `version/v0.2.0@3a5cfb6864b190469e5588a10dc597f38409173a`)
- **Repaired source validated at this exact SHA:** `ee52bdba43682ce57b4e4de938823493de5737eb`
- **Files:** `packages/recipe-runtime/src/scoped-file-search.ts`, `packages/recipe-runtime/test/scoped-file-search.test.ts` (plus `package.json` / `pnpm-lock.yaml` for the `koffi@3.3.3` runtime dependency required to reach Win32 from Node without a toolchain build)
- **Gate:** `tools/task-check.sh` exit 0 (`task-check: 全绿`), lint (Biome) and `tsc --noEmit` clean at the SHA above.

## Host facts (physical canary run)

| Item | Value |
| --- | --- |
| OS | Microsoft Windows 11 专业版 (Pro), build 26300.9711 |
| Account | `NILAR\15549` — **not** in Administrators group, non-elevated token (standard user) |
| Node | v24.21.0 (repo `.node-version` 24.21.0) |
| FFI | koffi 3.3.3 (prebuilt N-API binaries; no install scripts required) |

## Threat and fix shape (P1-01)

The pre-fix walk validated each path with `lstat`/`realpathSync.native` and then
re-opened the same mutable pathname (`opendirSync`). A concurrent writer could
replace a validated directory with a junction between validation and open, and
the host would open/enumerate an outside-scope directory before any later check
refused — outside-scope OS access that per-entry rejection cannot undo.

The repaired Windows walk is anchored to verified directory handles:

1. **Root acquisition.** One `NtOpenFile` of the root with
   `FILE_OPEN_REPARSE_POINT|FILE_DIRECTORY_FILE`; the handle is checked for the
   reparse attribute, and `GetFinalPathNameByHandleW` must equal `resolve(root)`
   case-insensitively. Aliased roots (junction/subst) fail the equality check;
   UNC-provenance (`\\?\UNC\...`) and device-form roots are refused (P2-01).
2. **Descent.** Every child directory is opened with `RootDirectory` set to the
   already-verified parent handle plus a single name component, again with
   `FILE_OPEN_REPARSE_POINT`. Path resolution therefore starts *inside the
   verified parent object*: ancestor renames/deletions cannot redirect it, and a
   junction entry yields the junction object itself (reparse attribute → refused)
   — the junction target is never resolved, not even for attributes.
3. **Enumeration.** `NtQueryDirectoryFile` (`FileIdBothDirectoryInformation`)
   reads the verified handle's own directory index; names, reparse bits and
   directory bits come from the same verified object. File entries are never
   opened (name-only matching). Reparse entries are refused from enumeration
   metadata alone.
4. **Bounds and failure semantics are unchanged:** `MAX_ENTRIES=4096`,
   `MAX_DIRS=512`, `MAX_MATCHES=128`, `MAX_DEPTH=8`; every anomaly throws the
   fixed `R0_FILE_SEARCH_REFUSED` with no partial result. All handles are closed
   on every exit path. Non-Windows hosts keep the pre-existing path-based walk
   (Linux CI executes that path; see coverage note below).

## Zero-outside-open proof

- **Structural:** after the root open, every kernel name resolution is one
  component relative to an already-verified directory object, with a no-follow
  open on the final component. There is no code path that opens a multi-segment
  pathname; a junction can only ever be opened as the reparse point itself.
- **Physical (OS primitive canary, `proves the OS primitive...`):** on the host
  above, `CreateFileW(junction, FILE_FLAG_OPEN_REPARSE_POINT)` returns a handle
  whose `GetFinalPathNameByHandleW` is the **junction's own path** (reparse
  attribute set), while the same open without the flag resolves to the outside
  target — demonstrating both the danger and that the shipped flag never
  dereferences it.
- **Physical (pinned target):** with the outside target held by an exclusive
  `CreateFileW` (share mode 0) owned by the canary, the search over a tree
  containing a junction to that target refuses with `R0_FILE_SEARCH_REFUSED`
  without resolving the target.
- **Physical (deterministic swap attack, `cannot be redirected...`):** the
  test-only `onDirectoryOpened` barrier performs rename / recursive delete /
  junction replacement on the root *mid-traversal*. On this host the delete and
  junction replacement **succeeded** (POSIX-semantics deletion is not blocked by
  open handles) and the walk **continued on the original verified objects**:
  the returned paths never contained the outside directory or its
  `secret.txt`. A successful attack cannot redirect the walk, not merely get
  detected afterwards.
- **Physical (worker-thread soak):** a real `worker_threads` attacker hammering
  renames on a visited directory for 1.5 s across five searches: every outcome
  was either the exact expected match set or the fixed refusal; no outside-scope
  path and no `__atk` swap name ever appeared in a result; the attacker recorded
  `attempts > 0` and `swaps > 0`.

## Canary matrix (vitest at SHA `ee52bdba`, exit 0)

`13 passed | 1 skipped (14)` — the suite runs on any host; tests marked (win32)
execute the new traversal core on the Windows host above:

- returns only bounded root-relative matching names... (inspectedEntries=4, no
  content/root leakage) — pass
- refuses changed scope, unsafe query, privileged operation and UNC root — pass
- refuses a link/junction at any visited child, never returns a partial result — pass
- refuses alias root and excessively deep scans (depth bound) — pass
- (win32) proves the OS primitive: no-follow open resolves the junction object — pass
- (win32) refuses an in-scope junction to outside scope; no outside directory
  open recorded — pass
- (win32) refuses a junction nested one level deep only after opening its
  verified parent (`opened == ['nested']`, non-vacuous refusal) — pass
- (win32) refuses a junction whose target is exclusively pinned elsewhere — pass
- (win32) cannot be redirected by deterministic swap attacks (rename + delete +
  junction replacement mid-traversal) — pass
- (win32) keeps the whole traversal object-anchored (renamed ancestor) — pass
- (win32) refuses junction roots, device-form `\\?\` roots and UNC roots before
  opening any directory (`opened == []`) — pass
- (win32) refuses a subst-style drive-letter alias root — pass
- (win32) survives a real concurrent rename attacker (worker soak) — pass
- (win32) refuses a directory symlink when the host can create one — **skipped:
  host lacks symlink-creation privilege (no Dev Mode); junction canaries cover
  the reparse surface**

## Mutation check (new tests must fail on the pre-fix source)

With the test file held fixed at SHA `ee52bdba` and
`src/scoped-file-search.ts` reverted to the R1-reviewed `0273709e` content,
`vitest run test/scoped-file-search.test.ts` on this host:

- `refuses a junction nested one level deep only after opening its verified
  parent` — **FAIL** (expected `['nested']`, received `[]`: the old walk has no
  verified-open instrumentation and no handle anchoring)
- `cannot be redirected by deterministic swap attacks...` — **FAIL** (barrier
  never fires; attempts never executed)
- `keeps the whole traversal object-anchored...` — **FAIL** (same)
- 10 tests pass as the regression net (the old walk also refuses stable
  junctions/UNC/alias roots; the primitive canary is source-independent).

The API boundary cannot distinguish "refused before target resolution" from
"refused after a failed outside attempt" — that distinction is carried by the
source-independent OS primitive canary plus the barrier hooks above.

## Not covered / NOT_RUN

- **Real SMB-backed mapped drive root:** mapping a network drive requires an
  SMB server/share that a standard user cannot create locally. Covered instead
  by: junction→UNC-target refusal, subst drive-letter alias refusal, and the
  `\\?\UNC\...` provenance refusal in the final-path check. A physical
  SMB-root canary remains NOT_RUN.
- **Directory symlink canary:** skipped (host lacks
  `SeCreateSymbolicLinkPrivilege`/Dev Mode). Junctions (mount points) exercise
  the same reparse-point handling; file symlinks are refused from enumeration
  metadata via the same attribute bit.
- **CI coverage:** `contracts` (ubuntu-latest) executes this suite against the
  legacy non-Windows walk; no GitHub workflow runs `packages/recipe-runtime`
  tests on windows-latest. The Windows physical canaries documented here are
  operator-gated evidence at the exact SHA above, consistent with the
  repository's evidence model.
- **Root-acquisition residual window:** the very first `NtOpenFile` of the root
  resolves the absolute pathname; an ancestor-of-root swap inside that single
  window yields an attributes-only open that the final-path equality check then
  refuses (fail-closed), but it cannot be prevented structurally before the
  first handle exists. Every step after acquisition is handle-anchored.
- **Non-Windows hosts** keep the legacy path-based walk, including its TOCTOU
  surface; that is outside this T04 slice (deployment gate is the Windows
  Standard User host) and is recorded honestly here rather than claimed fixed.
