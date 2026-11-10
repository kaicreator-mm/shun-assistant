# T04 Windows Host minimal end-to-end closed loop — physical standard-user evidence

- **PR / branch:** this PR `task/shun-i108-r2-zc` (base `version/v0.2.0`, stacked on `task/shun-i108-winhost` @ `5fabb7562a4dea39b51e778285938093479372ea`, not merged)
- **R2 scope:** closes the independent R1 BLOCK (`shun-v02-pr173-independent-r1-5fabb756`) — P1-01 oracle confinement, P1-02 receipt phase binding, P2-01 hard-kill proof strength, P2-02 mapped-SMB honesty.
- **Raw evidence log:** `docs/validation/v0.2/logs/t04-winhost-r2-75dec6d.log` (real vitest output, real exit codes recorded in the log header). R3 controller round at PR head `0062bb8` — native provenance rebuild, ABI checks and the deeper SMB feasibility trail: `docs/validation/v0.2/logs/t04-winhost-r3-0062bb8.log`
- **Write-set:** `packages/recipe-runtime/**` only (src + test + native). No overlap with open PRs #168/#171/#172/#174/#175.
- **Gate:** workspace `task-check.sh` (lint → typecheck → test, all packages) exit 0 at this SHA.

## Host facts (physical run)

| Item | Value |
| --- | --- |
| OS | Windows 11 Pro build 26300.9711 |
| Account | `NILAR\15549` — Administrators-group member running a **non-elevated UAC-filtered token** (Medium integrity `S-1-16-8192`, asserted by the privilege-gate test each run) |
| Node | v24.21.0 (`.node-version`) |
| Native addon | `packages/recipe-runtime/native/impl/shun_win32_impl.node`, SHA256 `7f85afc973ae8d49c817a9ae8c1d16e4225a313f4114eebe12760f038ce847fb`, rebuilt at this SHA from the exact Rust sources with the pinned toolchain (`stable-x86_64-pc-windows-gnu`, per `native/README.md`). Independently re-verified at `0062bb8` (see the R3 section below): GitHub blob bytes match the checkout, and a fresh `CARGO_TARGET_DIR` rebuild from the recovered PE epochs reproduces both committed addons byte-for-byte. |
| SQLite | real file-backed `ShunStore` per fixture (`WAL` + `synchronous=FULL`), real `AuthorizationAuthority`/`ActionController` |

## R2 P1-01 — the oracle performs ZERO pathname IO (confinement redesign)

`src/r0-independent-poststate-oracle.ts` was rewritten. The libuv path observer
(`lstatSync`/`opendirSync` over user-controlled pathnames) is GONE:

1. **Static root admission (zero IO)** — fixed-drive syntax only, no UNC/device paths, per
   component name sanity (independently written from the native walker's checks).
2. **OS-attested fixed-local drive admission (zero IO on the target drive)** — two purely local
   kernel questions via two new raw addon exports: `QueryDosDeviceW` (`dosDevice`) must map the
   letter to a `\Device\HarddiskVolume*` device (refuses `\Device\LanmanRedirector\...` mapped
   roots, `\??\C:\...` subst aliases and every other device form) and `GetDriveTypeW`
   (`driveType`) must be `DRIVE_FIXED`. A mapped SMB root is refused **before any handle on that
   drive exists** — zero network ops.
3. **Handle-anchored traversal** — every directory/file is opened through the raw NT adapter with
   a single name component anchored at an already-verified parent handle (`NtOpenFile` with
   `FILE_OPEN_REPARSE_POINT`), so no ancestor can redirect resolution; a junction anywhere
   (ancestor or in-tree) yields the reparse point itself and is refused from attributes — its
   target is never opened, not even for metadata.
4. **Object-identity cross-check** — every opened object is compared against the 64-bit FileId
   enumerated from its verified parent handle (`entryId`, new raw export). A same-name swap
   between enumeration and open is refused **before any content byte is read**. The file index
   crosses the addon boundary as an exact BigInt: NTFS file references exceed 2^53 and a JS
   Number silently rounds (found and fixed during this round — ±1 mismatches).
5. **Content-bound fingerprint** — each file's identity line carries relative path, kind, size,
   mtime, 64-bit FileId AND a SHA-256 of its content (per-file cap 256 KiB, walk budget 32 MiB,
   deterministic sorted processing), so a swap preserving superficial size/mtime changes the
   fingerprint.

Independence statement (updated honestly): the oracle shares only the raw-syscall adapter (no
parsing, bounds or policy in it) with the native walker; enumeration decoding here is a separate
DataView-based decoder, matching is this module's recursive-memo glob matcher (not the walker's
DP loop), and all traversal/validation/fingerprinting logic is separate code.

Mechanical negative controls (new `test/r0-oracle-confinement.test.ts`, all real filesystems):

| Falsifier | Result | Evidence line |
| --- | --- | --- |
| Junction ANCESTOR: root behind a junction | refused at that component; open log ends exactly at the junction name, zero file opens, zero opens below it | `ORACLE_JUNCTION_ANCESTOR_ZERO_IO=PASS` |
| In-tree junction | refused from enumeration metadata alone; target never opened | `ORACLE_INTREE_JUNCTION_REFUSED=PASS` |
| Subst alias root | refused by device attestation with **zero opens at all** | `ORACLE_SUBST_ZERO_IO=PASS` |
| Drive-attestation decision matrix incl. `\Device\LanmanRedirector\;Q:...` (mapped SMB device form) | only `\Device\HarddiskVolume*` + `DRIVE_FIXED` admits | `ORACLE_DRIVE_ATTESTATION_MATRIX=PASS` |
| Real mapped SMB drive (env-gated `SHUN_T04_SMB_DRIVE_ROOT`) | fail-closed with zero opens when provided | `ORACLE_SMB_MAPPED_ZERO_IO=SKIPPED_NO_SMB_DRIVE_PROVIDED` (this host provides none — see below) |
| ACTIVE concurrent swap of the ancestor and an in-tree directory (4 s swapper child) | 9686 admitted walks all observed the real world byte-identically outside the toggled subtree (incl. content hashes); 2315 refused (counts vary run to run — the cited log is quoted; every recorded run shows `SWAP_RACE_EXERCISED=true`); zero foreign worlds, zero match fabrications | `ORACLE_RACE_NO_FOREIGN_WORLD=PASS OK=9686 REFUSED=2315 SWAP_RACE_EXERCISED=true` |
| Content swap preserving name/size/mtime | fingerprint changes; task semantic verdict refuses (`SEMANTIC_EXPECTATION_MISMATCH`) | `ORACLE_CONTENT_SWAP_REFUSED_BY_SEMANTIC_VERIFIER=PASS` |

## R2 P1-02 — receipt phase binding (no positive before durable phase evidence)

`src/trusted-windows-r0-effect.ts` no longer mints `COMPLETED_VERIFIED` from the oracle result
alone. The positive receipt now exists only after:

1. two independent oracle walks bracket the single native scan with equal content-bound
   fingerprints and an equal match set;
2. the **immutable expected-state commitment** (expected-state fingerprint, observation digest,
   post-state fingerprint) is durably persisted as a **phase receipt** in a new journal table
   `recipe_r0_effect_phase_v02` (`SqliteR0EffectJournal.recordEffectPhase`), bound to the exact
   task/action/intent of the durable `STARTED` reservation (an unreserved attempt is refused);
3. the phase row is **re-read back** and its digest re-verified (`lookupEffectPhase`; a tampered
   or divergent row is refused — the row digest is recomputed from the stored fields);
4. the receipt's `journalRef` cites the REAL phase receipt digest
   (`recipe_r0_effect_phase_v02:<sha256>`) — the constant table name is gone.

The separate task semantic verifier (`r0-task-semantic-verifier.ts`) now additionally refuses
unless the receipt cites the persisted phase receipt and its own fresh walk still reproduces the
effect-time post-state fingerprint (content-bound), so a swap that preserves size/mtime between
effect and verification cannot mint a Task semantic PASS.

Mechanical falsifiers (new `test/trusted-windows-r0-effect.test.ts` + journal immutability):

| Falsifier | Result | Evidence line |
| --- | --- | --- |
| No phase journal wired | no positive receipt, ever | `PHASE_NO_JOURNAL_NO_POSITIVE=PASS` |
| Phase persistence refused | UNCERTAIN | `PHASE_RECORD_REFUSED_UNCERTAIN=PASS` |
| Phase readback corrupt/divergent | UNCERTAIN | `PHASE_READBACK_CORRUPT_UNCERTAIN=PASS` |
| Positive receipt cites the real phase digest | `journalRef` = `recipe_r0_effect_phase_v02:<digest>` | `PHASE_POSITIVE_CITES_REAL_RECEIPT=PASS` |
| Unreserved attempt / divergent re-record / tampered row | refused (`JOURNAL_REFUSED` / `PHASE_DIVERGED` / digest mismatch) | `PHASE_JOURNAL_IMMUTABILITY=PASS` |

## R2 P2-01 — hard-kill proof strengthened (mirrors #172 R2)

`test/windows-host-hardkill-replay.test.ts` now proves the forced death, not just a nonzero
exit: the acknowledged child is observed **still running** a bounded moment after its
synchronous `PRE_EFFECT` acknowledgement (liveness probe), the **PARENT** issues the kill and
asserts the request was accepted, and the close is validated by the same forced-death predicate
`#172` R2 reviewed (POSIX `SIGKILL`/null-code or the Windows TerminateProcess exit-code-1
identity — valid only on top of observed-alive + parent-issued). A negative control re-runs the
predicate over ordinary self-exits (codes 13/1/0, with and without a claimed kill acceptance)
and all are rejected. All durable `STARTED`/`RECONCILE_REQUIRED`/`JOURNAL_REFUSED`/zero
re-dispatch/fingerprint-unchanged assertions are preserved.

| Falsifier | Result | Evidence line |
| --- | --- | --- |
| Parent-issued kill with liveness + identity predicate | PASS (`signal=SIGKILL, code=null` on this host) | `E2E_HARDKILL_START_COMMITTED=PASS E2E_KILL_IDENTITY=code:null,signal:SIGKILL` |
| Ordinary-exit negative control | rejected for 13/1/0 × kill-accepted true/false | `E2E_HARDKILL_ORDINARY_EXIT_REJECTED=PASS` |
| Restart never replays | row stays `STARTED`; exact-intent `RECONCILE_REQUIRED`; changed intent `JOURNAL_REFUSED`; fresh composition dispatches zero effects | `E2E_RESTART_NO_REPLAY=PASS` |

## Full closed loop (unchanged coverage, re-run at this SHA)

| Falsifier | Result | Evidence line |
| --- | --- | --- |
| Standard-user privilege gate | PASS — Medium integrity token, High refused | `E2E_PRIVILEGE_TOKEN=MEDIUM` |
| Grant → durable STARTED → one native scan → independent oracle → phase receipt → receipt → journal observation → separate semantic verifier | PASS; 4 matches reproduced independently; second run of same identity refused with zero re-dispatch | `E2E_POSITIVE_LOOP=PASS E2E_REPLAY_REFUSED=PASS E2E_SEMANTIC=PASS` |
| In-scope junction pointing outside | native walk refuses the reparse entry; receipt `UNCERTAIN`; journal `UNCERTAIN`; retry never re-dispatches | `E2E_JUNCTION_REFUSED=PASS E2E_JUNCTION_NO_REPLAY=PASS` |
| 8.3 short-path spelling | accepted through handle expansion, loop closes positively | `E2E_SHORT_PATH_ACCEPTED=PASS` |
| Subst drive-letter alias as scope root | refused end to end | `E2E_SUBST_REFUSED=PASS` |
| Missing native addon (fresh child process) | run refuses `RECIPE_EXECUTION_UNCERTAIN`, durable row `UNCERTAIN`; restored addon closes the loop again | `E2E_MISSING_ADDON_FAIL_CLOSED=PASS` |

Package suite at this SHA: **11 test files, 64 passed, 1 skipped, 0 failed**. The one skipped test
is the pre-existing EPERM-gated directory-symlink canary (`test/scoped-file-search.test.ts`,
"refuses a directory symlink when the host can create one" — a non-elevated token cannot create
directory symlinks); the env-gated SMB canaries are NOT the skipped test — they execute and pass
with their honest console markers. Full-workspace `task-check.sh` exit 0 (see the raw log header
for exact codes). Re-run at the PR head `0062bb8` (R3 controller round, real
`PACKAGE_TEST_EXIT=0` in `logs/t04-winhost-r3-0062bb8.log` §4): **11 test files, 64 passed,
1 skipped, 0 failed**, physical operator-gated suites executed on the Medium token
(`E2E_PRIVILEGE_TOKEN=MEDIUM`), both SMB canaries printed their honest
`SKIPPED_NO_SMB_DRIVE_PROVIDED` markers.
The physical host-evidence suites (the closed-loop E2E and the hard-kill replay) are
**operator-gated**: `test/helpers/win-token.ts` skips them with an explicit
`E2E_PHYSICAL_SUITE=SKIPPED_ELEVATED_TOKEN` marker wherever the session token is elevated
(High integrity) — CI runner images may present one, and per the CI lane's own contract
(`.github/workflows/executor-windows.yml`) CI is source/ABI regression only, never standard-user
host integration. All unit-level falsifiers (oracle confinement, phase binding, journal
immutability, pack contents) run everywhere.

## R3 controller round at 0062bb8 — independent native rebuild byte-identity, ABI, SMB re-probe

Run on 2026-10-24 at the PR head `0062bb8429d8666a3c9e88080db3f24f151f0f31`
(tree `51211bab7e433ade0de6b68d7c0e0686566a97db`), fresh worktree, no source changes
(`git diff 75dec6d..0062bb84 -- packages/recipe-runtime/native` is empty; native artifacts
unchanged since the R2 rebuild). Raw trail: `logs/t04-winhost-r3-0062bb8.log`.

1. **Committed-artifact identity** — GitHub blob bytes (`gh api /git/blobs/<sha>` raw) match the
   checkout for both addons; `impl` SHA256
   `7f85afc973ae8d49c817a9ae8c1d16e4225a313f4114eebe12760f038ce847fb`, `canary` SHA256
   `b5f8d1bf5b4a3927ff7c259f751b50ee63fc5dfab99c85b66ca148985a87d5a0`.
2. **Independent rebuild, byte-identical** — fresh `CARGO_TARGET_DIR` outside the repo,
   `CARGO_INCREMENTAL=0`, `--locked`, pinned `stable-x86_64-pc-windows-gnu` rustc/cargo 1.99.1,
   node import library regenerated per `native/README.md` (node.exe
   `ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32`, libnode.dll
   `80741b7316820417f09fc5a226654a4b7b720ff470b7465d6e91aa1f04538ce6`). Link epochs were
   recovered from the committed PE headers (impl TimeDateStamp `1792836474`; canary
   `1792785321`, matching the value already recorded in `native/README.md`) and passed via
   `SOURCE_DATE_EPOCH`; the canary was relinked after `cargo clean -p shun-win32-canary`.
   Build exits `IMPL_BUILD_EXIT=0`, `CANARY_BUILD_EXIT=0`. Both rebuilt cdylibs are
   **SHA256-identical and `cmp`-byte-identical** to the committed `.node` artifacts
   (`REBUILD_BYTE_IDENTITY=PASS`).
3. **ABI verification of the committed artifacts** — PE machine `0x8664` (x64) for both; both
   load and run under Node `v24.21.0` with runtime NAPI version 10 (≥ the addon's `napi8`
   floor): all 10 `impl` exports (`close, dosDevice, driveType, entryId, entryInfo, enumerate,
   finalPath, openDir, openFile, readFile`) and all 6 `canary` exports are callable;
   functional smoke returns correct OS answers (`dosDevice("C:") = \Device\HarddiskVolume3`,
   `driveType("C:\") = 3` DRIVE_FIXED, root-dir open → DIRECTORY attributes → `finalPath` =
   `\\?\C:\` → close). `ABI_RUNTIME_LOAD_AND_CALL=PASS`.
4. **SMB feasibility re-probe** — see the section above; conclusion `NOT_RUN` stands, now with a
   mechanically exhaustive elevation/networking trail.

## Real SMB mapped drive negative — NOT_RUN (unchanged, honest)

Re-attempted within R2: the loopback mappings (`\\127.0.0.1\C$`, `\\localhost\C$`, LAN-IP) fail
with system error 67 — the SMB server hides administrative shares from the non-elevated
(filtered) token, and creating a user share requires elevation this host does not grant. WSL
mirrored networking still binds port 445 to the Windows SMB server, so no WSL-side server can
serve a mappable share without disrupting shared local services (R1 trail below stands). The
falsifier runs wherever `SHUN_T04_SMB_DRIVE_ROOT` (oracle-level, zero-open proof) or
`SHUN_E2E_SMB_DRIVE_ROOT` (full-loop refusal) is provided on a host with a real mapped drive.
The device-attestation decision itself is unit-covered for the exact mapped-SMB device string
(`\Device\LanmanRedirector\;Q:...`), and the physically equivalent alias case (subst) is proven
end-to-end with zero opens. **This item remains explicitly outstanding: it is NOT claimed.**

R3 controller round at `0062bb8` re-derived the same conclusion from a wider mechanical trail
(raw probe outputs in `logs/t04-winhost-r3-0062bb8.log` §3 — every probe read-only or refused by
the OS, zero state changed):

- `net use \\localhost\IPC$` / `\\localhost\C$` / `\\192.168.100.245\C$` → system error 67
  (找不到网络名); `New-SmbMapping -RemotePath \\localhost\C$` → same refusal.
- Share creation under the filtered token: `net share T04SMBPROBE=... /grant:NILAR\15549,FULL`
  → **system error 5, 拒绝访问** (needs elevation).
- Elevation paths, exhausted: Windows `sudo` disabled host-wide ("已在此计算机上禁用 Sudo");
  `schtasks /create /rl HIGHEST` from the filtered token → 拒绝访问; UAC policy is
  `EnableLUA=1, ConsentPromptBehaviorAdmin=0x5, PromptOnSecureDesktop=1` — every elevation
  requires interactive consent on the secure desktop, so no unattended path exists.
- Port 445 is owned by the kernel SMB server (`Get-NetTCPConnection -LocalPort 445` →
  OwningProcess 4 = System), closing every local bind for a third-party SMB server on any
  address. WSL is `networkingMode=mirrored` and the WSL docker bridge is unreachable from the
  host: `Get-NetRoute 172.17.0.0/16,172.18.0.0/16` → none, `Test-NetConnection 172.17.0.1:445`
  → False. A `\\wsl.localhost\Ubuntu` mapping (9P, non-SMB) also returns error 67 from this
  session, so no supplementary remote-provider control could be mapped either.

Conclusion unchanged: **`SMB_MAPPED_NETWORK_DRIVE_NEGATIVE=NOT_RUN`** on this host — the two
env-gated falsifiers executed honestly with `SKIPPED_NO_SMB_DRIVE_PROVIDED` markers in the R3
suite run (§ full loop below and the R3 log §4), and the SMB device-form refusal stays
unit-proven (`ORACLE_DRIVE_ATTESTATION_MATRIX=PASS`).

## What this PR does NOT claim

- No Task PASS beyond the single bounded read-only R0 fixture, no T04 acceptance, no T07
  unblock, no Release qualification. `T04_DONE=NO`.
- The oracle now shares the raw NT syscall adapter with the native walker (both sides parse,
  traverse, match and fingerprint independently). If the R2 reviewer judges the raw-adapter
  sharing a common-mode risk, the conservative fallback remains: refuse the oracle and keep the
  #171 UNCERTAIN path — every anomaly already degrades there.
- The receipts carry no file names/paths/content; only classifications and digests.
- Multi-node plans, mutating actions, real Host installation layout, revocation across a
  distributed authority and T09/T11 TOCTOU/native-code concerns remain open.
