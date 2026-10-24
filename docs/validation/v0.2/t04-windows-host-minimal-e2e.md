# T04 Windows Host minimal end-to-end closed loop — physical standard-user evidence

- **PR / branch:** this PR `task/shun-i108-winhost` (base `version/v0.2.0@a5667f289d4ca004215958a43edbe1c0c0c2d99d`, not merged)
- **Validated at this exact SHA:** `dae91c9eadafa0a55260672e17042cf68380b223` (tree `0bc6b2d192cbe0fc107a960c0b4ae13dfb7c2e64`, recorded in the raw log header)
- **Raw evidence log:** `docs/validation/v0.2/logs/t04-winhost-e2e-dae91c9.log` (real vitest output, real exit codes: `E2E_VITEST_EXIT=0`, `PACKAGE_VITEST_EXIT=0`)
- **Write-set:** new files only under `packages/recipe-runtime/**` (T04-owned). No existing source file touched; no overlap with open PRs #168/#171/#172.
- **Gate:** workspace `task-check.sh` (lint → typecheck → test, all packages) exit 0 at this SHA.

## What this closes from Issue #108 handoff (comment 6379665767)

The handoff names as the remaining hard gate: a trusted private Windows Host bootstrap composing
(1) real SQLite ShunStore/ActionController grant-currentness and immutable plan resolution,
(2) the fixed reviewed native R0 port, (3) durable pre-effect STARTED journal, and
(4) an actually INDEPENDENT expected-state/post-state oracle plus a separate task semantic verifier —
with physical falsifiers (junction/reparse/8.3, mapped-drive vs subst, fail-closed missing addon,
hard kill/restart without cross-process repeat) under a standard-user token.

## Host facts (physical run)

| Item | Value |
| --- | --- |
| OS | Windows 11 Pro build 26300.9711 |
| Account | `NILAR\15549` — Administrators-group member running a **non-elevated UAC-filtered token** (Medium integrity `S-1-16-8192`, no High `S-1-16-12288`; asserted by the privilege-gate test, recorded in the raw log) |
| Node | v24.21.0 (matches committed addon ABI) |
| Native addon | `packages/recipe-runtime/native/impl/shun_win32_impl.node` (committed, R3-validator-provenance Rust/windows-rs NAPI-RS build) |
| SQLite | real file-backed `ShunStore` per fixture (`WAL` + `synchronous=FULL`), real `AuthorizationAuthority`/`ActionController` |

## Composition under test (all in the T04-owned package)

1. `src/r0-independent-poststate-oracle.ts` — the **independent** post-state oracle. Shares no code,
   syscalls or implementation with the native walker: plain Node/libuv filesystem primitives,
   whole-tree fingerprint (relpath/kind/size/mtime, SHA-256), own bounded recursive-memo glob
   matcher (the native walk uses a DP matcher). Any reparse/symlink entry, bound overrun or read
   anomaly degrades to "not verified", never to PASS.
2. `src/trusted-windows-r0-effect.ts` — trusted host effect: captures the pre-effect fingerprint,
   runs exactly ONE genuine native scan, captures the post-effect fingerprint, then mints
   `SUCCEEDED / COMPLETED_VERIFIED / postStateVerified=true` **only** when the oracle independently
   reproduces the observation and proves the scope unmutated. Every other outcome returns the
   conservative `UNCERTAIN / MAY_HAVE_EXECUTED_UNCERTAIN / postStateVerified=false` receipt
   (no paths, no file names, no counts in receipts). This is the #171 R1 P1 remediation shape:
   the positive classification now has a separately implemented oracle + durable journal binding.
3. `src/r0-task-semantic-verifier.ts` — separate task semantic verdict. Reads the durable journal
   (state must be `OBSERVED_NOT_SEMANTICALLY_VERIFIED` with a receipt digest), verifies the digest
   binds the handed receipt, requires all-green effect-time oracle evidence, and recomputes its own
   fresh expected-state walk with the oracle matcher. Emits `taskSemantic` only; never mints or
   mutates journal rows, and the runner's `taskPass` stays `false` by construction.
4. `test/helpers/*` + `test/windows-host-*.test.ts` — physical falsifiers below.

## Physical falsifier results (real run, exit 0)

| Falsifier | Result | Evidence line |
| --- | --- | --- |
| Standard-user privilege gate | **PASS** — Medium integrity token, High refused | `E2E_PRIVILEGE_TOKEN=MEDIUM` |
| Full closed loop: persisted policy → real ActionController grant → durable `BEGIN IMMEDIATE` STARTED → one native Rust scan → independent oracle → receipt → journal observation → separate semantic verifier | **PASS** — `EXECUTED_NOT_SEMANTICALLY_VERIFIED`, `taskPass:false`; 4 matches reproduced independently; second run of same identity refused with zero re-dispatch | `E2E_POSITIVE_LOOP=PASS E2E_REPLAY_REFUSED=PASS E2E_SEMANTIC=PASS` |
| In-scope junction (`mklink /J`) pointing outside, with a matching file at the target | **PASS** — native walk refuses the reparse entry without following; receipt `UNCERTAIN/postStateVerified=false`; journal `UNCERTAIN`; retry never re-dispatches | `E2E_JUNCTION_REFUSED=PASS E2E_JUNCTION_NO_REPLAY=PASS` |
| Real process hard kill between durable STARTED commit and receipt | **PASS** — separate Node child composes the REAL host, acks `PRE_EFFECT` synchronously after the committed reservation, is `SIGKILL`ed; restart view: raw row `STARTED`, exact-intent reserve `RECONCILE_REQUIRED`, changed intent `JOURNAL_REFUSED`, fresh composition run refuses with **zero** native dispatches, scope fingerprint unchanged | `E2E_HARDKILL_START_COMMITTED=PASS E2E_RESTART_NO_REPLAY=PASS` |
| 8.3 short-path spelling of the approved scope | **PASS** — root expressed via `~` alias accepted through handle expansion, loop closes positively | `E2E_SHORT_PATH_ACCEPTED=PASS` |
| `subst` drive-letter alias as scope root | **PASS** — refused by final-path provenance (`V:` resolves to the real path ≠ drive root) | `E2E_SUBST_REFUSED=PASS` |
| Missing native addon (fail-closed) | **PASS** — proven in a fresh child process (in-process module cache would mask it): run refuses `RECIPE_EXECUTION_UNCERTAIN`, durable row `UNCERTAIN`; restored addon closes the loop again | `E2E_MISSING_ADDON_FAIL_CLOSED=PASS` |
| **Real SMB mapped drive negative** | **NOT_RUN — honest, root-caused (see below)** | `E2E_SMB_MAPPED_DRIVE_NEGATIVE=SKIPPED_NO_SMB_DRIVE_PROVIDED` |

The SMB test is **env-gated**: setting `SHUN_E2E_SMB_DRIVE_ROOT=<mapped drive>` on any host that
provides a real SMB mapped drive runs the same refusal negative against it.

## Why the real SMB mapped drive canary did NOT run on this host (root-caused attempt trail)

Per the "no mock may be reported as real host proof" rule, the SMB canary was genuinely attempted
and failed for host-topology reasons, recorded here rather than skipped silently:

1. Windows-only administrative shares (`C$`/`ADMIN$`/`IPC$`) exist; creating a share requires an
   elevated token the canary process does not hold (non-elevated Medium integrity).
2. Samba 4.23.6 was installed in the WSL2 Ubuntu distro to serve a real loopback SMB share; `smbd`
   PANICed at startup: `open_sockets_smbd() failed` (logged in `/var/log/samba/log.smbd`).
3. Root cause: `wslinfo --networking-mode` = **mirrored**; the Windows SMB server (System, PID 4)
   binds `0.0.0.0:445` and `[::]:445`, so no SMB server can bind port 445 on any reachable address
   in mirrored mode.
4. The fix would be switching WSL to NAT mode (`wsl --shutdown`), which stops the resident
   `docker-desktop` distro and its containers — a destructive side effect on shared local services
   that outweighs a negative canary, so it was not done. UNC-admission and final-path provenance
   refusals remain covered by the merged #162/#169 code path and the subst/8.3/junction canaries.

Consistent with the standing issue checkpoint (`REAL_SMB_MAPPED_VOLUME_NEGATIVE=NOT_RUN`), this
remains an explicitly outstanding T04 qualification item — it is NOT claimed here.

## What this PR does NOT claim

- No Task PASS, no T04 acceptance, no T07 unblock, no Release qualification. `T04_DONE=NO`.
- The semantic verdict proven here is for one bounded read-only R0 `file.search` fixture on one
  host; multi-node plans, mutating actions, real Host installation/package layout, revocation
  across a distributed authority and T09/T11 TOCTOU/native-code concerns remain open.
- The receipts carry no file names/paths/content; only classifications and digests.
