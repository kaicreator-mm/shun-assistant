# i87 U05 — core-only portable boot preflight on real Windows (non-admin): RESULT

Pilot executed against baseline `d812ca2f5d5e48dd637c5580cb4c30ecf4116663` (= live `version/v0.2.0` HEAD, 2026-10-14), worktree `i87-u05-zc`, branch `task/i87-u05-zc`. One-shot research harness in `research/i87-u05/` (231-line `events.ndjson`, per-step evidence JSON files); all staging/sandbox state under `C:\xDev\kAiCreator\_tmp\i87-u05\`. Nothing was merged into product source. **This is an architecture feasibility pilot, not a release-quality user package.**

## Host facts (measured)

- Windows 11 Pro 26H2, build 10.0.26300.9457, x64.
- Account `nilar\15549` is a member of Administrators but **every step ran non-elevated**: Medium integrity (`S-1-16-8192`), no high-integrity SID, `IsInRole(Administrator)=false`. The product's own token observation (via `whoami /groups`) classifies the process `FILTERED_ADMIN` and the signed host-facts gate enforces that exact value — the pilot's privilege facts were verified by Shun itself, not just by the harness.
- No UAC prompt ever appeared; `launch.cmd` is a plain batch file with no elevation manifest; a goal with `allowElevation:true` is refused (`REAL_STORAGE_GOAL_SCOPE_OR_PRIVACY_REFUSED`).

## Portable staging (what "core-only" means here, explicitly)

7 files, **94,672,411 bytes (90.3 MiB)**, every file listed with size + SHA-256 in `staging/manifest.json`:

| file | bytes |
|---|---|
| `runtime/node.exe` — **pinned Node v24.21.0, explicitly bundled** (sha256 `ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32`) | 93,580,104 |
| `server.mjs` — esbuild bundle of `apps/control-api/src/main.ts` (`--bundle --platform=node --format=esm`; zod + all `@shun/*` workspace packages inlined; `node:sqlite` needs no native module) | 1,058,288 |
| `app-ui/*` (index.html, app.js, view-model.js, styles.css) | 33,395 |
| `launch.cmd` (absolute-path launch via `%~dp0`) | 624 |

Manifest (self-excluded) sha256 `bc9ea8a4e28faa45ee8f04b7b23cfd5de5dbfb9face951b7d7218d5e50d2cf6b`. Cold start measured through `launch.cmd` exactly as a user would run it.

## Claim-by-claim verdicts

| # | Claim | Verdict | Evidence (all from real runs; events.ndjson + evidence JSONs) |
|---|---|---|---|
| 1 | Boots in a clean non-developer environment (no pnpm/npm/node on PATH) | **PASS** | `PATH=C:\Windows\System32;C:\Windows`; `where pnpm/npm/node/npx` all exit 1; server starts via bundled runtime |
| 2 | Served by the bundled pinned runtime, not a host Node | **PASS** | PowerShell `Win32_Process.ExecutablePath` == `<staging>\runtime\node.exe`, command line runs `server.mjs` (verified again for the Unicode dir copy) |
| 3 | No network egress; loopback-only surface | **PASS** (behavioral) | `netstat -ano -p tcp` snapshots before/after the full round: only `127.0.0.1:<port> LISTENING` plus the harness's own loopback client sockets; no non-loopback remote endpoints. **Limitation: a non-admin cannot force network isolation** — supported by code audit (loopback-only bind + non-loopback Host refusal; resolver `networkAccess: FORBIDDEN` gate; storage vertical touches local FS only) |
| 4 | Writes stay inside declared roots | **PASS** | Recursive tree snapshots pre→post entire round: staging **0 changed files**, redirected TEMP **0**, `%APPDATA%` top level **0**, `HKCU\Environment` **unchanged**; workspace diff = exactly the 5 deleted cache files; the backend wrote only its declared `state/`, `evidence/`, `registry/` dirs inside the sandbox |
| 5 | Protected-asset canary honored | **PASS** | Declared canary SHA-256 unchanged after a real destructive run; a decoy `cache\` dir *inside* the protected tree survived (PROTECTED beats disposable marker); a goal targeting the canary path is refused at submit |
| 6 | Real C-003 task end-to-end (no demo) | **PASS** | `u05-c003-main-4` (and Unicode round `u05-uni-1`): submit → RESOLVING → AWAITING_AUTHORIZATION → R2 preview (planHash, expiry) → explicit human approval by exact planHash → **SUCCEEDED**, verification `PASS` (`protected-assets-unchanged`, `reclaimed-bytes-verified`); 5/5 seeded cache files deleted; `health.simulated:false` |
| 7 | Conservative fail-closed classification | **PASS** | Lookalike `npm-cache\` (segment `npm-cache` ≠ `cache`) and `temp\` (TEMP not in `eligibleCategories=['CACHE']`) were **retained**; loose root files and user media untouched |
| 8 | Clean exit → restart → state intact | **PASS** | Quiescent stop then restart: durable task restored `SUCCEEDED` / `COMPLETED_VERIFIED` — *"Historical verified result … not a new post-restart measurement"* |
| 9 | Hard kill before effect → recovery | **PASS** | `taskkill /F /T` while `AWAITING_AUTHORIZATION` → restart → `FAILED` / `NOT_STARTED` — *"never crossed the effect-authorization boundary"* |
| 10 | Hard kill after effect boundary → honest uncertainty | **PASS** | Kill at `EXECUTING` (durable `EFFECT_AUTHORIZED` already committed) → restart → `NEEDS_INTERVENTION` / `MAY_HAVE_EXECUTED_UNCERTAIN`, `reconciled:false`; UI recovery → 409 `RECOVERY_NOT_APPLICABLE`; retry → 409 `RETRY_BLOCKED_UNCERTAIN` |
| 11 | Unicode + space paths | **PASS** | Full round from staging copy `…\便 携 包 拷贝` into sandbox `…\用 户 沙 箱`: boot, CIM process identity against the Unicode runtime path (UTF-8 sidecar proof), real task SUCCEEDED, identical filesystem truth. Harness note only: cmd's argv is codepage-mangled, so the launcher was invoked with ASCII argv + cwd while `%~dp0` resolves the wide path |
| 12 | UNC paths (15-min timebox) | **BLOCKED (honest SKIP)** | Over `\\wsl.localhost\Ubuntu`: provisioning **and** the Ed25519 issuance chain **succeeded**; server boot fails at `ShunStore` init — `PRAGMA journal_mode = WAL` → `SQLITE_BUSY: database is locked` (WAL unsupported on the Plan 9 network FS). State-on-UNC is unsupported today; exact error in events.ndjson |
| 13 | Real read-only Windows system observation | **BLOCKED_BY_NOT_YET_IMPLEMENTED** | Real mode ships only C-003 storage. There is no user-facing system-observation endpoint; residue/evidence endpoints return honest typed 404s. (Internal OS observations — token class, `statfs`, cpu/mem — exist solely as enforcement inputs for the signed-facts gates.) Per contract, DEMO was never used as real evidence; demo contrast boot is recorded only to show `health.simulated:true` vs real `false` |
| 14 | No model/provider assumed; honest unavailability | **PASS** | Zero model/provider configuration present; an image-model goal is refused (`REAL_STORAGE_ONLY_C003_SUPPORTED`); only the storage capability exists in the signed catalog |
| 15 | Cold start | **MEASURED** | 3 runs through `launch.cmd`: **173 / 195 / 206 ms** from process spawn to first HTTP 200 (`/api/health`); UI fetch 200 in the same runs |
| 16 | Core size / OS/arch | **MEASURED** | 90.3 MiB total, 7 files — 89.2 MiB is the explicitly bundled pinned Node runtime; application code 1.01 MiB. Requires Windows x64 (arm64 rejected by the real backend) |

## Operational findings (honest; product behaved fail-closed throughout)

1. **Issuance flow is strict by design.** The currentness envelope lives 60 s and the effect gate requires *exact* `currentRevision` equality with the revision bound at submit; `observationRevision` is part of the digest, so **any re-issuance between submit and approve is refused** (`REAL_STORAGE_REGISTRY_ISSUANCE_CHANGED_BEFORE_EFFECT`). On this shared dev host (C: churns by MBs in seconds) two tasks fail-closed this way before the correct operator flow (issue once → approve within the envelope lifetime) was applied.
2. **Privilege-mode pin must match the receiving process token class.** A `STANDARD_USER` pin was refused with a host-facts drift error because the backend observed `FILTERED_ADMIN` (admin-group account, UAC-filtered token). Exactly the intended anti-drift behavior.
3. **A second cleanup on an already-clean workspace correctly refuses** with `GROWTH_NOT_ATTRIBUTED` instead of fabricating work.
4. **Windows console Node has no graceful SIGTERM path** without an in-app handler (v0.2 installs none): orderly `taskkill` (no `/F`) is refused by the OS. Every restart scenario nevertheless recovered consistently — SQLite WAL + `synchronous=FULL` held up under `TerminateProcess` in all three recovery classifications.
5. **Windows phantom port reservations** (bind `EADDRINUSE` while `netstat` shows nothing) interfered with harness port selection; handled by probe-binding. Harness concern, not product.

## Limitations (repeated explicitly)

- Offline behavior is evidenced by runtime observation plus code audit; a non-admin cannot forcibly disable networking, so "offline" here = "no external connections observed + no egress code path exercised".
- State directory on a UNC volume is **not supported today** (SQLite WAL on network FS).
- User-facing read-only Windows system observation is **not implemented** in v0.2 real mode (`BLOCKED_BY_NOT_YET_IMPLEMENTED`); the C-003 storage task (with real preview, real approval, real deletion and post-state) serves as the real-execution evidence.
- Pilot on a single machine; the registry issuer ran operator-side on the same host (production runs it on a trusted build host with ACL-pinned keys).
- Not a user release package: no installer, no auto-start, no secret provisioning story beyond the harness generating them; secrets live in the sandbox `keys/` dir for reproducibility.

## Reproducibility

Harness: `research/i87-u05/*.mjs` (build → provision → issue → boot → negatives → task → recovery → timing → unc), `events.ndjson` (231 steps, appended live), per-round evidence JSONs in `_tmp\i87-u05\<sandbox>\`. Diagnostic note: a research-only bundle copy (`diag-src/`, one added `console.error` in the backend's error swallow) was used once to expose the `GROWTH_NOT_ATTRIBUTED` root cause; no product file was modified (`git status` shows only `?? research/`).

All staging servers killed at close; no listeners remain; no changes to PATH, registry, or firewall (verified by `HKCU\Environment` diff and the absence of any such command in the harness).
