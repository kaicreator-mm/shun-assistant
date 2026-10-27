# T08 C03 FINAL Windows incremental canary — daef8b4 + PR193, C05 preserved, hot revoke zero-send, exactly one consented real DeepSeek request

- **Under validation:** PR #193 head `304f2a1748b027779c6d091ed98fe238c1defcf7` against the advanced version baseline
- **Version baseline:** `daef8b485ff035316371c4137711206a409fb67f` (`feat(v0.2 T08): save immutable built-in Recipe candidate in Control UI (#196)` — C05 merged)
- **Integration tree (fresh actual merge, this worktree):** merge commit `15bba997f85e2a2794761dd48ceb0c08d2b3c2b5`, **exact resultant tree `ae292102c8781677700f48b223103490e0bd71f0`**, parents `daef8b485ff035316371c4137711206a409fb67f 304f2a1748b027779c6d091ed98fe238c1defcf7` (asserted at run time by the driver, `CANARY_MERGE_*` lines in `logs/t08c03-winfinal-ae292102.log`).
- **Merge conflicts (real, resolved in the original concern — both lanes kept):** the two branches share `main.ts`, `server.ts`, `app.js` (index.html auto-merged):
  - `main.ts` — both the C05 `saveBuiltinInventoryCandidate` wiring and the C03 `cloudInterpreterFromEnvironment()` are passed to `createControlServer`.
  - `server.ts` — options/ctx carry BOTH `saveBuiltinInventoryCandidate` and `cloud`; both the C05 route `POST /api/recipes/builtin/system-inventory/save` and the C03 routes `GET /api/cloud/status` + `POST /api/cloud/interpret` are registered.
  - `app.js` — C05 `wireBuiltinRecipeSave()` AND C03 `wireTrustedCloudInterpretation()` (with the preview-gated `onDisplayed` handoff into `wireCloudDisclosurePreview`) are both wired.
- **Native C02 pins at this tree:** `verifyArtifacts()` ok — broker exe `c85420cabd60e264e806fdfc5025287feb2f8168ce84d766b49fb2c91732c567`, host addon `a616ff35c0da830f1d6a3bd9e0f4df18cc2ef4deb97e565f92bbd3b53fe05f75` (reviewed PR194 bytes preserved).
- **Host facts:** Windows 11 Pro build 26300 x64, `NILAR\15549` non-elevated standard-user token, Node `v24.21.0` (repo `.node-version`; `--experimental-transform-types` runtime flag only, Node 24 strip-only cannot parse the TS parameter properties in `native/index.ts`).
- **Driver:** `logs/t08c03-winfinal-ae292102-driver.mjs.txt` (verbatim). Server child production-clean (no `SHUN_CONSENT_TEST_INSTRUMENTS`); only the separate driver process carried the R1-gated dialog automation. Bash exit code: **`DRIVER_EXIT=0`**.

## Scoped reuse (no full matrix repeated)

`vitest run test/cloud-interpret.test.ts test/recipe-ui.test.ts test/cloud-disclosure.test.ts` at this tree — **12/12 passed, exit 0** (`logs/t08c03-winfinal-ae292102-scoped-tests.log`). This reuses the reviewed C03 and C05 claim tests instead of re-running the historical full CN+EN provider matrix.

## Evidence (all assertions green, `CANARY_EXIT=0`)

### Phase 0 — material + real host

| Check | Result | Evidence line |
| --- | --- | --- |
| Exact tree asserted | `15bba99…` / `ae292102…` / parents `daef8b4 304f2a17` | `CANARY_MERGE_COMMIT/TREE/PARENTS` |
| Credential present, never logged | server child reads env only | `DEEPSEEK_API_KEY=PRESENT_IN_ENV_OF_SERVER_CHILD`, final `SANITIZATION_GUARD=PASS` |
| Operator Ed25519 material | fresh keypair; SPKI SHA-256 pinned via env | `OPERATOR_AUTHORITY_SPKI_SHA256=5ceb4eff…` |
| Host up, cloud lane enabled | pins + policy + key + broker availability | `PHASE0_STATUS_HTTP=200`, `PHASE0_STATUS_ENABLED=true`, `PHASE0_PINS_POLICY_KEY_BROKER=PASS` |

### C05 preservation probe (PR #196 kept by the merge)

| Check | Result | Evidence line |
| --- | --- | --- |
| Recipe save UI present in served page | `save-inventory-recipe` button found | `PHASE_C05_UI_SAVE_BUTTON_PRESENT=true` |
| `POST /api/recipes/builtin/system-inventory/save` alive | typed **503 `RECIPE_STORAGE_UNAVAILABLE`** on the demo host (route survived the merge; Demo still never claims durable storage — not a 404) | `PHASE_C05_SAVE_ROUTE_HTTP=503`, `PHASE_C05_SAVE_ROUTE_CODE=RECIPE_STORAGE_UNAVAILABLE` |
| C05 claim tests green at merge | `recipe-ui.test.ts` 2/2 in the scoped run above | exit 0 |

### Phase A — external signed policy hot revoke (server keeps running, same PID)

| Falsifier | Result | Evidence line |
| --- | --- | --- |
| Authority file deleted while host runs → interpret attempt | HTTP **503 `CLOUD_UNAVAILABLE`** in 5 ms | `PHASE_A_INTERPRET_HTTP=503`, `PHASE_A_INTERPRET_CODE=CLOUD_UNAVAILABLE`, `PHASE_A_INTERPRET_LATENCY_MS=5` |
| Status after revoke | `enabled=false` | `PHASE_A_STATUS_ENABLED_AFTER_REVOKE=false` |
| New broker spawns | **zero** | `PHASE_A_NEW_BROKER_SPAWNS=NONE` |
| New budget reservation | **zero** — ledger SQLite never created | `PHASE_A_LEDGER_FILE=ABSENT (zero new reservation)` |
| Active cloud egress to `api.deepseek.com` (`3.173.21.63`) | **zero rows** | `PHASE_A_CLOUD_EGRESS_ACTIVE_TCP_ROWS=0` |
| Overall | `PHASE_A_HOT_REVOKE_ZERO_SEND=PASS` — `DEEPSEEK_API_KEY` stayed set, so only the revoked policy prevented a send | |

### Phase B — same-material reissue + exactly one consented real request

| Falsifier | Result | Evidence line |
| --- | --- | --- |
| Re-signed policy, identical facts (fresh lease only) | re-enabled **without restart**, same PID | `PHASE_B_STATUS_ENABLED_AFTER_REISSUE=true`, `PHASE_B_SERVER_PID_UNCHANGED=4692` |
| Real Win32 consent dialog (C02 broker) | broker `pid=32948`; automation armed from driver; `found/clicked/done = true` | `PHASE_B_DIALOG_ARM=pid=32948 armId=1`, `PHASE_B_DIALOG_FOUND/CLICKED/DONE=true` |
| Exactly ONE real DeepSeek request | HTTP **200** in 2.3 s — `UNTRUSTED_REMOTE_PROPOSAL`, `deepseek-flash`, `UNKNOWN_COST`, `executed=false` | `PHASE_B_INTERPRET_*` lines |
| Broker cleanup | exited after run | `PHASE_B_BROKER_REMAINING_AFTER_RUN=NONE(shutdown)` |

### Durable SQLite receipt (sanitized; table stores only hashes/refs — no goal text, no credential)

`v02_cloud_attempts`, exactly **1** row after the whole canary (`LEDGER_ROWS_TOTAL=1`):

| field | value |
| --- | --- |
| attempt_id | `attempt-f64483…` |
| consent_id | `shun-consent-d16de4a9aab80f1ad790df9864984903` |
| task_id | `cloud-0d4a2599…` |
| scope_revision / pricing_revision | `v02-canary-scope-1` / `v02-canary-pricing-1` |
| request_sha256 | `da20af6932a2c92557f66c90ed20cce828d3e16ac2c6f60dfecc0777340b7fe5` |
| projection_sha256 | `d7bb97e848a61af62f245ba45485ed46a5183618610c2463d124d0b276312a31` |
| cost_micros | `24576` (full approved worst-case ceilings reserved before egress) |
| status | `UNKNOWN_COST` |
| created_at | `2026-10-27T05:12:44.632Z` |

Proposal returned to the UI as untrusted non-executable text: 41 chars, SHA-256 `885c6db8…`.

## Workspace gate at this tree

`tools/task-check.sh` at merge commit `15bba99` — full workspace gates (lint → typecheck → tests, all packages): **全绿, exit 0** (`_tmp/t08c03-wininc/taskcheck-final.log`).

## Non-claims

- Backend in `demo` mode; the C03 cloud lane is backend-independent (`/api/cloud/*` routes to `ctx.cloud` directly, identical to the reviewed test harness). No Recipe execution, promotion or action grant is claimed — C05 stays candidate-only, C03 proposal stays untrusted.
- Consent dialog was auto-clicked via the R1-gated instrument; physically human-clicked qualification is NOT claimed.
- This closes the signed-policy real-Windows Host gate for PR #193 at the current version baseline (`PR193_SIGNED_WINDOWS_INCREMENTAL_SMOKE`); review/merge-order decisions remain the controller's. The validated tree `ae292102` is what this branch merges into `version/v0.2.0` and nowhere else.
