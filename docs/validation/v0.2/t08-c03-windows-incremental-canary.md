# T08 C03 Windows incremental canary — signed-policy hot revoke ⇒ zero send; same-material reissue ⇒ exactly one consented real DeepSeek request

- **Under validation:** PR #193 head `304f2a1748b027779c6d091ed98fe238c1defcf7`
- **Integration tree (fresh actual merge, this worktree):** merge commit `aebac1ac67af7507dc03a0a8b0f1073da624e9b9` = `version/v0.2.0@27d9cc8e77e04a396946cf36bb8a06e621a1dd4f` + PR193 head `304f2a17…`, **exact resultant tree `53f54ee774c9b779f21b869f12c2771117d47b22`** (raw evidence: `logs/t08c03-wininc-aebac1a.log`, recorded by the driver from `git rev-parse` at run time; parents asserted equal to the two exact SHAs, else abort).
- **Determinism cross-check:** an earlier synthetic merge of the same two parents (local `task/t08c03-smoke` @ `c9ba2bc`) produced the byte-identical tree `53f54ee7…` — the old pre-#195 synthetic test-merge `8747144` is NOT the tree proven here.
- **Native C02 pins at this tree:** `apps/control-api/native/artifacts.ts` `verifyArtifacts()` returns ok — broker exe `c85420cabd60e264e806fdfc5025287feb2f8168ce84d766b49fb2c91732c567`, host addon `a616ff35c0da830f1d6a3bd9e0f4df18cc2ef4deb97e565f92bbd3b53fe05f75`. The #110 "digest pins disagree" blocker does not affect this merge (reviewed PR194 pins are preserved and match the committed bytes).
- **Host facts:** Windows 11 Pro build 26300 x64, account `NILAR\15549` (non-elevated), Node `v24.21.0` (repo `.node-version`), real file-backed SQLite ledger, real `shun-consent-broker.exe` Win32 dialog on the interactive desktop.
- **Driver:** `logs/t08c03-wininc-aebac1a-driver.mjs.txt` (verbatim copy of the executed script). The **server child ran production-clean** — `SHUN_CONSENT_TEST_INSTRUMENTS` was NOT set for it; only the separate driver process carried the R1-gated dialog-automation instruments. Exit code recorded as `DRIVER_EXIT=$?` in bash: **0**.
- **Protocol:** per the controller checkpoint on #110 — external operator Ed25519 policy hot revoke ⇒ `503` / zero new reservation / zero cloud egress; same-material reissue plus **one** consented DeepSeek request ⇒ untrusted suggestion, `UNKNOWN_COST`, real SQLite receipt. The historical full CN+EN matrix was NOT repeated.

## Evidence (run 3, all assertions green, `CANARY_EXIT=0`)

Driver was started with `SHUN_CONSENT_TEST_INSTRUMENTS=1` only on the driver process; every line below is quoted from `logs/t08c03-wininc-aebac1a.log`.

### Phase 0 — material + real host

| Check | Result | Evidence line |
| --- | --- | --- |
| Exact integration tree asserted | `aebac1a…` / tree `53f54ee7…` / parents `27d9cc8e 304f2a17` | `CANARY_MERGE_COMMIT`, `CANARY_EXACT_TREE`, `CANARY_MERGE_PARENTS` |
| API credential present (never logged) | key read by server child from env only | `DEEPSEEK_API_KEY=PRESENT_IN_ENV_OF_SERVER_CHILD`, `SANITIZATION_GUARD=PASS` |
| Operator Ed25519 material | fresh keypair per run; public SPKI SHA-256 pinned via env | `OPERATOR_AUTHORITY_SPKI_SHA256=03353158…` |
| Host up, cloud lane enabled | policy valid at startup, artifacts pinned, broker available | `PHASE0_STATUS_HTTP=200`, `PHASE0_STATUS_ENABLED=true`, `PHASE0_PINS_POLICY_KEY_BROKER=PASS` |

### Phase A — external signed policy hot revoke (server keeps running, same PID)

| Falsifier | Result | Evidence line |
| --- | --- | --- |
| Authority file deleted while host runs → interpret attempt | HTTP **503** `CLOUD_UNAVAILABLE` in 6 ms | `PHASE_A_INTERPRET_HTTP=503`, `PHASE_A_INTERPRET_CODE=CLOUD_UNAVAILABLE`, `PHASE_A_INTERPRET_LATENCY_MS=6` |
| `GET /api/cloud/status` after revoke | `enabled=false` | `PHASE_A_STATUS_ENABLED_AFTER_REVOKE=false` |
| New `shun-consent-broker.exe` spawns | **zero** (no dialog, no broker, no session) | `PHASE_A_NEW_BROKER_SPAWNS=NONE` |
| New budget reservation | **zero** — ledger SQLite file never created | `PHASE_A_LEDGER_FILE=ABSENT (zero new reservation)` |
| Cloud egress to `api.deepseek.com` (resolved `3.173.21.63`) during phase A | **zero active TCP rows** (one unrelated `TIME_WAIT` residue from an earlier diagnostic probe recorded honestly) | `PHASE_A_CLOUD_EGRESS_ACTIVE_TCP_ROWS=0`, `PHASE_A_EGRESS_TIME_WAIT_RESIDUE=…TIME_WAIT…` |
| Overall | `PHASE_A_HOT_REVOKE_ZERO_SEND=PASS` | `DEEPSEEK_API_KEY` remained set the whole time, so the only thing preventing a send was the revoked policy |

### Phase B — same-material reissue + exactly one consented real request

| Falsifier | Result | Evidence line |
| --- | --- | --- |
| Re-signed policy, **identical facts** (fresh `issuedAt`/`expiresAt` lease only) | cloud lane re-enabled **without host restart**, same server PID | `PHASE_B_STATUS_ENABLED_AFTER_REISSUE=true`, `PHASE_B_SERVER_PID_UNCHANGED=3480` |
| Real Win32 consent dialog (C02 broker) | broker spawned `pid=25756`; dialog automation armed from the separate driver (`allow`), then `found=true clicked=true done=true` | `PHASE_B_DIALOG_ARM=pid=25756 armId=1`, `PHASE_B_DIALOG_FOUND/CLICKED/DONE=true` |
| Interpret outcome | HTTP **200**, `UNTRUSTED_REMOTE_PROPOSAL`, model `deepseek-flash`, `costState=UNKNOWN_COST`, `executed=false` (2.1 s — one real provider round trip) | `PHASE_B_INTERPRET_HTTP=200`, `PHASE_B_INTERPRET_STATUS=UNTRUSTED_REMOTE_PROPOSAL`, `PHASE_B_INTERPRET_COST_STATE=UNKNOWN_COST`, `PHASE_B_INTERPRET_EXECUTED=false`, `PHASE_B_INTERPRET_LATENCY_MS=2057` |
| Broker cleanup | broker process exited after run (session shutdown in `finally`) | `PHASE_B_BROKER_REMAINING_AFTER_RUN=NONE(shutdown)` |

### Durable SQLite receipt (sanitized; the table stores only hashes/refs — no goal text, no credential)

`v02_cloud_attempts`, exactly **1** row after the whole canary (`LEDGER_ROWS_TOTAL=1`):

| field | value |
| --- | --- |
| attempt_id | `attempt-397820…` (full value in raw log) |
| consent_id | `shun-consent-a77cd485d7c5f33f77abafff03f97645` |
| task_id | `cloud-5e1d1d68…` |
| scope_revision / pricing_revision | `v02-canary-scope-1` / `v02-canary-pricing-1` |
| request_sha256 | `da20af6932a2c92557f66c90ed20cce828d3e16ac2c6f60dfecc0777340b7fe5` |
| projection_sha256 | `d7bb97e848a61af62f245ba45485ed46a5183618610c2463d124d0b276312a31` |
| cost_micros | `24576` (full approved worst-case ceilings, reserved before egress) |
| status | `UNKNOWN_COST` |
| created_at | `2026-10-27T03:57:30.047Z` |

`UNKNOWN_COST` is the honest post-send state by design (the send may be billed regardless of response outcome); the HTTP 200 proposal (44 chars, SHA-256 `087c65db…`) was returned to the UI as an untrusted, non-executable suggestion.

## Run history on this tree (honesty; each iteration is a separate operator rerun, and in every run the restored-authorization flow performed exactly ONE real provider request)

1. **Run 1** — operator policy `maxOutputTokens=512`: the single consented request WAS sent and billed (`UNKNOWN_COST` receipt), but `deepseek-flash` is a reasoning model and the reply hit `finish_reason=length` with empty `content`; the transport correctly refused it (`REMOTE_RESPONSE_INVALID` → HTTP 503 `REMOTE_REFUSED`). Product behavior correct; operator material at fault. Ledger row preserved in `_tmp/t08c03-wininc/run1-finish-reason-length/`.
2. **Run 2** — ceilings 8192: the single consented request WAS sent and billed, but end-to-end latency (15.6 s) met the product-hardcoded 15 s fetch timeout (`AbortSignal.timeout(15_000)` in `packages/llm-remote/src/deepseek-transport.ts`) → `REMOTE_UNAVAILABLE` → HTTP 503 `REMOTE_REFUSED`, receipt `UNKNOWN_COST`. Phase A passed unchanged in this run too.
3. **Run 3** — same ceilings with a short CN goal (measured 360 ms probe round trip, `finish_reason=stop`): **full PASS** as documented above.

Diagnostic (non-canary) probes: direct `fetch` to `https://api.deepseek.com/chat/completions` from this host returned HTTP 200 with model `deepseek-flash` — endpoint, key and model all valid; the run-1/2 refusals were response-shape/timeout, not network.

## Workspace gate at this tree

`tools/task-check.sh` at merge commit `aebac1a` (full workspace gates: lint → typecheck → tests, all packages) — **全绿, exit 0**, immediately before this evidence was committed.

## Deviations & non-claims

- Backend ran in `demo` mode (`T08 DEMO ONLY` banner): the C03 cloud lane is backend-independent — `/api/cloud/interpret` routes straight to `ctx.cloud` (`apps/control-api/src/server.ts`), identical to the reviewed `cloud-interpret.test.ts` harness. No Recipe/task execution was involved or claimed.
- The consent dialog was auto-clicked via the R1-gated `brokerTestInstruments.armDialog(…, 'allow', …)` from the driver process. Per the PR #194 R1 P2 caveat, this is real-dialog **automated-click** evidence; physically human-clicked qualification is NOT claimed here.
- Server child needed `node --experimental-transform-types` (Node 24 strip-only mode rejects the TypeScript parameter properties in `native/index.ts`); this is a runtime flag on the canary host, not a product change.
- This proves the two canary transitions on this exact integration tree. It does NOT by itself close PR #193 (independent review statuses and merge-order decisions remain the controller's), does not constitute a physically-human-clicked qualification, and repeats no claim about Demo Goal tasks, which remain labeled simulated.
