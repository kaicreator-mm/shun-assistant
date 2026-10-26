# T08 J0 — live Windows inventory from Control UI, physical standard-user validation

- **PR:** #190 `feat(v0.2 T08 J0): live Windows system inventory from Control UI, reuse T06` (`task/v02-t08-j0-live-inventory-ui` → `version/v0.2.0`)
- **Exact SHA validated:** `a2738f5f1f9723121f94e6b6a76766d7ca2741da` (PR head, worktree `shun-assistant/shun-pr190-j0-winval`)
- **Raw evidence log:** `docs/validation/v0.2/logs/t08-j0-winval-a2738f5.log` (test output with exit codes, launch banner, raw API JSON, Windows ground truth, UI transcript, netstat, git status)
- **Real UI screenshots:** `docs/validation/v0.2/logs/t08-j0-shots/` — `ui-before-click-fullpage.png`, `ui-after-click-system-section.png`, `ui-after-click-viewport.png` (SHA256 in the log)

## Host facts (physical run)

| Item | Value |
| --- | --- |
| OS | Windows 11 专业版 build 10.0.26300.9711 |
| Account | `15549`, non-elevated token — Mandatory Label **Medium** `S-1-16-8192` (standard-user equivalent) |
| Node | v24.21.0 (`.node-version`) |
| Launch | `node --experimental-transform-types apps/control-api/src/main.ts` (the repo-documented packaging-smoke entry; plain `node src/main.ts` fails in Node 24 strip-only mode on resolver parameter properties — pre-existing, not introduced by this PR) |

## Verdict: PASS

The first actual user gesture of T08 works end-to-end on a real Windows host, and every
honesty claim in the PR body held under physical validation.

### 1. Real launch + real click (J0's core claim)

Server started in the default demo mode on `http://127.0.0.1:7788`; the Control UI was
opened in a real browser and **Read system information** was clicked with a real pointer
event at the button's on-screen position. The section status moved
`Not requested yet. → Live local Windows facts read. No cloud call or file changes.`
and six facts were rendered (before/after screenshots committed).

### 2. CPU / memory / disk data comes from THIS Windows machine

`GET /api/system/inventory` compared against `Get-CimInstance` ground truth sampled in
the same window (full numbers in the log):

| Fact | API/UI | Windows truth | Result |
| --- | --- | --- | --- |
| Logical CPUs | 16 | 16 | exact |
| memoryTotalBytes | 59,262,226,432 | 59,262,226,432 | **byte-for-byte** |
| diskTotalBytes | 510,853,640,192 | 510,853,640,192 | **byte-for-byte** |
| diskFreeBytes | 83,743,293,440 | 83,743,416,320 | Δ 122,880 B (0.00015%) |
| memoryFreeBytes | 20,805,070,848 | 21,141,008,384 | Δ ≈1.6%, live free-memory drift between samples |
| uptimeSeconds | 175,340 | 175,352.8 | Δ 12.8 s = capture interval |

UI rendering cross-check: 59,262,226,432 B = 56,516.86328125 MiB, rendered by the UI
as "56516.9" (`toFixed(1)`); disk and uptime figures round the same way. Nothing is
invented: the totals are physically unforgeable byte-for-byte matches, and the code path
is the reviewed T06 collector (`node:os` + `statfsSync('C:\\')` only — no new OS native
code, no shell; the PowerShell helpers in the same package are NOT on this path).

### 3. No cloud call

`netstat -ano` for server PID 24484 captured right after the real click: every socket is
loopback (`127.0.0.1:7788` LISTENING + two `127.0.0.1` ESTABLISHED peers = the local curl
and the local browser). Zero non-loopback remotes. Code-side: UI fetch is relative
(`/api/system/inventory`), the API handler calls the local T06 collector synchronously,
and the response self-reports `localOnly: true, externalDisclosures: []`.

### 4. No file modification

`git status --porcelain` = 0 entries before launch and 0 entries after the full
launch + click + shutdown session. The worktree is byte-identical; the demo backend is
in-memory.

### 5. Demo labelling is truthful

`/api/health` still returns `simulated: true`; the server banner prints
`T08 DEMO ONLY`; the UI banner still says the surface runs the scripted DemoShunBackend
and nothing touches a real system. The new live-inventory section is visually separate
and states the opposite provenance for its own facts only. No demo task was renamed
REAL; `simulation-label.test.ts` and `real-inventory.test.ts` both pass, and the new
test asserts the two provenances stay distinguishable.

## Tests (exit codes recorded in the log)

| Suite | Result | Exit |
| --- | --- | --- |
| `apps/control-api` (includes new `real-inventory.test.ts`, `simulation-label.test.ts`) | 18 files / 88 tests passed | **0** |
| `apps/control-ui` | 20 tests passed | **0** |
| `packages/vertical-system` (reused T06 collector) | 5 files / 25 tests passed | **0** |

The new real-inventory test itself proves the negative contract: on non-Windows the
endpoint must answer explicit 503 `LIVE_SYSTEM_INVENTORY_UNAVAILABLE`, never fabricated
Windows numbers (the Linux CI leg exercises this; the Windows physical run above
exercises the 200 leg).

## R1 independent review — APPROVE (no P1)

An independent R1 reviewer audited the PR diff (all 7 commits), the endpoint/collector/UI
code paths, re-ran all three test suites (same counts, EXIT=0), and reconciled every number
in the evidence log. Verdict APPROVE with two evidence-hygiene findings, both addressed in
the amendment below:

- P2: the first `ui-after-click-viewport.png` actually captured the pre-click state
  ("Not requested yet." — the coordinate click had raced the freshly-loaded layout).
  The after-click claim was already carried by `ui-after-click-system-section.png`
  (verified by R1 to show the status line and the facts).
- P3: a MiB-conversion sentence in this file overclaimed "exactly"; reworded above.

### Amendment (post-R1 re-shoot)

Relaunched the server, opened a fresh UI tab, let the layout settle past one 2.5 s refresh
cycle, re-measured the button position (its settled centre is (330, 448)) and clicked. The
fresh click re-measured the machine live (memory available 22,812.1 MiB, uptime 49.1 h —
different from the first session's 19,981.3 MiB / 48.8 h, further proof each click is a
real new observation, not cached data). `ui-after-click-viewport.png` was replaced with a
full-viewport capture taken in the same instant the DOM read back
`"Live local Windows facts read. No cloud call or file changes."` with 6 facts rendered;
its SHA256 is in the log's amendment section. Worktree still byte-identical afterwards.

## Scope honesty

- PR diff touches exactly the declared files: `apps/control-api/{package.json,src/server.ts,test/real-inventory.test.ts}`, `apps/control-ui/public/{index.html,app.js}`, `pnpm-lock.yaml` (workspace link only). No other write-set.
- This validation covers J0 only: real read-only inventory. It does NOT claim real DeepSeek/consent, T08 close, or v0.2 release (per PR body, those remain open).
- Merge gating for `version/v0.2.0`: this Windows validation + independent R1 review + remote CI green.
