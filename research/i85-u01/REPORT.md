# i85 U01 — Real Windows LOCAL LLM origin and zero-egress falsification

**Overall verdict: BLOCKED** (honest blocker, no fabrication). The positive
acceptance leg — two real inferences through a user-provided local model —
cannot run on this host, because **no local model runtime exists** (every
scanner returns ABSENT, re-verified in this session) and the U01 contract
explicitly forbids silent installation/model download. The isolation half
also could not be *demonstrated* as a non-admin (details below). Everything
runnable without a model was executed for real against the pinned tree; no
source file was modified and the v0.1 `planner-seam` R3 fail-closed behavior
is untouched.

## Pinned tree and host identity

- Repo base SHA: `d812ca2f5d5e48dd637c5580cb4c30ecf4116663` (= live `version/v0.2.0` HEAD at run time), worktree branch `task/i85-u01-zc`.
- `packages/resolver/src/planner-seam.ts` SHA256 (bytes of the pinned tree):
  `f80c72abf77b43df927cfd144e2ed0e7422d218b8299a02ac437a63d08d69f0a` (14,257 bytes).
- Host: Microsoft Windows 11 Pro, build **10.0.26300.9457**, x64.
- User `15549`, **non-elevated for the entire run**. Correction (see follow-up
  comment): the account is a member of the local `BUILTIN\Administrators`
  group running under a UAC-filtered token — `whoami.exe /groups /fo csv /nh`
  (the exact call Shun's own backend uses) shows `S-1-5-32-544` as
  *"Group used for deny only"*, integrity `S-1-16-8192` (Medium),
  `IsInRole(Administrator)=false`, `net session` → rc=2 (access denied). The
  initial draft of this report claimed "not in Administrators group"; that was
  an artifact of invoking MSYS `whoami` (Git Bash), which silently swallows
  `/groups` and produced empty output. Shun's own signed host-facts gate —
  exercised live in the parallel U05 pilot (#87) — classifies this exact host
  as `FILTERED_ADMIN`, confirming the corrected reading. Every conclusion in
  this report is unchanged: no elevation was available or used at any step,
  and all privileged probes (`netsh advfirewall add rule`, `net session`) were
  denied. A true standard-user *account* was not tested on this host.
- Node: v24.21.0, ABI 137 (via fnm).

## Capture protocol

Every harness step appended one NDJSON line to
`research/i85-u01/evidence/events.ndjson` immediately after execution:
`{ts, step, cmd, rc, outTail, sha256}` where `sha256` covers the full raw
command output (large raw captures additionally persisted to
`C:\xDev\kAiCreator\_tmp\i85-u01\`). 77 event lines; SHA256 of each evidence
file is pinned in `evidence/results.json` (`evidenceIntegrity`, recomputed
over the final bytes before commit). All hashes
were computed by `crypto.createHash` over real bytes; every number below was
read back out of the recorded evidence JSONs.

## Local model absence (step 1 re-scan)

Scanners, all **ABSENT** (`evidence/fact-collection.json`): `tasklist /FO CSV`
process-name filter over all processes; `where` for `ollama.exe`,
`llama-server.exe`, `llama-cli.exe`, `lmstudio.exe`, `koboldcpp.exe`,
`gpt4all.exe`; 15 model install/model directories (`~/.ollama`, Ollama/LM
Studio/GPT4All under AppData, `C:\Program Files\Ollama`, …);
`netstat -ano -p tcp` LISTENING filter for ports 11434/8080/1234/7860/5000/1337/4891;
`docker images` model-name filter; live `GET http://127.0.0.1:11434/api/tags`
(FETCH_ERR — connection refused).

## Hostile matrix (real processes, real sockets)

Harmless fictional user goal: *"organize desktop screenshots by date"*. Each
case ran the real `interpretGoalViaPlanner` seam; planners were
invocation-counting wrappers whose first action on ANY invocation is a real
TCP fetch to a live observation sink; three live loopback listeners recorded
TCP connection + HTTP request counts (`evidence/hostile-matrix.json`).

Positive control (mandatory before believing any zero): the H4 hostile
planner — a `declareLocalPlanner`-wrapped planner whose `interpretGoal`
really POSTs through a live loopback reverse proxy which really forwards to a
second live origin listener — was invoked directly, producing proxy 1/1,
origin 1/1, sink 0/0 deltas; with `HTTP_PROXY` pointed at the sink listener,
the same planner produced sink 1/1. This validates that the observation
apparatus detects egress whenever it truly happens.

| Case | Hostile action | Observed result | Invocations | Socket deltas under seam |
|---|---|---|---|---|
| H1 | caller-supplied `{planner, transport:"LOCAL"}` pair | `PLANNER_UNAVAILABLE` — "caller-supplied planner/transport inputs are not accepted… a caller label is not provenance and the planner is never invoked" | 0 | proxy 0/0, origin 0/0, sink 0/0 |
| H2 | forged adapter carrying a module-foreign lookalike brand symbol | `PLANNER_UNAVAILABLE` — "…not minted by the trusted adapter factory… a forged adapter is never invoked" | 0 | 0/0 on all three |
| H3 | `localPlannerAdapter(plainPlanner)` (never `declareLocalPlanner`) | factory throws `TypeError`: "localPlannerAdapter requires a planner whose local provenance was declared…" | 0 | 0/0 on all three |
| H4 (core) | `declareLocalPlanner` wraps a pretend-local loopback-forwarding remote planner; `HTTP_PROXY` set to a third sink; LOCAL adapter presented to the seam | `PLANNER_UNAVAILABLE` — "LOCAL PlannerPort origin cannot be independently attested by this runtime; caller-declared local provenance is not proof of no network egress — refusing execution until an enforceable trusted host is provided" | 0 | **0/0 on proxy, origin and sink** |
| H5 | REMOTE adapter under frozen LOCAL_ONLY policy (`localOnly=true`, `externalDisclosure=FORBIDDEN`) | `PLANNER_UNAVAILABLE` — "local-only / no-disclosure policy makes a remote AI Runtime ineligible…" | 0 | 0/0 on all three |
| H6 | REMOTE adapter + `constraints.other.offline=true` while disclosure ALLOWED | `PLANNER_UNAVAILABLE` — "offline execution constraint makes a remote AI Runtime ineligible…" | 0 | 0/0 on all three |
| H7 | policy-eligible REMOTE planner fetches a genuinely dead loopback port (port taken via `listen(0)` then closed) | `PROPOSAL_REJECTED` — exact reason: `planner raised TypeError: fetch failed` (typed semantics, no fabricated plan) | 1 (the fetch itself, refused) | — |
| H8 | wrong planner binary / invalid model currentness / model-process swap | **BLOCKED_NOT_RUNNABLE** — there is no model process to attack (step-1 ABSENT evidence); not simulated | — | — |

The seam rejected every hostile LOCAL path **before any invocation**, and the
socket-level observation agrees with the invocation counters everywhere.

## Currentness before the planner call (step 2 finding)

**No such gate exists in v0.1 — recorded BLOCKED_NOT_RUNNABLE, no code
modified.** Empirically (`evidence/currentness-probe.json`):

- C1: `interpretGoalViaPlanner` with a REMOTE adapter against an **unattested**
  registry (`currentnessAuthority` serving a non-matching revision) → the
  planner **was invoked** (`calls=1`) and the proposal was ACCEPTED. The seam
  consumes no currentness record.
- C2: the same unattested registry in the deterministic `resolveGoal` path →
  stage `RESOLUTION`, `failureCode=REGISTRY_CURRENTNESS_INSUFFICIENT`
  ("registry currentness unverifiable — the trusted registry authority serves
  revision …, which does not bind the collected facts …"). The real currentness
  gate lives here — a path that contains **no model call at all**.
- C3: an attested registry (authority serves the matching
  `snapshotFactsRevision`) resolves past the gate (`selectedBindingId=b-im`).
- C4: a properly `declareLocalPlanner`-wrapped LOCAL adapter is still refused
  by the R3 disposition with 0 invocations (defense-in-depth re-confirmed at
  the pinned SHA).

Authorization-side currentness (`currentAuthority`/`authorizePlan`/
`authorizeEffect`, `packages/authorization/src/*`) and the signed registry
issuance (`apps/control-api/scripts/issue-registry-currentness.ts` consumed by
the real-storage backend) gate plan authorization and effects — downstream of
planning — so "invalid currentness → zero model calls" cannot be exercised
against the planner path in v0.1.

## Isolation mechanism exploration (explicitly NOT a U01 PASS)

1. **Windows Firewall rule** (`evidence/isolation-netsh.json`): attempted
   `netsh advfirewall firewall add rule name=SHUN-U01-PROBE-60ca4f091da8 dir=out action=block remoteip=192.0.2.0/24`
   as the standard user → rc=1, “请求的操作需要提升(作为管理员运行)”
   (elevation required). Follow-up `show rule name=…` → "no rules match" —
   the rule does not exist; nothing to clean up. Non-admin firewall-based
   enforcement is therefore unavailable without elevation.
2. **AppContainer (capability-less) launcher** (`evidence/appcontainer-probe.json`):
   real P/Invoke attempt as non-admin. `CreateAppContainerProfile` succeeds
   unelevated (hr=0x00000000, unique per-run names), container SID obtained,
   ACL grants applied (`icacls` for ALL APPLICATION PACKAGES RX + container-SID
   modify), control-group probe proves a plain process **CONNECTED** to the
   live loopback listener. But `UpdateProcThreadAttribute` with
   `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` was rejected with
   **ERROR_BAD_LENGTH (24)** in three independent rounds — including a pure-C#
   sequence (no PowerShell marshaling) and a cbSize sweep (24/28/32/40/48 all
   rejected) — while the `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` control
   attribute updates fine on the same list. The isolated child therefore never
   launched on this host. Recorded **ATTEMPTED / NOT DEMONSTRABLE**; this is
   evidence about this launcher path on this build, *not* a claim that
   AppContainer isolation is unavailable on Windows in general. All profiles
   were deleted (`DeleteAppContainerProfile` hr=0 in every run); a final sweep
   confirms **0 leftover** profile registry keys and 0 leftover Packages
   directories.

## Coverage and limitations

- Covered for real: provenance/brand/policy/transport fail-closed behavior of
  the pinned seam under seven hostile shapes, with invocation counters and
  socket-level zero-egress observation validated by positive controls; typed
  failure semantics for a dead planner endpoint; deterministic-path registry
  currentness gate; non-admin firewall denial; AppContainer profile lifecycle.
- Not runnable here (honest blockers): any real LOCAL model inference
  (no model; installation forbidden); H8 binary-currentness/swap attacks
  (no model process); OS-enforced zero-egress proof for a model process
  (no demonstrable non-admin enforcement mechanism on this host).
- The loopback listeners, sinks, proxies and dead ports were all real
  sockets; the "model" side of H4 is a hostile harness stand-in, never a real
  model.

## Must-not-claim (restated)

From this work it must **not** be claimed that: a real LOCAL model origin ever
executed or that U01 passed; Windows architecture-level model-process
isolation is ready (only that one non-admin launcher path failed on build
26300.9457); complete end-user privacy or absence of unobserved telemetry;
that loopback-only HTTP by itself proves no egress; or that the Shun product
feature is PASS/ready.

## Cleanup

No firewall rule created; no registry modification; no AppContainer profile
left (verified 0/0); no tracked file modified (`git status --porcelain` shows
only the untracked `research/` evidence); `_tmp` artifacts kept for review.
