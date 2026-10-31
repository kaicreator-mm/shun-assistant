# v0.3.0 R01 — Whole-version independent release qualification (RQ record)

- **Auditor round:** R01 (INDEPENDENT_RELEASE_QUALIFIER), executed 2026-10-31 on Windows 11 build 26300, Node `v24.21.0`, `win32`.
- **Candidate exact SHA:** `b2909a2141582dc2e9e083824f6a1dfd2c2f963e` (branch `JIT_only_task/v0.3.0-r01`, working tree clean at audit time; candidate = merge of V01 PR #257).
- **Verdict:** PASS with 4 × P2, no P0, no P1.

```ini
[RQ]
candidate_sha               = b2909a2141582dc2e9e083824f6a1dfd2c2f963e
candidate_branch            = JIT_only_task/v0.3.0-r01
integration_base            = version/v0.3.0
chain                       = 1165a70..b2909a2 = 55 commits, 16 merges (12 acceptance PR merges + 3 repair PR merges #250/#252/#256 + 1 internal T11 sync merge 7f60b1b, non-PR)
task_pack_r1_blob           = e988ccc6962d35bb1612f82c469086f54958dc1e  ; VERIFIED in tree
l2_frozen_blob              = 8c555aff66d3006a1dbd4fb523e350f70c5db490  ; VERIFIED in tree
dag_frozen_blob             = 73d06cb67e08187d3ee6ae1a820c5b1f99a169e4  ; VERIFIED in tree
product_checkpoint          = c8334c7723eecf7fbbb6895b1defd6439edc6b95  ; ancestor commit VERIFIED; freeze blob 0f8a67c2f06364d58a842502d3dee11bfeeedba4 VERIFIED in tree
issues_closed               = 13/13  ; #228..#240 all CLOSED with closeout evidence
prs_merged                  = 15/15  ; #243..#257 all MERGED, merge commits match local chain exactly
p0                          = 0
p1                          = 0
p2                          = 4
acceptance_nodes            = 14     ; T00..T11, V01, R01
acceptance_covered          = 14
acceptance_uncovered        = 0
owner_amendment_r1_items    = 3/3 PASS
independent_spot_checks     = 3/3 EXIT=0 (t04-cloud 15/15, t08-provider 21/21, t11-runtime 20/20)
RELEASE_ELIGIBLE            = YES
release_actions_from_pass   = NONE   ; tag/release/main promotion are separate Owner actions, NOT performable from this source PASS
```

## 1. Candidate identity and frozen-artifact verification (Exact-SHA)

| Artifact | Frozen value | Re-computation in candidate tree | Result |
| --- | --- | --- | --- |
| Task Pack R1 | blob `e988ccc6962d35bb1612f82c469086f54958dc1e` | `git hash-object docs/planning/v0.3/TASK-PACKS-R0.json` | MATCH |
| L2 R0 (frozen) | blob `8c555aff66d3006a1dbd4fb523e350f70c5db490` | `git hash-object docs/architecture/v0.3/L2-DOMAIN-HARNESS-R0.md` | MATCH |
| Task DAG R0 | blob `73d06cb67e08187d3ee6ae1a820c5b1f99a169e4` | `git hash-object docs/planning/v0.3/TASK-DAG-v0.3-R0.md` | MATCH |
| Product checkpoint | commit `c8334c7723eecf7fbbb6895b1defd6439edc6b95` | `git merge-base --is-ancestor` → true; blob of `docs/product/PRODUCT_FREEZE-v0.3.md` at that commit = `0f8a67c2f06364d58a842502d3dee11bfeeedba4`, identical to the candidate tree file | MATCH |

Merge-chain integrity: `git rev-list --count 1165a70..HEAD` = 55; 16 merges enumerated and each of the 15 PR merges cross-checked against GitHub (`gh pr view #243..#257` → all `MERGED`, merge SHAs identical to the local chain). The only non-PR merge is `7f60b1b` (T11 branch syncing `origin/version/v0.3.0`, parents contained in the chain; no foreign content — its diff is empty against first-parent history).

Task Pack R1 carries `owner_amendment_r1 = APPROVED_BY_OWNER_20261031`; the amendment diff entered the chain as PR #252 (`3307197`, minimal diff `bc1b4d3` on `docs/planning/v0.3/TASK-PACKS-R0.json` only) — the blob hash above is the post-amendment frozen value.

## 2. Acceptance coverage matrix (Task Pack R1: 14 nodes + owner_amendment_r1)

| Node | Issue | Positive/negative acceptance evidence | Coverage |
| --- | --- | --- | --- |
| T00 scaffold | #228 (CLOSED) | `tests/integration/v03/t00-scaffold` 6/6 (V01 composition sweep, exit 0; stage-aware repair PR #250) | COVERED |
| T01 Windows Host | #229 (CLOSED) | `t01-host` 11/11 (V01 sweep; adapter + no-side-effect scope per amendment) | COVERED |
| T02 diagnostics/B-040 | #230 (CLOSED) | `t02-computer` 14/14 (V01 sweep) + real B-040 re-run in t12: `ACTUAL_WINDOWS_HOST`, `localOnly:true`, `externalDisclosures:0`, canonical SHA `a4ca7724…` | COVERED |
| T03 Goal semantics | #231 (CLOSED) | `t03-semantic` 11/11 (V01 sweep) | COVERED |
| T04 DeepSeek trusted sender | #232 (CLOSED) | `t04-cloud` 15/15 (V01 sweep) + **R01 independent rerun EXIT=0 15/15** (log `_tmp/r01-zcode/r01-t04-cloud.log`) | COVERED |
| T05 Guided Journey | #233 (CLOSED) | `t05-guided` 12/12 (V01 sweep) | COVERED |
| T06 Meta feedback | #234 (CLOSED) | `t06-meta` 9/9 (V01 sweep) | COVERED |
| T07 Recipe replay | #235 (CLOSED) | `t07-recipes` 8/8 (V01 sweep) | COVERED |
| T08 Curated Provider | #236 (CLOSED) | `t08-provider` 21/21 (V01 sweep) + **R01 independent rerun EXIT=0 21/21** (log `_tmp/r01-zcode/r01-t08-provider.log`) | COVERED |
| T09 BUILD composition + gateway | #237 (CLOSED) | `t09-api` 23/23 (V01 sweep) | COVERED |
| T10 Control UI | #238 (CLOSED) | `t10-ui` 35/35 (V01 sweep) | COVERED |
| T11 central integration | #239 (CLOSED) | `t11-runtime` 20/20 (V01 sweep) + **R01 independent rerun EXIT=0 20/20** (`cloud-interpret-deadline` 4/4, `real-kernel-permit` 9/9, `server-v03-gateway` 7/7; log `_tmp/r01-zcode/r01-t11-runtime.log`); closeout `INDEPENDENT_R1_REVIEW=APPROVE_P0_0_P1_0_P2_3`, `AMENDMENT_ITEMS=4_OF_4_PASS`, write set exactly 22 authorized files | COVERED |
| V01 builder qualification | #240 (CLOSED) | t12 suite 27/27 independently re-run EXIT=0; 12/12 nested suites, 185/185 tests on candidate `e93fac9` (ancestor of this HEAD); negative matrix 8/8; closeout PASS with two P2s handed to R01 | COVERED |
| R01 (this record) | — | This audit: Exact-SHA verification, coverage matrix, 3 independent spot-check reruns, leftover grading | COVERED (self) |

### owner_amendment_r1 items

| # | Item | Evidence | Result |
| --- | --- | --- | --- |
| AM-1 | Real public selected-K Permit positive/negative integration proof + migrated-Case legacy `WorkflowEffectJournal` dispatcher retirement moved from T01 to T11 | `t11-runtime/real-kernel-permit.test.ts` 9/9 (positive full chain to terminal receipt; permitless/expired-grant negatives with zero physical effect; "retires the legacy WorkflowEffectJournal: the migrated Case never appends to it"; ShunStore idempotent receipts); T01 retains `t01-host` 11/11 | PASS |
| AM-2 | `T11.allowed_write_set += apps/control-api/src/cloud-interpret.ts` | Commit `d377b1d` (in chain) touches exactly `apps/control-api/src/cloud-interpret.ts` + `tests/integration/v03/t11-runtime/cloud-interpret-deadline.test.ts`; T11 closeout `WRITE_SET=EXACTLY_AUTHORIZED_22_FILES` | PASS |
| AM-3 | T11 acceptance += production Interpreter realizes frozen T04 `TrustedCloudInterpreterPort` (deadline rechecked at final pre-send/MAY_HAVE_SENT boundary, `DEADLINE_EXPIRED` documented zero-send, UNKNOWN preserved without blind retry, single sender) | `t11-runtime/cloud-interpret-deadline.test.ts` 4/4 green in R01 rerun: entry-deadline zero broker/ledger/fetch; final pre-send boundary zero send; exact closed request bytes single send; UNKNOWN single-call no retry/refund | PASS |

### Not covered by design (scope boundaries, not acceptance failures)

1. **Real paid CN/EN DeepSeek leg** — not authorized in any round of v0.3.0 (zero-paid scope, owner-controlled); all cloud surfaces proven at the seam level with in-process fakes plus real ledger/broker semantics. Optional post-release validation.
2. **Real Windows physical effect journeys** — the real-K positive chain runs with a recording-only executor (zero physical side effects, by design); physical standard-user journeys remain host/owner scope. Optional post-release validation.

## 3. Independent spot-check gates (this audit, real exit codes)

Full 12-suite replay was already independently performed by V01 on candidate `e93fac9` (ancestor of this HEAD, `candidateIsAncestorOfHead: true` in the committed evidence). R01 re-ran three spot-check groups on the exact candidate HEAD `b2909a2`:

| Suite | Focus | Result | Log |
| --- | --- | --- | --- |
| `t04-cloud` | Production Interpreter deadline / trusted sender boundary | EXIT=0, 15/15 tests | `_tmp/r01-zcode/r01-t04-cloud.log` |
| `t08-provider` | Production trust root (signed trusted Host adapter, curated Provider JIT) | EXIT=0, 21/21 tests | `_tmp/r01-zcode/r01-t08-provider.log` |
| `t11-runtime` | Real-K integration, production cloud-interpret deadline, v03 gateway | EXIT=0, 20/20 tests | `_tmp/r01-zcode/r01-t11-runtime.log` |

All three logs end with a real `EXIT=0` recorded from the process exit code (no pipe-swallowed codes).

## 4. P0/P1/P2 ledger

**P0: none. P1: none.**

| ID | Severity | Finding | Why it does not block RELEASE_ELIGIBLE |
| --- | --- | --- | --- |
| R01-P2-1 | P2 | `docs/validation/v0.3/VERSION-QUALIFICATION.md` composition-sweep **duration column is transcribed from a different run** than the committed `qualification-results.json` (e.g. t09 2302ms vs 2549ms, t11 1961ms vs 2219ms; all exit codes and pass counts agree). V01's own handoff P2. | Documentation transcription fidelity only. The machine-readable evidence (per-suite `exitCode`, `counts`, raw vitest `tail` with true durations) is the authoritative committed record and is internally consistent. No PASS/FAIL determination depends on the prose durations. Fix is a docs-only follow-up. |
| R01-P2-2 | P2 | `qualification-results.json` **writer format**: the results writer emits the B-040 `osName` as raw mojibake bytes (`"Microsoft Windows 11 רҵ…"`, GBK text surfaced through a UTF-8 decode) instead of normalizing/escaping undecodable display strings. V01's own handoff P2. | Cosmetic serialization defect in an evidence writer. The canonical report digest (`a4ca7724…`) is computed over `canonicalJson` and is stable/reproducible across runs; verification semantics are unaffected. Fix is a tooling follow-up; the committed file remains a faithful byte-level record of the run. |
| R01-P2-3 | P2 | **B-040 mojibake observation (pre-existing):** on a zh-CN Windows host the trusted support-context collector's OS display name arrives with U+FFFD replacement characters (GBK "专业版" decoded as UTF-8). Recorded as a V01 observation for R01 disposition. | Pre-existing collector behavior outside every v0.3 task write set; the collector is read-only, `localOnly:true`, zero egress — no disclosure or correctness impact beyond one display string. Cross-version cosmetic fidelity issue; belongs to the B-040 collector's own backlog, not this release gate. |
| R01-P2-4 | P2 | **T11 F-3:** `apps/control-api/src/main.ts` production composition does not inject `v03Gateway` (verified: zero references in `main.ts`), so the `/v03` route answers a typed **503 fail-closed** until a composition root supplies the gateway. Recorded as P2 informational by T11's independent review and by V01. | The fail-closed direction is safe (refuse, never misroute). The T11 acceptance surface per owner_amendment_r1 is the seam + route + proofs, all green (`server-v03-gateway` 7/7 in R01 rerun). This is a production-availability follow-up (wiring a composition root), not an authorization or safety gap. Must be stated in release notes as a known limitation. |

## 5. RELEASE_ELIGIBLE verdict and conditions

**RELEASE_ELIGIBLE = YES** for candidate `b2909a2141582dc2e9e083824f6a1dfd2c2f963e`.

Conditions and explicit boundaries:

1. **This source PASS grants nothing by itself.** Tag creation, `main` promotion and the GitHub release are separate Owner actions (R01 negative acceptance: "no tag/main/release from source PASS only; cannot waive P0/independent CJ"). None of them were performed in this round.
2. **P2 items (4) are recorded, non-blocking**, with owners/surfaces named above; they should ship as release-notes known limitations (especially R01-P2-4) and follow-up fixes.
3. **Optional post-release validation (not gating):** real paid CN/EN DeepSeek leg (requires owner authorization and `DEEPSEEK_API_KEY` provisioning) and real Windows physical effect journeys.
4. **Evidence trail:** this record + `docs/validation/v0.3/VERSION-QUALIFICATION.md` + `tests/integration/v03/t12-qualification/qualification-results.json` + `docs/implementation/v0.3/release/` implementation log + `_tmp/r01-zcode/r01-*.log` spot-check logs.
