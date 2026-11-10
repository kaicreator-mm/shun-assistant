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

---

## Addendum (2026-11-09, #401 P2 hygiene) — the R01 PASS binds ONLY the R01 candidate

The `RELEASE_ELIGIBLE = YES` verdict above is a **historical R01 record for exactly
`b2909a2141582dc2e9e083824f6a1dfd2c2f963e`** (branch `JIT_only_task/v0.3.0-r01`). It is
not, and must never be reused as, qualification of any later source.

Binding for every later WIP SHA on `wip/v0.3.0-r02-owner-repairs` — audited at
`b51b638a9ef787b9780807042a0db8762fb90945` (PR #272 head, review 5820185592) and unchanged
by the #401 Host-resolved-reference repair that follows it:

```ini
[RQ-BINDING]
later_wip_head              = b51b638a9ef787b9780807042a0db8762fb90945 (PR #272)
later_release_eligible      = NO / BLOCK
reasons                     = ENV_UNPROVISIONED production Guided trust pin (C:\ProgramData\Shun\authority absent — positive provisioned production E2E NOT_RUN); version merge not authorized (#297); R04 native Windows production qualification pending; P1-UX-REF-01 end-user journey repair in flight (#401)
prior_r01_pass_scope        = b2909a21… ONLY — not transferable
```

No tag, release, or main/version promotion may cite the R01 PASS for any SHA other
than `b2909a21…`. A fresh whole-version RQ at a new exact SHA is required before any
release-eligibility claim for later sources.

---

# R04 addendum — per-user LocalAppData Guided trust bootstrap (2026-11-09, Issue #404)

Owner-approved Product/L2 amendment (decision text in #404; L2 note
`docs/architecture/v0.3/R04-LOCALAPPDATA-GUIDED-TRUST.md`). The v0.3.0-r02
candidate remains **RELEASE BLOCK** for this lane until the R04 outcome gate
closes; historical R01 record above is retained unchanged.

```ini
[R04]
owner_decision              = 2026-11-09 per-user LocalAppData trust bootstrap; UAC allowed for install/first-run only
pack_pr                     = #405 head 4d5545e0aabe9ff8fc7a256fe92746c57d38e3ac (tree ba4cce9f…, manifest blob 5f74ce85…)
pack_ci                     = Woodpecker push #692 SUCCESS + PR #693 SUCCESS at exact 4d5545e
pack_repair                 = 4d5545e = 01e5e1c + test-only time-bomb defusal (packages/authorization/test/adversarial-r1.test.ts; detonated 2026-11-09T11:55Z between #684 PASS and #688/#690 FAIL; full evidence #404 comment 6739815992)
source_base                 = 4d5545e (Pack head; integration target wip/v0.3.0-r02-owner-repairs @ 0764c8ff…)
single_writer               = DISPATCH_CLAIMED generation 1 (#404 comment 6740103567)
frozen_write_set            = 12 files (manifest allowed_write_set; exactly respected)
localappdata_bootstrap      = IMPLEMENTED (per-user root/pin/secret dir, consented CLI, idempotent, identity-guarded)
native_no_effect_e2e        = tests/integration/v03/r02-e-production/startup-runner.test.ts "R04 native no-effect E2E" PASS on Windows Node 24 (isolated disposable profile; real main.ts composition, real desktop.js bytes, Guided state 200, DomainHarness activated, byte-stable NO-OP re-run)
residual_risk               = same-SID and other-local-user attackers outside frozen v0.3 attack model (recorded in L2 note)
RELEASE_ELIGIBLE            = BLOCK for v0.3.0 until R04 independent review + WIP integration + #272 whole-version qualification (unchanged)
```

R04 evidence summary (see #404 closeout for exact exits):

| Gate | Evidence |
| --- | --- |
| Resolver fail-closed matrix | `guided-provenance-issuance.test.ts` "R04 per-user LocalAppData trust-root resolution" (absent/relative/root-alias/missing/profile-mismatch/symlink/machine-scope/chain derivation) |
| Identity guard | same file "R04 bootstrap identity guard" (unelevated OK, same-account elevation OK, over-the-shoulder different-account refused, probe failures fail closed) |
| Bootstrap lifecycle | `guided-localappdata-bootstrap.test.ts` (consent gate, FRESH/COMPLETE/PARTIAL/INVALID, repair-only-completes-missing, no overwrite of invalid bytes, second DB without rotation, secret-absent stays COMPLETE, workspace/trust/secret scope refusals, CLI plan-only exit 3 + consented exit 0 with no key bytes in output) |
| Production composition | `production-startup.test.ts` 9/9 (SETUP_REQUIRED first-run refusal + guidance record; unchanged fail-closed vocabulary for malformed/aliased/ACL-violating material) |
| Native E2E (Windows Node 24) | `startup-runner.test.ts` 11/11 incl. plan-only → consented bootstrap → REAL production boot (positive Guided StepSpec state, served desktop.js byte-equal, DomainHarness activated) → stable NO-OP restart; and no-trust boot refusal with no listener/DB |
| Full local suites | `apps/control-api` 35 files / 241 passed EXIT=0; integration r02-e EXIT=0 ×2; typecheck EXIT=0; Biome lint EXIT=0 |
| Exact-SHA CI | Woodpecker on the final source SHA (Push+PR) — see #404 closeout comment |

## V030-WINDOWS-PORTABLE-G1 — signed Windows portable distribution (#407)

```yaml
task                        = V030-WINDOWS-PORTABLE-DISTRIBUTION (#407)
standard                    = ADS_1359_DELIVERY_FIRST
claim                       = CAS_CLAIM_ADMITTED generation 1 (#407 comment 6770578057)
pack                        = '#408 head 705a2d9261c6e58eb96cb3d41f81a22764895e70 tree 097b1b471a7cd92f3e8fea8772519fa52be4748e'
pack_ci                     = 'Woodpecker push #712 SUCCESS + PR #714 SUCCESS at exact 705a2d926 (prior #709/#710/#711 clone-stage network transient; agent git forced HTTP/1.1; #709 superseded by #710, not rerun)'
version_base                = version/v0.3.0 @ da3a36eb91d39c6bac8cd6b72b27c4b588adda4d (tree 55fdafeedc3936518e58e6813ea0d4abe47eea9)
reuse                       = 'v0.2 T09 PR #204 four packaging files present in version tree byte-identical (git diff vs 28db1877 empty); #202 manifest.mjs reused unmodified'
builder_outputs             = stage EXIT=0; unit tests node --test packaging/v03/stage.test.mjs 6/6 EXIT=0; offline smoke packaging/v03/smoke.mjs SMOKE_RESULT=PASS 19/19 EXIT=0; tools/task-check.sh EXIT=0
standard_user_pro           = PASS (13/13 steps EXIT=0, genuine standard account shun-qa, no Administrators group, real profile, Windows 11 Pro 10.0.26300 x64)
standard_user_home          = NOT_RUN (no Windows Home environment available in the delivery workspace; recorded per #407 — not claimed as PASS)
artifact                    = 'ShunAssistant-v0.3.0-windows-portable-x64.zip 38,011,868 bytes sha256 ed87e8c04d4667e5a2da823af2d8186982e71a1c7765b58f0370717e4c653f1d'
signing                     = 'qualification authority for this gate (Ed25519 SPKI pin 0e32d03b7930359a314ff7d9271dac46ef76fadd1f3e386dcf7a01ee579d7370, 151 manifest entries verified); production operator key + public Tag/Release remain a separate explicit release decision'
build_id                    = shun-v0.3.0-portable-g1
digests                     = 'node ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32 | controlBundle 7285fb813d95687df9bd3109f7216602a1de0a934e2b4b1f3c2f451b96004001 | consentBroker c85420cabd60e264e806fdfc5025287feb2f8168ce84d766b49fb2c91732c567 | consentHost a616ff35c0da830f1d6a3bd9e0f4df18cc2ef4deb97e565f92bbd3b53fe05f75 | win32Impl 801bc1b6a073bf773fb02445b8abec8352388436d9ec58178c010a7809336b7c | buildFile a1eac31dc4de669a93b2ac3e9b79c0ff21345aa357791d1c4c5b1f39ca73ca3c | guidedCase f6554ef2df0253f3a758536ca3854aa726f554fb4bbcd8ed5123c81fdb6f06f1'
```

### Qualification matrix evidence (G1 builder receipts)

| Gate | Evidence |
| --- | --- |
| Offline sign/verify | `manifest.mjs sign` → `verify` 151 entries, pin match; tampered file / extra file / wrong pin / wrong key / junction each refused (smoke + unit tests) |
| Per-user install | `lifecycle.mjs install` INSTALL signed, LocalAppData fixed-drive guard, state outside Core (smoke + Pro standard user) |
| Fail-closed first run | launcher without provisioning: `SETUP_REQUIRED` + visible `Shun-FirstRun.cmd` guidance, non-zero exit, no listener (smoke + Pro) |
| Consented bootstrap | bundled #404 CLI: BOOTSTRAP_CREATED then byte-stable ALREADY_COMPLETE; trust anchor/pin/secret under `%LOCALAPPDATA%\Shun` (smoke + Pro) |
| Provisioning | per-installation storage-registry pair + controller secrets + launch config; idempotent; never printed |
| Real production boot | REAL bounded C-003 banner + `v0.3 public DomainHarness activated`; `/api/v03/guided/state` 200 with live Case step; `/v03/desktop.js` byte-identical to shipped R04 UI; loopback only; hostile Host header → 403 `LOCAL_ONLY_VIOLATION` (smoke + Pro) |
| No paid calls | cloud lane forced off + DeepSeek credential stripped in every qualification child; no UAC at any step |
| Upgrade | re-install → `UPGRADE`; anchor/pin/guided secret/registry private key/user canary byte-identical before/after (smoke + Pro) |
| Uninstall | `UNINSTALL_CORE_ONLY`; core removed, `state` + `Shun\authority` + `Shun\secrets` retained, no listener remains (smoke + Pro) |
| Node 24 preflight | builder + all qualification on Node v24.21.0 x64; `task-check` lint/typecheck/tests EXIT=0 |

### Findings

- **P0**: none.
- **P1**: none.
- **P2**: (1) Windows Home lane NOT_RUN — no Home environment available in the delivery workspace; must run before public release claims Home support. (2) The bundled CLI tools inherit the source tree's inlined `invokedDirectly` guard, so a harmless `ISSUER_FAIL ISSUER_MISSING_SHUN_GUIDED_DATABASE_PATH` line appears on stderr while the exit code stays correct; cosmetic only. (3) The bundled bootstrap must sit exactly three directories below Core (`app/native/tools/`) because its forbidden-scope rule derives `resolve(dir,'../../..')`; documented in packaging/v03/README.md and pinned by unit tests. (4) The storage-registry currentness (120 s, workspace-bound) is issued per launch by the trusted launcher from the per-user state key — an offline-coherent design under the audited issuer script; distribution-wide operator re-issuance remains a release-design question. (5) Public Tag/Release and the production operator signing key remain BLOCK pending the separate release decision.
- **Residual risk**: same-interactive-user malicious processes remain outside the frozen v0.3 threat model (unchanged from R04/#404); the distribution zip and out-of-band public key/pin must travel through an authenticated channel — the signed manifest alone cannot attest a replaced verifier.

### R1 P1 corrective checkpoint — source G2 in progress (2026-11-10)

The G1 receipts above are retained as **historical, not current-release** proof. Fresh R1 review on PR #409 HEAD `47cce4dec849ed1ba26dce3167a0fd12fa1f2cf1` identified P1-PORTABLE-FOLDER-01 (PR comment 6772396458): shipped R04 UI requests the native `select-root` route, but the G1 launcher neither configured its per-user SQLite database nor shipped the SHA-pinned native picker. G2 repairs the existing 11-path scope and adds fail-closed digest and startup tests. **A new signed ZIP / digest, native Pro and Home matrix and exact G2 HEAD evidence are required before this correction is qualified.** Do not reuse the G1 ZIP digest as proof of G2. No public Tag/Release authorization.
