# Authorized real journeys receipt — J02 / J03 / J05 / J09

**Authority**: `OWNER_SHUN_V030_R02_J02030509_DISPOSITION_APPROVE` ([#259]) plus the J03 paid-ceiling amendment `OWNER_SHUN_V030_R02_J03_PAID_CEILING_AMEND_R1` (4 → 8 completions). This is a factual execution record, not a release certificate and not an R03 PASS.

**Environment**: Windows 11 专业版 (10.0.26300 x64), Node v24.21.0 (win32), worktree `r02-repairs-zc` on `wip/v0.3.0-r02-owner-repairs`, parent commit `6ea5569b26569c09ced9d965586ef7b3067060af`. All physical effects bounded to operator-owned mkdtemp roots; nothing outside them was written; no system/PATH mutation.

## Journey files (all inside the R02-V write set; J09's host store in the disclosed extension)

| File | Gate | What is real |
|---|---|---|
| `tests/integration/v03/r02-v-journeys/j02-windows-effect.test.ts` | `SHUN_R02V_PHYSICAL=1` + win32 | Real trusted authority store (HMAC grant/plan/currentness), real `LocalWindowsBackend` scoped `windows.fs.write`, independent `windows.fs.verify` poststate, journal + `COMPLETED_VERIFIED` recovery receipt |
| `tests/integration/v03/r02-v-journeys/j03-live-cloud.test.ts` | `SHUN_R02V_LIVE_CLOUD=1` + win32 + `DEEPSEEK_API_KEY` + `SHUN_CONSENT_TEST_INSTRUMENTS=1` | Production v0.3 gateway over real loopback HTTP, REAL `TrustedCloudInterpreter` + single `TrustedDeepSeekTransport`, ephemeral in-memory Ed25519 operator authority, real native C02 consent dialogs, durable SQLite budget ledger + cloud request journal |
| `tests/integration/v03/r02-v-journeys/j05-provider-install.test.ts` | `SHUN_R02V_PHYSICAL=1` + win32 | Real production curator root + signed descriptor + genuine ripgrep 14.1.1 bytes; real Verifier→Stager→Preflight→Activator chain; real staged `rg.exe` execution (`--version` + FILE_SEARCH canary); fresh-composition offline restart reuse; zero-residue removal; corrupted-cache falsifier |
| `tests/integration/v03/r02-v-journeys/j09-shadow-meta.test.ts` | none (runs everywhere) | Genuine guided-journey outcome on the real `HostGuidedService` SQLite store; real durable `HostMetaShadowStore` (new `packages/domain-host/src/meta/**`) implementing the frozen `MetaFeedbackHostPort`; restart durability; promotion/stale/expired falsifiers |
| `tests/integration/v03/r02-v-journeys/stack-harness.ts` | — | Shared production-stack boot extracted from `journeys.test.ts` (same lane); only the T04 interpreter port is injected |

## Command / exit-code record

```text
# J09 (ungated) — 6/6
vitest run --config tests/integration/v03/r02-v-journeys/vitest.config.ts j09          EXIT=0 (6/6)

# J02 physical leg — 4/4 (incl. three zero-effect falsifiers)
SHUN_R02V_PHYSICAL=1 vitest run ... j02                                                EXIT=0 (4/4)

# J05 physical leg — 8/8 (real rg 14.1.1 execution, offline reuse, removal)
SHUN_R02V_PHYSICAL=1 vitest run ... j05                                                EXIT=0 (8/8)

# J03 paid leg — final green run 6/6
SHUN_R02V_LIVE_CLOUD=1 SHUN_CONSENT_TEST_INSTRUMENTS=1 vitest run ... j03              EXIT=0 (6/6)

# Full suite, default gates (CI shape): j02/j03/j05 skip, j09+journeys run
vitest run --config tests/integration/v03/r02-v-journeys/vitest.config.ts               EXIT=0 (15 passed / 18 skipped)

# Full suite, physical gates: everything except the paid leg
SHUN_R02V_PHYSICAL=1 vitest run --config tests/integration/v03/r02-v-journeys/...       EXIT=0 (26 passed / 6 skipped)
```

## J02 receipt (scoped physical effect)

```json
{"actionId":"act-81567ca4","grantId":"grant-226b7b75","planHash":"68a2ed2ead113921","terminal":"SUCCEEDED","recovery":"COMPLETED_VERIFIED","target":"...\\shun-r02v-j02-ws-GQEGl7\\r2-approved-write.txt","canaryBytes":34}
```

Journey: plan record + independently issued R2 grant (separate authority-store artifacts) → executor revalidates OS currentness + grant → scoped write inside the fixture workspace only → `postStateVerified: true`, journal `EXEC_DONE`, independent read-only `windows.fs.verify` re-reads the exact canary bytes. Falsifiers all `FAILED_BEFORE_EFFECT`/`REFUSED` with zero artifacts: expired grant, revoked grant, out-of-scope target.

## J03 receipt (paid CN/EN through the production gateway)

Final green run console receipt (verbatim):

```json
{"paidProviderEvents":2,"observerAnomalies":0,
 "providerEvents":[{"httpStatus":200,"expectedResponseUrl":true,"json":true,"finishReason":"stop","hasFinalContent":true,"hasProviderError":false},
                   {"httpStatus":200,"expectedResponseUrl":true,"json":true,"finishReason":"stop","hasFinalContent":true,"hasProviderError":false}],
 "dialogSessions":3,"dialogArms":[{"pid":44716,"action":"allow","armed":true},{"pid":52512,"action":"allow","armed":true},{"pid":6756,"action":"deny","armed":true}],
 "journalRequests":[
   {"requestId":"v039124f5f727db5cddbbc4d5dcc8abf71e3779d2a0","requestSha256":"5b512788ceeabd82","resultDigest":"2632922ac3d9c0a5"},
   {"requestId":"v034065de53299c706780d3c0ea71e27c561ea22cf5","requestSha256":"cf155bf4d9a95f62","resultDigest":"6e828a459dedf4a6"},
   {"requestId":"v0392bc087a9e7d9a23d01ff2285fac1ab424dbf96f","requestSha256":"b8098c04a5a260f3","resultDigest":"712713048406f5e8"}]}
```

- The durable `dh.llm.generate/1` cloud request journal carries exactly 3 requests: **CN `completed`** (genuine Chinese read-only diagnostic advice, `finishReason:"stop"`), **EN `completed`** (genuine English steps), and the denied-consent request **`refused` / `CANCELLED` / `CONSENT_DECLINED`** with zero send.
- The API key never appears in any log, receipt, file name or env dump; proposal texts are recorded only as SHA-256 digests above (the journal file itself stays in the OS temp scratch and is deleted after the run).
- **Paid budget accounting: 7 of the amended ceiling of 8 completions** — diagnostic run 1 (256-token ceiling): 1; run 2 (first 1024-token run): 2; run 3 (assertion-accounting fix): 2; final green run: 2. All other sends on the negatives paths were zero-send by construction and verified by the journal.

### Disclosures (for R03)

1. **Instrument-driven consent**: each `interpretGoal` shows the REAL native C02 broker dialog; the Allow/Deny click was delivered by the gated `brokerTestInstruments` automation (`SHUN_CONSENT_TEST_INSTRUMENTS=1`) under the Owner authorization. Dialog, broker IPC, single-use nonce consumption and signature verification are all the real surface; only the click is automated.
2. **Truthful refusal of truncated responses (found by run 1)**: with a 256-token ceiling the model returned `finish_reason:"length"` and the transport truthfully refused (`REMOTE_RESPONSE_INVALID` → gateway 409 UNKNOWN) rather than accept a truncated proposal. The ceiling was raised to 1024 in the authority/composition and the brief-goal wording adjusted; no retry of an uncertain attempt ever occurred.
3. **Gateway vocabulary for a denied consent**: across runs the denied-consent submit surfaced as HTTP 422 `REFUSED` (interpreter-level) or 422 `KERNEL_REFUSED` (kernel turn vocabulary). Both are truthful zero-send refusals; the test accepts either and the journal pins the exact reason (`CONSENT_DECLINED`). Disclosed as an observed nondeterminism for R03's architecture review.
4. **Local gate flake (pre-existing, unrelated to this diff)**: one `task-check` run failed in `apps/control-api` `private-consent-host.test.ts` "auto-denies an unattended dialog" (expected `DENIED_TIMEOUT`, got `APPROVED` — real-dialog interference under parallel vitest workers on this host). Isolation rerun of that file: 8/8 EXIT=0; the immediately following full `task-check` rerun was **all green (EXIT=0)**. This is the documented Windows parallel-load dialog-flake class; the Linux CI agent is win32-gated away from these tests.

## J05 receipt (signed Provider first-use)

```json
{"bindingId":"rg-windows-x64-file-search","exitCode":0,"versionLine":"ripgrep 14.1.1 (rev 4649aa9700)"}
```

Chain: production curator root verifies the signed descriptor and binds the genuine bytes (`sha256` match) → JIT adapter returns frozen `PROPOSAL_ONLY`/`SEEDED` (zero authority) → offline staging (`VERIFIED_BYTES_ONLY`, zero fetch) → preflight admission → **real first-use execution of the staged rg.exe** under a per-run sandbox with scrubbed env (`VERSION_PROBE` + `FILE_SEARCH` canary `SHUN-R02V-J05-CANARY` matched) → a FRESH composition over the same durable cache re-executes offline with the identical version line → removal leaves the install root empty → corrupted cache bytes refuse `CACHE_UNTRUSTED` and never execute.

## J09 receipt (durable Shadow/Meta)

Journey: a genuine guided decision is recorded on the real `HostGuidedService` SQLite store → the trusted composition records the genuine outcome receipt (canonical SHA-256) and a separate explicit operator opt-in consent → `createMetaFeedbackAdapter` over the real `HostMetaShadowStore` returns `STORED_SHADOW` (`lifecycle: FUTURE_BUILD_SHADOW`, `active: false`, digest bound to the genuine receipt) → a fresh store instance over the same file reads the identical candidate (restart durability). Falsifiers: deselected form is an absolute no-op (zero Host calls, asserted by call counting); unknown case refuses; a promotion-shaped (`active: true`) candidate throws `META_PROMOTION_REFUSED` and is never persisted; after a newer genuine receipt the stale revision refuses `META_RECEIPT_NOT_CURRENT`.

**Future-BUILD promotion**: no promote/activate API exists anywhere on the store; the operator-approved future BUILD remains a versioned descriptor decision for the next version — this receipt records the candidate pipeline only, exactly as the PRD's "explicit operator-approved future BUILD" boundary requires.

## Non-waivers (unchanged)

No merge, no tag/release, no `main`/`version/v0.2.0` change, no R03 self-approval. The zero-paid suite `journeys.test.ts` is unchanged in behavior (its header comment now points here). Issue #259 stays open for the independent R03.

[#259]: https://github.com/kaicreator-mm/shun-assistant/issues/259
