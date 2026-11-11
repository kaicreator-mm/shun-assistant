# v0.3 V01 — Independent version candidate qualification (builder round, zero paid)

- **Candidate exact source:** `e93fac9bd400f222ea27cbea1fa36f4ecba1f414` (merge of T11 #255; branch `JIT_only_task/v0.3.0-v01`). This qualification run executed ON that exact source (`git merge-base --is-ancestor e93fac9… HEAD` asserted by the suite itself; at this round the qualification HEAD equals the candidate SHA because the evidence was produced before the qualification PR commit).
- **Qualification suite:** `tests/integration/v03/t12-qualification/` (27 tests, all green). Raw run output: `C:/xDev/kAiCreator/_tmp/v01-zcode/v01-full-run-2.log` (real vitest output, real exit code `EXIT=0` recorded at the end). Structured machine-readable evidence: `tests/integration/v03/t12-qualification/qualification-results.json` (written by the suite at run time, committed from this exact run).
- **Write set:** `tests/integration/v03/t12-qualification/**` and `docs/validation/v0.3/**` only. No source, no sibling task write sets, no `main` / `version/v0.2.0` mutations.
- **Reproduce:** `cd tests/integration/v03/t12-qualification && ../../../../packages/vertical-support/node_modules/.bin/vitest.CMD run`

## Paid-call scope declaration

**ZERO PAID CALLS.** Paid calling was not authorized for this builder round. Every cloud/ledger/broker/HTTP surface in the qualification suite is an in-process fake: the DeepSeek transport never leaves the process (`fetchTransport` fake), the consent broker session is a trusted-host fake, the durable budget ledger runs against throwaway local SQLite files, and no `DEEPSEEK_API_KEY` value is ever read for a real send. The real CN/EN controlled-DeepSeek leg of issue #240 and the real Windows effect journeys remain **R01 / independent-validator scope** (see Leftover items).

## Host facts (physical run)

| Item | Value |
| --- | --- |
| OS | Microsoft Windows 11, build `26300` (real read-only B-040 collection) |
| Runtime | Node `v24.21.0`, `process.platform === 'win32'` (asserted by the suite) |
| Workspace | pnpm workspace, deps installed per lockfile; consumer SDK installed offline from the four pinned `0.10.2-rc.0` tarballs (t00 fixtures), shared `node_modules/.t11-dh-consumer` layout with T11 |

## Verification matrix

| # | Verification item | Result | Evidence |
| --- | --- | --- | --- |
| 1 | Candidate identity: exact source is an ancestor of the run HEAD | PASS | `candidateIsAncestorOfHead: true`, run HEAD `e93fac9bd400f222ea27cbea1fa36f4ecba1f414` |
| 2 | Composition sweep: all 12 nested task suites (t00–t11) re-run as real subprocesses | PASS (12/12, exit code 0 each) | table below; `compositionSweep[]` in `qualification-results.json` |
| 3 | Production build surface | PASS (2/2 scripts BUILT) | `build:helper` + `build:anchor-writer` of `@shun/executor-windows`, exit 0, pinned artifacts below |
| 4 | Public interface anchoring (3 controlled Shun packages + B-040 public surface) | PASS | `@shun/domain-app`, `@shun/domain-computer`, `@shun/domain-host`, `@shun/vertical-support` — frozen named exports present, no import side effects |
| 5 | Real public `buildV10App` consumer composition re-proof | PASS | 4-module app composed from SHA-verified frozen payload bytes; `activateV10App` → `isV10AppFacade === true`, send/subscribe/queryScopedSnapshot/isClosed live, kernel identity readable, `dispose()` closes |
| 6 | Windows compatibility: win32 + Node ≥ 24 | PASS | `v24.21.0` / `win32` |
| 7 | Real B-040 read-only support-context re-run | PASS | `ACTUAL_WINDOWS_HOST`, `localOnly: true`, `externalDisclosures: 0`, canonical report SHA-256 `a4ca77244eeeb30e0e03f55cb14f53e0d0cd8a5b29044a02833ee2a765cd3aae` |
| 8 | Version-level negative matrix (8 items) | PASS (8/8) | table below |

## Composition sweep — 12/12 nested suites green (this candidate, real exit codes)

| Suite | Command | Exit | Passed | Duration |
| --- | --- | --- | --- | --- |
| t00-scaffold | `node --test t00-scaffold.test.mjs` | 0 | 6 | 1780ms |
| t01-host | `node vitest.mjs run` | 0 | 11 | 1294ms |
| t02-computer | `node vitest.mjs run` | 0 | 14 | 1570ms |
| t03-semantic | `node vitest.mjs run` | 0 | 11 | 1688ms |
| t04-cloud | `node vitest.mjs run` | 0 | 15 | 1698ms |
| t05-guided | `node vitest.mjs run` | 0 | 12 | 1283ms |
| t06-meta | `node vitest.mjs run` | 0 | 9 | 1141ms |
| t07-recipes | `node vitest.mjs run` | 0 | 8 | 1399ms |
| t08-provider | `node vitest.mjs run` | 0 | 21 | 1517ms |
| t09-api | `node vitest.mjs run` | 0 | 23 | 2302ms |
| t10-ui | `node vitest.mjs run` | 0 | 35 | 1394ms |
| t11-runtime | `node vitest.mjs run` | 0 | 20 | 1961ms |

Total: **185 nested tests, 0 failures** on the candidate exact source (t00 counted via the node:test spec reporter; the others via the vitest summary line).

## Production build surface

Discovery rule: every workspace `package.json` script matching `^build(:|$)`. Exactly two exist — `@shun/executor-windows#build:helper` and `@shun/executor-windows#build:anchor-writer` (both pure esbuild bundles; no package declares a plain `build`). Both built with exit 0 during the run; the bundles are byte-identical across independent builds (deterministic), SHA-256:

| Artifact | SHA-256 |
| --- | --- |
| `dist/executor-helper.mjs` | `949f037dca53957b3e276ab6844845f14e6e0c42290e55c6dd2e7e25b2675d1d` |
| `dist/anchor-writer.mjs` | `8cd9df5d50a7ee662dfd0ad84c90309e370d8aeed73022aeeab3fa73c3600e32` |

`dist/` is gitignored; these hashes are recorded here as receipts, not committed binaries. Spawn-level environment failures would be recorded `ENV_BLOCKED` (not hard-failed) per the build-surface policy; none occurred — both builds are real exit 0 on this host.

## Version-level negative matrix (against merged production sources)

| ID | Falsifier | Production surface exercised | Result |
| --- | --- | --- | --- |
| N1 | UNKNOWN-as-success: a hostile interpreter claiming `completed/executed` and an unparseable remote body must never render/report completed | T04 `createTrustedCloudHostBinding` mapping (`REMOTE_OUTCOME_UNRESOLVED` → unknown, journal records unknown) + T11 production `TrustedCloudInterpreter` (garbage body → `REMOTE_REFUSED`) | PASS |
| N2 | Expired deadline sending HTTP | T11 interpreter entry deadline gate: `DEADLINE_EXPIRED`, **zero fetch, zero reserve/MAY_HAVE_SENT/UNKNOWN_COST** | PASS |
| N3 | DTO `maxOutputTokens` overrun | T04 host binding (`OUTPUT_TOKEN_CEILING_UNSUPPORTED`, zero journal/interpreter) + T01 `TrustedDeepSeekTransport` (`DISCLOSURE_SCOPE_DRIFT` vs approved scope, zero reserve, zero fetch) | PASS |
| N4 | Duplicate requestId as permission | K request journal double (REPLAY of recorded result without a second attempt; different digest → `REQUEST_ID_CONFLICT` refusal) + real SQLite `DurableCloudBudgetLedger` (`IDEMPOTENCY_REPLAY` for the same attemptId; second attempt under exhausted `maxCalls=1` consent → `BUDGET_EXHAUSTED`) | PASS |
| N5 | refused/failed/unknown reported completed, or UNKNOWN_COST auto-refund | Ledger class has **no refund/release method at all** (prototype surface asserted); `UNKNOWN_COST` is terminal (re-mark refused, re-reserve → `IDEMPOTENCY_REPLAY`); interpreter on HTTP 500 → `REMOTE_REFUSED` + exactly one `markUnknownCost`, zero retry | PASS |
| N6 | Invalid Case poisoning a stable Case | T09 `createControlApiGateway`: 4 hostile submissions → `REFUSED` with `sendCalls: 0` / `journalEntries: 0` (facade never entered), then the **same stable Case** admits a valid submission (`SENT`, `sendCalls: 1`) | PASS |
| N7 | Secret leak | Canary-seeded hostile submissions (forged approval/currentness objects, traversal caseId, password/apiKey fields), broker crash carrying the canary, consent decline: every receipt/refusal detail/failure result scanned — zero canary matches, zero `PRIVATE KEY` / `password=` / `api key=` patterns | PASS |
| N8 | Stale grant / duplicate Windows effect | Real T01 `createWindowsEffectHost` with expired grant verdict → `SHUN_AUTHORIZATION_REFUSED` **before** the effect port (zero executor calls); real SQLite `ShunStore`: same-effectId replay → `applied: false` with the recorded receipt, same effectId + different mutation → `effect identity conflict`, exactly one durable effect row | PASS |

## Real B-040 evidence (this host, this run)

- `collectLocalComputerSupportContext()` really executed (read-only collector): source `ACTUAL_WINDOWS_HOST`, `localOnly: true`, `externalDisclosures: []`, report schema `shun.support-context.v1`, OS build `26300`.
- Canonical report digest: SHA-256 `a4ca77244eeeb30e0e03f55cb14f53e0d0cd8a5b29044a02833ee2a765cd3aae` over `canonicalJson(result)`.
- Zero disclosure channel was exercised; the only OS interactions of the whole suite are this read-only collection and throwaway local SQLite files.

## Leftover items (honest scope boundaries)

1. **R01 (independent validator) remains open.** This is the BUILDER qualification round: per #240, the independent validator must independently replay the selected evidence on the final candidate source; a builder self-report is not version-level PASS.
2. **Real controlled DeepSeek (CN/EN) paid leg: NOT exercised.** Not authorized for this round (`SHUN_CLOUD_ENABLED` untouched; no real API key read). The zero-paid fakes prove the seams, not the paid wire.
3. **Real Windows effect journeys: not performed by this suite.** The Windows negative proof runs the real T01 adapter against fakes; the real-K positive journey proof is T11's (re-run green by the sweep) and the physical standard-user journeys remain validator/host scope per #240.
4. **Observation (cosmetic, pre-existing):** on this zh-CN locale host, the trusted B-040 collector's OS display name arrives mojibake-decoded (`Microsoft Windows 11 ` + two U+FFFD replacement characters, the UTF-8 runner decoding a GBK "专业版"). Collector behavior is outside this write set; recorded here so R01 can decide whether it warrants a collector fix.
5. **Determinism receipts:** the pinned executor bundles built byte-identically in an independent manual trial before the recorded run (same SHA-256 as in the table), so the build surface is reproducible, not a one-off.

## Gate evidence (this round)

- Qualification suite: `EXIT=0`, 27/27 tests (log: `_tmp/v01-zcode/v01-full-run-2.log`).
- Workspace `pnpm -r --if-present run typecheck`: exit 0 (log: `_tmp/v01-zcode/v01-workspace-typecheck.log`).
- Suite-local `tsc -p tsconfig.json --noEmit`: exit 0.
- `biome check tests/integration/v03/t12-qualification docs/validation/v0.3`: clean.
