# R02 validation receipt — executed zero-paid / zero-physical subset + authorized real journeys

**This is a factual execution record, not a release certificate.** All
rows marked PASS carry a real command, exit code and evidence pointer
below; OWNER_DEFERRED rows were never executed and are never claimed PASS.

## Environment

| Item | Value |
|---|---|
| Host OS | Windows 11 专业版 (10.0.26300 x64), zh-CN host locale |
| Node | v24.21.0 (win32) |
| Workspace | `C:\xDev\kAiCreator\shun-assistant\r02-repairs-zc` (worktree of `wip/v0.3.0-r02-owner-repairs`) |
| Cloud interpreter | Controlled double behind the real frozen T04 port (zero paid calls, zero credentials) |
| Physical effects | None executed (read-only B-040 collection only) |

## Executed matrix (zero-paid / zero-physical subset)

| Journey | Disposition | Evidence |
|---|---|---|
| J01 read-only B-040 | **PASS (read-only, real host)** | `tests/integration/v03/r02-v-journeys` J01: real collector, `localOnly=true`, `externalDisclosures=[]`, genuine caption `Microsoft Windows 11 专业版`; skipped on the Linux CI agent (Windows-only journey) |
| J02 authorized Windows effect | **PASS (real physical effect, Owner-authorized)** | `AUTHORIZED-REAL-JOURNEYS-RECEIPT.md` J02: real R2 grant + scoped `windows.fs.write` + independent poststate + journal, expired/revoked/out-of-scope falsifiers zero-effect |
| J03 paid DeepSeek CN/EN | **PASS (real paid CN+EN, Owner-authorized)** | `AUTHORIZED-REAL-JOURNEYS-RECEIPT.md` J03: 2 real completions through the production gateway (journal `completed`×2), real C02 dialogs (2 allow + 1 deny, instrument click disclosed), denied consent zero-send, 7/8 amended paid ceiling |
| J04 replay determinism | **PASS** | V suite: identical resubmission fenced by the real K non-idempotency gate (HTTP 422, single sender entry) |
| J05 Provider JIT install | **PASS (real signed first-use, Owner-authorized)** | `AUTHORIZED-REAL-JOURNEYS-RECEIPT.md` J05: real signed rg 14.1.1 staged + executed (`--version`, FILE_SEARCH canary), offline restart reuse, zero-residue removal, tamper falsifier |
| J06 K unknown/restart recovery | **PASS** | V suite restart journey (SQLite reopen, replay fence, new-revision staging) + `r02-e-production/kernel-doc-store` CAS/reopen + `r02-a-build` UNKNOWN-throw semantics |
| J07 real UI/Control API | **PASS (loopback HTTP)** | V suite: real `createControlServer`: UI 200, guided state 200, submit 200 COMPLETED, replay 422, hostile 422 pre-send, gateway-less boot 503; 202 ADMITTED mapping covered by `r02-c1-gateway` |
| J08 Guided Step/Outcome | **PASS** | V suite: atomic decision 200 RECORDED (no auto-grant, no effect), 409 replay, consumed Case gates submits, restart fence |
| J09 Feedback/Shadow | **PASS (real durable Host store)** | `AUTHORIZED-REAL-JOURNEYS-RECEIPT.md` J09: genuine guided outcome receipt → opt-in candidate persisted on the real SQLite Shadow store (new `domain-host/src/meta`), restart-durable, promotion/stale falsifiers refuse |

## Command / exit-code record (local Windows Node v24.21.0)

Executed in the worktree (branch `wip/v0.3.0-r02-owner-repairs`); final
all-green local gates at HEAD `9980a9e0f543d2d9b993b4111759b91e0f115fb6`
(milestones: `e51aba3` A, `e6eeb5f` E, `e50ec5c`/`0004893` repairs,
`7526e6f`/`9ff6b20` V journeys, `2b25f78`/`120b68a`/`9980a9e` CI gating):

```text
pnpm install --registry=https://registry.npmmirror.com --ignore-scripts   EXIT=0
pnpm lint                                                                EXIT=0
pnpm typecheck                                                           EXIT=0
node scripts/v03-ci/typecheck-r02.mjs                                    EXIT=0 (7 suites)
pnpm test                                                                EXIT=0 ([integration] PASS 22/22 suites)
vitest run --config tests/integration/v03/r02-a-build/vitest.config.ts   EXIT=0 (8/8)
vitest run --config tests/integration/v03/r02-e-production/...           EXIT=0 (7/7)
vitest run --config tests/integration/v03/r02-v-journeys/...             EXIT=0 (8/8)
```

Woodpecker CI (self-hosted local docker agent, repo id 35, first activation
for this repository): see `WOODPECKER-CI-RECEIPT.md` for the exact-SHA run
records and the deliberately-failing nested-test proof.

## Non-waivers

No main/v0.2.0 mutation, no tag/release, no independent R03 self-approval.
J02/J03/J05/J09 were executed ONLY after the Owner authorization
`OWNER_SHUN_V030_R02_J02030509_DISPOSITION_APPROVE` (#259) plus the J03
paid-ceiling amendment `OWNER_SHUN_V030_R02_J03_PAID_CEILING_AMEND_R1`;
their evidence and disclosures live in `AUTHORIZED-REAL-JOURNEYS-RECEIPT.md`.
