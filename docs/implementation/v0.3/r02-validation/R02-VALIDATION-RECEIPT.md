# R02 validation receipt — executed zero-paid / zero-physical subset

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
| J02 authorized Windows effect | OWNER_DEFERRED (physical effect not authorized) | Module-seam evidence unchanged (T11 real-K fixture journey); no physical execution claimed |
| J03 paid DeepSeek CN/EN | OWNER_DEFERRED (paid calls not authorized) | Request/consent/deadline shapes verified end-to-end with the controlled double incl. CONSENT_DECLINED truth; zero paid sends |
| J04 replay determinism | **PASS** | V suite: identical resubmission fenced by the real K non-idempotency gate (HTTP 422, single sender entry) |
| J05 Provider JIT install | OWNER_DEFERRED (physical install not authorized) | Signed-material verification fixtures (T08) unchanged |
| J06 K unknown/restart recovery | **PASS** | V suite restart journey (SQLite reopen, replay fence, new-revision staging) + `r02-e-production/kernel-doc-store` CAS/reopen + `r02-a-build` UNKNOWN-throw semantics |
| J07 real UI/Control API | **PASS (loopback HTTP)** | V suite: real `createControlServer`: UI 200, guided state 200, submit 200 COMPLETED, replay 422, hostile 422 pre-send, gateway-less boot 503; 202 ADMITTED mapping covered by `r02-c1-gateway` |
| J08 Guided Step/Outcome | **PASS** | V suite: atomic decision 200 RECORDED (no auto-grant, no effect), 409 replay, consumed Case gates submits, restart fence |
| J09 Feedback/Shadow | UNKNOWN (module logic only; not re-executed here) | Pre-existing opt-in Shadow tests unchanged |

## Command / exit-code record (local Windows Node v24.21.0)

Executed in the worktree at HEAD `9ff6b20f75c52832fd8ed0a5f8673336da1ff98f`
(branch `wip/v0.3.0-r02-owner-repairs`; earlier milestones at `e51aba3`,
`e6eeb5f`, `e50ec5c`, `0004893`):

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

No paid DeepSeek request, no physical Windows effect, no main/v0.2.0
mutation, no tag/release, no independent R03 self-approval. J02/J03/J05
stay OWNER_DEFERRED until separately authorized.
