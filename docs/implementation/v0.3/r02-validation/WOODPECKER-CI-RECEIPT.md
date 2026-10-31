# Woodpecker CI receipt — shun-assistant first real activation (R02-D2 #267)

Server `https://ci.kaicreator.com` (repo registered 2026-11-01, id 35 —
this repository had **no** Woodpecker history before R02; the earlier
"CI unavailable" ledger rows were accurate). Sole agent:
`woodpecker-agent-local` (local backend, Node v24.21.0 Alpine worker, npm
registry pinned to the workspace Verdaccio cache). The server retains no
finished-step logs on this deployment, so since `120b68a` the pipeline
persists its full `set -x` trace on the agent volume
(`/var/lib/woodpecker/shun-ci-last.log`).

## Pipeline history on `wip/v0.3.0-r02-owner-repairs`

| # | Event | SHA | Result | Cause |
|---|---|---|---|---|
| 1–2 | push/PR | `0004893` | failure | step `image: node:24-bookworm` executed as a binary under the LOCAL backend (`exec: "node:24-bookworm": executable file not found`) — pipeline-format defect; fixed with `labels: backend: local` + `image: bash` |
| 3–5 | push/PR | `588c15e`/`9ff6b20` | failure (real, correct red) | `r02-v-journeys` J01 Windows-only journey threw on the Linux agent; fixed by platform-gated skip (Windows keeps the leg mandatory) |
| 6–7 | push/PR | `d293535` | failure (real, correct red) | `t12-qualification` Windows legs + candidate-ancestor check fail on Linux; fixed by platform/full-history gating |
| 8–11 | push/PR | `2b25f78` | failure | concurrent pnpm-store contention with same-container manual reproduction runs (no retained artifacts at the time; the identical SHA passed the full command sequence in the same container afterwards) |
| 12–13 | push/PR | `120b68a` | **success — but fail-open defect found** | the persisted trace revealed one failed nested suite (`t12` ancestry on a shallow clone) masked by the trace wrapper lacking `set -e`; the trace persistence added at this same SHA is what exposed it |
| 14–15 | push/PR | `9980a9e` | **success (fail-closed verified)** | final gate: `set -eo pipefail` wrapper; full sequence green |

## Final exact-SHA qualification run (9980a9e0f543d2d9b993b4111759b91e0f115fb6)

Pipeline #14 (push) and #15 (pull_request), both `success`. Trace (persisted
on the agent volume) shows, in order, with real exit propagation:

```text
git 2.54.0 / node v24.x (agent worker)
test "$(git rev-parse HEAD)" = "$CI_COMMIT_SHA"        → 9980a9e… = 9980a9e… PASS
corepack enable && corepack prepare pnpm@10.34.5
pnpm install --frozen-lockfile
pnpm -r --if-present run lint                           → PASS
pnpm -r --if-present run typecheck                     → PASS ([r02-typecheck] PASS 7)
pnpm -r --if-present run test                          → PASS (all nested suites;
                                                         Windows-only legs skipped)
node scripts/v03-ci/verify-fail-closed.mjs             → {"nestedGate":"PASS",
                                                         "injectedFailExit":1,"cleanExit":0}
```

## Deliberately failing nested test — nonzero exit proof

Two layers of proof that a red nested suite fails CI:

1. **Inside every green run**: `verify-fail-closed.mjs` executes the nested
   `r02-d2-gate` suite with `SHUN_R02_FAULT_INJECT_NESTED=1`; the injected
   failing assertion makes vitest exit `1` (recorded in the green pipelines'
   traces as `injectedFailExit:1`), and the verifier fails the pipeline if
   that ever stops being true.
2. **Real red builds**: pipelines 3–7 above are genuine pipeline failures
   caused by really failing nested suites — the gate demonstrably propagates
   nested red to a nonzero pipeline exit.
3. **Fail-open defect caught and fixed**: the `120b68a` trace wrapper lacked
   `set -e`, masking one failed suite (caught by reading the persisted
   trace of a green pipeline); `9980a9e` runs under `set -eo pipefail`.

## Local Windows final gates at the same SHA

`9980a9e` on Windows 11 (Node v24.21.0): `pnpm lint` EXIT=0,
`pnpm typecheck` EXIT=0, `pnpm test` EXIT=0 (integration 23/23 suites
including the Windows-only legs; see `R02-VALIDATION-RECEIPT.md`).
