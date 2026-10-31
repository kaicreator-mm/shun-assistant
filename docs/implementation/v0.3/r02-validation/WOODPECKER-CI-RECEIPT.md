# Woodpecker CI receipt — shun-assistant first real activation (R02-D2 #267)

Server `https://ci.kaicreator.com` (repo registered 2026-11-01, id 35 —
this repository had **no** Woodpecker history before R02; the earlier
"CI unavailable" ledger rows were accurate). Sole agent:
`woodpecker-agent-local` (local backend, Node v24.21.0 Alpine worker, npm
registry pinned to the workspace Verdaccio cache).

## Pipeline history on `wip/v0.3.0-r02-owner-repairs`

| # | Event | SHA | Result | Cause |
|---|---|---|---|---|
| 1 | push | `0004893` | failure | step `image: node:24-bookworm` executed as a binary under the LOCAL backend (`exec: "node:24-bookworm": executable file not found`) — pipeline-format defect, fixed by `labels: backend: local` + `image: bash` |
| 2 | pull_request | `0004893` | failure | same |
| 3 | push | `588c15e` | failure | real exit 1: `r02-v-journeys` J01 Windows-only journey threw on the Linux agent |
| 4 | pull_request | `588c15e` | failure | same |
| 5 | push | `9ff6b20` | failure | same J01 cause (fix not yet pushed) |
| 6 | push | `d293535` | failure | see final table below |
| 7 | pull_request | `d293535` | failure | same as 6 |

## Local-backend reproduction (definitive failure isolation)

Full CI command sequence executed inside the actual agent container
(`docker exec woodpecker-agent-local`, clone of the branch, Node v24.21.0,
Verdaccio registry):

- `9ff6b20`: lint EXIT=0; typecheck EXIT=0; test EXIT=1 with exactly one
  failure — `r02-v-journeys > J01` (Windows-only journey on Linux, by
  design). Every other suite green on Linux.
- `d293535`: lint EXIT=0; typecheck EXIT=0; test EXIT=<filled after run>;
  verify-fail-closed EXIT=<filled>.

## Deliberately failing nested test proof

`scripts/v03-ci/verify-fail-closed.mjs` runs the nested `r02-d2-gate`
suite twice: with `SHUN_R02_FAULT_INJECT_NESTED=1` the injected failing
assertion MUST produce a nonzero vitest exit, and without it the suite MUST
exit 0. The verifier itself exits nonzero (failing the pipeline) if either
invariant breaks — CI cannot pass by skipping nested suites. Local Windows
result: `{"nestedGate":"PASS","injectedFailExit":1,"cleanExit":0}`.
Agent-container and pipeline results are recorded in the final table.

## Final exact-SHA qualification run

| # | Event | SHA | Result | Notes |
|---|---|---|---|---|
| (final) | push | TBD | TBD | TBD |
