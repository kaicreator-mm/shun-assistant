# T02 Execution Contract — Windows diagnostics and B-040 local-only support context

## Authority and exact subject
- Task Pack T02 / Issue #230: `docs/planning/v0.3/TASK-PACKS-R0.json@8aef87cac27297cc32e4e79e0141658a712484fb`.
- Product/L1 #214 checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95`; L2 #217 blob `8c555aff66d3006a1dbd4fb523e350f70c5db490`.
- DAG #218 freeze `b47e02f59704ed1699c651b89fd8f26291312ff0`, DAG blob `73d06cb67e08187d3ee6ae1a820c5b1f99a169e4`; Owner authorization #218@6510839827.
- Completed predecessor T00 #228 = `1165a70a9271f570cbb313210f20aa013db72f86`; dependency completion `T00@1165a70a9271f570cbb313210f20aa013db72f86`.
- Effective ADS `4.18.0@2c395c55569fe2edf3f4135f12d3d069e526d0b7`; exact integration base `1165a70a9271f570cbb313210f20aa013db72f86`.
- JIT source branch `JIT_only_task/v0.3.0-t02`.

## Contract and invariants
1. Preserve the existing B-040 report schema `shun.support-context.v1`, `localOnly:true`, and `externalDisclosures:[]`.
2. Reuse the original `collectWindowsSupportContext` / `minimizeSupportContext` behavior through the public `@shun/vertical-support` package surface; do not fork or modify that package.
3. Read-only observations only. No process launch beyond the existing trusted read-only collector, no file mutation, no arbitrary root, no broad inventory.
4. Minimize before any presentation/return. Environment values/key names, process command lines, secrets, sensitive absolute paths and unrelated document bodies never leave the local boundary.
5. No model, Meta, error reporter, SDK issue or network forwarding; no automatic external disclosure.

## Exact write set
- `packages/domain-computer/src/computer/**`
- `tests/integration/v03/t02-computer/**`

## Forbidden
- All paths outside the two write-set patterns; no changes to `packages/vertical-support/**`, `packages/vertical-system/**`, root config, manifests, exports or lockfile.
- No physical mutation, paid API, credentials, raw B-040 data export, main or v0.2 changes.

## Read-only source references
- `packages/vertical-support/src/schema.ts`
- `packages/vertical-support/src/minimize.ts`
- `packages/vertical-support/src/windows.ts`
- `packages/vertical-support/src/internal/windows-runner.ts`
- `packages/vertical-system/src/diagnostics.ts`
- `tests/integration/b040-run.test.mjs`

## Completion
Implement the bounded read-only Domain Computer adapter and adversarial tests under the allowed paths. Run focused tests, local typecheck/lint, B-040 regression, and actual Windows read-only collection on the local Windows host if available. If Windows host is unavailable, mark it NOT_RUN; do not synthesize real-host evidence. Publish a stable exact-HEAD PR to version/v0.3.0; independent Review and exact-HEAD CI remain mandatory.

## Blocker rule
Unknown source provenance, nonlocal disclosure, unbounded root, malformed observation, stale authority or any required write outside the frozen set => HOLD/BLOCK and report exact evidence; do not weaken B-040 or widen Product/L2.
