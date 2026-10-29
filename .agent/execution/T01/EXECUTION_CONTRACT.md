# T01 Execution Contract — Windows Host authorization/currentness and state semantics

## Authority and exact subject

- Frozen Task Pack: `docs/planning/v0.3/TASK-PACKS-R0.json@8aef87cac27297cc32e4e79e0141658a712484fb`, Task T01 / Issue #229.
- Product/L1: #214 checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95`.
- L2: #217 frozen blob `8c555aff66d3006a1dbd4fb523e350f70c5db490`.
- DAG: #218 freeze blob `b47e02f59704ed1699c651b89fd8f26291312ff0`, DAG blob `73d06cb67e08187d3ee6ae1a820c5b1f99a169e4`.
- Owner authorization for T01–T08 bounded implementation: #218@6510839827.
- Completed predecessor: T00 #228 merged as `1165a70a9271f570cbb313210f20aa013db72f86`; dependency completion identity is `T00@1165a70a9271f570cbb313210f20aa013db72f86`.
- Effective ADS: `4.18.0@2c395c55569fe2edf3f4135f12d3d069e526d0b7`.
- Exact integration base: `1165a70a9271f570cbb313210f20aa013db72f86`; source branch: `JIT_only_task/v0.3.0-t01`.

## Contract and invariants

1. A K-issued Permit is necessary but never sufficient for a physical Windows effect. The trusted Host must re-check the Shun ActionController authorization/currentness and actual OS authority for the same exact bounded effect.
2. The selected public K→C adapter calls the real `ActionController.authorizeEffect` immediately before the effect boundary; no advisory, cached, or earlier authorization is substituted.
3. Preserve ShunStore business records and transactional `apply(effectId)` idempotency. The migration changes effect scheduling ownership to K; it does not delete or disable ShunStore business-data persistence.
4. Retire the old WorkflowEffectJournal only as the active dispatcher for the migrated Case. Do not create two active dispatchers/journals for one effect.
5. Unknown, stale, mismatched, duplicated or partially observed state fails closed. No effect without both guards.

## Exact write set

- `packages/domain-host/src/windows/**`
- `packages/domain-host/src/state/**`
- `tests/integration/v03/t01-host/**`

## Forbidden

- Any path outside the three patterns above.
- `packages/domain-host/tsconfig.json`, package manifests, package entrypoints, root workspace/config, shared exports or `pnpm-lock.yaml` (T00/T11 ownership).
- Sibling T02/T03/T04/T05/T06/T07/T08 paths; `main`; `version/v0.2.0`.
- SDK private/deep imports, direct effects bypassing K and Host, credentials, real Windows mutations, paid model/API calls or unapproved external disclosure.

## Existing implementation inputs (read-only)

- `packages/authorization/src/controller.ts`
- `packages/authorization/src/authority.ts`
- `packages/store/src/shun-store.ts`
- `packages/workflow/src/kernel.ts`
- `packages/workflow/src/journal.ts`
- `packages/executor-windows/src/backend.ts`
- `packages/recipe-runtime/src/sqlite-r0-effect-journal.ts`

## Completion rule

Implement only the frozen concern; add task-local tests/config under the test write set. Run focused positive/negative tests, task-local typecheck and lint, preserve lockfile byte identity, then publish a stable exact-HEAD PR to `version/v0.3.0`. Required independent exact-HEAD Review and exact-HEAD CI remain mandatory. Report physical Windows effect validation as NOT_RUN/BLOCKED because this Owner authorization explicitly excludes real Windows side effects; do not fabricate PASS.

## Blocker rule

Missing/stale authority, unknown currentness, write-set collision, inability to prove the two guards, ambiguous journal migration, or need for real Windows mutation => stop the affected path, publish exact evidence and route upward. Do not widen Product/L2 or silently modify shared wiring.
