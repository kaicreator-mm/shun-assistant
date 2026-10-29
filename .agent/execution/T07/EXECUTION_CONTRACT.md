# T07 Execution Contract — deterministic Recipe replay with exact source and graph identity

## Authority and exact subject

- Frozen Task Pack: `docs/planning/v0.3/TASK-PACKS-R0.json@8aef87cac27297cc32e4e79e0141658a712484fb`, T07 / Issue #235.
- Product/L1 #214 checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95`; L2 #217 blob `8c555aff66d3006a1dbd4fb523e350f70c5db490`.
- DAG #218 freeze `b47e02f59704ed1699c651b89fd8f26291312ff0`; DAG blob `73d06cb67e08187d3ee6ae1a820c5b1f99a169e4`.
- Owner authorization #218@6510839827; T00 predecessor merge `1165a70a9271f570cbb313210f20aa013db72f86`.
- Effective ADS `4.18.0@2c395c55569fe2edf3f4135f12d3d069e526d0b7`; exact base `1165a70a9271f570cbb313210f20aa013db72f86`; JIT branch `JIT_only_task/v0.3.0-t07`.

## Contract and invariants

1. Resolve and replay only a trusted Recipe with exact immutable source identity, revision and canonical action-graph identity. Do not treat display name or mutable latest pointer as identity.
2. Replaying the same eligible Recipe is deterministic and performs zero LLM/model requests. No model is consulted to reconstruct or expand a saved graph.
3. Validate graph hash, action order, registered capability/effect identity, source revision and current approval before execution. Tampering, unknown effects or stale approvals fail closed.
4. Read-only steps may be evaluated without physical effects. Any effectful step is routed through the existing Kernel/authorization boundary; the recipe adapter cannot directly invoke Windows/OS effects or create grants.
5. T07 creates only the bounded Domain Computer recipe adapter and tests. Existing resolver, Store, Workflow and Recipe Runtime sources remain read-only; shared wiring belongs to T11.

## Exact write set

- `packages/domain-computer/src/recipes/**`
- `tests/integration/v03/t07-recipes/**`

## Forbidden

Any path outside the two patterns; changes to resolver/store/workflow/recipe-runtime source, T11 exports/wiring/lockfile, LLM sender, provider, grants/approvals, real OS effects, main or v0.2.

## Read-only implementation inputs

- `packages/contracts/src/v02.ts` and Recipe graph/revision schemas
- `packages/resolver/src/active-recipe-resolver.ts`, `recipe-resolver.ts`, `revision.ts`, `trusted-recipe-host.ts`
- `packages/store/src/recipe-repository.ts`
- `packages/workflow/src/recipe-seam.ts`
- `packages/recipe-runtime/src/sqlite-r0-effect-journal.ts`, `sqlite-effect-boundary.ts`, `trusted-windows-r0-effect.ts`

## Completion and blocker rule

Implement a deterministic, exact-identity Recipe B adapter and positive/negative tests. Run focused tests, resolver/recipe-runtime/store regressions, typecheck/lint and exact-HEAD CI. Use fake Kernel/Host boundaries only; do not perform physical effects. If identity, graph hash, effect registry or approval currentness is ambiguous, reject and route upward; never silently recompile, retry or widen the graph.
