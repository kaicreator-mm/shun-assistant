# T07 Implementation Map — exact base 1165a70a9271f570cbb313210f20aa013db72f86

## Write areas
- `packages/domain-computer/src/recipes/**` — typed Recipe B adapter, immutable source/revision/graph binding and deterministic replay orchestration.
- `tests/integration/v03/t07-recipes/**` — valid replay, tampered graph/source, unknown effect, stale approval and zero-LLM oracles.

## Read-only inputs
- `packages/contracts/src/v02.ts` and Recipe graph/revision schemas
- `packages/resolver/src/active-recipe-resolver.ts`, `recipe-resolver.ts`, `revision.ts`, `trusted-recipe-host.ts`
- `packages/store/src/recipe-repository.ts`
- `packages/workflow/src/recipe-seam.ts`
- `packages/recipe-runtime/src/sqlite-r0-effect-journal.ts`, `sqlite-effect-boundary.ts`, `trusted-windows-r0-effect.ts`

## Cross-task boundaries
- T07 does not change resolver/store/workflow/recipe-runtime or ShunStore data.
- Any effectful action is mediated by existing K; this Task does not issue grants or approvals.
- T11 owns package exports and runtime wiring; T04 owns LLM and T08 owns Provider.

## Out of scope
Recipe authoring UI, model-generated replay, physical Windows effects, shared exports, lockfile, package manifests, main and v0.2.
