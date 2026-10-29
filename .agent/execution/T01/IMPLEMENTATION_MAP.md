# T01 Implementation Map — exact base 1165a70a9271f570cbb313210f20aa013db72f86

## Write areas

- `packages/domain-host/src/windows/**` — create the bounded trusted Windows Host adapter; consume K Permit and re-check real Shun ActionController/current OS authority immediately before the effect seam.
- `packages/domain-host/src/state/**` — create state adapters that preserve ShunStore business records and idempotent transactional `apply(effectId)`; migrate effect-dispatch ownership without deleting business-data persistence.
- `tests/integration/v03/t01-host/**` — task-local Vitest config, tsconfig, fixtures and positive/negative integration tests.

## Read-only implementation inputs

- `packages/authorization/src/controller.ts`
- `packages/authorization/src/authority.ts`
- `packages/store/src/shun-store.ts`
- `packages/workflow/src/kernel.ts`
- `packages/workflow/src/journal.ts`
- `packages/executor-windows/src/backend.ts`
- `packages/recipe-runtime/src/sqlite-r0-effect-journal.ts`

## Cross-task boundaries

- T00 owns `packages/domain-host/tsconfig.json`, manifests and the existing `domain-computer/src/contracts/**`.
- T04 owns `domain-host/src/cloud/**`; T08 owns `domain-host/src/provider/**`. Do not touch either.
- T11 alone owns package root exports, workspace dependency wiring, root server wiring and lockfile.
- Do not change old package sources as a shortcut; this Task creates only its declared Domain Host subareas and tests.

## Out of scope on this base

- UI, public entrypoints, package manifests/dependencies, root config, pnpm-lock, SDK package internals, real physical Windows mutation, paid LLM or any main/v0.2 path.
