# T02 Implementation Map — exact base 1165a70a9271f570cbb313210f20aa013db72f86

## Write areas
- `packages/domain-computer/src/computer/**` — Domain Computer's bounded read-only diagnostics adapter; preserve the B-040 local-only contract.
- `t02-computer` — scoped Vitest/TypeScript config, fixtures and tests; a read-only Windows test may be included.

## Read-only sources
- `packages/vertical-support/src/schema.ts`
- `packages/vertical-support/src/minimize.ts`
- `packages/vertical-support/src/windows.ts`
- `packages/vertical-support/src/internal/windows-runner.ts`
- `packages/vertical-system/src/diagnostics.ts`
- `tests/integration/b040-run.test.mjs`

## Wiring and isolation
- T00 owns `packages/domain-computer/src/contracts/**`, package manifests and package tsconfig.
- T11 owns `packages/domain-computer/src/index.ts`, package dependency/exports wiring and lockfile.
- Do not edit `packages/vertical-support/**` or `packages/vertical-system/**`; consume existing public behavior, do not fork it.
- Do not write UI, cloud, feedback or Provider modules owned by sibling Tasks.

## Out of scope
Any mutation, external disclosure, raw support-context upload, model dependency, new generic diagnostic engine, root configuration, package manifest, lockfile, main or v0.2.
