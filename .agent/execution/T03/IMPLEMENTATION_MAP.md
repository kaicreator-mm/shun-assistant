# T03 Implementation Map — exact base 1165a70a9271f570cbb313210f20aa013db72f86

## Write areas
- packages/domain-computer/src/semantic/** — typed Goal/Proposal normalization and registered S/B selection.
- tests/integration/v03/t03-semantic/** — task-local Vitest/TypeScript config, fixtures and tests.

## Read-only source inputs
- packages/contracts/src/goal.ts
- packages/contracts/src/capability.ts
- packages/contracts/src/registry.ts
- packages/resolver/src/normalize.ts
- packages/resolver/src/planner-seam.ts
- packages/resolver/src/registry.ts
- packages/resolver/src/feasibility.ts
- packages/resolver/src/gates.ts

## Cross-task boundaries
- T00 owns packages/domain-computer/src/contracts/**, package manifests and package tsconfig.
- T05 owns domain-computer/src/guided/**; T04 cloud; T06 feedback; T07 recipes; T08 provider.
- T11 owns domain-computer/src/index.ts, package dependency/exports wiring and lockfile.
- Existing @shun/contracts and @shun/resolver sources are read-only inputs.

## Out of scope
Grant/approval issuance, model transport, provider loading, command execution, Windows effects, package wiring, lockfile and root config.
