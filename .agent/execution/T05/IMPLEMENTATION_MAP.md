# T05 Implementation Map — exact base 1165a70a9271f570cbb313210f20aa013db72f86

## Write areas
- `packages/domain-computer/src/guided/**` — bounded one-step specification, typed form/answer validation and StepOutcome provenance binding.
- `tests/integration/v03/t05-guided/**` — positive, malformed, stale/replay and authority-negative cases.

## Read-only inputs
- `packages/domain-computer/src/contracts/**`
- `packages/contracts/src/goal.ts`, `receipts.ts`, `capability.ts`
- `packages/resolver/src/normalize.ts`, `planner-seam.ts`, `gates.ts`
- `packages/workflow/src/kernel.ts`

## Cross-task boundaries
- T03 owns semantic Goal/Proposal selection; T05 consumes its trusted typed output, not raw model text.
- T10 owns CN/EN Control UI and display; T11 owns public exports and runtime wiring.
- No grants, approvals, provider calls, commands, effects or external disclosures are part of T05.

## Out of scope
UI/API wiring, model/LLM, Provider, Windows/OS operations, shared exports, manifests, lockfile, main and v0.2.
