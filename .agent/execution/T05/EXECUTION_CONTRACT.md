# T05 Execution Contract — bounded Guided Journey one-step form and answer provenance

## Authority and exact subject

- Frozen Task Pack: `docs/planning/v0.3/TASK-PACKS-R0.json@8aef87cac27297cc32e4e79e0141658a712484fb`, T05 / Issue #233.
- Product/L1 #214 checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95`; L2 #217 blob `8c555aff66d3006a1dbd4fb523e350f70c5db490`.
- DAG #218 freeze `b47e02f59704ed1699c651b89fd8f26291312ff0`; DAG blob `73d06cb67e08187d3ee6ae1a820c5b1f99a169e4`.
- Owner authorization #218@6510839827; T00 predecessor merge `1165a70a9271f570cbb313210f20aa013db72f86`.
- Effective ADS `4.18.0@2c395c55569fe2edf3f4135f12d3d069e526d0b7`; exact base `1165a70a9271f570cbb313210f20aa013db72f86`; JIT branch `JIT_only_task/v0.3.0-t05`.

## Contract and invariants

1. Produce at most one bounded `StepSpec` from an approved trusted observation and frozen template/contract; bind every result to the exact step identity and source observation.
2. A `StepOutcome` is accepted only for the currently active StepSpec, same Case/step identity and current source/provenance. Old, replayed, cross-case or superseded outcomes fail closed.
3. The form is an offline typed interaction contract. It does not create grants, approvals, authorization, capabilities, commands or physical effects; advisory text cannot become authority.
4. Only approved templates and registered answer fields are accepted. Unknown fields, missing required evidence, malformed input or untrusted observations are rejected.
5. UI presentation/locale integration belongs to T10. Do not modify UI, API, package exports or shared wiring.

## Exact write set

- `packages/domain-computer/src/guided/**`
- `tests/integration/v03/t05-guided/**`

## Forbidden

Any path outside the two patterns; T00 contracts, T03 semantic paths, T10 UI, T11 entrypoints/API/lockfile, package manifests, root config, model/provider calls, grants/approvals, OS commands/effects, main or v0.2.

## Read-only implementation inputs

- `packages/domain-computer/src/contracts/**`
- `packages/contracts/src/goal.ts`, `receipts.ts`, `capability.ts`
- `packages/resolver/src/normalize.ts`, `planner-seam.ts`, `gates.ts`
- `packages/workflow/src/kernel.ts`

## Completion and blocker rule

Implement the one-step typed form/outcome lifecycle and adversarial offline tests only. Run focused tests, resolver/contracts regressions, task-local typecheck/lint and exact-HEAD CI. If a requirement needs UI wiring, a grant/effect, new shared contract, LLM call or write outside the frozen set, stop and route to the owning Task/authority; do not widen scope.
