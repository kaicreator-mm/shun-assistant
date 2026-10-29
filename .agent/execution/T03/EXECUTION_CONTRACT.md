# T03 Execution Contract — typed Goal/Proposal semantics and registered capability selection

## Authority and exact subject
- Task Pack T03 / Issue #231: `docs/planning/v0.3/TASK-PACKS-R0.json@8aef87cac27297cc32e4e79e0141658a712484fb`.
- Product/L1 #214 checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95`; L2 #217 blob `8c555aff66d3006a1dbd4fb523e350f70c5db490`.
- DAG #218 freeze `b47e02f59704ed1699c651b89fd8f26291312ff0`; Owner authorization #218@6510839827.
- T00 predecessor completion: `T00@1165a70a9271f570cbb313210f20aa013db72f86`; exact integration base `1165a70a9271f570cbb313210f20aa013db72f86`.
- Effective ADS: `4.18.0@2c395c55569fe2edf3f4135f12d3d069e526d0b7`; JIT branch `JIT_only_task/v0.3.0-t03`.

## Contract and invariants
1. Preserve and reuse the existing strict Shun GoalRequest/GoalProposal/GoalContract schemas and resolver provenance model.
2. Map untrusted model/advisory output into typed semantic S and a registered bounded capability B; only registered capability identifiers and schemas are eligible.
3. User-selected folder/scope and trusted Host observations are immutable authority inputs. Model text cannot expand roots, objects, operations, commands, capabilities or privacy scope.
4. Fake/forged provenance, unknown schema fields, stale evidence, undeclared commands/capabilities and self-asserted grants fail closed.
5. This Task selects semantics/capabilities only; it does not create grants, approvals, run commands, call providers or execute effects.

## Exact write set
- `packages/domain-computer/src/semantic/**`
- `tests/integration/v03/t03-semantic/**`

## Forbidden
Any path outside the two patterns; changes to T00 contracts, shared exports, package manifests, tsconfig, root config, lockfile, UI, cloud sender, provider activation, grant/approval issuance, command execution, main or v0.2.

## Read-only implementation inputs
- `packages/contracts/src/goal.ts`
- `packages/contracts/src/capability.ts`
- `packages/contracts/src/registry.ts`
- `packages/resolver/src/normalize.ts`
- `packages/resolver/src/planner-seam.ts`
- `packages/resolver/src/registry.ts`
- `packages/resolver/src/feasibility.ts`
- `packages/resolver/src/gates.ts`

## Completion
Implement the bounded typed semantic/capability adapter and positive/negative tests under the allowed paths. Run focused resolver regression, task-local typecheck/lint and exact-HEAD CI. Publish one stable exact-HEAD PR to version/v0.3.0; independent Review required.

## Blocker rule
If the frozen public contract is insufficient, the Task Pack conflicts with L2, or implementation requires widening selected scope or adding grant/effect behavior, stop and report TASK_PACK_DEFECT/ARCHITECTURE_CONTRADICTION. Do not solve it by prompt-only restrictions.
