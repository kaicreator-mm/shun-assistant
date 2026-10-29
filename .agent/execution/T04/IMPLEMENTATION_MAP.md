# T04 Implementation Map — exact base 1165a70a9271f570cbb313210f20aa013db72f86

## Write areas
- `packages/domain-computer/src/cloud/**` — typed neutral request/response adapter for selected LLM capability; preserve one-user-goal/output-format contract.
- `packages/domain-host/src/cloud/**` — trusted Host bridge to the existing interpreter/transport; enforce consent, currentness, token ceiling and deadline before the single sender boundary.
- `tests/integration/v03/t04-cloud/**` — fake-HTTP selected C/Host integration, canonical byte identity, zero-paid and adversarial cases.

## Read-only inputs
- `packages/llm-remote/src/deepseek-transport.ts`, `atomic-budget.ts`, `planner-port.ts`
- `packages/domain-computer/src/contracts/llm-generate-v1.ts`
- `apps/control-api/src/cloud-authority.ts`, `cloud-interpret.ts`
- `packages/contracts/src/authorization.ts`

## Cross-task boundaries
- T00 owns the existing domain-computer contracts and package manifests/tsconfigs.
- T11 owns singleton selected-C wiring, package entrypoints, API/UI integration and lockfile.
- Existing llm-remote transport and Control API files are read-only; do not add another sender or modify root wiring.
- T04 must not consume B-040 support-context data or widen disclosure.

## Out of scope
Paid DeepSeek, real credentials, actual user data disclosure, physical Windows mutation, package wiring, exports, root config, lockfile, main and v0.2.
