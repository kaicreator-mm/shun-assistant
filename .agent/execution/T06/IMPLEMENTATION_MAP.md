# T06 Implementation Map — exact base 1165a70a9271f570cbb313210f20aa013db72f86

## Write areas
- `packages/domain-computer/src/feedback/**` — opt-in selection, strict redaction/allowlist, provenance-bound candidate and narrow Host port contract.
- `tests/integration/v03/t06-meta/**` — synthetic local fixtures, redaction negatives, consent/currentness and Shadow-only tests.

## Read-only inputs
- `packages/domain-computer/src/contracts/**`
- `packages/contracts/src/receipts.ts`, `goal.ts`
- `packages/workflow/src/kernel.ts`
- `packages/store/src/shun-store.ts`
- `apps/control-api/src/ports.ts`, `cloud-authority.ts`

## Cross-task boundaries
- T06 owns no Host package or public entrypoint implementation; expose only the narrow injected `runMetaFeedbackWorkflow` port needed by the frozen contract.
- T11 owns public exports and central activation. Any external disclosure requires separate explicit user consent and is not part of this dispatch.
- Feedback is not a second learning/authorization authority and cannot self-promote a candidate.

## Out of scope
External transmission, cross-user learning, live Meta calls, telemetry, current-runtime mutation, UI/API wiring, package exports, lockfile, main and v0.2.
