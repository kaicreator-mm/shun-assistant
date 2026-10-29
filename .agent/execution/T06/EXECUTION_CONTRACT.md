# T06 Execution Contract — opt-in redacted feedback and future-build Meta candidate/Shadow

## Authority and exact subject

- Frozen Task Pack: `docs/planning/v0.3/TASK-PACKS-R0.json@8aef87cac27297cc32e4e79e0141658a712484fb`, T06 / Issue #234.
- Product/L1 #214 checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95`; L2 #217 blob `8c555aff66d3006a1dbd4fb523e350f70c5db490`.
- DAG #218 freeze `b47e02f59704ed1699c651b89fd8f26291312ff0`; DAG blob `73d06cb67e08187d3ee6ae1a820c5b1f99a169e4`.
- Owner authorization #218@6510839827; T00 predecessor merge `1165a70a9271f570cbb313210f20aa013db72f86`.
- Effective ADS `4.18.0@2c395c55569fe2edf3f4135f12d3d069e526d0b7`; exact base `1165a70a9271f570cbb313210f20aa013db72f86`; JIT branch `JIT_only_task/v0.3.0-t06`.

## Contract and invariants

1. Feedback is opt-in only. No selected feedback, no payload, no workflow invocation. Consent is explicit, current and scoped to the exact feedback candidate.
2. Redact/minimize before any persistence or Host handoff. Use a strict allowlist; never include raw prompts, answers, credentials, secrets, environment values, process arguments, sensitive absolute paths, unrelated document bodies or cross-user data.
3. Host workflow is represented by a narrow injected `runMetaFeedbackWorkflow` port. T06 may create only a future-build candidate/Shadow record; it cannot promote, activate, self-train or change current runtime behavior.
4. Candidate provenance must identify source/consent/revision and preserve operator attribution. Missing operator, forged provenance, cross-user evidence or self-promotion rejects.
5. This wave authorizes no external data disclosure. Use local synthetic fixtures and a fake/in-process Host port only; no network sender, telemetry or remote Meta call. Any later export requires separate explicit user authorization and a current disclosure scope.

## Exact write set

- `packages/domain-computer/src/feedback/**`
- `tests/integration/v03/t06-meta/**`

## Forbidden

Any path outside the two patterns; Host package implementation outside the port boundary, T11 wiring, UI/API, package manifests/exports/lockfile, provider/model calls, external network, cross-user aggregation, raw data export, candidate promotion, main or v0.2.

## Read-only implementation inputs

- `packages/domain-computer/src/contracts/**`
- `packages/contracts/src/receipts.ts`, `goal.ts`
- `packages/workflow/src/kernel.ts`
- `packages/store/src/shun-store.ts`
- `apps/control-api/src/ports.ts`, `cloud-authority.ts`

## Completion and blocker rule

Implement the pure opt-in selection, redaction and future-build Shadow candidate contract plus fake Host tests. Run focused tests and workflow/store/contracts regressions, typecheck/lint and exact-HEAD CI. If safe redaction, operator provenance or consent currentness cannot be proven, fail closed. If an external disclosure, new Host implementation path or activation is required, stop and request the owning authority; do not widen the write set.
