# T04 Execution Contract — exact-byte DeepSeek sender behind selected public C/Host binding

## Authority and exact subject

- Frozen Task Pack: `docs/planning/v0.3/TASK-PACKS-R0.json@8aef87cac27297cc32e4e79e0141658a712484fb`, T04 / Issue #232.
- Product/L1 #214 checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95`; L2 #217 blob `8c555aff66d3006a1dbd4fb523e350f70c5db490`.
- DAG #218 freeze `b47e02f59704ed1699c651b89fd8f26291312ff0`; DAG blob `73d06cb67e08187d3ee6ae1a820c5b1f99a169e4`.
- Owner authorization: #218@6510839827. Completed predecessor T00 #228 merge `1165a70a9271f570cbb313210f20aa013db72f86`.
- Effective ADS `4.18.0@2c395c55569fe2edf3f4135f12d3d069e526d0b7`; exact integration base `1165a70a9271f570cbb313210f20aa013db72f86`; JIT branch `JIT_only_task/v0.3.0-t04`.

## Contract and invariants

1. Selected DH capability `capability-llm-openai-compatible` uses `llm.openai.generate`; the new Domain Computer C imports only the deployment-supplied static `domain-harness-openai-host.generate` binding. Do not install/import the optional SDK OpenAI client subpath or create a second physical sender.
2. The trusted Shun Host adapter consumes the existing `TrustedCloudInterpreter.interpretGoal` and existing `TrustedDeepSeekTransport`; final selected-C/Host singleton wiring is T11-owned. Do not edit T11 files or old transport sources.
3. The existing transport must pass the identical canonical request Buffer through `ledger.reserve`, `markMayHaveSent` and the sole fake-HTTP fetch boundary; preserve `thinking:{type:'disabled'}` and strict neutral DTO (one user goal and outputFormat text only).
4. The actual approved sender must enforce `maxOutputTokens` at or below the configured ceiling and `deadlineUnixMs` against remaining approved time, or reject unsupported/expired requests before any HTTP/MAY_HAVE_SENT boundary.
5. Preserve exact `completed/refused/failed/unknown` mapping at selected C and Kernel/UI-facing result surfaces. Ambiguous send remains UNKNOWN/UNKNOWN_COST; no blind retry, refund, alternate sender or false success.
6. This dispatch is zero-paid: use fake HTTP and synthetic consent/ledger fixtures only. No real DeepSeek request, API-key use, physical Windows effect or external user-data disclosure is authorized.

## Exact write set

- `packages/domain-computer/src/cloud/**`
- `packages/domain-host/src/cloud/**`
- `tests/integration/v03/t04-cloud/**`

## Forbidden

Any path outside the three patterns; all root/package exports/manifests/lockfile and T11 wiring; `packages/llm-remote/**`, `apps/control-api/**`, sibling Task paths, SDK private imports, credentials, paid DeepSeek requests, actual external disclosure, main or v0.2.

## Read-only implementation inputs

- `packages/llm-remote/src/deepseek-transport.ts`, `atomic-budget.ts`, `planner-port.ts`
- `packages/domain-computer/src/contracts/llm-generate-v1.ts`
- `apps/control-api/src/cloud-authority.ts`, `cloud-interpret.ts`
- `packages/contracts/src/authorization.ts`

## Completion and blocker rule

Implement only the bounded C/Host adapters and fake-HTTP boundary tests. Run focused positive/negative tests, llm-remote/contracts/workflow regressions, task-local typecheck/lint and exact-HEAD CI. Any need for a second sender, altered canonical bytes, paid call, broader disclosure, missing token/deadline enforcement or T11 wiring is BLOCKED and routed upward; do not weaken the frozen acceptance.
