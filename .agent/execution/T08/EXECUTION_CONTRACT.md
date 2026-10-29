# T08 Execution Contract — curated Provider JIT capability and signed trusted Host adapter

## Authority and exact subject

- Frozen Task Pack: `docs/planning/v0.3/TASK-PACKS-R0.json@8aef87cac27297cc32e4e79e0141658a712484fb`, T08 / Issue #236.
- Product/L1 #214 checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95`; L2 #217 blob `8c555aff66d3006a1dbd4fb523e350f70c5db490`.
- DAG #218 freeze `b47e02f59704ed1699c651b89fd8f26291312ff0`; DAG blob `73d06cb67e08187d3ee6ae1a820c5b1f99a169e4`.
- Owner authorization #218@6510839827; T00 predecessor merge `1165a70a9271f570cbb313210f20aa013db72f86`.
- Effective ADS `4.18.0@2c395c55569fe2edf3f4135f12d3d069e526d0b7`; exact base `1165a70a9271f570cbb313210f20aa013db72f86`; JIT branch `JIT_only_task/v0.3.0-t08`.

## Contract and invariants

1. Select only a curated Provider definition whose signature, digest, ABI and capability binding resolve against an existing trusted root and the exact selected environment.
2. Verify signature and artifact digest before staging or loading. The offline cache is content-addressed and cannot be treated as authority by path/name alone.
3. Unsupported ABI, unsupported npm dependency graph, missing trust root, unsigned/tampered binary, wrong capability binding or stale cache identity fails closed before activation.
4. Reuse the existing provider-loader and vertical-jit curated-provider semantics as read-only sources. Do not fork a second loader, create a new trust root or widen Provider registry authority.
5. This dispatch is offline and non-effectful. Use existing curated signed fixtures/artifacts only where their provenance verifies; do not invent a production signature/trust root. No network download, actual Windows install, native activation, system mutation or external disclosure is authorized.
6. T11 owns public exports and runtime activation wiring; T08 implements only its isolated B/Host adapter folders and tests.

## Exact write set

- `packages/domain-computer/src/provider/**`
- `packages/domain-host/src/provider/**`
- `tests/integration/v03/t08-provider/**`

## Forbidden

Any path outside the three patterns; `packages/provider-loader/**`, `packages/vertical-jit/**`, package manifests/exports, T11 wiring/lockfile, untrusted provider downloads, live installation/activation, OS mutation, main or v0.2.

## Read-only implementation inputs

- `packages/provider-loader/src/activation.ts`, `preflight.ts`, `staging.ts`, `native-pe.ts`
- `packages/vertical-jit/src/curated-provider.ts`
- `packages/contracts/src/provider.ts` and provider schemas
- `packages/domain-computer/src/contracts/**`

## Completion and blocker rule

Implement the typed Provider capability adapter and trusted Host verification/staging boundary using existing contracts only. Run focused positive/negative tests, provider-loader/vertical-jit/contracts regressions, task-local typecheck/lint and exact-HEAD CI. If no existing curated signed artifact/trust root can be proven, report BLOCKED rather than creating one. No real installation or activation is performed in this dispatch.
