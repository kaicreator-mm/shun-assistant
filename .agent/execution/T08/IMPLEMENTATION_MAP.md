# T08 Implementation Map — exact base 1165a70a9271f570cbb313210f20aa013db72f86

## Write areas
- `packages/domain-computer/src/provider/**` — curated Provider capability selection and typed B binding.
- `packages/domain-host/src/provider/**` — signature/digest/ABI verification and offline cache Host adapter; no real activation.
- `tests/integration/v03/t08-provider/**` — positive/negative signed-artifact, cache, ABI and trust-root tests.

## Read-only inputs
- `packages/provider-loader/src/activation.ts`, `preflight.ts`, `staging.ts`, `native-pe.ts`
- `packages/vertical-jit/src/curated-provider.ts`
- `packages/contracts/src/provider.ts` and provider schemas
- `packages/domain-computer/src/contracts/**`

## Cross-task boundaries
- T08 does not edit provider-loader or vertical-jit; it reuses their public behavior as source inputs.
- T00 owns package manifests/tsconfigs/contracts; T11 owns package exports, dependencies, activation wiring and lockfile.
- Use only a verified existing curated artifact/trust root. If none is available, block rather than fabricate provenance.

## Out of scope
Network downloads, live Windows installation/activation, native system mutation, new trust roots, package wiring, lockfile, main and v0.2.
