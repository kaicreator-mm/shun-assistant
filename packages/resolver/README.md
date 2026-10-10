# @shun/resolver

T01 goal/capability/provider resolution for Shun v0.1. Authority:
`docs/architecture/L2-v0.1.md` §6 (Planner boundary), §7 (Provider Registry /
Resolver), §13 (failure ownership), C-000
(`docs/product/capability-contracts-v0.1.md`) and the frozen Product resolver
v0.1 rules (`docs/product/provider-resolver-v0.1.md`). Resolution is read-only
and deterministic: hard gates precede ranking, risk is never a score
component, ambiguity and failure are typed, and planner output is untrusted
proposal data only.

## Constraint-evaluation boundary (P1-04, Issue #33)

The frozen contracts (`packages/contracts/**`) are immutable authority for the
resolver. They deliberately carry **no per-binding capability-format
metadata** (`ProviderCapabilityBinding` and `CapabilityDefinition` are
`strictObject` schemas with no format field). The resolver therefore applies
the following bounded, deterministic rules — it does not silently widen the
frozen authority:

| Goal constraint | Gate evaluation (USER_ORG_POLICY) |
| --- | --- |
| `constraints.format` | Evaluated **only** against an opt-in curated fact `formatSupport: string[]` on `provider.provenanceFacts` (the single unconstrained curated record in the frozen `ProviderDefinition`). Covered-but-different requested format ⇒ REJECT. No curated facts ⇒ not gate-evaluable: the binding passes, but the PASS reason records the explicit **deferral** to downstream verification; it is never silently certified. A present-but-malformed `formatSupport` fact ⇒ REJECT (fail closed). |
| `constraints.licensing` | Enforced as an exact, case-insensitive license identity match against `provider.licenseFacts.license` (a required frozen field). Any requested licensing identity the license facts do not satisfy verbatim ⇒ REJECT. Descriptive licensing preferences that do not name a license identity fail closed rather than being interpreted heuristically. |
| `capability.requiredPolicyFacts` | Every declared policy-fact key must be present in `constraints.other`; a missing key cannot be proven current ⇒ REJECT. |

Curated-fact granularity note: `formatSupport` is provider-level (the frozen
binding schema cannot carry per-binding facts). Two bindings of the same
provider therefore share one format declaration; per-binding format splitting
requires a frozen-contract change and is out of scope for resolver v0.1.

## Registry snapshot currentness seam (P1-06, Issue #33)

`ShunRegistry.fromPort` collects capability/provider/binding/environment fact
classes through several async port calls; the frozen `RegistryReadModelPort`
cannot express an atomic read. The resolver therefore requires an explicit
**snapshot seal** for port-built registries:

- `sealRegistrySnapshot(snapshot)` derives a verifiable content digest
  (`shun.registry-snapshot/1:sha256:<hex>`) from the exact collected facts.
  The digest — not a caller-asserted label — binds the seal to the facts.
- `ShunRegistry.fromPort(port, { snapshotSeal })` with a matching seal yields
  a currentness-attested registry. Without a seal the registry can be built
  for inspection, but `resolveGoal` over it fails closed with
  `REGISTRY_CURRENTNESS_INSUFFICIENT` (reads-between-changed cannot be
  excluded).
- `ShunRegistry.fromSnapshot(snapshot, { snapshotSeal? })` is the synchronous
  in-memory path (construction is inherently atomic). A provided seal is
  verified against the facts; a mismatch throws at construction — the
  snapshot is stale or was altered after sealing.
- The `observationRevision` string on `EnvironmentFacts` is a durable identity
  input, **not** freshness proof; the seal binds all facts (including the
  environment) instead.

## Benchmark gold evidence (P1-07, Issue #33)

`evidence/gold-ranking-evidence.ts` holds the versioned gold provenance and
evidence records for the resolver unit scenarios B-033/B-034/B-035. They are
**synthetic-agreement records**: the gold dispositions are derived from the
hard requirements of the frozen scenario inputs, not from the resolver score —
but no observed real execution evidence exists yet. Real independent
validation (independent evaluator, real task outcomes, top-k agreement
recording per `docs/validation/benchmark-v0.1.md`) belongs to a later
Integration gate; these records must not be cited as independent validation.
