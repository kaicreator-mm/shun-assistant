# @shun/resolver

T01 goal/capability/provider resolution for Shun v0.1. Authority:
`docs/architecture/L2-v0.1.md` §6 (Planner boundary), §7 (Provider Registry /
Resolver), §13 (failure ownership), C-000
(`docs/product/capability-contracts-v0.1.md`) and the frozen Product resolver
v0.1 rules (`docs/product/provider-resolver-v0.1.md`). Resolution is read-only
and deterministic: hard gates precede ranking, risk is never a score
component, ambiguity and failure are typed, and planner output is untrusted
proposal data only.

This README describes the behavior after the R2 remediation (Issue #33, fresh
independent review of PR #42). Earlier R0/R1 descriptions (snapshot seals,
deferral PASS notes, key-presence policy facts) are obsolete — do not
reinstate fail-open wiring.

## Constraint-evaluation boundary (P1-04, Issue #33)

The frozen contracts (`packages/contracts/**`) are immutable authority for the
resolver. They deliberately carry **no per-binding capability-format
metadata** (`ProviderCapabilityBinding` and `CapabilityDefinition` are
`strictObject` schemas with no format field). The resolver therefore applies
the following bounded, deterministic rules — it does not silently widen the
frozen authority:

| Goal constraint | Gate evaluation (USER_ORG_POLICY) |
| --- | --- |
| `constraints.format` | Evaluated **only** against an opt-in curated fact `formatSupport: string[]` on `provider.provenanceFacts` (the single unconstrained curated record in the frozen `ProviderDefinition`). Covered-but-different requested format ⇒ REJECT. No curated facts, or a present-but-malformed fact ⇒ REJECT — an unprovable mandatory format is **never** a deferred PASS. |
| `constraints.licensing` | Enforced as an exact, case-insensitive license identity match against `provider.licenseFacts.license` (a required frozen field). Any requested licensing identity the license facts do not satisfy verbatim ⇒ REJECT. |
| `capability.requiredPolicyFacts` | Every declared policy-fact key is evaluated **exclusively** through the injected trusted `PolicyFactEvaluator`; a verdict is accepted only from an evaluator carrying a non-empty provenance identity (`evaluatorId` + `policyRevision`, recorded in the gate evidence). No evaluator, a missing identity, or an UNSATISFIED/UNVERIFIABLE verdict ⇒ REJECT. Values in the caller-supplied `constraints.other` are never proof (R1). |
| `constraints.privacy`, `constraints.executionEnvironment`, `constraints.resourceLimits`, `constraints.retainRemove` | Descriptive strings with no curated fact class at resolver v0.1: a present descriptive constraint ⇒ **typed REJECT** naming the constraint (R2). The R1 behavior — a PASS note saying "not certified" — was a review blocker: a free-text disclaimer is not a typed unresolved mandatory condition, and the frozen Product resolver requires necessary user constraints before ranking. These goals become resolvable only when the constraint is expressed in gate-evaluable contracts (a frozen-contract change, owned by the Controller/L2). |

Curated-fact granularity note: `formatSupport` is provider-level (the frozen
binding schema cannot carry per-binding facts). Two bindings of the same
provider therefore share one format declaration; per-binding format splitting
requires a frozen-contract change and is out of scope for resolver v0.1.

## Policy-fact evaluator provenance (P2, R2)

`PolicyFactEvaluator` is a trust anchor wired by the integration layer, like
the registry port itself. It must carry `evaluatorId` (who issued the
verdicts) and `policyRevision` (which policy-state revision the verdicts are
current for); the resolver records both in every gate note so a PASS is
auditable. The composition layer owns evaluator construction AND the
currency of `policyRevision`; the resolver does not guess it.

## Registry snapshot currentness seam (P1-06, R1; tightened R2)

`RegistryReadModelPort` collects its fact classes through separate async calls
and cannot express an atomic read, so currentness attestation requires a
trusted source-side authority:

- `RegistryCurrentnessAuthority { currentRevision(): Promise<string> }` is the
  trusted seam; the integration layer injects it (the same trust boundary as
  the port itself). The revision it serves (`shun.registry-snapshot/1:sha256:<hex>`,
  derived by `snapshotFactsRevision`) is the unit it ISSUES — deriving it
  locally proves nothing.
- `ShunRegistry.fromPort(port, { currentnessAuthority? })`: after collecting
  the fact classes, the computed content revision is compared against the
  authority's CURRENT revision. Only a binding revision attests; a disagreeing
  or unreachable authority leaves the registry unattested.
- `ShunRegistry.fromAttestedSnapshot(snapshot, { currentnessAuthority? })` is
  the trusted path for an already-held snapshot — the same comparison against
  the authority's current state. A stale-but-self-consistent snapshot never
  attests.
- `ShunRegistry.fromSnapshot(snapshot, { additionalObjectiveMatchers? })`
  builds an **unattested local view**. R2: it accepts NO attestation input of
  any kind — the R1 `authorityRevision` option was self-attestation (the
  caller could compute the revision from the same snapshot) and the
  `asyncCollectionAttested` flag was a bypass; both are removed.
- `resolveGoal` over an unattested registry fails closed with
  `REGISTRY_CURRENTNESS_INSUFFICIENT` (reads-between-changed cannot be
  excluded). The `observationRevision` string on `EnvironmentFacts` is a
  durable identity input, **not** freshness proof.

## Planner transport provenance (P2, R1; tightened R2)

A configured PlannerPort must carry bound transport provenance — never a
caller-asserted label:

- `remotePlannerAdapter(planner)` / `localPlannerAdapter(planner)` mint a
  frozen `TrustedPlannerAdapter` binding the PlannerPort to its transport;
  `interpretGoalViaPlanner` accepts ONLY adapters minted by the factory
  (module-private brand; forged adapters fail closed at zero invocations).
- R2: the caller-supplied `{ planner, transport }` pair form is REMOVED. A
  caller-labeled `'LOCAL'` transport previously let a remote-backed planner
  run under local-only/offline policy.
- R2: `localPlannerAdapter` requires the planner's local provenance to be
  declared at the trusted composition boundary via
  `declareLocalPlanner(planner)`; minting throws otherwise. The composition
  layer is the trust anchor that asserts a planner executes in-process.
- Policy enforcement is unchanged: REMOTE is ineligible under local-only /
  no-disclosure policy and under the offline constraint, always at zero
  planner invocations.

## Benchmark gold evidence (P1-07, Issue #33)

`evidence/gold-ranking-evidence.ts` holds the versioned gold provenance and
evidence records for the resolver unit scenarios B-033/B-034/B-035. They are
**synthetic-agreement records**: the gold dispositions are derived from the
hard requirements of the frozen scenario inputs, not from the resolver score —
but no observed real execution evidence exists yet. Real independent
validation (independent evaluator, real task outcomes, top-k agreement
recording per `docs/validation/benchmark-v0.1.md`) belongs to a later
Integration gate; these records must not be cited as independent validation.
