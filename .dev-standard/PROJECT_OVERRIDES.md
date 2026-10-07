# Shun Assistant Project Overrides

## Project Identity

- Repository: `kaicreator-mm/shun-assistant`
- Product: **Shun Assistant**
- Product role: AI usability layer for computers and software.
- Standard revision: read `.dev-standard/VERSION`; it is immutable and must never be replaced with a mutable `main` / `latest` reference.

## Current lifecycle state

- Current phase: **Product/L1 candidate**.
- Product authority candidate: `docs/product/PRD-v0.1.md` plus the Product/L1 evidence and decision documents.
- Product Freeze: **NOT YET CLAIMED**.
- L2 Architecture: **NOT STARTED**.
- Task DAG / implementation authorization: **NOT STARTED**.
- Existing benchmark runs are product-validation evidence only; they do not authorize implementation scope.

## v4 Adoption / Compatibility Profile

- `v4.adoption_level`: `A1_MANUAL_PROTOCOL`
- `v4.compatibility_mode`: `native-v4`
- `v4.assurance.default`: `manual-minimum`
- `v4.model_diversity.default_basis`: `none`
- `v4.interchange`: `disabled`
- `v4.reducer`: `disabled`
- `v4.controllers`: `disabled`
- `v4.fast_path`: `canonical`

Rationale: the project is at Product/L1 and uses GitHub durable facts, exact-SHA review, and manual gates. It does not yet truthfully operate machine-contract reducers/controllers or full orchestration.

## Repository / execution profile

- Integration mode: `main` plus one-concern candidate branches while Product/L1 is being established.
- GitHub Issues are durable work items.
- One concern -> one branch -> one PR.
- Chat history is not project authority.
- Review and validation bind only to the exact SHA actually inspected/executed.

## Product hard boundaries

- North Star: **make systems and software easier to use**.
- The product is not defined as a universal Computer Use / arbitrary-UI agent.
- Primary abstraction: `Goal -> Capability -> Provider -> Environment -> Execute -> Verify -> Recipe/Lifecycle State`.
- Capability is the task boundary; applications are Providers.
- Agent-friendly Provider selection precedes UI automation.
- UI-last means UI is a fallback/collaboration surface, not forbidden.
- Complex CAD/3D/video creative work may require Guide/Co-pilot and visual review.
- Outcome verification is mandatory where an outcome contract is available.
- Risk/safety gates are independent from Provider ranking.
- RunX is an execution-environment abstraction and is P1 for v0.1; local P0 flows must stand alone.
- P0 collection follows data minimization: exclude credentials/tokens/private keys/session secrets and unrelated content by default; external disclosure is distinct from local collection and is constrained by user/policy requirements.
- Provider trust is fail-closed by default: unknown provenance cannot be converted to trusted by user confirmation alone.

## P0 MVP closure loops

1. **Process an object** — file/document/media -> verified result.
2. **Acquire and use capability** — resolve Provider -> trusted acquire/configure -> execute -> verify -> retain/remove.
3. **Make the system understandable** — observe -> evidence-backed diagnosis -> safe bounded action -> verify.

The first executable MVP proof requires one end-to-end reference vertical per loop plus the shared Capability/Provider core. Other P0 capability families are staged expansion coverage and must not create independent foundational architectures before the reference proof passes.

P0 software lifecycle is narrow: trusted acquisition, provenance, basic repair/reset, safe uninstall, residue classification, retain/remove. Driver/firmware changes, aggressive registry cleanup, and broad system repair are not P0 lifecycle scope.

## Required Product Freeze gate

Before Product Freeze:

1. Candidate artifacts must exist on one exact GitHub SHA.
2. Fresh Independent Adversarial Review must review that exact SHA.
3. No unresolved P0 finding may remain.
4. Any required P1 product contradiction must be closed.
5. Any successor change invalidates prior PASS currentness and requires affected re-review.
6. Freeze terminal must state the exact candidate SHA/tree and `PRODUCT_FREEZE_ELIGIBLE=YES`.

PR PASS != Product Freeze.

## Validation profile at Product/L1

- Cross-platform deterministic benchmark evidence may be produced before Product Freeze to test falsifiable product hypotheses.
- Windows-specific Store/driver/OneDrive/device truth requires a real Windows executor.
- RunX placement truth requires a real RunX-capable integration environment.
- UI-free targets in plans are targets, not PASS evidence.
- Safety/data integrity has priority over task success, semantic verification, recovery, user friction, and UI-free optimization.

## Hidden / release claims

- Hidden Validation: NOT APPLICABLE at current Product/L1 candidate phase.
- Release Qualification: NOT APPLICABLE.
- No tag/release/publication is claimed.
