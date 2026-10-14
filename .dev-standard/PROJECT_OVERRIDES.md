# Shun Assistant Project Overrides

## Project Identity

- Repository: `kaicreator-mm/shun-assistant`
- Product: **Shun Assistant**
- Product role: AI usability layer for computers and software.
- Standard revision: read `.dev-standard/VERSION`; it is immutable and must never be replaced with a mutable `main` / `latest` reference.

## Current lifecycle state

- **v0.1.0 historical release:** exact tagged commit `2313ba2773dac7aa535570e22760147d9b383b65` / immutable v0.1 product/security/implementation artifacts; version 0.1.0 closed with documented qualifications. Do not retroactively rewrite historical candidate posture.
- **Current active version:** v0.2.0, Stage 1 **PRODUCT_FROZEN**; exact authority and frozen scope in `docs/product/PRODUCT-FREEZE-v0.2.md` and #80 Product Freeze terminal.
- Current PRD candidate: `docs/product/PRD-v0.2.md`; supporting `docs/product/L1-product-evidence-v0.2.md`, `docs/product/script-recipe-v0.2-DRAFT.md`, `docs/research/v0.2/open-source-provider-candidates.md`; controller #80 and PR #81.
- v0.2 integration target: `version/v0.2.0` (version branch), based initially on `main@217364b0c308e6089ea884ef7cb84eda752f7102`.
- v0.2 Product Freeze: **FROZEN** at semantic subject `79f47be5ff08a54588790e8abdacffd8697ac4d8` / tree `10c0ad768fee849ada952b038b0b1a653fd9a6d7`, current independent review #84 PASS; integration PR #81 -> `version/v0.2.0@aa395c397810004f113bbec12838db6197fc72fa` with identical tree.
- v0.2 L2 Architecture: **IN_PROGRESS**, candidate `docs/architecture/L2-v0.2-CANDIDATE.md`; #83 architecture controller, #85 U01, #86 U04, #87 U05 real-host high-impact unknowns. L2 Freeze and Task DAG **NOT_YET**; v0.2 implementation not authorized.
- v0.1 evidence is reusable by exact source identity; it never substitutes for v0.2 host tests, generic dynamic code loading, local model egress or other new semantics.

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

- v0.2 Integration mode: `version/v0.2.0` plus bounded concern branches/PRs; PR #81 is the merged Stage-1 product checkpoint and later version commits add only successor metadata/architecture until L2 Freeze. v0.1 main/tag baseline remains immutable.
- GitHub Issues are durable work items.
- One concern -> one branch -> one PR.
- Chat history is not project authority.
- Review and validation bind only to the exact SHA actually inspected/executed.

## Product hard boundaries

- North Star: **make systems and software easier to use**.
- The product is not defined as a universal Computer Use / arbitrary-UI agent.
- Primary abstraction: `Goal -> Capability -> Provider×Environment Binding -> Execute -> Verify -> Lifecycle State -> optional Recipe`.
- Capability is the task boundary; applications are Providers.
- Agent-friendly Provider selection precedes UI automation.
- UI-last means UI is a fallback/collaboration surface, not forbidden.
- Complex CAD/3D/video creative work may require Guide/Co-pilot and visual review.
- Outcome verification is mandatory where an outcome contract is available.
- Risk/safety gates are independent from Provider ranking.
- RunX is an execution-environment abstraction and is P1 for v0.1; local P0 flows must stand alone.
- P0 collection follows data minimization: exclude credentials/tokens/private keys/session secrets and unrelated content by default; external disclosure is distinct from local collection and is constrained by user/policy requirements.
- Provider trust is fail-closed by default: unknown provenance cannot be converted to trusted by user confirmation alone.

## Historical v0.1 P0 MVP closure loops

> Retained as the v0.1 baseline; does not independently define v0.2 acceptance. v0.2 requirements are in the separately reviewed/frozen PRD candidate.

### P0 MVP closure loops

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
