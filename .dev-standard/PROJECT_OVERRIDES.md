# Shun Assistant Project Overrides

## Project Identity

- Repository: `kaicreator-mm/shun-assistant`
- Product: **Shun Assistant**
- Product role: AI usability layer for computers and software.
- Standard revision: read `.dev-standard/VERSION`; it is immutable and must never be replaced with a mutable `main` / `latest` reference.


## Current lifecycle state

- **v0.1.0** historical release/tag at `2313ba2773dac7aa535570e22760147d9b383b65`. No retroactive changes to historical source, PASS/FAIL or qualification.
- **v0.2.0** uses integration branch `version/v0.2.0`. Product Freeze (including DeepSeek-first re-freeze #96), L2 Freeze #101 and Task DAG Freeze #102 are completed. Frozen P0 DAG: **11 mandatory tasks, 26 dependency edges**; owner is `docs/planning/TASK-DAG-FREEZE-v0.2.md`.
- **Current stage:** implementation and scoped verification, not Product/L1 or L2 candidate. At this adoption checkpoint T00 #103, T01 #104 (source-ready admission), T03 #105, T06 #107 are closed (**4/11**). T04 #108 and T05 #106 remain open; T07–T11 are not qualified. No v0.2 Release PASS.
- **Active predecessor-source work:** PR #150 (T05) and PR #152 (T04) were authored under existing ADS v4.9.0; independent reviews #151/#153 have blocking P1 findings, so neither PR is merge-eligible. The ADS adoption does not rebind their accepted task identity, source evidence or review to a new standard.


## v4 Adoption / Compatibility Profile

- `v4.adoption_level`: `A1_MANUAL_PROTOCOL`
- `v4.compatibility_mode`: `native-v4`
- `v4.assurance.default`: `manual-minimum`
- `v4.model_diversity.default_basis`: `none`
- `v4.interchange`: `disabled`
- `v4.reducer`: `disabled`
- `v4.controllers`: `disabled`
- `v4.fast_path`: `canonical`
- Standard update preference: `PINNED/MANUAL`. This is an explicit one-off project opt-in, not a floating latest pin, automatic updater or unverified compatible recommendation.
- A1 does not enable machine records/reducers, extra controllers, Tally v2, automated cross-project PR writers or organization-wide toolchain installers. Native Issue Dependencies, exact Git SHA, real permissions, Validation and risk-based Review remain authoritative.


## Repository / execution profile

- Version-branch integration: `version/v0.2.0`; one concern → short PR → required exact-SHA CI/source review → merge after currentness, not per-change full release regression.
- This standards-only migration changes the current project's future/checkpointed development instructions. No frozen Product/L2/Task DAG, runtime, interface, security permission, code, GitHub dependencies, evidence or release status is changed.
- **In-flight isolation:** T04 #108 / PR #152 and T05 #106 / PR #150 retain ADS `4.9.0@7929012f36a2202dcc2edc7a414b8163adc7afbd` for their already-authored/reviewed source and accepted Task work until their lawful next checkpoint. No existing CI/Review PASS is upgraded by assertion. Eligible new/checkpointed work adopts `4.13.1@f35fcdb153ff171aaa0027b6e1b9c7592f28d3cd`.
- Behavior/authority compatibility: retain self-declared logical Actor identity (GitHub account is transport only), no Owner-credential gate, no mandatory independent review for every fix, risk-based required Review, exact-source Validation and PR PASS ≠ Release PASS. New v4.13 optional tooling/profiles remain disabled; no schema, runtime or external effects migrate.
- Root adoption: `AGENTS.md`, `.dev-standard/VERSION`, and this `PROJECT_OVERRIDES.md` are the effective root files. Exactly one operative `v4.adoption_level`. Check immutable ADS `VERSION=4.13.1` at the pinned release commit, not ADS main.

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


## Validation profile during v0.2 implementation

- This exact revision-only docs/standard change uses repository/source validation and actual branch readback. No source Build Host or Windows matrix is triggered just to change documentation.
- Windows CIM, native addon, DACL/reparse, COM, packaging and Windows Home/Pro release checks belong to their actual Task gates. Reuse accepted real-host evidence at original exact source.
- Integrated Candidate T10/T11 owns cross-component critical journeys, required hidden/platform validation and Release Qualification; no PR-only CI or review can imply those PASS. A1 does not impose extra identity approvals or machine reducers.

## Hidden / release claims

- v0.1 historical Release evidence is preserved.
- v0.2 integrated release qualification, Windows Home/Pro critical journeys and packaging: **NOT_RUN / NOT_PROVEN** at this adoption checkpoint, not READY.
- ADS v4.13.1 being a public published release never implies Shun Assistant v0.2 is released.
