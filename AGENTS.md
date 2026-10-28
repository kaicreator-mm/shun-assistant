# AGENTS.md

This project follows the immutable `kaicreator-mm/ai-development-standard` revision recorded in `.dev-standard/VERSION`.

## Read order

1. `.dev-standard/VERSION`
2. `.dev-standard/PROJECT_OVERRIDES.md`
3. The pinned standard's `AGENTS.md`
4. `standards/DEVELOPMENT_WORKFLOW.md`
5. Product authority under `docs/product/`
6. Relevant validation/review artifacts under `docs/validation/` and `docs/review/`

## v0.3 version-branch routing and current admission

- On `version/v0.3.0`, read its own actual `.dev-standard/VERSION` before any action; the project-local ADS v4.18.0 revision is **proposed by #216 until its reviewed adoption PR is lawfully merged**. A review-only PR source checkout is not proof that the version integration branch has adopted it.
- v0.3 Product/L1 [#214](https://github.com/kaicreator-mm/shun-assistant/issues/214) and L2 [#217](https://github.com/kaicreator-mm/shun-assistant/issues/217) are Owner-frozen. Task DAG [#218](https://github.com/kaicreator-mm/shun-assistant/issues/218) is independently R2 PASS and Owner-frozen: [`docs/planning/v0.3/TASK-DAG-FREEZE.md`](docs/planning/v0.3/TASK-DAG-FREEZE.md), 14 planned Tasks/22 edges/8 safely parallel post-T00 lanes. These are immutable **planning** sources, not native GitHub Issue dependencies.
- **Current v0.3 stage** is post-DAG-Freeze, **before** 14 native Task Issues, 22 GitHub native `blocked_by` relationships, accepted T00 CAS Builder Claim and three-package source Scaffold. A Work Item, diagram, isolated PR or passing CI cannot stand in for native dependency write/readback, accepted source Claim or real runtime validation. Keep T00 and all T01–T11/V01/R01 unclaimed until admitted.
- Preserve two L2 R2 hard implementation acceptance groups: T04/T11/V01 must test a real selected public SDK C→trusted Host with **one original approved DeepSeek request Buffer**, per-request output ceiling/deadline, refused/failed/unknown mapping and cost/UNKNOWN fence; T09/T11/V01 must prove Shun's **pre-public-`DomainApp.send`** Case gateway blocks malformed/forged/stale input with zero facade send and zero Kernel Journal before valid same stable Case. These are not pre-certified.
- Only qualified Git **source tag** DomainHarness `v0.10.3@061376f4a023070f215f9feffad5c24d96d503cb` exists; do not assume npm package `0.10.3`, and do not run unapproved external effects.
- The project's A1_MANUAL_PROTOCOL, native-v4, PINNED/MANUAL profile and risk-based actual Review/Validation remain unchanged. Existing `version/v0.2.0` and in-flight v0.2 Task/PR snapshots retain their original historical ADS identities; **do not rebind or overwrite** them from v0.3 planning. This v0.3 adoption does not authorize main merges, native Task materialization, paid API, Windows effects or a second automation/controller.

## v0.2 historical phase rules (apply to v0.2 source only)

- Active `version/v0.2.0` is **Stage 3 implementation**. Product (including DeepSeek-first re-freeze), L2 and P0 Task DAG are already frozen; do not reopen them to change the development-standard pin.
- Frozen Task DAG: 11 P0 tasks, 26 dependencies, `docs/planning/TASK-DAG-FREEZE-v0.2.md`. Source and runtime progress must be read from current GitHub Issues/PRs, not from historical planning headers or chat.
- At this upgrade checkpoint T00/T01/T03/T06 are closed (4/11). T04/T05 remain active; PR #150 and #152 have blocking independent review findings (#151/#153) and must be fixed before merge. T07–T11 remain dependent; no v0.2 Release PASS is claimed.
- New/checkpointed work applies ADS `4.13.1` at the immutable commit in `.dev-standard/VERSION` with `A1_MANUAL_PROTOCOL` overrides. Accepted in-flight old-standard Task and PR evidence retain their original `4.9.0@7929012f36a2202dcc2edc7a414b8163adc7afbd` identity until a lawful checkpoint; do not retroactively relabel or use a mutable latest reference.
- Use one concern/PR, review only risks actually requiring review, reuse valid deterministic tests and real-host evidence; CI PASS is not release qualification. Agent logical roles are self-declared independently of GitHub transport accounts.
- Do not weaken frozen Product/Architecture/security/approval, invent PASS or skip native Windows validation when the affected Task requires it. Shun v0.1 historical freeze/release evidence remains immutable.
