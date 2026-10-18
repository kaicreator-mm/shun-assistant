# AGENTS.md

This project follows the immutable `kaicreator-mm/ai-development-standard` revision recorded in `.dev-standard/VERSION`.

## Read order

1. `.dev-standard/VERSION`
2. `.dev-standard/PROJECT_OVERRIDES.md`
3. The pinned standard's `AGENTS.md`
4. `standards/DEVELOPMENT_WORKFLOW.md`
5. Product authority under `docs/product/`
6. Relevant validation/review artifacts under `docs/validation/` and `docs/review/`

## Current phase rules

- Active `version/v0.2.0` is **Stage 3 implementation**. Product (including DeepSeek-first re-freeze), L2 and P0 Task DAG are already frozen; do not reopen them to change the development-standard pin.
- Frozen Task DAG: 11 P0 tasks, 26 dependencies, `docs/planning/TASK-DAG-FREEZE-v0.2.md`. Source and runtime progress must be read from current GitHub Issues/PRs, not from historical planning headers or chat.
- At this upgrade checkpoint T00/T01/T03/T06 are closed (4/11). T04/T05 remain active; PR #150 and #152 have blocking independent review findings (#151/#153) and must be fixed before merge. T07–T11 remain dependent; no v0.2 Release PASS is claimed.
- New/checkpointed work applies ADS `4.13.1` at the immutable commit in `.dev-standard/VERSION` with `A1_MANUAL_PROTOCOL` overrides. Accepted in-flight old-standard Task and PR evidence retain their original `4.9.0@7929012f36a2202dcc2edc7a414b8163adc7afbd` identity until a lawful checkpoint; do not retroactively relabel or use a mutable latest reference.
- Use one concern/PR, review only risks actually requiring review, reuse valid deterministic tests and real-host evidence; CI PASS is not release qualification. Agent logical roles are self-declared independently of GitHub transport accounts.
- Do not weaken frozen Product/Architecture/security/approval, invent PASS or skip native Windows validation when the affected Task requires it. Shun v0.1 historical freeze/release evidence remains immutable.
