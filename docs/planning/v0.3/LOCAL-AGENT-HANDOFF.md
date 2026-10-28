# v0.3 Local Agent Handoff — staged planning to legal implementation

**STATUS:** Planning bundle ready; do **not** run implementation yet. Authority: [v0.3 controller #214](https://github.com/kaicreator-mm/shun-assistant/issues/214), [L2 #217](https://github.com/kaicreator-mm/shun-assistant/issues/217), [DAG #218](https://github.com/kaicreator-mm/shun-assistant/issues/218), [ADS adoption #216](https://github.com/kaicreator-mm/shun-assistant/issues/216), [Product PR #215](https://github.com/kaicreator-mm/shun-assistant/pull/215).

## What has been authored / what has NOT

1. Product/L1 Freeze **DONE**: independent PR #215 R2 PASS 0/0/0 exact `4c2f8e84b6e6f3f5b526e52d01356159f2dce0e7`, explicit Product Owner Issue #214 comment 6477255283, version checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95` and exact verified Product/L1 blobs. This does NOT imply L2 Freeze.
2. L2 architecture draft, three-package minimal scaffold source layout, DAG (14 nodes/22 edges) and full bounded machine Task Packs are on **separate planning branch** `planning/v0.3-domain-harness-l2-dag-r0`; these are **not** active source implementation and not yet frozen.
3. Version staging `version/v0.3.0` at initial snapshot `f01233a002f65b9bfea04828f6e56914666a160a`. v0.2 still needs independent T10/T11 closeout. No new v0.3 packages, Task issues, native edges or source Claims created.
4. DomainHarness v0.10.3 Product/data Contract/L2 are frozen; source snapshot `7d571858bd6524ffd13a7985227183dbecb2924a`. LLM/Guided/Meta are designed in scope, but SDK final public packed artifact and RQ are pending. Node >=24, use only four public SDK package roots.

## Exact next controller actions (do not mark done without real evidence)

**A. Product (COMPLETE)**: independent R2 PASS and Owner Freeze [#214](https://github.com/kaicreator-mm/shun-assistant/issues/214#issuecomment-6477255283) exact reviewed Product PRD blob `f062b7f2c3dc3bf4aeeb7594ab5c2bc75b34d0ab` and L1 blob `4c703c3f0c283f4d3918babef8f87f56869698e5`, version-branch checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95`. Do not re-review Product or treat this as L2 Freeze.

**B. ADS v4.18 adoption**: #216 exact `4.13.1 → 4.18.0` project-local compatibility and pre-merge activation. Do not rewrite v0.2 pin or retroactively rebind older tasks. Actual adopted `.dev-standard/VERSION` on v0.3 branch determines effective standard; proposed version alone is not effective.

**C. L2 (NEXT)**: [L2 R0](../../architecture/v0.3/L2-DOMAIN-HARNESS-R0.md) rebound to approved Product. U01 source-backed K Permit + Shun ActionController; U02 single K orchestration Journal with existing ShunStore business receipts; U03 selected **single** DomainHarness OpenAI C / Host sender after private broker/ledger. Independent exact-HEAD L2 R1, P0/P1/P2 and `L2_FREEZE_READY` now required; Architecture Owner explicitly freezes afterwards. Scoped runtime tests belong to T01/T04/T11/V01 unless reviewer finds static basis insufficient to choose ABI or failure semantics.

**D. DAG / Scaffold**: review [Task DAG](TASK-DAG-v0.3-R0.md), [Task Packs](TASK-PACKS-R0.json), [Scaffold Layout](SCAFFOLD-LAYOUT.md) against frozen L2 and current v0.2 eligible source. Obtain proportional independent DAG review and explicit freeze. Materialize 14 native GitHub Task Issues + 22 native `blocked_by` edges and read back; **without native-write/readback, HOLD all dispatch**. Do not split a second parallel mini-DAG merely to generate Scaffold. The first local Builder only gets **T00**.

**E. Local Builder**: after native T00 READY and accepted single CAS Claim, generate `packages/domain-computer`, `packages/domain-host`, `packages/domain-app` scaffold using T00 exclusive manifest files, verify Node24 with selected SDK public exports, scoped tests and negative checks, create PR target `version/v0.3.0`, obtain required review. After T00 real integration, parallel release T01–T08 across disjoint directories, with their own current valid Claims. No local Agent may claim all tasks in one giant overlapping branch.

**F. Integration**: T09 API/BUILD and T10 UI in parallel after predecessors. T11 alone owns central exports, existing `server.ts`/`app.js` and lockfile. V01 real selected SDK consumer, Windows Host, DeepSeek CN/EN as required, guided forms, feedback/Shadow, signed JIT, Recipes and failures; R01 independent RQ. v0.2 accepted source differences must reconcile at actual final integration. No v0.3 main merge/tag without explicit RQ.

## Ready-to-paste local Agent *controller* trigger — not a global write permission

```text
项目：kaicreator-mm/shun-assistant v0.3
按 ADS v4.18 #1241，只能基于仓库 .dev-standard/VERSION 实际已生效
exact SHA 和 GitHub 原生 Issue/Claim 准入来执行，不凭聊天/README 推断。

先只读：
- 当前 #214 / #215 / #216 / #217 / #218；
- Product/L2 冻结记录与精确 source/tree；
- docs/planning/v0.3/{SCAFFOLD-LAYOUT.md,TASK-DAG-v0.3-R0.md,TASK-PACKS-R0.json}；
- native blocked_by 真实 GET；接受的唯一 Builder CAS Claim；
- v0.2 accepted source/currentness；DomainHarness v0.10.3 选定公开 SDK
  exports 和实际 source/安装包 hash。

若 Product/L2/DAG 未冻结、ADS 未合法采用、未见原生依赖或
真实 accepted Claim：只输出 HOLD、缺失事实和最小化下一步；
不要执行任何源码写入，不假设文档计划=授权。

仅在 T00 合法 READY 时，按 Task Pack T00 的 exclusive write set 生成
三包 scaffold；只做 public SDK shape/Node24 clean consumer 与负例；
不得有外部 Effect、密钥、无审批网络调用或改动 v0.2/main。
提交 task/v0.3.0-t00-... → version/v0.3.0 PR，
输出 exact head SHA、路径差异、真实 CLI EXIT、Review/CI 状态，
并更新 GitHub Task Claim 的合规 handoff。T01–T08 必须分别领取
各自合法 Claim；能并行的并行，不用一个 Agent/branch 串行包办。
```

## Review prompts

**Independent L2 R1 reviewer trigger:** `按 ADS v4.18 #1241，独立只读审核 Shun Assistant v0.3 PR #219 当前精确 HEAD，冻结 Product version/v0.3.0@c8334c7723eecf7fbbb6895b1defd6439edc6b95。审查 U01 K Permit 与 Shun ActionController 终态授权；U02 唯一 K effect Journal 与 ShunStore 业务记录/幂等回执；U03 DeepSeek 单 HTTP sender 与签名同意/费用台账/UNKNOWN，及动态表单、Meta、B-040、中英文验收。输出 P0/P1/P2、PASS/BLOCK、L2_FREEZE_READY，写回 #217/PR #219。只读、不修改、不合并、不运行付费 API、不触碰 v0.2/main。`

**Independent L2 R1 (only after Product Freeze):** `审查 shun-assistant L2 R0 当前 PR exact HEAD；核验 frozen Product 精确 blob/适用性、U01–U03、公开选定 SDK 路由、State/Journal 所有权、三包最小 scaffold、数据迁移/Windows Host/隐私成本。P0/P1/P2、PASS/BLOCK、L2_FREEZE_READY。只读。`

**Independent DAG R1 (only after L2 Freeze):** `审查 shun-assistant v0.3 TASK-DAG 和 TASK-PACKS exact HEAD；14 nodes/22 edges、冲突写集、Agent/WEB/CI/LOCAL 路由、T00 scaffold 合法准入、8 平行 lanes、native Issue Dependencies planned vs actual、V01/R01 Gate。输出 PASS/BLOCK、DAG_FREEZE_READY，不改源码、不自行物化未冻结 Task。`

## Stop/return contract

Every Agent response should include `STAGE`, `SOURCE_SHA`, `ROLE`, `TASK_ID`, `CLAIM_CURRENTNESS`, `NATIVE_DEPENDENCIES`, `ACTUAL_TEST_EXIT`, `REVIEW`, `BLOCKERS`, `GITHUB_URL`. No cost estimate, fake PASS or unbounded negative testing. If Host physical execution required, provide a **single minimum local trigger**, not repeated Windows CI.
