# v0.3 Local Agent Handoff — staged planning to legal implementation

**STATUS:** Planning bundle ready; do **not** run implementation yet. Authority: [v0.3 controller #214](https://github.com/kaicreator-mm/shun-assistant/issues/214), [L2 #217](https://github.com/kaicreator-mm/shun-assistant/issues/217), [DAG #218](https://github.com/kaicreator-mm/shun-assistant/issues/218), [ADS adoption #216](https://github.com/kaicreator-mm/shun-assistant/issues/216), [Product PR #215](https://github.com/kaicreator-mm/shun-assistant/pull/215).

## What has been authored / what has NOT

1. Product/L1 Freeze **DONE**: independent PR #215 R2 PASS 0/0/0 exact `4c2f8e84b6e6f3f5b526e52d01356159f2dce0e7`, explicit Product Owner Issue #214 comment 6477255283, version checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95` and exact verified Product/L1 blobs. This Product authority is distinct from the subsequently completed L2 Owner Freeze.
2. L2 architecture has **passed independent R2 0/0/2, received explicit Architecture Owner Freeze**, and its reviewed five-document planning PR #219 was actually merged **only into `version/v0.3.0`** (`7a4d498d166eb3dc4dc0b9a23c5b53e7fad6e704`); frozen L2 blob `8c555aff66d3006a1dbd4fb523e350f70c5db490`, checkpoint [L2-FREEZE.md](../../architecture/v0.3/L2-FREEZE.md) Git blob `2f1601de193ad79c12bd3ccd660039836bac56f9`. Three-package scaffold *plan*, DAG 14 nodes/22 edges and Task Packs remain **provisional**, with independent DAG R1 BLOCK 0/1/1 at version snapshot `3358080bd8fabd097347ef6df12f9b7e9b223fd0`; the current DAG correction must obtain separate R2/Owner Freeze. No actual source scaffold.
3. Version stage after L2 checkpoint: `version/v0.3.0@3358080bd8fabd097347ef6df12f9b7e9b223fd0` is the **frozen L2 predecessor** to this separate DAG R1 correction PR. v0.2 still requires T10/T11 real closeout. Effective v0.3 ADS pin remains `4.13.1@f35fcdb153ff171aaa0027b6e1b9c7592f28d3cd` pending authorized #216 adoption. No new v0.3 packages, native Task issues/edges or Builder source Claims.
4. DomainHarness v0.10.3 **Git-source-only release is COMPLETE**: [tag](https://github.com/kaicreator-mm/domain-harness/tree/v0.10.3) `061376f4a023070f215f9feffad5c24d96d503cb`, tree `099cdc831aef63befd62aaede7e7a853d1be468f`, identical to qualified version source `7d571858bd6524ffd13a7985227183dbecb2924a`. [#1419 conditional Q closeout](https://github.com/kaicreator-mm/domain-harness/issues/1419#issuecomment-6478048574), P0/P1/P2=0/0/3, Full EXIT0, Hidden 7/7. **No npm publish:** public workspace package manifests still `0.10.2-rc.0`. `docs/current`/installed default SDK Skill still v0.10.2. Source is ready; T00 must build/pack four public SDK packages from immutable v0.10.3 Git Tag and prove clean Node>=24 external Shun consumer/actual tarball hashes. Do not await another SDK release or claim packed Shun test PASS.

## Exact next controller actions (do not mark done without real evidence)

**A. Product (COMPLETE)**: independent R2 PASS and Owner Freeze [#214](https://github.com/kaicreator-mm/shun-assistant/issues/214#issuecomment-6477255283) exact reviewed Product PRD blob `f062b7f2c3dc3bf4aeeb7594ab5c2bc75b34d0ab` and L1 blob `4c703c3f0c283f4d3918babef8f87f56869698e5`, version-branch checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95`. Do not re-review Product or treat this as L2 Freeze.

**B. ADS v4.18 adoption**: #216 exact `4.13.1 → 4.18.0` project-local compatibility and pre-merge activation. Do not rewrite v0.2 pin or retroactively rebind older tasks. Actual adopted `.dev-standard/VERSION` on v0.3 branch determines effective standard; proposed version alone is not effective.

**C. L2 (COMPLETE, exact-source Owner Freeze)**: Historical independent R1 at `e081645a...` BLOCK 0/1/1 was repaired by selecting original trusted DeepSeek sender behind static SDK C Host. Latest independent R2 [#217](https://github.com/kaicreator-mm/shun-assistant/issues/217#issuecomment-6478302812) on PR #219 exact `ce6846021056ef5f89f8009ceeccec58c359d745` PASS `P0/P1/P2=0/0/2`; explicit [Architecture Owner authorization](https://github.com/kaicreator-mm/shun-assistant/issues/217#issuecomment-6478493811), GitHub version-only merge `7a4d498...` and real freeze record at `3358080bd...`. **Do not repeat L2 review or alter frozen L2 blob.** Two retained P2 are future hard gates: (1) T04/T11 selected C→Shun Host fake-HTTP tests prove per-call `maxOutputTokens`, `deadlineUnixMs`, status truthfulness `completed/refused/failed/unknown`, one sender, original approval/UNKNOWN_COST; (2) T09/T11/V01 trusted app gateway before `DomainApp.send` with bad→valid same stable Case and zero send/journal on bad input.

**D. DAG / Scaffold (R1 BLOCK → R2 candidate)**: [Independent DAG R1](https://github.com/kaicreator-mm/shun-assistant/issues/218#issuecomment-6478737511) at real frozen L2 checkpoint returned `P0/P1/P2=0/1/1 BLOCK` (no DAG topology/write-set failure). A bounded new planning PR updates only T04/T11/V01 Task Pack hard acceptance (per-call limits/deadline, non-authorizing request ID, honest refused/failed/unknown status and zero-paid tests) and binds machine DAG metadata/handoff to actual L2 Owner Freeze. Independent **new-exact-SHA DAG R2** and separate DAG Owner Freeze remain mandatory; [Task DAG](TASK-DAG-v0.3-R0.md), [Task Packs](TASK-PACKS-R0.json), [Scaffold Layout](SCAFFOLD-LAYOUT.md) remain planning only. Materialize 14 native GitHub Task Issues + 22 native `blocked_by` edges and read back; **without native-write/readback, HOLD all dispatch**. Do not split a second parallel mini-DAG merely to generate Scaffold. The first local Builder only gets **T00**.

**E. Local Builder**: after native T00 READY and accepted single CAS Claim, pin Git-only DH v0.10.3 tag `061376f4a023070f215f9feffad5c24d96d503cb` (tree `099cdc...`), build/pack four public workspace packages locally with SHA256 receipts (never install nonexistent npm v0.10.3), then generate `packages/domain-computer`, `packages/domain-host`, `packages/domain-app` scaffold using T00 exclusive manifest files, verify Node24 with selected SDK public exports, scoped tests and negative checks, create PR target `version/v0.3.0`, obtain required review. After T00 real integration, parallel release T01–T08 across disjoint directories, with their own current valid Claims. No local Agent may claim all tasks in one giant overlapping branch.

**F. Integration**: T09 API/BUILD and T10 UI in parallel after predecessors. Upstream [DH #1437](https://github.com/kaicreator-mm/domain-harness/issues/1437) remains a known raw-send poisoned stable-Case problem: T09 implements one existing trusted API source/Case gateway and validates malformed/stale/forged intent *before calling* DomainApp.send. T11 must not expose raw facade; V01 requires invalid-then-valid same-Case fake/real selected-K denial proof with `facade.sendCallCount=0` and zero K Effect Journal on bad input. **No generic Kernel recovery fix is claimed.** T11 alone owns central exports, existing `server.ts`/`app.js` and lockfile. V01 real selected SDK consumer, Windows Host, DeepSeek CN/EN as required, guided forms, feedback/Shadow, signed JIT, Recipes and failures; R01 independent RQ. v0.2 accepted source differences must reconcile at actual final integration. No v0.3 main merge/tag without explicit RQ.

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

**Independent DAG R2 reviewer trigger (current corrected PR exact SHA when published):** `按 ADS v4.18 #1241，独立只读审核 shun-assistant #218 的 DAG R1 P1/P2 修复。检查当前修复 PR exact HEAD：保留冻结 L2 blob 8c555aff66d3006a1dbd4fb523e350f70c5db490；T04/T11/V01 必须对每次 maxOutputTokens/deadlineUnixMs 超限或过期拒绝且零 HTTP，requestId 不自授权，completed/refused/failed/unknown 不能互相误报；保留原 DeepSeek exact-body 预算审批和 K UNKNOWN_COST。Task Pack/DAG/交接元数据明确 L2 R2 PASS 0/0/2、Owner Freeze；14 Task/22 边/44 写集无变更。输出 P0/P1/P2、PASS/BLOCK、DAG_FREEZE_READY；写回 #218。只读，无 DAG Freeze/Claim/main/v0.2/paid 调用。`

**Independent L2 R2 reviewer trigger:** `按 ADS v4.18 #1241，独立只读审核 shun-assistant PR #219 当前最新精确 HEAD，核验 R1 P1 U03 和 P2 thinking 已由 DH 选定 llm.openai.generate C 静态 domain-harness-openai-host.generate 接入原 Shun TrustedCloudInterpreter/TrustedDeepSeekTransport，同一 exactRequestBytes Buffer 贯穿 ledger reserve→markMayHaveSent→fetch，thinking:disabled。新增核对 SDK Git tag v0.10.3@061376f4a023070f215f9feffad5c24d96d503cb/tree099cdc831aef63befd62aaede7e7a853d1be468f 的 CONDITIONAL Git-only 发布、不存在 npm v0.10.3、T00 tag pack/install，及 DH #1437 由 T09 可信 pre-send Case gateway 阻断错误输入污染 K Journal（原始异常 Case 恢复仍不合格）。核验 U01/U02/冻结 Product 不回归，输出 P0/P1/P2、PASS/BLOCK、L2_FREEZE_READY，写回 #217/PR #219，只读不合并不付费。`

**Independent L2 R1 (only after Product Freeze):** `审查 shun-assistant L2 R0 当前 PR exact HEAD；核验 frozen Product 精确 blob/适用性、U01–U03、公开选定 SDK 路由、State/Journal 所有权、三包最小 scaffold、数据迁移/Windows Host/隐私成本。P0/P1/P2、PASS/BLOCK、L2_FREEZE_READY。只读。`

**Independent DAG R1 (only after L2 Freeze):** `审查 shun-assistant v0.3 TASK-DAG 和 TASK-PACKS exact HEAD；14 nodes/22 edges、冲突写集、Agent/WEB/CI/LOCAL 路由、T00 scaffold 合法准入、8 平行 lanes、native Issue Dependencies planned vs actual、V01/R01 Gate。输出 PASS/BLOCK、DAG_FREEZE_READY，不改源码、不自行物化未冻结 Task。`

## Stop/return contract

Every Agent response should include `STAGE`, `SOURCE_SHA`, `ROLE`, `TASK_ID`, `CLAIM_CURRENTNESS`, `NATIVE_DEPENDENCIES`, `ACTUAL_TEST_EXIT`, `REVIEW`, `BLOCKERS`, `GITHUB_URL`. No cost estimate, fake PASS or unbounded negative testing. If Host physical execution required, provide a **single minimum local trigger**, not repeated Windows CI.
