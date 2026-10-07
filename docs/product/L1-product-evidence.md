# Shun v0.1 — L1 Product Evidence

## Evidence posture

This document is the canonical summary of Product/L1 evidence used to justify the PRD candidate. The raw research workbook is an external supporting archive; it is not Product authority.

For exact-SHA auditability, `docs/research/source-evidence-manifest-v0.1.tsv` materializes all 500 DirectNeed/source-record units used by R1–R5 with round, source-record ID, coded summary, capability/domain coding, and source URL. This manifest is part of the GitHub candidate authority for provenance/traceability; the external workbook remains supporting raw research.

- Pilot: **134 coded evidence atoms**
- R1–R4: **2,000 coded evidence atoms**
- R5 software-review round: **500 coded evidence atoms**
- Total supporting archive: **2,634 coded evidence atoms**

R1–R4 use 400 source-record units encoded across five analysis dimensions. They are purposefully stratified/adversarial exploratory samples, not 400 independent users and not a random population sample.

## Supported conclusions

1. Users commonly express goals, symptoms and constraints rather than application click sequences.
2. Capability-first decomposition frequently maps a goal to multiple possible Providers.
3. Human UI usability and Agent usability are distinct.
4. Software lifecycle is part of the user problem, not merely implementation detail.
5. System maintenance benefits from evidence-driven stewardship rather than generic cleanup buttons.
6. Many file/document/media workflows are deterministic and composable without visual UI.
7. Environment resolution matters when the local machine is incompatible.
8. Stable UI-heavy counterexamples concentrate where the core work itself requires continuous visual/spatial/creative judgment.

## Non-claims

- No population-wide 80%/90% UI-free claim is made.
- No market-share, willingness-to-pay, retention, or population-frequency claim is made.
- Windows-specific Store/driver/OneDrive/device truth is not established by exploratory sampling.
- Product Freeze is not implied.

## Methodology

| Field | Definition_or_Note |
| --- | --- |
| Dataset | AI Computer Assistant - L1 Product Evidence / Four-Round Exploration |
| Snapshot date | 2026-10-07 |
| Pilot | 134 evidence atoms；用于建立初始 taxonomy、字段与六类来源框架。 |
| Four-round extension | R1–R4 各 500 coded evidence atoms，共 2,000 atoms。 |
| Source-record units | 四轮共 400 个 source-record units；每轮 100。它们不是 400 个独立用户。一个真实页面可以在有多个可独立编码需求/约束/结果时贡献多个 source-record units，并共享同一 Source_URL。 |
| Atom coding | 每个 source-record unit 固定编码 5 个 atom：DirectNeed、Friction、Constraint、DesiredBehavior、CapabilityInference。 |
| Frequency rule | 需求分布、UI-free、Lifecycle、Risk 等频率只按 DirectNeed/source-record unit 统计；绝不把 5 个 atom 当成 5 个用户需求。 |
| DirectNeed | 来自用户原始问题或来源中明确可见的需求/结果/限制的中文释义。 |
| Friction | 分析编码：用户为完成目标额外承担的软件选择、学习、配置、排障或重复操作成本。 |
| Constraint | 分析编码：隐私、数据安全、离线、兼容性、成本、硬件、保留数据等约束。 |
| DesiredBehavior | 产品推断：电脑助手在该需求下应怎样吸收复杂性。 |
| CapabilityInference | 产品推断：把需求映射到稳定 capability 及推荐执行路径。 |
| Sources | Reddit；Microsoft Q&A；Windows Feedback/Insider public signals；Microsoft Support；Bilibili/YouTube tutorial demand；software reviews (AlternativeTo). |
| Round 1 | 故障/支持切片：偏 Reddit tech support 与 Microsoft Q&A，用于验证系统/设备诊断与 repair DAG。 |
| Round 2 | 普通任务/软件切片：提高软件选择、文件、PDF、媒体、批处理、OCR 等，用于验证 Capability Resolver 与多工具组合。 |
| Round 3 | Stewardship 切片：更新、驱动、睡眠、搜索、存储、加密等长期状态，用于验证历史/last-known-good/持续维护。 |
| Round 4 | GUI-heavy 对抗切片：故意加入 CAD、3D、视频创作、scanner、legacy、remote 等，用于寻找 UI-last 的失败边界。 |
| UI_Free_Feasibility = High | 分析判断：任务主路径存在或很可能存在稳定 CLI/API/library/OS API/文件格式/脚本组合/远程环境路径，可避免视觉 Computer Use。不是执行基准测试。 |
| UI_Free_Feasibility = Medium | 确定性步骤大多可机器接口完成，但任务仍需要视觉预览、物理设备确认、OEM/legacy UI 或用户主观判断。 |
| UI_Free_Feasibility = Low | 任务核心本身高度依赖持续视觉/空间/创意交互，例如复杂 CAD 学习/建模、3D 创作、视频时间轴审美。低并不表示周边安装、转码、导出、环境处理必须走 UI。 |
| Four-round designed-slice aggregate | 400 source-record units：UI-free High 322 (80.5%)；Medium 68 (17.0%)；Low 10 (2.5%)。仅描述这四个目的性切片。 |
| Lifecycle aggregate | High 266 (66.5%)；Medium 96 (24.0%)；Low 38 (9.5%)。表明大量问题需要跨任务保存软件/设备/环境状态。 |
| Risk aggregate | High 93 (23.3%)；Medium 167 (41.8%)；Low 140 (35.0%)。高风险执行必须 plan/preview/backup/verify。 |
| Collection strategy | Purposeful + stratified + adversarial exploratory sampling。四轮刻意使用不同切片对冲单一社区偏差，并在 R4 主动寻找反例；不是随机抽样。 |
| Copyright/data handling | 保存简洁中文释义/归纳，不复制长篇用户原文；保留 Source_URL 供复核。 |
| Known bias | Windows/英语社区权重较高；Reddit/Q&A 过度代表主动求助和严重故障；教程代表主动搜索；软件评论过度代表强烈体验；一些官方来源是聚合/标准流程而非第一人称用户记录。 |
| Interpretation rule | 本数据集适合发现需求簇、产品边界和验证假设，不可直接推断总体市场发生率、用户人口分布或真实 UI-free 成功率。 |
| Product hypothesis tested | Goal-first + Capability-first + Agent-friendly-provider-first + UI-last；用户管理目标，Agent 管理软件与计算环境。 |
| Strong convergence | 多轮共同支持：Provider 选择本身是任务；软件/系统生命周期需要维护；批处理和转换适合 deterministic tools；系统诊断应 evidence-driven；本机不适合时应解析到 RunX/远程/legacy 环境。 |
| True UI boundary | 真正稳定的反例集中在创作本身：复杂 CAD/3D、视频时间轴、构图等。推荐模式是 Guide/Co-pilot，而不是强求 100% 自动。 |
| Next validation stage | 建立真实执行 benchmark：从各 cluster 抽任务，实际运行 Capability Resolver → Provider → Environment → Execute → Verify，测 UI-free task completion rate、首次成功率、用户确认次数和故障恢复率。 |
| Next sampling stage | 若要估计总体占比，必须定义目标人群与采样框，按来源/语言/用户类型加权采样并做去重；不能继续用目的性案例直接算总体比例。 |
| R5 extension | 新增 500 coded evidence atoms：20 个代表性软件 × 5 个 review-theme units × 5 个编码 atom。 |
| R5 unit of analysis | Review-theme unit：来自一个软件评论页中的独立主题（如性能、易用性、CLI/automation、许可/信任、稳定性等），不是独立评论者。 |
| R5 purpose | 专门验证 Provider Resolver：什么样的软件对 Agent 更容易可靠使用，同时普通用户又更容易接受/信任。 |
| R5 interpretation | R5 不用于估计普通用户任务发生率，也不与 R1–R4 的 task/source-record aggregate 直接混算。 |
| R5 key implication | Human UI usability 与 Agent usability 必须分开建模；一个对人难学但 CLI/API 强的软件，可能是 Agent 最优 Provider。 |
| Dataset total after R5 | Pilot 134 atoms + R1–R4 2,000 atoms + R5 500 atoms = 2,634 coded evidence atoms。 |
| Post-R5 next stage | L1 product decisions + Provider Resolver v0.1 + MVP Capability Map + 36-task execution Benchmark 已固化到同一工作簿。 |
| Benchmark purpose | 把“UI-last/Agent-friendly Provider”从探索性证据转成可执行验证：实际测 task success、UI-free、用户确认次数、rollback、provider ranking。 |
| Benchmark minimum release signal | P0 task 首次成功率、UI-free task rate、错误恢复、风险 gate 和 verification 必须以真实执行数据填充；当前表中的 UI-free target 是目标，不是结果。 |

## Cross-round summary

| Four-round designed evidence summary |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- |
| Metric | R1 Fault/Support | R2 Tasks/Software | R3 Stewardship | R4 GUI-heavy adversarial | Designed-slice aggregate |
| Evidence atoms | 500 | 500 | 500 | 500 | 2000 |
| Source-record units | 100 | 100 | 100 | 100 | 400 |
| UI-free High | 90 / 100 (90%) | 93 / 100 (93%) | 95 / 100 (95%) | 44 / 100 (44%) | 322 / 400 (80.5%) |
| UI-free Medium | 10 / 100 (10%) | 7 / 100 (7%) | 5 / 100 (5%) | 46 / 100 (46%) | 68 / 400 (17.0%) |
| UI-free Low | 0 / 100 (0%) | 0 / 100 (0%) | 0 / 100 (0%) | 10 / 100 (10%) | 10 / 400 (2.5%) |
| Lifecycle High | 85 / 100 (85%) | 46 / 100 (46%) | 94 / 100 (94%) | 41 / 100 (41%) | 266 / 400 (66.5%) |
| Risk High | 34 / 100 (34%) | 32 / 100 (32%) | 27 / 100 (27%) | 0 / 100 (0%) | 93 / 400 (23.3%) |
|  |  |  |  |  |  |
| Interpretation |  |  |  |  |  |
| R1 | 故障/支持切片 | System/Devices 高占比 | 验证自动诊断与 repair DAG |  |  |
| R2 | 普通任务/软件切片 | Files/Software/Media/Documents 上升 | 验证 Capability Resolver、多工具组合与软件生命周期 |  |  |
| R3 | 长期维护切片 | System/Devices/Lifecycle 高 | 验证 last-known-good、更新/驱动历史与 Stewardship |  |  |
| R4 | GUI-heavy 反例切片 | Media/Environment/Documents；Medium/Low UI-free 显著上升 | 验证 UI-last 的真实边界：创作核心保留 UI，周边步骤仍无 UI 化 |  |  |
|  |  |  |  |  |  |
| Aggregate domain | Count | Share |  |  |  |
| System | 98 | 24.5% |  |  |  |
| Devices | 57 | 14.3% |  |  |  |
| Media | 51 | 12.8% |  |  |  |
| Software | 41 | 10.3% |  |  |  |
| Documents | 37 | 9.3% |  |  |  |
| Files | 33 | 8.3% |  |  |  |
| Environment | 30 | 7.5% |  |  |  |
| UX | 22 | 5.5% |  |  |  |
| Data | 14 | 3.5% |  |  |  |
| Security | 13 | 3.3% |  |  |  |
| Network | 4 | 1.0% |  |  |  |
|  |  |  |  |  |  |
| Aggregate source group | Count | Share |  |  |  |
| Reddit | 240 | 60.0% |  |  |  |
| Microsoft Q&A | 80 | 20.0% |  |  |  |
| Feedback/Insider | 20 | 5.0% |  |  |  |
| Microsoft Support | 20 | 5.0% |  |  |  |
| Tutorial demand | 20 | 5.0% |  |  |  |
| Software reviews | 20 | 5.0% |  |  |  |
|  |  |  |  |  |  |
| Most recurring capabilities | Count | Reading |  |  |  |
| system.explorer_search.diagnose_optimize | 25 | 需要按领域继续细分与实测 |  |  |  |
| environment.legacy_app.run | 17 | 需要按领域继续细分与实测 |  |  |  |
| device.bluetooth.diagnose_repair | 15 | 设备/驱动适合版本感知的诊断与修复 |  |  |  |
| system.usability.adapt | 14 | 需要按领域继续细分与实测 |  |  |  |
| system.performance.diagnose | 13 | 需要按领域继续细分与实测 |  |  |  |
| device.driver.diagnose_repair | 12 | 设备/驱动适合版本感知的诊断与修复 |  |  |  |
| system.storage.diagnose | 12 | 存储/空间是稳定高频问题，需解释+维护而非传统清理按钮 |  |  |  |
| files.find_duplicates | 12 | 适合 deterministic tools + workflow composition |  |  |  |
| cad.model_assist | 12 | 需要按领域继续细分与实测 |  |  |  |
| data.sync.reconcile | 10 | 同步/备份需要长期状态和数据安全语义 |  |  |  |
| environment.remote_access | 10 | 需要按领域继续细分与实测 |  |  |  |
| software.app.diagnose_repair | 9 | 需要按领域继续细分与实测 |  |  |  |
| software.lifecycle.repair | 9 | 需要按领域继续细分与实测 |  |  |  |
| document.diagram.generate_edit | 9 | 适合 deterministic tools + workflow composition |  |  |  |
| software.resolve_provider | 8 | Provider/能力解析是核心产品能力 |  |  |  |
| files.search_content | 8 | 适合 deterministic tools + workflow composition |  |  |  |
| system.storage.explain_cleanup | 8 | 存储/空间是稳定高频问题，需解释+维护而非传统清理按钮 |  |  |  |
| system.power.sleep_diagnose | 8 | 需要按领域继续细分与实测 |  |  |  |
| security.bitlocker.recovery_steward | 7 | 需要按领域继续细分与实测 |  |  |  |
| document.scan.workflow | 7 | 适合 deterministic tools + workflow composition |  |  |  |
|  |  |  |  |  |  |
| Cross-round conclusion | Evidence | Implication |  |  |  |
| Goal-first 比 App-first 更贴合真实表达 | 四轮中大量 DirectNeed 都以结果/症状/约束描述，而非指定应用操作 | 入口应是对象+目标+约束；软件只是 Provider |  |  |  |
| Capability-first 比 UI-first 更稳定 | R1/R2/R3 机器接口可行性高；R4 即使 GUI-heavy，也有大量准备/转换/环境步骤可结构化 | 优先 API/CLI/library/MCP/脚本；UI 是必要时的兼容层 |  |  |  |
| 软件生命周期是独立价值 | 安装、Store、卸载残留、默认应用、旧软件、版本兼容跨轮出现 | 维护安装原因、版本、依赖、配置、last-known-good、保留/移除 |  |  |  |
| RunX 与产品方向互补 | R4 legacy/remote/旧硬件案例明确存在“本机不合适但任务仍需完成” | 把 local/remote/legacy/sandbox 当 execution environment，而非失败 |  |  |  |
| 真正 UI-heavy 的边界可识别 | 复杂 CAD/3D/视频创作在 R4 集中进入 Medium/Low | 对这些场景做 Guide/Co-pilot；不强求全自动 |  |  |  |
|  |  |  |  |  |  |
| Critical caveat | 这 400 个 source-record units 是目的性分层/对抗采样，且部分页面拆成多个独立 signal；不是 400 个独立用户，也不是随机总体样本。 | Aggregate UI-free 数值只描述这四个设计切片，不能宣称普通用户总体比例。 |  |  |  |
|  |  |  |  |  |  |
| R5 — Software Reviews Focus |  |  |  |  |  |
| Metric | Value | Interpretation |  |  |  |
| Evidence atoms | 500 | 20 软件 × 5 review-theme units × 5 编码 atom |  |  |  |
| Review-theme units | 100 | 不是 100 个独立评论者；来自 20 个代表性软件评论页的 100 个独立评论主题/产品信号 |  |  |  |
| UI-free High | 60 / 100 (60%) | 大量软件核心能力存在 CLI/API/library/batch/headless 路径 |  |  |  |
| UI-free Medium | 30 / 100 (30%) | 通常为 GUI-first 软件，但确定性子能力仍可自动化 |  |  |  |
| UI-free Low | 10 / 100 (10%) | 主要集中在 Blender/Kdenlive 等创作核心本身 |  |  |  |
|  |  |  |  |  |  |
| R5 conclusion | Evidence | Provider Resolver implication |  |  |  |
| Human UI usability ≠ Agent usability | Strong | FFmpeg/MPV/7-Zip/FreeCAD 等可对人有学习门槛，但机器接口强，适合作为后台 Provider |  |  |  |
| Provider score needs more than features | Strong | 加入 Reliability / Agent Usability / Trust / Resource Cost / Installability / Batchability / Interaction Complexity |  |  |  |
| More powerful is not always better | Strong | 低频/单一任务优先最小满足 Provider，避免不必要安装体积、学习成本和高风险能力 |  |  |  |
| Trust is a first-class dimension | Strong | 开源/免费不等于自动可信；需要来源、签名、安装器历史、更新行为、许可和维护状态 |  |  |  |
| Aggressive cleanup needs stronger safety | Strong | 卸载/清理 Provider 必须结合 provenance、dry-run、rollback 和用户资产保护 |  |  |  |
|  |  |  |  |  |  |
| Recommended Provider Score |  | Capability Fit × Reliability × Agent Usability × Trust × Environment Compatibility × Performance ÷ Interaction Complexity |  |  |  |
| Recommended Agent Usability fields |  | CLI/API/library/MCP; structured I/O; batch; headless; deterministic; portable; installability; version stability; observability; validation fixtures |  |  |  |
| Recommended Human-friction fields |  | learning curve; UI complexity; subscription/ads; install friction; resource/startup cost; confusing defaults; privacy/cloud dependence |  |  |  |
|  |  |  |  |  |  |
| R5 caveat | Software-review focused purposeful sample | 用于建立 Provider 评分模型，不与 R1–R4 的普通任务发生率直接合并计算 |  |  |  |
