# shun-assistant — 项目与 DKE 领域范围分析 R0

> 日期：2026-11-10；状态：**SCOPE_CANDIDATE / DOCUMENTATION_AND_SOURCE_SAMPLE / NOT_KNOWLEDGE_QUALIFIED**。  
> 分支：`dke/domain-scope-r0`；从 `main@217364b0c308e6089ea884ef7cb84eda752f7102` 创建。业务/产品版本权威不因本研究分支改变。
>
> 本文用于建立后续知识抽取准备清单。已核对主要产品资料及一份代表性真实业务源码，不构成全仓逐行审计、完整源清单、独立领域专家认证、Element Freeze 或 DIS Package 资格声明。项目文档里的“应当”与源码中的“当前实现”必须区别。

## 一、项目定位与核心任务

- **产品/领域主题**：目标驱动的软件能力选择与受限计算机操作。
- **主要使用者**：希望以目标方式完成 Windows/软件操作的终端用户、可管理 Provider 的技术支持人员。
- **用户任务闭环**：User Goal → Capability → Provider → Environment → 授权与预览 → Action Execution → Verification → Recovery/Lifecycle。
- **版本/事实注意事项**：**重要时序**：当前 main README 仍写 v0.1 初始化，不代表活跃 v0.3；真实 v0.3 产品裁定及 R04 修改需追踪 Issue #259、#273、#404、PR #272、具体版本/Writer SHA。本 R0 以 main 固定分支快照形成范围候选，不能称 v0.3 实现全审。
- **相关代码和模块**：
- packages/{contracts,resolver,authorization,workflow}/（意图、能力、选择与规则）
- packages/{executor-windows,vertical-image,vertical-storage,vertical-support,vertical-jit}/（受限执行适配）
- packages/workflow/src/kernel.ts（状态机、重试、效果 Journal）
- apps/control-api/、apps/control-ui/（面向用户的适配和交接）

## 二、涉及领域与候选子领域

### 1. 目标与 Capability 模型

GoalContract、用户约束、能力类别、输入条件、预期效果和验收条件。

DKE 暂定为一个候选职责 Context；要用独立 CQ、所有权、来源和反例决定后续是否拆成 Element 或仅保留 Graph Record。

### 2. Provider/环境选择

工具提供商能力、环境支持、版本、风险、可用性与降级。

DKE 暂定为一个候选职责 Context；要用独立 CQ、所有权、来源和反例决定后续是否拆成 Element 或仅保留 Graph Record。

### 3. 用户批准和执行边界

行动计划、授权/身份、Effect 可验证性、风险级别与拒绝条件。

DKE 暂定为一个候选职责 Context；要用独立 CQ、所有权、来源和反例决定后续是否拆成 Element 或仅保留 Graph Record。

### 4. 恢复、纠错与软件生命周期

执行结果、状态重建、不可确定副作用的重新确认、软件安装/修复/管理生命周期。

DKE 暂定为一个候选职责 Context；要用独立 CQ、所有权、来源和反例决定后续是否拆成 Element 或仅保留 Graph Record。

## 三、应纳入知识固化范围

- Concept：Goal、Capability、Provider、ExecutionEnvironment、ActionPlan、Authorization、EffectReceipt、Recovery。
- Rule：风险与批准要求；执行前 currentness、重复/过期、无法确认副作用时 fail-closed；状态转移与恢复策略。
- Practice：目标澄清、最小权限、预览和实际结果验证、出现未知效果时先核查再重试。
- Case：Provider 不可用、授权过期、同一 Effect 重放、操作执行成功但用户目标未满足。

来源状态要区分 `PROJECT_POLICY`（产品规范）、`IMPLEMENTATION_BEHAVIOR`（已实现代码行为）、`EXTERNAL_DOMAIN_CLAIM`（外部资料提出的主张）、`OBSERVED_CASE`（真实案例）、`LLM_DERIVED_CANDIDATE`（待审推论）。不能将内部规则或合成测试直接转成广泛领域事实。每个知识候选至少记录：ID、Scope、Source SHA/Locator、适用对象/版本/地区、断言、证据、反例、冲突、UNKNOWN、审查决定及变更失效关系。

## 四、排除或外部权威

- Windows SID/LocalAppData、Node SQLite、Tauri 等是宿主/安全实现决策，不能单凭源码归纳成所有操作系统通用规则。
- 不限授权的 GUI 自动点击不属于当前能力；LLM 无 OS 权限，不得从生成计划直接授予真实物理操作。
- 当前 R04 代码/安全模型必须由活跃版本 PR 验证，不能从历史 main 默认推断。

## 五、原始证据入口（同一个 main 精确提交）

- [`README.md`](https://github.com/kaicreator-mm/shun-assistant/blob/217364b0c308e6089ea884ef7cb84eda752f7102/README.md)
- [`docs/product/PRD-v0.1.md`](https://github.com/kaicreator-mm/shun-assistant/blob/217364b0c308e6089ea884ef7cb84eda752f7102/docs/product/PRD-v0.1.md)
- [`packages/workflow/src/kernel.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/217364b0c308e6089ea884ef7cb84eda752f7102/packages/workflow/src/kernel.ts)
- [`packages/contracts/`](https://github.com/kaicreator-mm/shun-assistant/blob/217364b0c308e6089ea884ef7cb84eda752f7102/packages/contracts/)
- [`packages/resolver/`](https://github.com/kaicreator-mm/shun-assistant/blob/217364b0c308e6089ea884ef7cb84eda752f7102/packages/resolver/)
- [`packages/authorization/`](https://github.com/kaicreator-mm/shun-assistant/blob/217364b0c308e6089ea884ef7cb84eda752f7102/packages/authorization/)
- [`apps/control-api/src/`](https://github.com/kaicreator-mm/shun-assistant/blob/217364b0c308e6089ea884ef7cb84eda752f7102/apps/control-api/src/)
- [外部记录](https://github.com/kaicreator-mm/shun-assistant/issues/259)
- [外部记录](https://github.com/kaicreator-mm/shun-assistant/issues/404)

**真正直接检查的源码锚点**：[`packages/workflow/src/kernel.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/217364b0c308e6089ea884ef7cb84eda752f7102/packages/workflow/src/kernel.ts)；Git Blob `eee1a8ac18a12fa4275ace3fd94a6ef4a2384551`。其余入口需要后续逐个核查及建立证据清单；并未声称所有源码文件已检查。

### 跨项目知识权威边界

- xDownload 可作为限定下载任务的 Provider/能力，但下载范围授权和成员资格仍由 xDownload 自己决定。
- DomainHarness 作为运行机制，不自动拥有 Shun 软件操作的业务语义。

## 六、候选 Competency Questions（不是已通过测试）

1. **CQ1** 给定用户目标和环境，如何证明确有符合约束且可验证的 Provider？
2. **CQ2** 风险动作启动前应满足哪些授权、当前性与身份条件？
3. **CQ3** 外部操作已执行但确认回执丢失时如何安全恢复，何时保持 UNKNOWN？
4. **CQ4** 运行时状态机的约束与普遍性软件操作实践应如何分别标注来源？

每题需准备正例、错误来源、过期/冲突版本、漏掉横向关系或不当归属的反例。只有定位来源并验证实际结论后，才能从 candidate 晋升；结构检查绿灯不能替代语义审查。

## 七、待调查事实与执行顺序

- 需基于 active v0.3 PRD、Issue、WIP 版本和真实启动入口做第二轮权威校准。
- 目前不能以这份 main 分支研究文件证明正式 Windows Guided 用户旅程已达 RQ。

- **SC01 — 版本校准**：绑定当前有效 Product/L1、实际业务开发分支和 exact SHA，区分历史 README。
- **SC02 — 全源清单**：枚举领域模型、规则、核心算法、外部资料、业务案例、相应测试；按可访问/可传播权限分类。
- **SC03 — 规则对齐**：PRD↔源码↔测试标记 MATCH / DOC_ONLY / CODE_ONLY / CONFLICT。
- **SC04 — 独立语义审查**：复查词汇、Source/Claim、例外、反例和不确定范围。
- **SC05 — DKE 建模**：再选择合适的 Context/Global/Recursive Element 拆分策略，检查组合和增量变化。
- **SC06 — 消费准入**：仅将已资格化、具体消费者需要的子图映射到 DIS/DomainHarness，不急于生成 Package。

`FULL_CODE_REVIEW=NOT_RUN` / `INDEPENDENT_DOMAIN_ORACLE=NOT_RUN` / `KNOWLEDGE_GRAPH=NOT_BUILT` / `SAP_QUALIFIED=NO` / `ELEMENT_FREEZE=NO` / `PACKAGE=NOT_GENERATED`。

研究归档留在该项目 Git 分支；DKE 方法与 Demo 单一进度源仍由 [domain-forge #209](https://github.com/kaicreator-mm/domain-forge/issues/209)、Product 范围候选 [#207](https://github.com/kaicreator-mm/domain-forge/issues/207) 维护，不建立新的竞争性知识真相。
