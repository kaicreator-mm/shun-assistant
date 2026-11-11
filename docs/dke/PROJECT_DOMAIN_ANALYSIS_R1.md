# shun-assistant — DKE 项目与领域分析 R1：当前版本校准与知识候选

> **2026-11-10 / BOUNDED_SOURCE_AUDIT / NOT_SEMANTICALLY_QUALIFIED**。研究分支 `dke/domain-scope-r0` 起点 `main@217364b0c308e6089ea884ef7cb84eda752f7102`；原始 [R0](PROJECT_DOMAIN_ANALYSIS_R0.md) 不改写。  
> **关键权威偏移**：活跃业务主语 `version/v0.3.0@91420edca44009aa2c984c876104b40814a7c265`；PR #272 Draft HEAD dd8ce9251fb617200826827ebbc8fcbb57290959。R0 main 的历史叙述**不能覆盖**该版本事实。本次未进行完整源码扫描、没有实机执行或独立专业认证。
>
> 本研究探讨 **软件操作 Capability/Provider 选择、授权、效果确认与恢复** 的可固化知识，不能把软件或 OS 的具体实现等同于通用知识定理。

## 1. 版本及来源权威

1. [权威/Review/产品资料](https://github.com/kaicreator-mm/shun-assistant/issues/259)。
2. [权威/Review/产品资料](https://github.com/kaicreator-mm/shun-assistant/issues/404)。
3. [权威/Review/产品资料](https://github.com/kaicreator-mm/shun-assistant/pull/272)。

下列源文件以已核对的活跃版本 commit 固定。它们用于**代码事实与既有测试定义审计**，不是本轮实际动态执行的凭证：

| 证据角色 | 精确源文件 | 源 Git Blob | 相对版本 |
| --- | --- | --- | --- |
| 版本业务代码 | [`apps/control-api/src/main.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/version/v0.3.0/apps/control-api/src/main.ts) | `b86f791d7823c206b438ef7c5b91cb57c6a30187` | `version/v0.3.0` |
| 版本业务入口 | [`apps/control-api/src/server.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/version/v0.3.0/apps/control-api/src/server.ts) | `b5f22ce4189eb851b78509a9ec7a34dee5bb728d` | `version/v0.3.0` |
| 集成测试 | [`tests/integration/v03/t11-runtime/real-kernel-permit.test.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/version/v0.3.0/tests/integration/v03/t11-runtime/real-kernel-permit.test.ts) | `d1f57bebf6a0896fea23938f277ce7e752f91498` | `version/v0.3.0` |

## 2. 领域范围、知识归属及外部依赖

| 领域 Context | DKE 候选知识 | 事实归属/适用边界 |
| --- | --- | --- |
| 用户目标与能力知识 | Goal/Capability/Provider/Environment：能力适用、前提及缺失时的降级 | Shun 业务领域（不是 KDP 通用运行规则） |
| 授权与效果 | Risk Class/Authorization/Permission/Receipt：用户目标与执行效果必须独立验证 | Shun Controller + Host 事实，OS 执行安全仍依赖真实宿主 |
| 有界 Workflow 与恢复 | 执行生命周期、持久回执、不确定动作、重试和恢复决定 | Shun 业务结果与 Kernel 执行机制区分 |
| 首次运行可信自举 | 每交互用户 %LOCALAPPDATA%/Shun/authority/guided-provenance 的可信锚，以及 UAC/账户边界 | v0.3 特定 Windows 产品决策，不应泛化为所有系统普遍权威 |

上下文不能机械映射为 Element/Function；领域图可以有跨 Context 关系，但 Runtime 执行权限、OS 效果和 Package 依赖必须按对应原生契约另行审核。状态与适用范围随版本变化需具备局部失效能力。

## 3. 待抽取的具体主张、来源类型及可证伪反例

| ID | 候选主张 | 来源属性 | 证据定位 | 负例/失败 |
| --- | --- | --- | --- | --- |
| SH-01 | main README 的 v0.1 初始化不是 v0.3 真相 | SOURCE_AUTHORITY | main README vs Issue #259 + version/v0.3.0 | 从 main 读取缺失 gateway 并断言所有 v0.3 都不可用 |
| SH-02 | v0.3 默认 Control API 的 selected gateway 装配曾被 #259 指出 BLOCK；v0.3 风险必须以当前 Draft PR #272 再核 | KNOWN_REVIEW_GAP | Issue #259 F01/F02 和版本 API main.ts/server.ts | 有一份 v0.3 集成测试就宣布真实用户 Guided 完整 |
| SH-03 | Permit 和 K→C Effect 接口受限制，但集成测试写明授权/OS/Executor 用 fake、零真实副作用 | TEST_SCOPE | real-kernel-permit.test.ts | 把测试被模拟的 Host 当成真 Windows 物理授权 |
| SH-04 | LocalAppData 信任自举是 per-user setup，运行时应 verify-only；切账户 UAC 需避免错配 | PROJECT_POLICY | Issue #404 owner decision | 将 ADMIN 的 LocalAppData 信任下沉到交互用户并宣称安全 |

这些只分别代表 `SOURCE_AUTHORITY`、`KNOWN_REVIEW_GAP`、`TEST_SCOPE`、`PROJECT_POLICY`、`IMPLEMENTATION_BEHAVIOR` 或 `EXTERNAL_DOMAIN_CLAIM_CANDIDATE` 的研究分类，**不是已批准 DKE Schema Enum**。尤其要单独记录 `CodeReviewed`、`TestDefined`、`TestActuallyExecuted`、`ProfessionalOracle` 和 `PhysicalEffect`，绝不混并为单个 PASS。

## 4. Competency Questions 与反例验证

| CQ | 目标查询 | 负例或 UNKNOWN 约束 |
| --- | --- | --- |
| CQ-01 | 某能力能否在当前版本/Provider/OS 环境达成用户目标？ | 注册 Provider 却不可运行或返回 UNKNOWN |
| CQ-02 | 签名/当前性/批准不成立的动作有哪些可观察拒绝？ | 模板执行却没有授权/真实效果读回 |
| CQ-03 | 丢失回执和需恢复的副作用是否可单靠 Workflow 自身声明完成？ | 物理副作用无法确认时必须 NEEDS_INTERVENTION |

每个候选 Claim 需具备 exact SourceLocator、适用对象/版本、关系 owner、否证条件、可信来源审查与消费者失效清单；结构测试成功不能替代语义/外部证据。

## 5. 下一阶段最小补全清单

1. **SC01 首要**：冻结研究输入的 active v0.3 与 Draft WIP 两个精确提交，在 #272 变更后重新读取 G1/G2/User Journey 的有效行为。
2. 完整映射 Goal/Capability/Authorization/Host/Registry 规则与负例，并标注哪些是产品政策、实现事实或未证明的宿主效果。
3. 源先行独立审查 SCOPE；不得在本次研究分支上主动改变任何真实 Windows 物理操作。

**当前收据的上限**：`R1_DOC_SOURCE_SAMPLE=YES` / `ACTIVE_VERSION_POINTER_RECHECK=YES` / `FULL_SOURCE_INVENTORY=NOT_RUN` / `LIVE_DEVICE_OR_OS_EFFECT=NOT_RUN` / `DOMAIN_ORACLE=NOT_RUN` / `KNOWLEDGE_GRAPH=NOT_BUILT` / `ELEMENT_FREEZE=NO` / `DIS_PACKAGE=NOT_GENERATED`。

仍通过 [domain-forge #209](https://github.com/kaicreator-mm/domain-forge/issues/209) 统一协调 DKE Demo 证据，文档仍由各产品分支管理，不创建二次业务事实源。
