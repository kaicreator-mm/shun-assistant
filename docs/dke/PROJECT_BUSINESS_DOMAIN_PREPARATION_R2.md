# shun-assistant — Five-stage business/domain preparation R2

> 2026-11-10 · [devkit Issue #5](https://github.com/kaicreator-mm/devkit/issues/5) · **BOUNDED BUSINESS MODEL CANDIDATE / NOT DKE QUALIFIED**. 现有 [R0](PROJECT_DOMAIN_ANALYSIS_R0.md) / [R1](https://github.com/kaicreator-mm/shun-assistant/blob/cfff7635ac2bb6ccf47e459f009f49a51888cd25/docs/dke/PROJECT_DOMAIN_ANALYSIS_R1.md) 保留。清单固定来源 `91420edca44009aa2c984c876104b40814a7c265`，参见 [SOURCE_PATH_INVENTORY_R2.json](https://github.com/kaicreator-mm/shun-assistant/blob/9457a680a799bb30a6ab2089f1b5a09d1f27d902/docs/dke/SOURCE_PATH_INVENTORY_R2.json)。**全路径/Blob 枚举 ≠ 全源内容审计 ≠ 运行/语义资格**。

## G1 — 项目目标

让 Windows 普通用户以目标提出软件操作，通过受限 Capability/Provider、授权和效果回执完成有界操作；核心是可信的首次使用和可恢复执行，而不是让 AI 自由点击整个系统。

**参与者与职责**：Windows 交互用户／Controller 目标与授权边界／Capability/Provider 注册／可信 Host/Executor／用户效果确认。

**成功判据候选**：真实用户能在明确目标/适用条件下沿业务闭环获得带来源且不虚报结果的产物；业务实际完成、专业正确性和发布资格仍需独立证据。非目标是替代现有 Product 事实源、任意共享跨产品业务真相、自动生成未经来源审核的行业结论。

## G2 — 完整业务体系候选

### 目标导向业务过程
1. 首次安装/启动建立与交互用户一致的可信 LocalAppData 身份及权限前提
2. 用户提供目标 Goal、上下文、限制条件与验收标准
3. 根据环境和 Capability Catalog 选择 Provider，解释不能执行/需要授权的原因
4. 生成预览/受限 ActionPlan，并由用户审核授权；未批准不得产生 Effect
5. 执行来自已准入 Host 的动作、记录 receipt 和实际效果验证
6. 结果未知、拒绝或局部完成时阻断盲目重试并提供安全恢复/重新授权

### 业务对象、状态/关系和所有权
- GoalContract/Capability/Provider/Environment 与适用范围
- Authorization/Permit/RiskClass/ActionPlan 人的授权与执行计划不同
- TrustedLocalAppDataBootstrap/OSUserContext 设备信任必须映射正确交互账号
- ExecutionReceipt/Effect/Observation/UnknownOutcome 实际结果与规划不同
- Recovery/Retry/Revocation 失败后不扩大权限

### 关键异常及恢复路径
- 使用管理员账户 LocalAppData 信任锚冒充另一个交互用户
- fake Host/Executor 测试 PASS 就宣布物理 Windows Effect 已执行
- Control API gateway 不可用仍宣称首次用户完整链已经通过

当来源过期或缺失、用户未批准、外部依赖失败、结果无法确认时，应保留 `UNKNOWN / NEEDS_REVIEW / BLOCKED` 与继续核查/安全恢复的明示动作，而不是自动推进至业务完成。上述模型仅对主要产品旅程的计划覆盖，不声明所有业务源和例外已被逐文件核验。

## G3 — 领域体系候选

**跨域归属纪律**：Shun 负责业务目标/Provider 选择/用户授权和结果语义，DomainHarness KDP 负责技术执行权限边界，真实 Windows Host 掌握物理效果；设备使用场景不要求跨 OS 用户隔离，per-user 本地信任自举仍须与交互身份一致。

## 2. 领域范围、知识归属及外部依赖

| 领域 Context | DKE 候选知识 | 事实归属/适用边界 |
| --- | --- | --- |
| 用户目标与能力知识 | Goal/Capability/Provider/Environment：能力适用、前提及缺失时的降级 | Shun 业务领域（不是 KDP 通用运行规则） |
| 授权与效果 | Risk Class/Authorization/Permission/Receipt：用户目标与执行效果必须独立验证 | Shun Controller + Host 事实，OS 执行安全仍依赖真实宿主 |
| 有界 Workflow 与恢复 | 执行生命周期、持久回执、不确定动作、重试和恢复决定 | Shun 业务结果与 Kernel 执行机制区分 |
| 首次运行可信自举 | 每交互用户 %LOCALAPPDATA%/Shun/authority/guided-provenance 的可信锚，以及 UAC/账户边界 | v0.3 特定 Windows 产品决策，不应泛化为所有系统普遍权威 |

上下文不能机械映射为 Element/Function；领域图可以有跨 Context 关系，但 Runtime 执行权限、OS 效果和 Package 依赖必须按对应原生契约另行审核。状态与适用范围随版本变化需具备局部失效能力。

上述 Context 是语义归属候选而非一个 Context = 一个 Element/Package；共享术语/数据引用不转移事实的拥有者；领域关系可有环，实际执行依赖 DAG 必须另行定义。

## G4 — 领域知识范围与具体 Claim 候选

## 3. 待抽取的具体主张、来源类型及可证伪反例

| ID | 候选主张 | 来源属性 | 证据定位 | 负例/失败 |
| --- | --- | --- | --- | --- |
| SH-01 | main README 的 v0.1 初始化不是 v0.3 真相 | SOURCE_AUTHORITY | main README vs Issue #259 + version/v0.3.0 | 从 main 读取缺失 gateway 并断言所有 v0.3 都不可用 |
| SH-02 | v0.3 默认 Control API 的 selected gateway 装配曾被 #259 指出 BLOCK；v0.3 风险必须以当前 Draft PR #272 再核 | KNOWN_REVIEW_GAP | Issue #259 F01/F02 和版本 API main.ts/server.ts | 有一份 v0.3 集成测试就宣布真实用户 Guided 完整 |
| SH-03 | Permit 和 K→C Effect 接口受限制，但集成测试写明授权/OS/Executor 用 fake、零真实副作用 | TEST_SCOPE | real-kernel-permit.test.ts | 把测试被模拟的 Host 当成真 Windows 物理授权 |
| SH-04 | LocalAppData 信任自举是 per-user setup，运行时应 verify-only；切账户 UAC 需避免错配 | PROJECT_POLICY | Issue #404 owner decision | 将 ADMIN 的 LocalAppData 信任下沉到交互用户并宣称安全 |

这些只分别代表 `SOURCE_AUTHORITY`、`KNOWN_REVIEW_GAP`、`TEST_SCOPE`、`PROJECT_POLICY`、`IMPLEMENTATION_BEHAVIOR` 或 `EXTERNAL_DOMAIN_CLAIM_CANDIDATE` 的研究分类，**不是已批准 DKE Schema Enum**。尤其要单独记录 `CodeReviewed`、`TestDefined`、`TestActuallyExecuted`、`ProfessionalOracle` 和 `PhysicalEffect`，绝不混并为单个 PASS。

显式区分 `PROJECT_POLICY` / `IMPLEMENTATION_BEHAVIOR` / `OBSERVED_CASE` / `EXTERNAL_DOMAIN_CLAIM_CANDIDATE` / `LLM_CANDIDATE`。知识记录至少应含 Git SHA/Blob/locator、origin/许可、Scope/Context、owner、适用版本/时间、证据、反例、未知、冲突、独立 reviewer 和下游 invalidation；框架/模型/模拟测试并非行业权威。

## G5 — DKE 抽取准备

### SC01/SC02 权威版本与全路径源清单

- 当前分析 pin：[`91420edca44009aa2c984c876104b40814a7c265`](https://github.com/kaicreator-mm/shun-assistant/tree/91420edca44009aa2c984c876104b40814a7c265)，不是自动证实无后续活跃版本。
- [R2 全 Git 跟踪路径与 Git Blob SHA](https://github.com/kaicreator-mm/shun-assistant/blob/9457a680a799bb30a6ab2089f1b5a09d1f27d902/docs/dke/SOURCE_PATH_INVENTORY_R2.json) 已生成，分类仅按路径启发式，**尚未逐项筛成专业知识相关来源清单或取得每份内容使用许可**。
- 代表性业务代码、测试/第二见证 exact Blob 见 [R1](https://github.com/kaicreator-mm/shun-assistant/blob/cfff7635ac2bb6ccf47e459f009f49a51888cd25/docs/dke/PROJECT_DOMAIN_ANALYSIS_R1.md)。进一步的现行 Product/分支/PR/Tag 校准及每来源影响分析必须有独立校验记录。

### SC03 文档—代码—测试有界核对

R1 的 Issue #259、#404、version/v0.3.0 来源与 real-kernel-permit.test.ts 区分真实 K/模拟 Host。当前 PR #272 HEAD 5bb4e4b27e319d0104406c3389f8b8e6149b7f0b 为 Draft，比 R1 所述 dd8ce 更新；没有对该 PR 现行所有源码做独立 Gate。

当前状态 `BOUNDED_R1_SOURCE_TEST_TEXT`，不是全业务源 `DOC_CODE_TEST_MATRIX`，也不是测试结果。未检查的对应关系必须保持 `DOC_ONLY / CODE_ONLY / UNKNOWN`，冲突则为 `CONFLICT`，需要专业来源则 `EXTERNAL_ORACLE_REQUIRED`。

### SC04 CQ、反例与验证方案

1. Capability 能力存在却真实 Host 不可用，是否可以自动批准/执行？
2. 首次启动 UAC 切换交互用户时信任锚应绑定哪个账户？
3. 一个 fake Executor 的成功回执是否足以证明真实系统操作效果？

对每条 CQ 必须有一条固定源码/权威资料的正例、一条缺源、一条过期或冲突、一条错误归属/非法晋升反例；保留 `ABSTAIN/UNKNOWN`，独立 Reviewer 不能只是同一模型自我重述。候选最小包需 3–5 个 Claim、1 个跨 Context Relation、2–3 个 CQ 和真实 failure case，作为 [domain-forge #209](https://github.com/kaicreator-mm/domain-forge/issues/209) 的受限输入。

### SC05 阶段阻塞和权限界线

当前活跃 Draft PR #272 与本 manifest 的 version baseline 需要 exact-diff 校准；首次安装/授权/Host 真实 Windows Critical Journey 和独立 Review 尚未取得。

**验收判定**：`G1=STRUCTURED_CANDIDATE`；`G2=BUSINESS_MODEL_CANDIDATE`；`G3=CONTEXT_CANDIDATE`；`G4=CLAIMS_AND_CQ_CANDIDATE`；`G5=PATHS_ENUMERATED_ONLY`；`EXTRACTION_READY=NO`；`INDEPENDENT_ORACLE=NOT_RUN`；`SAP_QUALIFIED=NO`；`ELEMENT_FREEZE=NO`；`DIS_PACKAGE=NOT_GENERATED`。

**后续推进**：对全路径机器清单做人工领域源筛选、业务全链 DOC↔CODE↔TEST 核对、真实反例与独立专业资料来源准入；再将本项目源证据包交给 domain-forge #209，且只在 [devkit #5](https://github.com/kaicreator-mm/devkit/issues/5) 更新经过真正验收的 G1..G5 状态。
