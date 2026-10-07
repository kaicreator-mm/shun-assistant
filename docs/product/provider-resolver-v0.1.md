# Shun v0.1 — Provider Resolver v0.1

Status: **Product candidate. Scoring weights are experimental until benchmark-calibrated.**

Hard gates execute before ranking **feasible Provider × Environment bindings**. Risk remains a separate execution gate and is not hidden inside the Provider score.

A Provider is discovered before environment binding. Environment feasibility is not allowed to reject a Provider until its environment requirements have been resolved against the currently allowed environment candidates.

| Section | Item | Definition / Rule | Weight_or_Level | Hard_Gate | Why | Evidence | Implementation_Note | Metric | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Hard Gate | Capability Fit | Provider 必须满足用户目标的必要 capability/输出格式/约束 | mandatory | YES | 功能不匹配时其他分数没有意义 | R2/R5 Provider 选择 | 先做 contract match，再评分 | contract match pass rate | v0.1 |
| Hard Gate | Trust / Supply Chain | 来源可信、签名/哈希、许可可接受、无已知高风险捆绑或恶意历史 | mandatory | YES | 系统工具和安装器拥有高权限 | R2/R5 trust signals | UNKNOWN provenance 默认 fail-closed；若 policy 显式允许例外，仍保持 UNKNOWN/UNTRUSTED 标签并按风险要求进入隔离环境 | trusted acquisition rate | v0.1 |
| Hard Gate | Binding Feasibility | 已解析的 Provider × Environment binding 满足 OS/arch/runtime/driver/resource/permission 要求 | mandatory | YES | 避免在 Environment Resolution 前错误淘汰可远程/隔离运行的 Provider | R4 legacy/remote | P0 仅解析 local bindings；P1 加入 RunX remote/legacy/sandbox bindings | environment resolve success | v0.1 |
| Hard Gate | Policy / Safety | Provider 不违反用户隐私/离线/许可/企业策略和风险限制 | mandatory | YES | 用户约束必须先于排名 | R2 privacy/offline; R1/R3 risk | policy filter precedes score | policy rejection correctness | v0.1 |
| Score | Capability Fit | 满足目标的完整程度；避免为了一个小任务选功能过重 Provider | 0–100 | NO | 最小满足比最大功能集更重要 | R5 more-powerful-is-not-always-better | 建议基准权重 25% | task fit score | v0.1 |
| Score | Reliability | 版本稳定、真实输出成功率、崩溃/数据损坏/已知 bug | 0–100 | NO | 功能存在不代表可可靠执行 | R5 reliability/Czkawka/Kdenlive | 按 exact provider version 记分 | first-attempt success | v0.1 |
| Score | Agent Usability | 机器接口、结构化 I/O、batch、headless、determinism、observability | 0–100 | NO | 这是与普通 App 推荐最不同的核心维度 | R5 strongest implication | 建议基准权重 20% | agent-usability predictive power | v0.1 |
| Score | Trust | 官方来源、签名、开源可审计性、许可、更新/安装器行为、维护状态 | 0–100 | NO | 免费/开源也不自动等于可信 | R5 trust | 建议基准权重 15% | supply-chain incidents | v0.1 |
| Score | Environment Compatibility | 安装难度、架构/OS/driver 要求、remote/sandbox 可用性 | 0–100 | NO | 环境是 Provider 选择的一部分 | R4 | 建议基准权重 10% | provision success | v0.1 |
| Score | Performance / Resource Cost | 执行速度、RAM/CPU/GPU/磁盘/启动成本 | 0–100 | NO | 轻量/速度跨软件评论反复出现 | R5 | 建议基准权重 5% | latency/resource budget | v0.1 |
| Score | Human Usability | 100=低摩擦；用户若需介入时，综合学习曲线、UI 复杂度、订阅/广告、配置成本 | 0–100 | NO | UI-last 不是忽略人的体验；评分方向必须与正向加权一致 | R5 | 建议基准权重 5% | human interventions | v0.1 |
| Penalty | Interaction Complexity | 执行需要多少 probabilistic UI/视觉步骤 | 0–20 penalty | NO | 应显式惩罚 UI dependency | R1–R5 | 从 interface class 自动映射 | UI actions/task | v0.1 |
| Penalty | Lifecycle Cost | 安装体积、常驻服务、升级维护、卸载残留、依赖复杂度 | 0–10 penalty | NO | 低频软件应优先 JIT/portable/可回收 | R2/R5 | 低频任务对 lifecycle cost 权重可动态放大 | retain/remove cost | v0.1 |
| Risk | Risk Class 0 | 只读/无副作用，如查询、分析、预览 | R0 | NO | 无需不必要审批 | cross-round risk | 默认自动 | confirmation count | v0.1 |
| Risk | Risk Class 1 | 可逆写操作，如生成新文件、非破坏配置 | R1 | NO | 可自动但必须验证结果 | cross-round risk | 失败自动回滚/删除生成物 | rollback rate | v0.1 |
| Risk | Risk Class 2 | 潜在破坏，如覆盖、批量移动、卸载、驱动更新 | R2 | approval | 需要 plan/preview | cross-round risk | 用户确认或已有 durable policy | unsafe-action rate | v0.1 |
| Risk | Risk Class 3 | 高风险/难逆，如数据恢复写入、加密、系统回滚、分区 | R3 | approval+backup | 错误后果严重 | R1/R3 | 强制 backup/checkpoint/explicit approval | zero-loss target | v0.1 |
| AgentUsability | Machine Interface | native API/library/CLI/MCP/IPC 是否存在且稳定 | 0–15 |  | 核心接口质量 | R5 | MCP 只是 transport，不等于 domain core | machine interface coverage | v0.1 |
| AgentUsability | Structured I/O | 输入/输出是否可结构化解析 | 0–12 |  | 降低文本/UI 解析不确定性 | R5 | JSON/typed result > human prose | parse failure rate | v0.1 |
| AgentUsability | Headless | 是否无需桌面 session/视觉交互 | 0–10 |  | 适合后台、远程、sandbox | R5 | true headless 优先 | headless success | v0.1 |
| AgentUsability | Batchability | 是否原生支持批处理/目录/队列 | 0–10 |  | 普通用户大量重复任务 | R2/R5 | 没有 batch 可由 adapter 补齐 | items per invocation | v0.1 |
| AgentUsability | Determinism | 同样输入/版本是否能稳定复现 | 0–12 |  | Recipe/verification 依赖确定性 | cross-round | 随机/隐式 UI state 扣分 | replay success | v0.1 |
| AgentUsability | Observability | 进度、日志、错误码、输出路径是否明确 | 0–10 |  | 可诊断失败且减少 LLM 猜测 | R1/R3/R5 | structured error taxonomy | diagnosis time | v0.1 |
| AgentUsability | Dry-run / Preview | 能否先展示会做什么 | 0–8 |  | 高风险任务关键 | R5 uninstall/cleanup | 无原生能力可由 wrapper 实现 | preview coverage | v0.1 |
| AgentUsability | Cancel / Timeout | 长任务能否取消、超时和恢复 | 0–5 |  | 媒体/扫描/批量任务需要 | R2/R5 | runtime contract | cancel correctness | v0.1 |
| AgentUsability | Version Stability | 接口是否跨版本稳定或可 pin | 0–8 |  | 长期 Recipe 维护关键 | R3/R5 | 记录 exact version / adapter compatibility | version replay | v0.1 |
| AgentUsability | Portable / JIT Fit | 是否可 portable、按需安装、容器/remote 获取 | 0–5 |  | 低频软件生命周期成本 | R2/R5 | JIT provider 加分 | acquire/remove time | v0.1 |
| AgentUsability | Safe Replay / Idempotency | 重试/重放是否可识别已完成状态、避免重复副作用，并支持明确 recovery | 0–5 |  | Agent 执行与 Recipe 重放需要可恢复语义；补足 Agent Usability 100 分制 | cross-round / recipe | 无原生能力时由 adapter/transaction wrapper 提供并降级评分 | replay/recovery correctness | v0.1 |
| InterfacePreference | I0 Native library / stable API | 优先；最小交互复杂度 | preferred |  | 最适合 deterministic execution |  | interaction penalty 0 | success rate | v0.1 |
| InterfacePreference | I1 Structured CLI / MCP / IPC | 优先；MCP 作为 Agent-facing transport，CLI 适合执行/调试/CI | preferred |  | 可组合、可观测 |  | interaction penalty 1 | success rate | v0.1 |
| InterfacePreference | I2 File / protocol / config interface | 可接受；适合文档、项目格式、配置、数据库 | preferred |  | 绕过 GUI 且通常稳定 |  | interaction penalty 2 | success rate | v0.1 |
| InterfacePreference | I3 Semantic UI / Accessibility / DOM | fallback |  | 比视觉点击稳定，但仍受应用 UI 生命周期影响 |  | interaction penalty 6 | semantic UI actions | v0.1 |  |
| InterfacePreference | I4 Vision Computer Use | last resort |  | 仅当无结构化路径或任务本身视觉交互 | R4 | interaction penalty 15–20 | vision actions/task | v0.1 |  |
| Formula | Base Score | 0.25 Fit + 0.20 Reliability + 0.20 AgentUsability + 0.15 Trust + 0.10 BindingCompatibility + 0.05 Performance + 0.05 HumanUsability | 0–100 |  | 初始实验权重，不是冻结真理 | R5 | 用 benchmark 校准 | rank correlation with success | EXPERIMENTAL |
| Formula | Final Score | Base Score - InteractionPenalty - LifecyclePenalty | rank |  | 风险不塞进分数；由独立 gate/approval 控制 |  | 同 capability 下排名 | top-1 success | EXPERIMENTAL |
| Resolver Flow | 1. Parse Goal | 提取 object / desired outcome / constraints / risk / verification criteria |  |  |  |  | Goal contract | parse accuracy | v0.1 |
| Resolver Flow | 2. Resolve Capability | 匹配 capability contract；必要时拆 Capability DAG |  |  |  |  | Capability Registry | coverage | v0.1 |
| Resolver Flow | 3. Discover Providers | 查 local/installed/portable/provider registry；仅发现 Provider，不提前因本地不兼容淘汰 |  |  |  |  | 先复用已安装且可信的候选，但保持完整候选 requirements | discovery recall | v0.1 |
| Resolver Flow | 4. Derive Environment Requirements | 为每个 Provider 解析 OS/arch/runtime/driver/resource/permission requirements |  |  |  |  | requirements 不是 feasibility verdict | requirement completeness | v0.1 |
| Resolver Flow | 5. Resolve Environment Candidates | P0 解析 local；P1 可加入 RunX remote/legacy/sandbox |  |  |  |  | 形成允许的 environment candidates | placement candidate recall | v0.1 |
| Resolver Flow | 6. Apply Hard Gates to Bindings | 对 Provider × Environment binding 应用 fit/trust/feasibility/policy hard gates |  |  |  |  | gate before scoring；UNKNOWN trust 默认 fail-closed | bad-binding rejection | v0.1 |
| Resolver Flow | 7. Score / Rank Bindings | 按任务类型动态调整权重；低频任务放大 lifecycle cost |  |  |  |  | 返回 top bindings + reason | ranking quality | v0.1 |
| Resolver Flow | 8. Plan Execution | 尽量选 I0–I2；I3/I4 明确标记 fallback |  |  |  |  | 生成 verify + rollback plan | plan quality | v0.1 |
| Resolver Flow | 9. Execute / Verify | 执行后验证用户目标而非只看 exit code |  |  |  |  | 结果 contract | task success | v0.1 |
| Resolver Flow | 10. Learn / Persist | 记录成功 Provider/version/config/recipe/last-known-good |  |  |  |  | 可重放但需 currentness check | repeat-task latency | v0.1 |
