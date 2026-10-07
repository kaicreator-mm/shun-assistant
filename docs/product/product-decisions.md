# Shun v0.1 — Product Decisions

Status: **Candidate; pending Fresh Independent Adversarial Review.**

| Decision_ID | Decision | Evidence_Status | Evidence_Basis | Product_Implication | Still_Unproven | Next_Validation | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| D-001 | North Star：让系统和软件更好用，而不是做“会点 UI 的通用电脑 Agent” | Strong | R1–R5 多轮共同显示用户主要表达目标、症状与约束；UI/应用只是实现路径 | 产品入口围绕 Goal/Object/Constraint，而非 App launcher | 市场愿意为这一抽象买单的程度 | MVP task benchmark + 真实用户任务访谈 | CANDIDATE |
| D-002 | Goal-first | Strong | 文件、媒体、软件选择、系统诊断、legacy 等场景均以结果导向表达 | 用户描述“我要什么”，系统解析 capability | 复杂专业任务中 Goal 是否足够精确 | Benchmark 中记录澄清次数 | CANDIDATE |
| D-003 | Capability-first | Strong | R2/R5 显示同一目标常有多个 Provider；单一应用边界并不自然 | Capability 是稳定任务边界，App 是 Provider | Capability taxonomy 是否足够稳定 | 从 Benchmark 失败案例迭代 taxonomy | CANDIDATE |
| D-004 | Agent-friendly Provider first | Strong | R5 明确 Human UI usability ≠ Agent usability；FFmpeg/MPV/7-Zip/FreeCAD 等具有机器接口优势 | Resolver 优先结构化、可批处理、确定性 Provider | 评分权重是否能预测真实成功率 | Provider A/B benchmark | CANDIDATE |
| D-005 | UI-last，不是 UI-never | Strong | R4 对抗采样：真正 Low 主要集中复杂 CAD/3D/视频创作；大量周边步骤仍可无 UI | Computer Use 作为 fallback/协作层，不作为默认执行抽象 | 真实总体 UI-free 比例 | 执行 benchmark；禁止用探索样本推断总体比例 | CANDIDATE |
| D-006 | 软件生命周期属于核心产品 | Strong | 安装、Store、默认应用、卸载残留、版本兼容、legacy 跨轮反复出现 | 维护 install reason/version/config/dependencies/provenance/retain-remove | 长期用户是否信任 Assistant 自动维护 | 长期使用实验 + approval UX | CANDIDATE |
| D-007 | 系统维护应是 evidence-driven stewardship，不是传统清理按钮集合 | Strong | R1/R3 的存储、更新、驱动、性能问题需要状态/历史/last-known-good | Observe→Diagnose→Plan→Approve→Execute→Verify | 诊断准确率与误修率 | System benchmark + failure injection | CANDIDATE |
| D-008 | 本机不适合运行不等于任务失败 | Strong | R4 legacy/remote/旧硬件反例显示执行环境本身是变量 | Environment Resolver 对接 RunX：local/remote/legacy/sandbox | 环境切换成本与用户接受度 | 至少 Local Windows + 1 Remote/isolated backend benchmark | CANDIDATE |
| D-009 | 多工具组合优先于强迫单 App 完成全流程 | Strong | OCR→分类→重命名、扫描→OCR→路由、媒体转换等天然形成 capability DAG | 允许 deterministic workflow + Python/shell glue | 生成 glue 的安全性/复用率 | Workflow benchmark + recipe reuse | CANDIDATE |
| D-010 | 一次成功应固化为可复用 Recipe/Workflow | Supported | 多轮出现重复任务、批处理、相同 repair path；重复 LLM reasoning 没有必要 | LLM 负责计划；成功后转 deterministic execution | Recipe 老化与版本漂移 | 重放测试 + provider/version pin | CANDIDATE |
| D-011 | 高风险动作必须 plan/preview/backup/verify | Strong | R1–R5 中删除、同步、恢复、加密、驱动、深度卸载反复显示误操作风险 | 风险策略独立于 Provider score；高风险需 approval gate | 审批是否过多导致 UX 变差 | 按风险级别测确认次数/误操作率 | CANDIDATE |
| D-012 | 不把‘支持多少 App’作为核心指标 | Strong | 跨轮证据显示 capability coverage 比 App coverage 更能解释用户价值 | 核心指标改为 Capability coverage / task success / UI-free / confirmations | Capability coverage 与用户留存关系 | MVP telemetry/benchmark | CANDIDATE |
| D-013 | Computer Use 的关键价值是 fallback、探索与视觉协作 | Strong | R4 明确创作、构图、复杂 CAD 等存在视觉反馈不可替代部分 | UI Agent 不承担统一执行层；仅在结构化接口不足或任务本身视觉化时使用 | Fallback 触发条件是否足够准确 | Adversarial benchmark | CANDIDATE |
| D-014 | Provider trust 是一等公民 | Strong | R2/R5 多次出现广告、捆绑、非官方版本、订阅、隐私与供应链顾虑 | Resolver 纳入 provenance/signature/source/license/update behavior | 可获得的供应链元数据覆盖率 | Top providers trust audit | CANDIDATE |
| D-015 | 当前证据足够进入 MVP/Benchmark，不足以宣称普通用户 80%/90% UI-free | Strong limitation | Methodology 明确 purposefully sampled；R1–R4 aggregate 不是总体估计 | 停止继续用探索样本堆比例，进入真实执行验证 | 总体用户需求分布 | 后续若需要总体比例再做加权抽样 | READY_FOR_NEXT_STAGE |
