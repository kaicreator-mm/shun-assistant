# Shun v0.1 — Fresh Independent Adversarial Review Pack

## Reviewer role

Use a **fresh, independent, high-capability reviewer context**. Review is read-only and must attempt to falsify the candidate rather than improve or expand it.

### Forbidden reviewer actions

- Do not implement code.
- Do not expand MVP scope.
- Do not silently redesign the product.
- Do not treat prior self-review as independent evidence.
- Do not transfer PASS from another SHA.

### Required terminal

- `PASS | NEEDS_REVISION | BLOCK`
- P0/P1/P2 findings with exact file/section references
- exact reviewed commit SHA
- `PRODUCT_FREEZE_ELIGIBLE=YES|NO`

## Review matrix

| Review_ID | Review_Area | Adversarial_Question | Expected_Evidence | P0_Failure_Example | Disposition | Required_Action | Can_Freeze_If | Source | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R-001 | Positioning | PRD 是否仍可能退化成另一个 ChatGPT Work/Kimi/Computer Use Agent？ | Product Definition + Non-Goals + Core Resolution Flow | 主路径仍是 Agent→UI→App；Capability/Provider 只是装饰 | PASS / NEEDS_REVISION | 若失败，重写核心价值和 MVP 指标 | 核心 value 可在完全不展示 UI 的任务中成立 | PRD §1/2/5/12 | PRECHECK_CLEAR_PENDING_FRESH_REVIEW |
| R-002 | User problem | 真实痛点是否是‘需要 Agent’，还是软件选择/学习/维护成本？ | R1–R5 evidence + Product Problem | PRD 把 AI 自身当用户价值而没有具体摩擦 | PASS / NEEDS_REVISION | 将需求描述回归 user job/friction | 每个 P0 能映射多个真实 evidence cluster | L1_Product_Decisions | PRECHECK_CLEAR_PENDING_FRESH_REVIEW |
| R-003 | Capability abstraction | Capability 是否足够稳定，还是过度抽象导致无法实现？ | MVP capability contracts + benchmark tasks | 同一 capability 输入输出无法定义或验证 | PASS / NEEDS_REVISION | 拆分/合并 capability taxonomy | P0 capability 都有明确 outcome contract | MVP_Capability_Map | PRECHECK_UPDATED_PENDING_FRESH_REVIEW |
| R-004 | Provider Resolver | 评分模型是否会选出‘机器好用但不安全/不满足用户约束’的软件？ | Hard gates + risk model + R5 evidence | FFmpeg/CLI 分高但违反用户许可/隐私/格式要求仍被选 | PASS / NEEDS_REVISION | 强化 hard gate；风险独立于排序 | 所有不可妥协约束在评分前淘汰 | Provider_Resolver_v0.1 | PRECHECK_CLEAR_PENDING_FRESH_REVIEW |
| R-005 | Human vs Agent usability | 是否错误地把 CLI 当作天然更好？ | R5 + Agent Usability subscore | CLI 无结构化错误/版本不稳定却因为无 GUI 得高分 | PASS / NEEDS_REVISION | Agent usability 必须包含 observability/determinism/stability | CLI 只是接口类型，不自动获得高分 | R5_Analysis | PRECHECK_CLEAR_PENDING_FRESH_REVIEW |
| R-006 | UI-last boundary | 是否把 UI-last 变成教条，损害 CAD/创作类任务？ | R4 adversarial evidence + P2 counterexamples | 系统为了追求 UI-free 生成低质量视觉结果且不让用户审阅 | PASS / NEEDS_REVISION | 引入 mode selection / Co-pilot gate | 视觉/主观核心任务明确保留 review | R4_Analysis + PRD §3/10 | PRECHECK_CLEAR_PENDING_FRESH_REVIEW |
| R-007 | Lifecycle | 软件生命周期是否真是 MVP 核心还是过度扩大范围？ | R1/R2/R5 + P0 lifecycle benchmark | 安装/卸载维护开发量吞噬核心任务执行能力 | PASS / NEEDS_REVISION | 限定 P0 为 acquisition/provenance/basic repair/uninstall | P0 lifecycle 能直接支持 JIT software loop | MVP_Capability_Map | PRECHECK_UPDATED_PENDING_FRESH_REVIEW |
| R-008 | Safety | 删除/同步/驱动/恢复操作的安全模型是否充分？ | Risk classes + preview/backup/approval/verify | Provider 成功但用户文件丢失 | BLOCK | 补 R2/R3 gate 与 failure injection | 无未处理的不可逆 P0 路径 | Provider Resolver + Benchmark | PRECHECK_CLEAR_PENDING_FRESH_REVIEW |
| R-009 | Verification | 系统是否能验证用户结果，而不是只验证工具成功？ | Benchmark verification column | CLI exit 0 但视频不可播放/PDF 丢页/文件命名冲突 | BLOCK | 每个 P0 task 定义 semantic verification | 所有 P0 都有 outcome-level verify | Benchmark_v0.1 | PRECHECK_CLEAR_PENDING_FRESH_REVIEW |
| R-010 | Environment abstraction | RunX 是否被过早耦合进产品？ | R4 evidence + Environment Resolver tasks | MVP 强制依赖完整 RunX 导致 local MVP 无法交付 | PASS / NEEDS_REVISION | Local backend 为默认；RunX P1 接入 | P0 local flow 可独立成立 | PRD §5/6 | PRECHECK_CLEAR_PENDING_FRESH_REVIEW |
| R-011 | MVP size | P0 是否过大，无法形成最小闭环？ | P0 list + Run Packs | 同时做系统诊断、媒体、PDF、生命周期导致没有核心闭环 | PASS / NEEDS_REVISION | 将 P0 收敛为 3 个 validation loops | 每个 P0 模块服务 A/B/C 三条闭环之一 | MVP_Capability_Map | PRECHECK_UPDATED_PENDING_FRESH_REVIEW |
| R-012 | Differentiation | 如果 Windows/Copilot 原生加入更多 API/agent actions，产品是否仍有价值？ | Capability/Provider/Environment/Lifecycle architecture | 差异化只来自能调用系统 API | PASS / NEEDS_REVISION | 强调跨 Provider/环境、JIT lifecycle、provenance/recipe | OS 原生能力可以成为 Provider，而不是替代整个产品 | L1_Product_Decisions | PRECHECK_CLEAR_PENDING_FRESH_REVIEW |
| R-013 | Recipe persistence | Recipe 是否会因版本漂移变成危险自动化？ | B-036 + version stability/currentness | 旧 recipe 在新版本 silent wrong behavior | PASS / NEEDS_REVISION | 每次 replay 做 provider/version currentness + verification | recipe 不绕过 verify | Benchmark B-036 | PRECHECK_CLEAR_PENDING_FRESH_REVIEW |
| R-014 | Metrics | 指标是否鼓励错误行为？ | Success Metrics | 为了提高 UI-free rate 强行避免必要 UI；为了减少确认跳过安全 gate | BLOCK | task success/safety 优先于 UI-free/confirm count | 指标有明确优先级与 safety override | PRD §13 | PRECHECK_UPDATED_PENDING_FRESH_REVIEW |
| R-015 | Evidence validity | 是否把目的性样本的 80.5% 当成总体事实？ | Methodology + PRD Validation Plan | PRD/市场材料声称‘80%/90%用户需求无需UI’ | BLOCK | 只描述探索证据；总体比例需独立采样/实测 | 无 population-wide 未证实 claim | Methodology | PRECHECK_CLEAR_PENDING_FRESH_REVIEW |
| R-016 | Freeze terminal | 是否存在 unresolved P0 产品矛盾？ | Fresh review of all rows | 任何 BLOCK 或关键 NEEDS_REVISION 未关闭 | FREEZE / HOLD | 关闭 P0 后再冻结 | R-008/R-009/R-014/R-015 必须 PASS，其他无重大冲突 | All | HOLD_FRESH_REVIEW_TERMINAL |
| TRIGGER | Fresh Independent Adversarial Review | 执行 `AI Computer Assistant - PRD v0.1` Fresh Independent Adversarial Review；以同目录 L1 Product Evidence - 5 Rounds、Provider Resolver v0.1、MVP Capability Map、Benchmark v0.1 为证据，逐条审查 PRD_Review_Pack R-001–R-016；禁止扩需求或实现；输出 PASS/NEEDS_REVISION/BLOCK 与 exact findings。 |  |  |  |  |  |  | READY |
