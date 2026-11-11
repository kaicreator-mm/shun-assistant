# Shun Assistant — DKE R3 Current-Authority Delta and Business-Flow Reconciliation

> 2026-11-11 · [devkit #5](https://github.com/kaicreator-mm/devkit/issues/5) · **SOURCE-DRIFT-REPAIR / RESEARCH CANDIDATE ONLY**。R0/R1/R2 的历史事实保持。对活跃 [PR #272](https://github.com/kaicreator-mm/shun-assistant/pull/272) 的现行 HEAD `5bb4e4b27e319d0104406c3389f8b8e6149b7f0b` 做有界 readback；原 R2 pinned `version/v0.3.0@91420edca44009aa2c984c876104b40814a7c265` **不可代表当前活跃功能代码**。本文件不是整个活跃 PR 的独立 Source Review，也不提升 Release/DKE 资格。

## SC01 — exact version drift

- GitHub compare `91420edc... → 5bb4e4b...`: **ahead 159 commits、changed 179 files**；不是仅文档变化。
- 影响入口：`apps/control-api/src/main.ts`、`apps/control-api/src/server.ts`、Guided/Journey/production composition、first-run LocalAppData bootstrap 和相关测试新增/修改。
- main `217364b0c308e6089ea884ef7cb84eda752f7102` 是历史基线，既不等于 R2 version source，也不等于 PR #272 active HEAD。
- Source 级研究应区分：**Product/L1 经过既有独立审核的冻结语义**、**新的业务接线实现行为**、**真实 Windows 环境执行资格**；不能从历史 `RQ PASS` 推导活跃 PR 具备相同 Release 资格。

## G1 当前 Product 目标

[已冻结 v0.3 Product/L1](https://github.com/kaicreator-mm/shun-assistant/blob/5bb4e4b27e319d0104406c3389f8b8e6149b7f0b/docs/product/PRODUCT_FREEZE-v0.3.md) · Blob `0f8a67c2f06364d58a842502d3dee11bfeeedba4`；声明 Windows-first 用户目标、Approval、真实 Host 效果与结果可信度、有限 Guided Journey、Provider 和 Meta Candidate，而非任意模型生成系统级 Effect。**当前实现实际效果不由 Product Freeze 单独证明。**

## G2 业务闭环及失败恢复的本轮 Source Delta

| Business gate | Product/责任归属 | 活跃源码或规范固定文件 | 本次可确认事实 | 仍需核查 |
|---|---|---|---|---|
| 1. 首次可信身份与安装 | 用户与 Installer/Host；交互 SID 与首次授权分开 | [R04 L2 Note](https://github.com/kaicreator-mm/shun-assistant/blob/5bb4e4b27e319d0104406c3389f8b8e6149b7f0b/docs/architecture/v0.3/R04-LOCALAPPDATA-GUIDED-TRUST.md) blob `3d7002caa230f8337a7b0ec245f1fa471cac9be0` | Trust tree、pin、secret 在每交互用户 LocalAppData；同账户 UAC 可允许，不同账户需 fail-closed；设备场景威胁模型不要求跨用户安全隔离 | 真实交互用户身份/系统 ACL/初次 provision 的 Windows 效果及并发首次安装 |
| 2. 已部署 Guided 本地 Trust | 可信 Host 创建，不接受 HTTP/model 任意设置 | [main.ts](https://github.com/kaicreator-mm/shun-assistant/blob/5bb4e4b27e319d0104406c3389f8b8e6149b7f0b/apps/control-api/src/main.ts) blob `b27e32917eccafb1433c0971b2b3413fd74f1be5` | 启动缺可信 LocalAppData 资料时明确提示一次性同意引导；有条件才装配 real Guided；DEMO/Guided 无法通过虚假成功 | 与真实 Windows 安装、真实 Guided Store 及恢复完整 E2E |
| 3. Controller Gateway / 授权 | Goal、用户审批、selected K 与 Provider 有各自权限 | [server.ts](https://github.com/kaicreator-mm/shun-assistant/blob/5bb4e4b27e319d0104406c3389f8b8e6149b7f0b/apps/control-api/src/server.ts) blob `59f0bb1d42b737fbc69065f7977ad6965a033335` | HTTP 表面是 non-authoritative，由进程侧注入 Gateway；缺可信 Gate 时 typed refuse/503，不从 HTTP 请求接受 grant | 实际主入口接线 + K Permit + Effect 的当前审查和动态验收 |
| 4. Scoped selected-root & effect | Shun 的业务目标/授权与 Windows Host 实际效果分工 | 同上 main.ts / server.ts；[PR #272](https://github.com/kaicreator-mm/shun-assistant/pull/272) | 代码具有 selected-root 的分段 Guard、预览、操作前再次验证的有界结构；代码存在不等于真实 OS 效果 | 本机权限、实际 GUI 操作、真实收据与 UNKNOWN 恢复 |
| 5. Bootstrap 自检/修复 | per-user Trust 生命周期 | [guided-localappdata-bootstrap.test.ts](https://github.com/kaicreator-mm/shun-assistant/blob/5bb4e4b27e319d0104406c3389f8b8e6149b7f0b/apps/control-api/test/guided-localappdata-bootstrap.test.ts) blob `3bbb7ed84dbb75d46490c89e88ca9b1b37737ba6` | 有临时 profile/ephemeral key 的 FRESH、PARTIAL、INVALID、idempotent 负面用例，**不是本轮执行，也不触及真实 Windows 用户资料** | 首次运行、不同账户 UAC、错误权限真实 Host 证据 |
| 6. 当前发布/业务效果上限 | Product vs Source/RQ 分离 | [v0.3 RELEASE-QUALIFICATION.md](https://github.com/kaicreator-mm/shun-assistant/blob/5bb4e4b27e319d0104406c3389f8b8e6149b7f0b/docs/release/v0.3/RELEASE-QUALIFICATION.md) blob `089d55ff7e83e012c27720d6dc1aa6138d552f88` | 既有 R01 通过只属于旧 candidate；R04 addendum 显示活跃整版本 `RELEASE_ELIGIBLE=BLOCK` 直至独立 Review/集成/资格；无需混淆为 DKE 的知识准备失败 | 以最新 PR 及 Owner 记录对齐最终当前审查结果 |

## G3/G4 领域与知识界线修订

- **UserGoal/Capability/Provider**：应用业务可记录哪些目标满足前提；DomainHarness 权限与真实 Windows Host Effect 各有自己的 Owner。
- **Guided Trust Provenance/Authority**：v0.3 实施选择是 **per-interactive-user LocalAppData**，不得把过时 ProgramData 或仅 admin 同意当成当前可靠性知识。
- **Authorization/Effect/Receipt**：用户授权、K Permit、真实 Windows 影响、回执与 Outcome UNKNOWN 是不同语义，不可凭一个 mock test 认定另一层成功。
- **VERSION/ADMISSION**：已通过独立审核的历史 SHA 与活跃变更不自动共享身份和资格；将当前变更作为 `SOURCE_STALE` 传播到受影响 Claim/CQ 和 Consumer。
- 可采纳作为项目 **政策/实现行为** 候选；**不是普适 OS 安全定律**，更不能成为无需真实 Host 支持的自动执行许可。

## SC03/SC04 源验证与 CQ 反例

| CQ | Source-first observation | 反例/UNKNOWN |
|---|---|---|
| CQ-SH-1: 首次安装权限/交互身份如何绑定？ | R04 设计规定 process interactive user SID 归属和同账户 UAC；测试 fixture 为隔离临时 profile | 不同管理员账户 elevate 后 LocalAppData 错配；未执行真实 OS 实例则 `NOT_PHYSICALLY_PROVEN` |
| CQ-SH-2: Gateway 当前能否无授权执行？ | current main.ts/server.ts 明确 fail-closed 注入与受限 selected root | 仅有 route or mock pass 而生产未装配时，应 `REFUSED/503` |
| CQ-SH-3: 已有授权/执行回执是否证明目标完成？ | Goal/Approval/Permit/Host/Effect 有层级分离 | 模拟 no-effect/部分完成/UNKNOWN 不能标为真实完成 |
| CQ-SH-4: 历史 R01 PASS 能否覆写新版本资格？ | RELEASE-QUALIFICATION.md 精确绑定历史 candidate SHA | 159 新 commits 后无需复核直接引用旧 PASS 必须拒绝 |

## Gate & ownership decision

`SC01_ACTIVE_DRAFT_HEAD_PINNED_FOR_BOUNDARY_STUDY`，`ACTIVE_DELTA_IDENTIFIED`，`SC03_PARTIAL_CODE_AND_TEST_TEXT`；**G1–G5 INDEPENDENT ACCEPTANCE = PENDING**，`EXTRACTION_READY=NO`，`INDEPENDENT_CURRENT_SOURCE_REVIEW=NOT_RUN`。更完整的新版本见项目正式 PR #272；不在 DKE 研究分支实施产品修复。下步先对 active PR 用户 Journey 的真实关键环节做 Product↔Source↔Test Review，再交 domain-forge #209 消费有限、可证伪的源事实。
