# Shun Assistant v0.3.0 使用与部署指南（中文）

> **状态：R02 修复工作分支；尚未通过最终 Windows 与 Woodpecker 验证，不是发布版本。**

## 运行准备

- Windows 10/11，Node.js **24 或更高**，pnpm 10.34.5；无需 WSL 或 Ubuntu。
- 从 `version/v0.3.0` 或经过审核的准确 SHA 克隆完整 monorepo；执行 `corepack enable`、`pnpm install --frozen-lockfile`。
- 控制界面使用 loopback 地址 `http://127.0.0.1:7788`。开发演示模式可使用 `pnpm --filter @shun/control-api dev`，但演示后端**不代表真实授权、持久化或完整 v0.3 操作**。
- 真实存储模式 `SHUN_CONTROL_MODE=real-storage` 需要可信配置的工作区、SQLite、注册表当前性、公钥与 Host 授权密钥；缺失时应拒绝启动，不得使用测试密钥或绕过权限。
- v0.3 的 BUILD、Guided 路由、授权流程和 UI 仅在生产入口完成实际绑定及最终验收后才可宣称可用；目前不允许将单元/模拟测试 PASS 解释为成品可用。

## 安全控制

- 本地诊断和 B-040 系统信息只能读取经过严格裁剪的操作系统字段；`localOnly=true` 不代表远程模型流量也被禁止。必要时检查实际发送路径。
- Goal/对象/范围/隐私/当前性均由 Host 绑定，AI Planner 提议只能作为不可信数据。
- Guided 表单确认、云发送披露同意、ActionController 人工批准、Kernel Effect Permit 是四种独立事实。任何一种不能代替其他三种。
- 对 `UNKNOWN`、超时、已发送但无终态的情况，**禁止自动重试**，先查询 Journal/Host 的可信状态。
- 任何 Provider 必须来源于受控目录、签名经过独立信任根验证、内容哈希一致；浏览器与模型不能直接配置受信任根或可执行文件。
- 禁止把真实 API Key、私钥、用户资料或系统命令结果写入 Issue、日志、构建产物。

## 恢复与回退

1. 记录当前应用 Git SHA、SQLite 数据版本、可信 Provider 签名目录修订；关闭本地控制入口。
2. **先备份** SQLite/受保护目录，避免在不确定状态下执行清理；备份本身需要符合用户隐私约束。
3. 如果 Kernel/ActionController 状态为 UNKNOWN：保持只读排查，避免重新提交同一 Case 的外部效果。
4. 仅在经过独立审核的兼容迁移和真实 Windows 回归验证后，恢复到旧版本；不得混用不匹配的 Journal 数据与执行器。
5. v0.3 尚无经过完整生产验证的 Windows 安装/自动升级/自动回滚方案，不能宣称已有成品安装器。

## 版本与验收说明

DomainHarness v0.10.3 来源是 Git Tag `v0.10.3`，并不意味着 npm 存在同名包。只允许验证过的**公共 SDK** 构建/安装源；禁止私有 deep import。详情参见 [Provider 信任根与离线恢复](../../provider/v0.3/TRUST.zh-CN.md)。

最终需在 Windows Node>=24 对 J01–J09 逐项保留运行日志、精确 SHA、真实退出码、使用的 BUILD/K/Host 身份；付费 DeepSeek 请求与会产生物理副作用的操作必须分别取得明确批准。未运行者记为 UNKNOWN。

## v0.3 可信 BUILD 启用（待真实环境验证）

运营方先用 DomainHarness v0.10.3 Git Tag 构建并验证四个公共 SDK 包，并获取真实的 K/S 源码与经审核的 Shun B/C Domain Package 源码。准备一个**位于可信本地目录**的构建规格 JSON，其中包括 `appId`、`audience`、`buildId`、`targetProfile=node24-esm/1`、`routes`、`hardBudget`，以及四个 `modules`。每项包含 `module`（packageId/role/abiVersion/endpoint/provides/requires 等公开 BUILD 元数据）、绝对路径 `sourceFile`、经独立确认的 `sourceSha256` 与 `provenance`（K/S：`PUBLIC_DOMAIN_PACKAGE_V0103`；B/C：`SHUN_TRUSTED_DOMAIN_PACKAGE`）。

在 Windows Node>=24 上执行：

```text
node scripts/v03-ci/assemble-trusted-build.mjs C:\\ShunHost\\build-spec.json C:\\ShunHost\\shun-v03.build.json
```

记录命令输出的整体 SHA256，并由可信启动环境分别提供 `SHUN_V03_BUILD_FILE`、`SHUN_V03_BUILD_SHA256`、`SHUN_V03_SDK_CONSUMER_DIR`、`SHUN_V03_KERNEL_DOC_DATABASE`、`SHUN_V03_DEPLOYMENT_ROOT`、`SHUN_V03_TENANT_ID`、`SHUN_V03_DEPLOYED_APP_ID`，以及真实存储模式的安全配置。Guided 需要可信 SQLite 路径 `SHUN_V03_GUIDED_DATABASE`，可选的已签核 Host 选中 Case 文件由 `SHUN_V03_GUIDED_CASE_FILE` 及 `SHUN_V03_GUIDED_CASE_SHA256` 精确绑定。**这些配置不表示自动批准或自动允许物理效果**；未有真实权限与当前性证明时运行仍应拒绝。
