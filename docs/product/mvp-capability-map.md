# Shun v0.1 — MVP Capability Map

MVP acceptance is organized around three closed loops:

1. **Process an object** — file/document/media → verified result.
2. **Acquire and use capability** — resolve Provider → trusted acquire/configure → execute → verify → retain/remove.
3. **Make the system understandable** — observe → evidence-backed diagnosis → safe bounded action → verify.

## First executable MVP proof

The first executable MVP proof is deliberately smaller than the complete P0 coverage map. It MUST prove:

- shared core: Capability Resolver + Provider Registry;
- Loop A reference vertical: one real object-processing capability with Provider selection and semantic verification;
- Loop B reference vertical: trusted JIT acquisition → use → lifecycle-state capture → retain/remove for one real Provider;
- Loop C reference vertical: storage/context observation → diagnosis → previewed safe bounded action → recovery verification;
- data minimization/redaction for collected system context.

The other P0 rows below are **v0.1 expansion coverage** after these reference verticals work. They do not each justify a separate foundational architecture before the reference proof passes.

| Priority | Capability_Area | Representative_Intents | Why_Now | Preferred_Providers_or_Path | Environment | Risk | MVP_Success_Criterion | UI_Last_Target | Evidence | Out_of_Scope_v0 | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P0 | Capability Resolver + Provider Registry | “我想做 X，用什么最合适？” | 整个产品核心；R2/R5 最强差异化 | Registry + Provider metadata + score v0.1 | Local metadata | Low | Top-1 Provider 在 benchmark 中满足 contract 且理由可解释 | 100% no visual UI for resolution | R2/R5 | 自动适配所有软件 | MVP |
| P0 | Trusted Software Acquire | 找到官方/可信来源并按需安装/portable 获取 | 软件选择不完成 acquisition 就不能闭环 | winget/official release/portable + signature/hash/provenance | Local Windows | Medium | 可重复 acquire；记录来源/版本/安装原因 | ≥95% UI-free | R2/R5 | 破解/未知来源软件 | MVP |
| P0 | Software Lifecycle | repair/reset/uninstall/残留/retain-remove | JIT 软件与长期 Stewardship 的关键 | native uninstaller/package APIs + provenance reconciliation | Local Windows | High | 卸载不误删用户资产；可验证残留与回滚 | ≥90% UI-free | R1/R2/R5 | 任意驱动/内核级清理 | MVP |
| P0 | File Batch Operations | 批量重命名、移动、归档、搜索、哈希 | 高频、低成本、最适合验证组合工具路线 | filesystem APIs + 7z + Everything-like index + Python glue | Local Windows | Medium | 100–10k 文件任务结果正确且可预览/撤销 | ≥98% UI-free | R2/R5 | 复杂数据恢复 | MVP |
| P0 | PDF / OCR Workflow | 合并、拆分、压缩、OCR、可搜索 PDF | 普通用户低频但高痛点，机器接口成熟 | NAPS2/OCRmyPDF/Tesseract/PDF engine | Local Windows | Low/Medium | 输出可打开、页数/文本/尺寸验证通过 | ≥95% UI-free | R2/R5 | 复杂版式人工设计 | MVP |
| P0 | Image Batch | 缩放、格式转换、压缩、简单裁剪 | 高覆盖且可验证 | libvips/ImageMagick/IrfanView CLI | Local Windows | Low | 尺寸/格式/质量约束自动验证 | ≥98% UI-free | R2/R5 | 高级修图/审美创作 | MVP |
| P0 | Video Transform | 压缩、转码、抽音频、目标大小 | 真实需求强且 GUI 参数复杂 | FFmpeg/HandBrakeCLI + ffprobe | Local/RunX | Low | 输出可播放、时长/轨道/目标大小满足约束 | ≥95% UI-free | R2/R5 | 创意时间轴剪辑 | MVP |
| P0 | Storage Diagnosis | C盘为什么满、谁在增长、什么能安全清 | R1/R3 高价值；能证明“系统也变好用” | WizTree-like scan + filesystem/app attribution + Windows APIs | Local Windows | High | 解释主要占用来源；清理方案区分用户资产/缓存/系统数据 | ≥95% diagnosis UI-free | R1/R3/R5 | 自动大规模删除 | MVP |
| P0 | System Context Collector | 电脑慢/软件坏时自动采集版本、更新、日志、设备上下文 | 减少用户截图/复制型号/重复修复 | PowerShell/WMI/EventLog/perf APIs | Local Windows | Low | 一次采集形成结构化 support context | 100% UI-free | R1/R3 | 全自动修复所有系统故障 | MVP |
| P1 | Basic Performance Diagnosis | 电脑卡顿、应用冻结 | 高价值但根因空间大 | ETW/perf/process/storage correlation | Local Windows | Medium | 能给 evidence-backed hypothesis + next safe action | ≥90% UI-free | R1/R3 | 硬件实验室级诊断 | NEXT |
| P1 | Update / Driver Stewardship | 更新后蓝牙/音频/性能坏了 | R1/R3 强证据，体现 last-known-good | update history + hardware IDs + OEM resolver + rollback | Local Windows | High | 识别关联版本并能安全 rollback/verify | ≥85% UI-free | R1/R3 | 自动 BIOS/firmware flash | NEXT |
| P1 | Backup / Sync Stewardship | 本地+云端、OneDrive 文件去哪了 | 高价值但数据风险高 | known-folder/sync APIs + manifests + hashes | Local/remote storage | High | 用户可理解真实位置；detach/backup 可验证无丢失 | ≥90% UI-free | R1/R3 | 复杂企业同步系统 | NEXT |
| P1 | Environment Resolver / RunX binding | 本机跑不了、旧软件、远程电脑 | 架构差异化；R4 明确需求 | RunX local/remote/legacy/sandbox | Local + one remote backend | Medium | Provider 可透明绑定至少两种 environment | 100% placement no visual UI | R4 | 全平台全环境 | NEXT |
| P1 | Common Device Repair | Bluetooth/audio/printer/camera/USB | 需求强但物理/OEM 差异大 | PnP/service/driver/device APIs + guide fallback | Local Windows | Medium | 标准故障 DAG 可自动采证并明确物理步骤 | ≥80% UI-free steps | R1/R3 | 所有专有硬件控制面板 | NEXT |
| P2 | Legacy App Capsules | 旧 16-bit/长期依赖软件 | 价值高但覆盖窄 | RunX legacy Windows/compatibility layer + pinned recipe | Remote/isolated | Medium | 单个示范 legacy app 可复现运行 | ≥90% setup UI-free | R4 | 广泛兼容数据库 | LATER |
| P2 | Creative Co-pilot | CAD/3D/video timeline | R4 明确是真 UI 边界 | structured substeps + native GUI/viewport | Local/remote GPU | Low | 自动化准备/导出；用户保留创意决策 | 不以 UI-free 为目标 | R4/R5 | 全自动替代专业创作 | LATER |
