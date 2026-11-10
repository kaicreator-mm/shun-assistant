# Shun Assistant

**Shun** is an AI usability layer for computers and software.

Its product goal is not to teach an AI to click arbitrary interfaces. Shun starts from the user's goal, resolves the required **Capability**, chooses an **Agent-friendly Provider**, selects an execution environment, executes, verifies the result, and retains useful lifecycle state.

Core direction:

```text
User Goal / Object / Constraints
  → Capability
  → Provider
  → Environment
  → Execute
  → Verify
  → Recipe / Lifecycle State
```

Principles:

- Goal-first
- Capability-first
- Agent-friendly Provider first
- UI-last, not UI-never
- Outcome verification
- Safe software/system lifecycle stewardship

## Current status

**v0.3.0** is undergoing the approved Issue #259 R02 whole-version repair. The repair
DAG and minimal Amendment R1 are integrated on `version/v0.3.0`; source corrections
are prepared separately and are **not** a Windows-qualified release. A test
fixture demonstrating DomainHarness activation is not evidence that the shipping
Control API activates the same BUILD. Unqualified J01–J09 journeys, real paid
DeepSeek calls and real physical system effects remain UNKNOWN, not PASS.

- [中文：v0.3 Windows 使用与恢复](docs/guide/v0.3/README.zh-CN.md)
- [English: v0.3 operator guide](docs/guide/v0.3/README.en.md)
- [中文：Provider 信任根与离线恢复](docs/provider/v0.3/TRUST.zh-CN.md)
- [English: Provider trust / offline recovery](docs/provider/v0.3/TRUST.en.md)
- [R02 修复规划与任务契约](docs/planning/v0.3/R02-REPAIR-TASK-PACKS-R1.json)


**v0.1.0** is a previously qualified reference release at immutable tag `2313ba2773dac7aa535570e22760147d9b383b65`; source-level validation is not a claim that all v0.1 Windows installer/UX paths were production packaged.

**v0.2.0** is **Product-Frozen / Stage 2 L2 Architecture in progress** on `version/v0.2.0`. Its scope is a real LLM-first Windows computer steward: system diagnostics and bounded optimization, safely mediated JS/TS Recipes with model-free replay, human-friendly UI, and allowlisted Provider binaries downloaded only as needed. See [v0.2 Product Freeze](docs/product/PRODUCT-FREEZE-v0.2.md), [frozen PRD](docs/product/PRD-v0.2.md), and [L2 candidate](docs/architecture/L2-v0.2-CANDIDATE.md).

**Not yet proven/implemented for v0.2:** trusted LOCAL LLM egress, generic on-demand Provider native loading, portable first-run installer, L2 Freeze, Task DAG, v0.2 runtime features or Release Qualification. L2 real Windows feasibility Issues #85/#86/#87 are open; current controller #83. Product Freeze is not a runtime validation PASS.

This project follows the immutable `kaicreator-mm/ai-development-standard` revision pinned in `.dev-standard/VERSION`.
