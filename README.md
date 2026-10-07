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

The repository is being initialized for **v0.1 Product/L1 candidate review**.

No Product Freeze, L2 Architecture Freeze, implementation baseline, or release status is claimed yet.

This project follows the immutable `kaicreator-mm/ai-development-standard` revision pinned in `.dev-standard/VERSION`.
