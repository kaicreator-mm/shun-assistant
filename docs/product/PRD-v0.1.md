# Shun Assistant — PRD v0.1

> Status: **Product/L1 candidate materialized on GitHub; pending Fresh Independent Adversarial Review.**

## 1. Product Definition

**Shun Assistant** is an AI usability layer for computers and software.

Its job is to make existing computing capabilities easier to use by managing the gap between a user's goal and the software, tools, configuration, lifecycle state, and execution environment required to achieve that goal.

The user manages goals and results. Shun manages software and computing complexity.

Shun is **not** defined by its ability to click arbitrary interfaces. Its preferred path is:

```text
User Goal / Object / Constraints
  → Capability Resolver
  → Discover Provider Candidates
  → Resolve Provider × Environment Bindings
  → Apply Hard Gates
  → Rank Feasible Bindings
  → Acquire / Configure
  → Execute
  → Verify
  → Persist Lifecycle State
  → Optionally Promote a Reusable Recipe
```

## 2. User Problem

Ordinary computer use repeatedly forces users to:

- search for software;
- compare providers;
- avoid untrusted downloads;
- install and configure tools;
- learn unfamiliar UI and software concepts;
- understand system terminology;
- troubleshoot failures;
- remember why software/settings exist;
- later update, retain, remove, or recover them safely.

This cost is especially wasteful for low-frequency tasks where learning and setup cost can exceed the value of the task itself.

The product hypothesis is that a large part of this complexity can move from the user side to the Agent side.

## 3. Product Principles

### 3.1 Goal-first

The primary input is the user's desired result, object, constraints, and acceptable risk—not an application name or a click sequence.

### 3.2 Capability-first

Stable capabilities such as `files.find_duplicates`, `media.video.transform`, `document.ocr`, `software.uninstall_reconcile`, or `system.storage.diagnose` are the task boundary.

Applications are Providers of capabilities.

### 3.3 Agent-friendly Provider first

Human UI usability and Agent usability are separate dimensions.

A Provider with strong API/CLI/library support, structured I/O, batch execution, headless operation, determinism, observability, and version stability may be preferable even when its human-facing UI is difficult.

### 3.4 UI-last, not UI-never

Preferred execution order:

1. native library / stable API;
2. structured CLI / MCP / IPC;
3. file / protocol / configuration interface;
4. semantic UI / accessibility / DOM;
5. vision-based Computer Use.

GUI interaction remains valid when no stable structured path exists or when the task itself depends on continuous visual/spatial/creative judgment.

### 3.5 Verify outcomes

Success is defined by the user's outcome contract, not by an exit code, completed click sequence, or Provider-reported success.

### 3.6 Safety outranks convenience

Metric and decision priority is:

```text
Safety / Data Integrity
> Task Success
> Semantic Verification
> Recovery Correctness
> User Friction
> UI-free Rate
```

UI-free completion and low confirmation count are optimization metrics. They never override a required safety gate or necessary human review.

## 4. Primary User Jobs

### 4.1 Files and digital assets

Search, batch rename, convert, compress, archive, deduplicate, move, verify, back up, and organize files.

### 4.2 Software and capability lifecycle

Discover suitable software, acquire it from a trusted source, configure it, repair it, use it, update it, retain it when useful, or safely remove it and reconcile leftovers.

### 4.3 System understanding and maintenance

Explain why storage is full, collect support context, diagnose performance or device problems, correlate failures with updates/drivers, and maintain stable last-known-good states.

### 4.4 Execution environments

Decide whether a task should run on local Windows, WSL/Linux, a remote Windows host, home server, disposable sandbox, legacy environment, or another RunX backend.

## 5. Capability Contract

Every MVP capability must expose a compact contract containing:

- input/object schema;
- user constraints;
- preconditions;
- expected output;
- side effects;
- verification criteria;
- failure taxonomy;
- supported execution-interface classes.

This contract allows different Providers and execution environments to remain interchangeable.

For the first executable MVP proof, the minimum authoritative contracts are materialized in `docs/product/capability-contracts-v0.1.md` for the shared resolver surface and the three reference verticals. L2 may refine implementation schemas but may not weaken their user-observable semantics without returning to Product/L1 review.

## 6. MVP Scope

MVP acceptance is organized around **three closed user loops**, not nine independent feature projects.

For the **first executable MVP proof**, each loop requires one representative end-to-end reference vertical. Other P0 capability families remain in v0.1 product scope but are expansion coverage after the three reference verticals prove the shared contracts. They must not force separate foundational architectures before the reference loops work.

### Loop A — Process an object

Select files/documents/media → resolve capability/provider → execute → obtain a verified result without learning an application.

P0 examples:

- file batch operations;
- PDF/OCR workflows;
- image batch processing;
- video transformation.

### Loop B — Acquire and use capability

Need capability → resolve Provider → trusted acquire/configure → execute → verify → retain/remove.

P0 software lifecycle is intentionally narrow:

- trusted acquisition;
- install/provenance capture;
- basic repair/reset;
- safe uninstall;
- residue classification;
- retain/remove.

Driver/firmware changes, aggressive registry cleanup, and broad system repair are **not** P0 software-lifecycle scope.

### Loop C — Make the system understandable

Observe → evidence-backed diagnosis → safe bounded action → verify recovery.

P0 examples:

- storage diagnosis;
- structured system-context collection.

### P1

- basic performance diagnosis;
- update/driver stewardship;
- backup/sync stewardship;
- RunX environment resolution;
- common device repair.

### P2

- legacy application capsules;
- creative Co-pilot workflows for CAD/3D/video where visual interaction is part of the actual work.

## 7. Provider Resolver v0.1

Provider selection has two stages.

### 7.1 Hard gates

A **Provider × Environment binding** is not ranked if it fails:

- Capability Fit;
- Trust / Supply Chain;
- Binding Feasibility for the selected environment;
- User / Policy / Safety constraints.

Unknown or unverifiable provenance is fail-closed for normal host acquisition/execution. A user preference alone does not convert unknown provenance into trusted provenance. Any explicitly authorized exception must remain labeled UNKNOWN/UNTRUSTED, be policy-bounded, and use an isolated environment when the risk profile requires it.

### 7.2 Experimental ranking

Initial score dimensions:

- Capability Fit — 25%
- Reliability — 20%
- Agent Usability — 20%
- Trust — 15%
- Environment Compatibility — 10%
- Performance / Resource Cost — 5%
- Human Usability — 5% (100 = lower human interaction friction)

Interaction Complexity and Lifecycle Cost are penalties.

These weights are experimental and must be calibrated against benchmark results.

### 7.3 Risk is separate from ranking

Risk is an execution gate, not a hidden score adjustment.

Read-only and low-risk reversible operations may run automatically.

Destructive or difficult-to-reverse operations require the appropriate combination of plan, preview, backup/checkpoint, explicit approval, rollback strategy, and semantic verification.

## 8. Environment Resolution

Provider and environment are orthogonal dimensions, but feasibility is evaluated on their **binding**, not by rejecting a Provider before its possible environment is known.

The resolution order is:

```text
Capability
→ discover Provider candidates
→ derive each Provider's environment requirements
→ resolve feasible environment candidates
→ create Provider × Environment bindings
→ apply hard gates
→ rank feasible bindings
```

For P0, the environment resolver only needs to prove local feasibility and choose among local-compatible Providers. A local incompatibility may therefore cause selection of another local Provider rather than task failure.

RunX-backed remote/legacy/sandbox placement is P1. When enabled, it expands the environment candidates rather than changing the Provider contract.

## 9. Software Lifecycle State

For managed software, Shun should retain lifecycle state:

- why it was acquired;
- source and provenance;
- exact version;
- dependencies;
- required environment;
- relevant configuration;
- created resources;
- last use;
- last-known-good state;
- whether associated files are user assets, configuration, cache, or generated data.

Low-frequency software should support:

```text
Need → Acquire → Use → Verify → Retain / Remove
```

A Provider should not remain installed indefinitely merely because it was needed once.

Reusable Recipe promotion is separate from mandatory lifecycle-state persistence. Recipe promotion is P1 in v0.1 and must re-check Provider/version currentness and re-run semantic verification on replay.

## 10. Interaction Modes

- **DO** — execute a well-bounded low-risk task.
- **GUIDE** — instruct the user when physical or strongly visual steps are required.
- **CO-PILOT** — share control for creative or complex visual work.
- **AUTOMATE** — persist a validated recurring workflow or maintenance policy.

## 11. Safety and Control

High-risk classes include:

- deletion;
- bulk move/overwrite;
- sync detach;
- deep uninstall;
- driver changes;
- system rollback;
- encryption;
- partitioning;
- recovery operations.

Shun must distinguish user assets from software residue and system data before destructive action.

High-risk operations require risk-appropriate preview, checkpoint/backup, approval, and outcome verification.

### 11.1 Data and privacy boundary

P0 system-context collection and file inspection are subject to data minimization:

- collect only fields required by the active capability/diagnosis;
- exclude credentials, tokens, private keys, browser/session secrets, and unrelated document contents by default;
- preserve the distinction between **local collection** and **external model/provider disclosure**;
- do not send collected system/file context to a remote model or service when user/policy constraints require local-only handling;
- redact or summarize sensitive paths/identifiers when full fidelity is unnecessary;
- make any required external disclosure explicit in the execution plan and subject to policy/approval;
- never treat consent as proof that a source or Provider is trusted.

The Product contract must remain implementable with local-only execution for P0 reference loops where their selected Providers support it.

## 12. Non-Goals for MVP

The MVP will not:

- attempt universal visual operation of every application;
- replace professional creative software;
- support every device-vendor control panel;
- build a compatibility database for all legacy applications;
- make RunX a prerequisite for all P0 flows;
- use number of supported apps as the primary success metric;
- claim a population-wide UI-free percentage from exploratory evidence.

## 13. Success Metrics

Primary product-validation metrics:

- Task Success Rate;
- First-attempt Success;
- Semantic Verification Pass Rate;
- Provider Top-1 Accuracy;
- UI-free Completion Rate;
- User Confirmation Count;
- Rollback / Recovery Success;
- Recipe Replay Success.

For repeated tasks, planning/tool-call cost should decrease after a validated Recipe is persisted.

## 14. Validation Plan

The benchmark contains component tasks plus three required end-to-end reference journeys spanning:

- files;
- documents/OCR;
- images;
- video;
- software acquisition and lifecycle;
- storage/system diagnosis;
- drivers;
- sync;
- RunX environment placement;
- workflow composition;
- Provider ranking;
- Recipe replay;
- deliberate creative/UI-heavy counterexamples.

Exploratory research supports the product direction but does not prove a population-wide UI-free percentage.

The next evidence must come from real execution: target completion, semantic verification, user-confirmation count, Provider-ranking correctness, failure recovery, and controlled failure injection.

Initial execution evidence covers 13 cross-platform deterministic component tasks:

- 9 full PASS;
- 3 scale-smoke PASS;
- 1 partial PASS caused by the absence of a 7-Zip Provider on that host;
- all 13 executed without UI interaction.

This evidence applies only to the tested subset. It does not validate Windows-specific Store, driver, OneDrive, device, or RunX behavior.

## 15. Product Freeze Gate

PRD v0.1 may freeze only when:

1. the candidate is materialized on one exact GitHub SHA;
2. Fresh Independent Adversarial Review is performed against that exact SHA;
3. no unresolved P0 product contradiction remains;
4. required P1 product contradictions are closed;
5. the benchmark plan contains one end-to-end reference journey for each P0 MVP loop, with explicit inputs, resolution decisions, verification, risk gates, and failure cases;
6. any changed successor SHA receives affected re-review;
7. a durable terminal records `PRODUCT_FREEZE_ELIGIBLE=YES` and the exact candidate identity.

Implementation scope must not broaden before this gate.

PR PASS != Product Freeze.

## 16. Evidence Authority

Canonical Product/L1 authority for this candidate is the exact GitHub commit under review, comprising:

- `docs/product/PRD-v0.1.md`
- `docs/product/L1-product-evidence.md`
- `docs/product/product-decisions.md`
- `docs/product/provider-resolver-v0.1.md`
- `docs/product/mvp-capability-map.md`
- `docs/validation/benchmark-v0.1.md`
- `docs/validation/benchmark-results-v0.1.md`
- `docs/review/prd-v0.1-adversarial-review-pack.md`

The detailed Google Drive workbook is a supporting research archive, not Product authority.
