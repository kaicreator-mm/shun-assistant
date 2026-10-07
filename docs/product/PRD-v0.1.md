# Shun Assistant — PRD v0.1

> Status: L1 evidence complete; cross-platform execution benchmark started; PRD ready for fresh independent adversarial review.

## 1. Product Definition

AI Computer Assistant is an AI assistant that makes systems and software easier to use by managing the user’s computing capabilities, software lifecycle, and execution environments. The user manages goals; the assistant manages software and computing environments.

The product is not defined by its ability to click arbitrary interfaces. It should resolve the user’s goal into a semantic capability, choose the most reliable machine-friendly provider, select an appropriate execution environment, execute, verify the result, and retain useful lifecycle state.

## 2. Problem

Ordinary computer use repeatedly forces users to search for software, compare providers, avoid untrusted downloads, install and configure tools, learn unfamiliar interfaces, understand system terminology, troubleshoot failures, and later remember why software or settings exist. This cost is especially wasteful for low-frequency tasks.

Current general computer agents often optimize for universal UI operation. The evidence collected for this product suggests a different default: use native APIs, libraries, CLI, IPC, file/protocol interfaces, or composed scripts first; use semantic UI automation next; use vision and raw mouse/keyboard only when no stable structured path exists or when the task itself genuinely depends on visual judgment.

## 3. Product Principles

Goal-first. The primary input is the user’s desired result, object, constraints, and acceptable risk—not an application name or sequence of clicks.

Capability-first. Stable user intents such as files.find_duplicates, media.video.transform, document.ocr, software.uninstall_reconcile, or system.storage.diagnose are the main abstraction. Applications are providers of capabilities.

Agent-friendly-provider-first. Human UI usability and Agent usability are separate dimensions. A provider with strong CLI/API/library, structured I/O, batch, headless execution, deterministic behavior, observability, and version stability may be preferable even when its human-facing UI is difficult.

UI-last, not UI-never. GUI interaction is a fallback or collaboration surface. Complex CAD/3D creation, video timeline editing, framing, and other inherently visual work should use Guide/Co-pilot modes instead of pretending to be fully UI-free.

Verify outcomes. Success is defined by the user’s goal and output contract, not by an exit code, a completed click sequence, or a provider reporting success.

## 4. Primary User Jobs

File and digital asset jobs: search, batch rename, convert, compress, archive, deduplicate, move, verify, back up, and organize files.

Software jobs: discover suitable software, acquire it from trusted sources, configure it, repair it, use it, update it, retain it when useful, or safely remove it and reconcile leftovers.

System jobs: explain why storage is full, collect support context, diagnose performance or device problems, correlate failures with updates or drivers, and maintain stable last-known-good states.

Environment jobs: decide whether a task should run on local Windows, WSL/Linux, a remote Windows host, home server, disposable sandbox, legacy environment, or another RunX backend.

## 5. Core Resolution Flow

User Goal / Object / Constraints → Capability Resolver → Provider Resolver → Environment Resolver → Acquire / Configure → Execute → Verify → Persist Recipe / Lifecycle State.

Provider and environment resolution are orthogonal. The same provider can bind to different environments, and a failed local compatibility check should trigger environment resolution rather than automatically failing the user task.Every MVP capability must expose a compact contract: input/object schema, user constraints, preconditions, expected output, side effects, verification criteria, failure taxonomy, and supported execution-interface classes. This contract is what allows different providers and environments to remain interchangeable.

## 6. MVP Scope

P0 capabilities are: Capability Resolver + Provider Registry; trusted software acquisition; software lifecycle management; file batch operations; PDF/OCR workflows; image batch processing; video transformation; storage diagnosis; and structured system-context collection.MVP acceptance is organized around three closed user loops rather than nine independent feature projects. Loop A — Process an object: select files/documents/media and obtain a verified result without learning an application. Loop B — Acquire and use capability: resolve suitable software, acquire/configure it, execute the task, verify the result, then retain or remove it safely. Loop C — Make the system understandable: observe why the computer is full/slow/broken, produce evidence-backed diagnosis, take a safe bounded action, and verify recovery.
P0 software lifecycle is intentionally narrow: trusted acquisition, install/provenance capture, basic repair/reset, safe uninstall, residue classification, and retain/remove. Driver/firmware changes, aggressive registry cleanup, and broad system repair are not P0 lifecycle scope.

P1 follows with basic performance diagnosis, update/driver stewardship, backup/sync stewardship, RunX environment resolution, and common device repair.

P2 includes legacy application capsules and creative Co-pilot workflows for CAD/3D/video where visual interaction is part of the actual work.

## 7. Provider Resolver v0.1

Hard gates: Capability Fit, Trust/Supply Chain, Environment Compatibility, and user/policy constraints. Providers that fail a hard gate are not ranked.

Initial score dimensions: Capability Fit 25%; Reliability 20%; Agent Usability 20%; Trust 15%; Environment Compatibility 10%; Performance/Resource Cost 5%; Human Friction 5%. Interaction Complexity and Lifecycle Cost are penalties. These weights are experimental and must be calibrated against the benchmark.

Risk is not folded into provider score. Risk is a separate execution gate: read-only actions can run automatically; destructive or difficult-to-reverse operations require preview, appropriate backup/checkpoint, explicit approval where required, and outcome verification.

## 8. Execution Interface Preference

Preferred order: native library/stable API → structured CLI/MCP/IPC → file/protocol/config interface → semantic UI/accessibility/DOM → vision-based Computer Use. MCP is an Agent-facing transport, not the domain core; CLI remains important for deterministic execution, debugging, CI, SSH, and remote environments.

## 9. Software Lifecycle State

For managed software, the assistant should retain why it was acquired, source and provenance, exact version, dependencies, required environment, configuration, created resources, last use, last-known-good state, and whether associated files are user assets, configuration, cache, or generated data.

Low-frequency software should support Need → Acquire → Use → Verify → Retain/Remove. A provider should not remain installed indefinitely merely because it was needed once.

## 10. Interaction Modes

DO: execute a well-bounded low-risk task. GUIDE: instruct the user when physical or strongly visual steps are required. CO-PILOT: share control for creative or complex visual work. AUTOMATE: persist a validated recurring workflow or maintenance policy.

## 11. Safety and Control

High-risk classes include deletion, bulk move/overwrite, sync detach, deep uninstall, driver changes, system rollback, encryption, partitioning, and recovery operations. These require plan/preview/backup-or-checkpoint/verify appropriate to the risk. The assistant must distinguish user assets from software residue and system data before deletion.

## 12. Non-Goals for MVP

The MVP will not attempt universal visual operation of every application, replace professional creative software, support every device vendor control panel, build a compatibility database for all legacy applications, or use ‘number of supported apps’ as the primary success metric.

## 13. Success Metrics

Primary metrics: task success rate, first-attempt success, UI-free completion rate, Provider Top-1 accuracy, user-confirmation count, rollback/recovery success, verification pass rate, and recipe replay success. For repeated tasks, planning/tool-call cost should decrease after a validated recipe is persisted.Metric priority is Safety and data integrity → task success → semantic verification → recovery correctness → user friction → UI-free rate. UI-free completion and low confirmation count are optimization metrics; they must never override a necessary safety gate or human visual judgment.

## 14. Validation Plan

The current benchmark contains 36 tasks spanning files, documents/OCR, images, video, software acquisition and lifecycle, storage/system diagnosis, drivers, sync, RunX environment placement, workflow composition, provider ranking, recipes, and deliberate creative/UI-heavy counterexamples.

Exploratory sampling supports the product direction but does not prove a population-wide UI-free percentage. The next evidence must come from real execution: measure target completion, verification, number of user confirmations, provider-ranking correctness, and failure recovery under controlled failure injection.Initial execution evidence now covers 13 cross-platform deterministic benchmark tasks: 9 full PASS, 3 scale-smoke PASS, and 1 partial PASS caused by a missing 7-Zip provider on the current host. All 13 completed without UI interaction. This is execution evidence for the tested subset only; it does not validate Windows-specific Store, driver, OneDrive, device, or RunX behavior.

## 15. Release Gate for PRD v0.1

PRD v0.1 may freeze after independent adversarial review finds no unresolved P0 product contradiction and the benchmark plan covers every P0 MVP capability with explicit inputs, verification, risk gates, and at least one failure case. Implementation should not broaden scope before this gate.

## 16. Evidence Source

Evidence workbook:

## Evidence provenance

Canonical Product/PRD authority is the GitHub exact SHA under review. The detailed Google Drive workbook remains a supporting research archive only.