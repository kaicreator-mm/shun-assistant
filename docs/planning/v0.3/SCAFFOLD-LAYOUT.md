# Shun v0.3 — Minimal Domain App Scaffold Contract (planning, non-executable)

**STATUS:** `SCAFFOLD_PLAN_READY / SCAFFOLD_SOURCE_NOT_AUTHORIZED`. Related L2 [#217](https://github.com/kaicreator-mm/shun-assistant/issues/217) and Product [#214](https://github.com/kaicreator-mm/shun-assistant/issues/214). This layout is a **source-only generation specification**, not an actual generated runnable project or authority to write the listed paths.

## 1. Design choice: only 3 new workspace packages, reuse existing modules

Reuse existing `pnpm-workspace.yaml` matching `packages/*`; **no new monorepo, nested private node_modules, custom framework, global scaffold engine or new UI framework**.

```text
shun-assistant/                # existing pnpm monorepo (Node >=24)
├── .dev-standard/             # v0.3 separate ADS adoption #216; do NOT copy old effective pin as v4.18
├── apps/
│   ├── control-api/           # existing; activation only at integration owner T11
│   └── control-ui/            # existing; activation only at integration owner T11
├── packages/
│   ├── domain-computer/      # NEW, owned manifest/exports T00
│   │   ├── package.json       # T00 exclusive manifest; no lane may edit
│   │   ├── tsconfig.json      # T00 exclusive
│   │   └── src/
│   │       ├── contracts/     # T00 frozen internal, non-authoritative Shun DTO adapter
│   │       ├── semantic/      # T03 goal/typed proposal mapping
│   │       ├── computer/      # T02 Windows diagnosis B/declared C
│   │       ├── cloud/         # T04 explicit LLM request B/C routing data
│   │       ├── guided/        # T05 approved guided step business logic
│   │       ├── feedback/      # T06 redacted Meta candidate + Shadow workflow
│   │       ├── recipes/       # T07 identity/replay B
│   │       └── provider/      # T08 signed JIT lifecycle B
│   ├── domain-host/          # NEW, selected trusted Host adapter, T00 manifest
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   └── src/
│   │       ├── windows/       # T01 real ActionController & OS gate; no duplicate K
│   │       ├── cloud/         # T04 strict DTO→CloudInterpretPort bridge; one legacy exact-byte Host sender
│   │       ├── provider/      # T08 real signed artifact/ABI
│   │       └── state/         # T01 old-workflow-journal read-only + authorized ShunStore business-record bridge
│   ├── domain-app/           # NEW, T00 skeleton / T09 assembly and T11 activation only
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   └── src/
│   │       ├── build/         # T09 only; external BUILD, chosen real public SDK modules
│   │       ├── api/           # T09 only; typed API bridge
│   │       └── index.ts       # T11 only: versioned installed App composition/entrypoint
│   ├── contracts/            # KEEP v0.2
│   ├── authorization/        # KEEP v0.2
│   ├── executor-windows/     # KEEP v0.2
│   ├── store/                # KEEP v0.2 history
│   └── ...                    # KEEP remaining v0.2 legacy packages
├── tests/
│   └── integration/
│       └── v03/              # each Task owns its own subfolder tests
│           ├── t00-scaffold/
│           ├── t01-host/
│           ├── t02-computer/
│           ├── t03-semantic/
│           ├── t04-cloud/
│           ├── t05-guided/
│           ├── t06-meta/
│           ├── t07-recipes/
│           ├── t08-provider/
│           ├── t09-api/
│           ├── t10-ui/
│           ├── t11-runtime/
│           └── t12-qualification/
└── docs/implementation/v0.3/    # frozen packs / future actual evidence
```

**Business-data preservation:** selected K is the single migrated **external effect/orchestration Journal owner**. Existing `packages/store/src/shun-store.ts` persists authorized business records and stable idempotent `apply(effectId)` receipts; it is **not a competing Kernel**. The old `packages/workflow/src/journal.ts` is read-only for migrated cases; no second active physical operation dispatcher. Actual Host adapter must enforce K Permit + fresh ActionController grant, never rely on old ShunStore receipts as permission.

### T00 first source Scaffold (post-freeze only)

Generate *only* three workspace package manifests, minimal TypeScript configs, empty non-effectful module entrypoints and contracts derived from **actual selected** SDK public exports, plus one Node24 test verifying a clean public import; keep all adapters `NOT_IMPLEMENTED` and no-op **only where no side effects are possible**. No fake permit, mock authorized Windows effect or stale v0.10.2 selected ABI declared v0.10.3.

**T00 SDK dependency is now qualified Git source, NOT a missing upstream release.** Pin `kaicreator-mm/domain-harness` Git tag `v0.10.3` at exact main/tag SHA `061376f4a023070f215f9feffad5c24d96d503cb`, source tree `099cdc831aef63befd62aaede7e7a853d1be468f` (identical to reviewed candidate `7d571858bd6524ffd13a7985227183dbecb2924a`). Release Qualification is CONDITIONAL Git-source-only (RQ P0/P1/P2=0/0/3); npm v0.10.3 was NOT published, package workspace manifests are still versioned `0.10.2-rc.0`. Build/pack four public SDK workspace packages **locally from this exact tag**, install pinned pack artifacts with SHA256 into an isolated Node>=24 consumer; never resolve them as supposedly public npm `v0.10.3`. Avoid relying on `docs/current`/default Skill (still v0.10.2); use `docs/guides/v0.10.3` and tag-qualified exports. This is now a deterministic T00 acceptance obligation, not a reason to wait. The imported dependencies are:
```text
@kaicreator/domain-harness-contracts
@kaicreator/domain-harness-build     # BUILD producer only
@kaicreator/domain-harness-microkernel
@kaicreator/domain-harness-host-node
```
Use only documented package roots. The optional `@kaicreator/domain-harness-host-node/llm/openai` client exists but **must NOT be installed as a second physical sender for Shun v0.3**: it independently serializes its body without the existing Shun ledger's actual-wire-byte callback. Selected `capability-llm-openai-compatible` C imports the trusted static deployment-provided `domain-harness-openai-host.generate`, which T04 maps to the existing signed-approval `TrustedCloudInterpreter.interpretGoal` via a strict one-user-goal neutral DTO adapter and T11's real Control API wiring. The original `TrustedDeepSeekTransport` alone constructs/sends the identical approved ledger-checked bytes (`thinking:disabled`). T00 is structural only and must **not** fake this wiring or send traffic. No provider fallback, no Host-owned model choice from untrusted payload. Unit scaffolding alone does not prove the installed consumer/Host semantics.

**T00 source allowed writes, and no others**:
```text
packages/domain-computer/package.json
packages/domain-computer/tsconfig.json
packages/domain-computer/src/contracts/**
packages/domain-host/package.json
packages/domain-host/tsconfig.json
packages/domain-app/package.json
packages/domain-app/tsconfig.json
tests/integration/v03/t00-scaffold/**
```
Package metadata must not add postinstall/install scripts, privileged effects, downloads or recursive new workspace imports; live `pnpm-lock.yaml` is owned solely by T11 if needed and must be reviewed. Public package entrypoints/index exports are reserved to T11 integration; T00 may prepare only internal non-dispatchable module stubs and exact documented static shape.

## 2. Scaffold effect/safety guardrails

- **No executable public App** is available before T09/T11; the Scaffold is structural proof, not a bypass execution path. The qualified upstream Git tag itself does NOT prove the Shun packed/installed external consumer succeeded.
- **No second K, no second effect Journal, no arbitrary code evaluation, no execution via chat/LLM advisory, no automatic permission, no broad install commands.**
- **No file copy or migration of private ShunStore/Windows user data.** Existing v0.2 modules remain in place.
- Source subdirectories are reserved by concern; task code must not edit sibling manifest/export/entrypoint. Composition/build `packages/domain-app/src/build/**` and `src/index.ts` have separate owners.
- CI tests run on Node 24; **actual compiler/pack/install result** must use the exact Node24 and SDK source. The plan itself has `EXIT=NOT_RUN`, never PASS.

**Known published SDK safety limitation (#1437):** raw untrusted `DomainApp.send()` may write K Effect Journal before rejecting malformed Case input. T09 creates one pre-send trusted Control API source/Case gateway; T11 owns route wiring without a second raw-send. T00 must **not** expose `DomainApp.send` to callers, invent a recovery API, mark a malformed Case safe to replay or confuse a poisoned Case with a no-effect guarantee. Later negative tests show malformed Case rejected with **zero calls into the facade** and zero K Effect Journal rows; next valid same Case permitted only under genuine authorization.

## 3. ADS §2.4A scaffold admission (mandatory, current fail-closed)

To turn this draft into source **before** full Task DAG:
1. Independent Product R1 + owner explicit Product Freeze on exact PRD and L1.
2. L2 R1 source proof and owner explicit L2 Freeze on exact L2.
3. Shun **v0.3** explicit qualified ADS v4.18 adoption (or restrictive effective 4.13.1 if compatible Scaffold permission not established — normally no pre-DAG Scaffold).
4. Existing canonical planning Work Item records actual **exact allowed paths** above, risk `high` (public ABI, external-effect Host seam), `review:required` and original frozen product/L2 identities.
5. Single **accepted native CAS Builder Claim**, actual native dependencies and JIT base readback; no active colliding writer.
6. Generate T00 only; verify installed public exports and negative denial tests; independent required source R1; owner authorized merge. Freeze/evidence checkpoint does not itself authorize effects.

**Default simpler route:** after Product/L2 freeze, freeze and materialize the [proposed Task DAG](TASK-DAG-v0.3-R0.md), then the local Builder uses regular T00 implementation Claim and generates the same Scaffold. **Prefer this route** unless a real earlier Scaffold delivers a falsifiable advantage. This avoids a redundant source-only pre-DAG pipeline.

## 4. Verification checklist / handoff

```text
PASS only when observed:
- GitHub current accepted v0.3 Product/L2/Task DAG and Task T00 Claim
- selected exact DH v0.10.3 public package export identity + Node24 clean consumer
- no BUILD import from running App and no private SDK deep import
- exact T00 write set, sibling lane directories absent
- project pnpm workspace already covers packages/* (verified source)
- no postinstall/remote/Windows effect
- actual scoped lint/typecheck/Node24 test exit = 0
- independent R1 if required, current SHA, lawful merge version-only
CURRENT: SCAFFOLD_PLAN_READY; SCAFFOLD_SOURCE=NOT_RUN
```

## 5. Consumer-facing first implementation trigger (after authorization only)

```text
按 ADS v4.18 #1241 执行 Shun Assistant v0.3 T00。
先读取 GitHub v0.3 版本总控、精确 Product/L2 Freeze、冻结 Task Pack、
当前原生 Issue blocked_by、Task Claim/角色、ADS 实际采用 SHA、SDK v0.10.3
候选或 Release 的精确包 SHA。若任一主体尚未准入则只读报告 HOLD。
仅在合法时生成 docs/planning/v0.3/SCAFFOLD-LAYOUT.md 所列 T00 三个
packages 的 package.json/tsconfig + 内部 non-effectful stub 与 Node24 公共
SDK import 负例。不得导入私有 SDK、启动网络/Windows Effect、变更
v0.2/main、抢占 T01–T12 写集或伪造测试 PASS。
给出 exact commit SHA、实际 CLI EXIT、PR 到 version/v0.3.0 及待审核状态。
```
