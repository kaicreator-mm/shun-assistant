# Shun Assistant v0.3 — DomainHarness L2 Architecture R0 / UNFROZEN

**State:** `L2_R0_REBASED_TO_FROZEN_PRODUCT / ARCHITECTURE_R1_NOT_RUN / NO_SOURCE_AUTHORITY`. Owner [#217](https://github.com/kaicreator-mm/shun-assistant/issues/217); Product [#214](https://github.com/kaicreator-mm/shun-assistant/issues/214). Exact Product/L1 Owner Freeze [checkpoint](https://github.com/kaicreator-mm/shun-assistant/blob/version/v0.3.0/docs/product/PRODUCT_FREEZE-v0.3.md) at `version/v0.3.0@c8334c7723eecf7fbbb6895b1defd6439edc6b95`, freeze blob `0f8a67c2f06364d58a842502d3dee11bfeeedba4`; reviewed Product PR #215 `4c2f8e84b6e6f3f5b526e52d01356159f2dce0e7`, reviewed PRD `f062b7f2c3dc3bf4aeeb7594ab5c2bc75b34d0ab`, L1 `4c703c3f0c283f4d3918babef8f87f56869698e5`, independent R2 P0/P1/P2=0/0/0, explicit Product Owner [approval](https://github.com/kaicreator-mm/shun-assistant/issues/214#issuecomment-6477255283). This L2 still requires its **own independent R1 and Architecture Owner Freeze**.

**Source identities:** ADS v4.18.0 qualified `2c395c55569fe2edf3f4135f12d3d069e526d0b7` (project adoption #216 pending); Shun v0.3 frozen Product checkpoint `c8334c7723eecf7fbbb6895b1defd6439edc6b95` derived from initial v0.2 **planning snapshot** `f01233a002f65b9bfea04828f6e56914666a160a` (not v0.2 Release); DH v0.10.3 Product/data Contract/L2 frozen, SDK version branch observed `7d571858bd6524ffd13a7985227183dbecb2924a` (not immutable published package).

## 1. Architecture drivers, domains and selected deployment profile

Goal: user `Goal` → normalized `S` → typed bounded `B` → selected `C` operations → one `K` admission/Journal → trusted Windows, LLM or Provider `Host` → externally verified results → optional immutable Recipe and redacted feedback. Explicit human approval remains separate from AI suggestion and K admission.

- **System boundary**: Windows 11 Home/Pro x64 local primary user; desktop Control UI + local Control API; Node 24+ for selected Domain App/Host; native NAPI-RS/UAC used only by existing Shun physical executor (as required). Chinese and English real nondeveloper UI must preserve identical scope/approval/refusal/UNKNOWN semantics.
- **Build boundary**: selected external `@kaicreator/domain-harness-build` builds immutable closed-world App. Do not import BUILD in production runtime. Load via the selected `@kaicreator/domain-harness-microkernel` public load/send/query/subscribe/stop; contracts/guards from `...-contracts`, Host/CAS from `...-host-node`. No private deep imports or shadow Kernel. Exact SDK package identity and installed consumer ABI to be recorded after qualified SDK packaging.
- **Selection profile**: one DomainHarness K; selected semantic S; private Shun Business B and declared C; zero or one OpenAI-compatible selected C for current DeepSeek use (Anthropic optional future, **not** required for Shun v0.3), existing selected Meta S/Host. Explicit BUILD B→C binding, no runtime provider auto-routing.
- **Compatibility**: retain original Shun v0.2 packages in-place; put new Domain components in disjoint `packages/domain-*` packages. Integration is adapter-first, no rewrite of native executor or signed Provider loader.

### Package and responsibility diagram

```text
apps/control-ui (existing Shun user UI, real explicit user gesture)
           |
apps/control-api (existing authentication and API, integration only)
           |
packages/domain-app (single BUILD output and composition writer)
      |               [K] one selected DomainHarness K
      |                         | Permit + Journal + UNKNOWN
      +-- packages/domain-semantic [S: typed goal normalization]
      +-- packages/domain-windows  [B: inventory/folder diagnosis intents]
      +-- packages/domain-llm      [B: explicit DeepSeek task advice / selected OpenAI C]
      +-- packages/domain-guided   [B: approved current StepSpec, choices/outcomes]
      +-- packages/domain-feedback [B/S: meta-feedback with Host validation/shadow]
      +-- packages/domain-recipes  [B: stable recipe graph / replay]
      +-- packages/domain-provider [B: JIT Provider lifecycle]
      +-- packages/domain-host     [trusted Shun Host adapter]
                                   |
                           Shun ActionController grant + currentness
                                   |
               trusted existing Windows Executor / LLM Host / signed Provider
                                   |
                          observed user-visible result
```

**Important:** The illustrated selected S/B/C grouping is a design seam, not a claim that these package identifiers are actual DomainHarness SDK-selected IDs. The Scaffold must derive selectable identities from **actual public exports and frozen contract**. No SDK private entrypoints may be invented.

## 2. Trust and effect authorization

1. User goal and remote proposal are **untrusted**. Validate canonical GoalRequest/GoalProposal + scoped source DTO **before calling `DomainApp.send`**. No unknown target, unapproved disclosure, arbitrary command, auto-grant or faux provenance from model content.
2. The user previews bounded plan and accepts precisely the targeted operation; capture an authenticated Shun authorization currentness proof tied to current file object, effect, Case, expected state, selected Provider and expiry. UI/form selection alone is not a grant.
3. DomainHarness K receives a typed admitted operation and issues **its own** effect Permit after K policy. K is sole authority over migrated effect operation identity, Journal and Replay/UNKNOWN. Host cannot fake K permission.
4. **Right before an external effect**, trusted Shun Host verifies current human consent/grant, OS/UAC rights, root/path/policy currentness and effect-specific typed parameters; refusal means **zero external side effect** and truthful K receipt. No second implicit Shun Journal commit is permitted for the same physical-effect identity.
5. Real Windows effect executes once via existing executor, followed by independently observed poststate/canary. Model, callback and UI success messages do not establish poststate. If uncertain whether an effect occurred, retain UNKNOWN/admission fence until independent reconciliation; never blind replay.
6. Host secret, endpoint, protected operator approval, K Permit and output provenance are separate trusted facts. External GitHub/remote provider/LLM responses cannot supply permission.

**P0 L2 open verification:** Prove K Permit / Shun grant final-currentness composition ordering with actual SDK public selected-K API; a test-only shim that bypasses either guard is BLOCK. Distinguish old `WorkflowEffectJournal` (orchestration intents/attempts) from `ShunStore` (authoritative business records with idempotent application receipts). The **old workflow orchestration journal** must not dispatch migrated Case/effect; `ShunStore.apply(effectId, mutation)` may legitimately continue a K-mediated **business-data write**, with its transaction/receipt semantics retained. Do not reject all live ShunStore writes or conflate business idempotency receipts with a second Kernel Permit journal. A bounded public-SDK integration test must prove exact binding and no duplicate physical effect (no new generic Host CAS library).

## 3. LLM and remote privacy

- Reuse v0.10.3 neutral `dh.llm.generate/1`, explicit selected `llm.openai.generate` C and `@kaicreator/domain-harness-host-node/llm/openai`, plus Shun's existing pre-send privacy/budget/consent and purpose-limited prompt. DeepSeek is OpenAI-compatible from trusted Host config; no model text controls endpoint, key, external disclosure, extra tools or cost. No automatic fallback to Anthropic.
- Separate Shun private disclosure & at-most-once-send reservation from K external Effect Permit; only after **both** satisfy policy does Host send. Select **one** network sender: DomainHarness v0.10.3 `llm.openai.generate` C imports the trusted static `domain-harness-openai-host` `generate` binding, implemented in Shun's trusted Host using the public `createOpenAIHostClient(OpenAI, pinnedPolicy).generate` and **existing Shun consent/budget ledger as an outer preflight**. The old `TrustedDeepSeekTransport` must NOT separately issue HTTP for a migrated request. Host binds an approved `requestId` to the original consent projection, performs signed broker and operator currentness, then reserves and marks `MAY_HAVE_SENT` before invoking the single SDK client send (SDK maxRetries=0). Preflight denial does not invoke the SDK; conservative post-reservation refusal may retain UNKNOWN_COST until independently reconciled, never retroactively invent no-network proof. A timeout / 408 / 504 / cancellation after-send remains `MAY_HAVE_SENT` / UNKNOWN_COST; do not assume K's `failed` is evidence of no network send. No raw prompt/secret in meta telemetry or issue.
- Strict typed proposal is only an advisory candidate. To actuate an effect, a new user plan/approval and current Windows admission are required. No synthesized approval, grant or command from LLM.

## 4. Guided user journey and forms

- Reuse frozen `StepTemplate/FormSchema/ChoiceCatalog`, `step.spec/step.outcome/next-step.request/next-step.decision/llm.advisory` wire concepts in the v0.10.3 Contract Freeze.
- Shun Business creates **one next** StepSpec from trusted Windows/Host observation; UI renders only approved choices. StepOutcome references exact case/step/choice and current evidence. Pause/resume/back recheck facts; do not replay effects.
- Optional bounded LLMAdvisory may explain choices but cannot add template, change command, skip R2 approval or generate an effect Permit. Explicit consent and user-level accessibility continue to belong to Shun Control UI/Host.
- First pilot is **read-only selected-folder diagnosis → candidate plan/explicit approval → real verified scoped effect**, with Chinese and English user-facing selected-root/approval/progress/refusal flows; no generic form designer or model-led UI generation.

## 5. Feedback and learning

- Reuse selected DomainHarness meta-feedback/candidate-validation plus public Host `runMetaFeedbackWorkflow`. Shun observes actual outcome and consented, redacted user feedback; evidence bound to Case, user-scope, App/Business source identity and exact receipt.
- Candidate → validate → independent read-only Shadow → explicit trusted operator approval → **new immutable future BUILD**. No model/self-feedback promotion, data-based grant, old Build hot swap or user content upload.
- SDK usage defects: find existing domain-harness issue, create sanitized minimal repro, obtain explicit user authorization before posting; no credentials or raw private source. **Frozen B-040 `shun.support-context.v1` report is local-only and cannot be silently reclassified as remote Meta, DeepSeek, error reporting or SDK Issue evidence.** The Shun user can separately authorize purpose-bound, re-minimized evidence without reusing the local-only report itself as an exfiltration channel.

## 6. Frozen B-040 local support-context preservation

- Retain `packages/vertical-support/**` `collectWindowsSupportContext` + `minimizeSupportContext` and the exact `shun.support-context.v1` output with `localOnly:true` and `externalDisclosures:[]`. This is part of existing Windows diagnostics, not a feature request.
- B-040 is a dedicated read-only Computer Business behavior within **T02**'s already exclusive `packages/domain-computer/src/computer/**` domain (no new package/task or critical path). It is never an automatic input to the selected OpenAI C, Guided Journey advisory, Meta candidate, exception/usage reporter or SDK feedback.
- Tests verify no automatic network egress and deterministic rejection/minimization of env keys/values, process names/command lines, unrelated document bodies, absolute paths and secret words. Retain original privacy/frozen schema and do not extend data collection solely for DomainHarness.
- Chinese and English real Control UI presentation and independent user approvals are T10/T11 acceptance, not satisfied by model language responses.

## 7. Durability, lifecycle and migration strategy

- v0.2 existing `packages/store`, `workflow`, `executor-windows`, `authorization`, `recipe-runtime` retain historical data. `packages/workflow/src/journal.ts` is the **old orchestration intent/attempt journal** and `packages/workflow/src/kernel.ts` is the old operation scheduler. They become **read-only/inactive for migrated Case/effect identities**. `packages/store/src/shun-store.ts` is **business authority** (records + a transactional idempotent `effects`/`effect_receipts` ledger), not merely an obsolete execution journal. Keep business reads and K-mediated authorized business writes (with unchanged stable `effectId` and record hash); do not add a second independent external-effect dispatcher or erase its receipts. Legacy unmigrated workflows may continue only in a proven disjoint Case namespace; mixed writer collision must HOLD.
- Prove crash boundaries: write reservation, K permit, Host grant and effect, physical result, K journal recording and independent re-observation. A lost ACK or crash cannot accidentally run two effects.
- Persistent token/SQLite mapping, backup, rollback and historical replay must be specified by migration task before irreversible changes. Do not delete/overwrite old Journal/unknown intents and do not invent successful migration.
- Candidate scope is v0.3 in an isolated branch. v0.2 T10/T11 continue; before v0.3 integration rebaseline to accepted exact v0.2 successor(s), source-diff reconciliation and all actual required Windows/CI evidence. The v0.2 version Release gate is not silently satisfied by v0.3.

## 8. Reuse and decisions: KEEP / ADAPT / REPLACE

| Concern | Existing source | Direction |
|---|---|---|
| Security/OS authority | `packages/authorization/**`, `packages/executor-windows/**` | KEEP physical source, ADAPT Host; independent K admission |
| Goal/type validation | `packages/contracts/**`, `packages/resolver/**` | KEEP DTO semantics; ADAPT selected S/B; reject untrusted before send |
| Local support context B-040 | `packages/vertical-support/**` | KEEP schema/minimizer/localOnly semantics, ADAPT read-only Computer B; never auto-forward into LLM/Meta |
| LLM | `packages/llm-remote/**` | REUSE private broker/budget; ADAPT DH neutral LLM & selected C |
| GUI | `apps/control-ui/**`, `apps/control-api/**` | KEEP, compose with bounded Guided Journey |
| Recipe | `packages/recipe-runtime/**` | ADAPT via Domain B; preserve identity and no-model replay |
| Provider | `packages/provider-loader/**`, `vertical-jit/**` | KEEP signature checks; ADAPT lifecycle B/Host |
| Store/workflow | `packages/store/**`, `packages/workflow/**` | REPLACE only migrated `WorkflowEffectJournal` + `DurableWorkflowKernel` effect scheduling with selected K; retain `ShunStore` **business records and transactional application-effect idempotency receipts** for authorized business updates. Preserve old workflow data read-only and disjoint unmigrated Case scopes; no physical-effect dual dispatch |
| Feedback | selected v0.10.3 meta-feedback/Host | REUSE existing public Meta; Shun provenance/consent bridge |

## 9. L2 uncertainties, evidence needed before freeze

| ID | Critical uncertainty | Falsifier / bounded resolution | Until satisfied |
|---|---|---|---|
| U01 P0 | K Permit and Shun Host real auth can combine at final effect boundary | **STATIC_EVIDENCE_SUFFICIENT for design**: selected K gate `readEffectAuthorityView` before selected C dispatch + Shun `ActionController.authorizeEffect` on same payload immediately before Windows executor; forged/stale/denied guards require real T01/T11 negative tests. If selected binding cannot expose both gates in real consumer, L2 amendment/Research Demo | Runtime proof OPEN; architecture can be independently reviewed |
| U02 P0 | One active **orchestration** effect identity/Journal with legacy source, while ShunStore persists business records | **STATIC_EVIDENCE_SUFFICIENT for ownership decision**: selected K owns migrated effect Journal/UNKNOWN; old `WorkflowEffectJournal` is inactive for migrated Case, old/unmigrated namespaces fenced; `ShunStore.apply(effectId)` retains business transaction + idempotency receipts, not a second dispatcher. T01/T11 prove collision/restart/rollback failures | Runtime migration proof OPEN; architecture can be independently reviewed |
| U03 P0 | Real remote send UNKNOWN & cost double-reservation | **STATIC_EVIDENCE_SUFFICIENT for selected path**: C `domain-harness-openai-host` → exactly one trusted `createOpenAIHostClient(OpenAI,...).generate` call after existing Shun broker/ledger reservation+MAY_HAVE_SENT; disable old `TrustedDeepSeekTransport` HTTP path for migrated attempt; never mark zero send from an ambiguous SDK error; T04/T11 tests prove single network attempt and no double budget. If binding cannot retain exact private approval/attempt semantics, mark `EXECUTABLE_DEMO_REQUIRED` and BLOCK affected implementation | Runtime sending/charge proof OPEN; architecture can be independently reviewed |
| U04 P1 | v0.10.3 source and final selected packed public exports | contract fixed; package SHA, pack & Node24 consumer as future implementation gate | L2 may freeze with explicit consumer gate |
| U05 P1 | Native NAPI-RS / old script/provider integration | reuse path, manifest/public ABI review; later physical Windows evidence | L2 may freeze with bounded Host task |
| U06 P1 | Form chosen/current & feedback workflow trust boundaries | selected SDK example and Shun UI/Host seam, negative cases and operator gate | L2 source concept with real E2E later |
| U07 P1 | v0.2 / v0.3 overlap and migration rollback | exact Case/source maps, version-branch isolation and future rebase plan | L2 needs clear nonoverlap policy |

**ADS Stage-2.1 disposition:** U01/U02/U03 have source-backed **STATIC_EVIDENCE_SUFFICIENT for their proposed architecture**; production validation remains REQUIRED in T01/T04/T11 and V01, not represented as pre-run PASS. This disposition is conditional on the selected public SDK ABI staying compatible with the exact final package. If an actual SDK integration exposes a materially different effect or admission boundary, stop that concern, change disposition to `EXECUTABLE_DEMO_REQUIRED` or `BLOCKED`, and follow the Architecture Research/Amendment protocol. No gratuitous research demo or second transport implementation now.

## 10. Source-grounded pre-L2 decision evidence (not execution proof)

**Exact frozen inspection anchors:** `shun-assistant@f01233a002f65b9bfea04828f6e56914666a160a` `packages/authorization/src/controller.ts` blob `032fe68c28125d39f420cdbd2e9832e767f087ab`; `packages/store/src/shun-store.ts` blob `e44f941384e143b106751c1f64e7f83ab6df7268`; `packages/workflow/src/kernel.ts` blob `eee1a8ac18a12fa4275ace3fd94a6ef4a2384551`; `packages/workflow/src/journal.ts` blob `e896f74ad8dbe0ea2e78916470e446741f146692`; `packages/llm-remote/src/atomic-budget.ts` blob `c4e64262756ff96f87f8bd1704e8ec22795693ea`; `packages/llm-remote/src/deepseek-transport.ts` blob `4a1c8dc82ffe33e081369ca72cd5d0c2e60ea843`. Upstream `domain-harness@7d571858bd6524ffd13a7985227183dbecb2924a` `packages/microkernel/src/domain-app.ts` blob `a3f36f9de86b164c1a7057a01da624a9fb491680`, `packages/microkernel/src/internal/external-effect.ts` blob `1a2f62f81585c5cca24f9ad9664cfeb3add70da0` (implementation *observation*, **not an allowed deep import**), published Host guide [LLM](https://github.com/kaicreator-mm/domain-harness/blob/version/v0.10.3/docs/architecture/v0.10.3/INTEGRATION.en.md).

- **U01 design candidate:** Selected public Domain App `load/send` dispatches by real selected BUILD; K gate re-reads K-issued effect authority before invoking chosen C. The Host C adapter invokes existing `ActionController.authorizeEffect` before every Windows operation; it checks fresh Shun grant/currentness. The double gate is `K permit AND fresh Shun Host authorization`, never a fused grant. Runtime selected public operation binding and denial/zero-effect tests still **NOT_RUN**.
- **U02 important correction:** Current Shun `WorkflowEffectJournal` is a physical-operation/intent scheduler journal; current `ShunStore` carries business-authority records and idempotent `apply` receipts in SQLite WAL, explicitly independent from workflow orchestration. K must replace **only the migrated workflow effect Journal and dispatch owner**, not the application business DB. Continue approved ShunStore application transactions behind K, with stable effectId and old history protected. Real restart/collision/dual-executor test still **NOT_RUN**.
- **U03 design candidate:** Existing Shun cloud ledger makes a transactionally bounded `RESERVED → MAY_HAVE_SENT → UNKNOWN_COST/SETTLED` transition, revalidating real Windows private consent right before send. The K gate cannot replace the financial/privacy reservation or infer no egress from K `failed`; wrapping the selected OpenAI-compatible C requires **one** real transport boundary and **both** K admission and independent Shun ledger permission. After-send ambiguity retains UNKNOWN and no blind retry; real consumer test still **NOT_RUN**.
- **Scope discipline:** No new CAS store, duplicate provider router, separate Meta engine or full Windows experimentation merely to decide this architecture. Source-read evidence narrows the remaining falsifiable runtime proof, but source inspection alone **does not discharge U01–U03** or substitute for independent L2 R1.

## 11. Architecture-stage checkpoint and required independent review

This R0 began before Product Freeze but is now **explicitly source-rebound** to the exact frozen Product/L1 blobs and `version/v0.3.0@c8334c7723eecf7fbbb6895b1defd6439edc6b95` checkpoint. It is NOT itself a Product or L2 Freeze. Separate architecture reviewer must issue `P0/P1/P2; PASS/BLOCK; L2_FREEZE_READY` at exact reviewed L2 HEAD; Product/Architecture Owner must explicitly freeze when qualified. Scaffold/source §2.4A depends on both freezes plus current accepted Claim.

```ini
SHUN_L2_R0=REBOUND_TO_FROZEN_PRODUCT_REVIEW_CANDIDATE
DH_V0103_PRODUCT_CONTRACT_L2=FROZEN_UPSTREAM
SHUN_PRODUCT_FREEZE=YES_C8334C7723EECF7FBBB6895B1DEFD6439EDC6B95
SHUN_L2_INDEPENDENT_R1=NOT_RUN
SHUN_L2_FREEZE=NO
SCAFFOLD_SOURCE_ADMISSION=HOLD
NATIVE_DAG_ADMISSION=HOLD
```
