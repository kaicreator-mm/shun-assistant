# Shun Assistant DKE-D0 — Knowledge Demand, Implementability and Functional Closure R0

**OUTPUT_LABEL:** `SHUN_ASSISTANT_DKE_D0_DEMAND_FEASIBILITY_CLOSURE_R0`  
**Status:** `AUTHOR_CANDIDATE_NOT_INDEPENDENTLY_REVIEWED` · Product implementation NOT_AUTHORIZED · K5 SAP NOT_QUALIFIED · DIS BLOCKED · Windows native DKE tests NOT_RUN.  
**Main Issue:** [shun-assistant #411](https://github.com/kaicreator-mm/shun-assistant/issues/411)  
**Machine matrix:** [DEMAND_TO_FUNCTION_CLOSURE_R0.json](./DEMAND_TO_FUNCTION_CLOSURE_R0.json)  
**Upstream knowledge dossier:** [PR #414](https://github.com/kaicreator-mm/shun-assistant/pull/414) @ `a18374a18c920d4975e09be649d0a98e5dc87b32` (Git Blob `f05934349a76dde19687731c2e367de95b333700`)  
**Knowledge upstream review policy:** do not alter PR #414's pending exact-SHA independent review subject in order to add this follow-on study.

## 1. Key finding

The current knowledge dossier defines 17 Elements, 17 Claims and 20 CQs, but a **knowledge model is not itself a user-facing computer management function**. The DKE obligation now is to trace each real Product journey through required knowledge, feasible action level, the appropriate authorization boundary, an independent postcondition and an explicit UNKNOWN/recovery route. This R0 matrix is **research and engineering analysis**, not an accepted SAP, Product amendment, Function/ECP contract, real AOT Package or a native Windows effect receipt.

**Scope:** 15 user tasks, comprising 10 exact frozen v0.3 Product §2 parity journeys (D0) and 5 future candidate computer-management tasks (D1/D2). Frequency, business value and implementation cost are UNKNOWN where no measured source was provided; priority classes are planning labels, not fake ROI estimates.

## 2. Original Product authority

- The later [v0.3 Product Freeze](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/docs/product/PRODUCT_FREEZE-v0.3.md) records **PRODUCT_AND_L1_ONLY**, `IMPLEMENTATION_AUTHORIZED=NO`, `SOURCE_SCAFFOLD=NOT_AUTHORIZED`, `L2_FREEZE=NO`, `TASK_DAG_FREEZE=NO`, `RELEASE_READY=NO`.
- Original [PRD](https://github.com/kaicreator-mm/shun-assistant/blob/4c2f8e84b6e6f3f5b526e52d01356159f2dce0e7/docs/product/PRD-v0.3-domain-harness-R0.md) Blob `f062b7f2c3dc3bf4aeeb7594ab5c2bc75b34d0ab` and [L1 parity](https://github.com/kaicreator-mm/shun-assistant/blob/4c2f8e84b6e6f3f5b526e52d01356159f2dce0e7/docs/product/L1-v0.3-domain-harness-parity-R0.md) Blob `4c703c3f0c283f4d3918babef8f87f56869698e5` are read at exact original revisions. The Product Freeze checkpoint supersedes the older draft-status headers in those two files.
- Observed source/test definitions are pinned to `version/v0.3.0@1224fea4097799467e2c0c454885e680f1f28248`. No test definition alone is a runtime receipt, and present source is not proof of release or integration.

## 3. Demand-to-knowledge-to-closure inventory

| Job | User-facing goal | Demand status | Target feasibility | Source maturity (not native proof) |
|---|---|---|---|---|
| `CA-JOB-01` | Goal-to-registered-capability resolution | Frozen Product requirement | `I2` | `BOUNDED_SEMANTIC_ADAPTER_SOURCE_OBSERVED` |
| `CA-JOB-02` | Windows diagnosis and B-040 local support context | Frozen Product requirement | `I1` | `READ_ONLY_SYSTEM_AND_SUPPORT_ADAPTER_SOURCE_OBSERVED` |
| `CA-JOB-03` | Exact-root cleanup preview and approved bounded cleanup | Frozen Product requirement | `I3` | `BOUNDED_STORAGE_PLAN_AND_EXECUTE_SOURCE_OBSERVED` |
| `CA-JOB-04` | Offline deterministic Recipe replay | Frozen Product requirement | `I3` | `RECIPE_SEMANTIC_ADAPTER_SOURCE_OBSERVED_NOT_END_TO_END` |
| `CA-JOB-05` | Private consent and cost-bounded DeepSeek request | Frozen Product requirement | `I3` | `SOURCE_OBSERVED_GOAL_ADAPTER_ONLY_NO_REAL_PAID_CALL_PROOF` |
| `CA-JOB-06` | Curated signed Provider JIT lifecycle | Frozen Product requirement | `I3` | `CURATED_JIT_LIFECYCLE_SOURCE_OBSERVED_NOT_GENERAL_APP_INSTALLER` |
| `CA-JOB-07` | Durable journal and truthful UNKNOWN recovery | Frozen Product requirement | `I3` | `SCOPED_STORAGE_JOURNAL_SOURCE_OBSERVED_NO_WHOLE_APP_PROOF` |
| `CA-JOB-08` | CN/EN selected-root, approval, refusal and history UI | Frozen Product requirement | `I2` | `PRODUCT_REQUIREMENT_ONLY_NO_UI_CODE_IN_PINNED_DKE_SOURCE_SLICE` |
| `CA-JOB-09` | Bounded one-step Guided Journey | Frozen Product requirement | `I2` | `ONE_STEP_GUIDED_ADAPTER_SOURCE_OBSERVED_UI_END_TO_END_UNKNOWN` |
| `CA-JOB-10` | Opt-in redacted feedback and candidate Shadow | Frozen Product requirement | `I2` | `META_FEEDBACK_ADAPTER_SOURCE_OBSERVED_HOST_INTEGRATION_UNKNOWN` |
| `CA-JOB-11` | General installed-app management | Future candidate / not admitted | `I3` | `LIMITED_REGISTRY_SAMPLE_AND_PROVIDER_JIT_ONLY_NOT_GENERAL_MANAGER` |
| `CA-JOB-12` | Disk topology, partition and format management | Future candidate / not admitted | `I4` | `NO_DISK_PARTITION_MUTATION_SOURCE_ESTABLISHED` |
| `CA-JOB-13` | PnP hardware and driver diagnosis/change | Future candidate / not admitted | `I4` | `NO_GENERAL_PNP_OR_DRIVER_MANAGER_OBSERVED` |
| `CA-JOB-14` | Process and service diagnosis/control | Future candidate / not admitted | `I3` | `BOUNDED_PROCESS_STARTUP_COUNTS_ONLY_NO_GENERIC_MUTATION` |
| `CA-JOB-15` | Network diagnosis and configuration | Future candidate / not admitted | `I4` | `NO_GENERAL_NETWORK_ADMIN_SOURCE_ESTABLISHED` |

No row currently qualifies its own Function, SAP or runtime closure. A suggested DIS Function name in JSON is a **proposal placeholder** and deliberately has no executable schema, Pipeline or authority.

## 4. First recommended end-to-end demonstration

**Preferred bounded demonstration: CA-JOB-03, selected-root storage diagnosis → safe plan → explicit approval → bounded effect → independently verified poststate.** Its source-based feasibility is more concrete than destructive partitioning or generic software/driver management because its source slice already contains plan, execute and verification boundaries.

Trace:

```text
Product §2.3 requirement / user selects exact folder
  → CA-STORAGE + CA-FILE-ASSET + CA-TASK-LIFECYCLE
  → Source claims CA-CLM-006/007/014
  → CQ-CA-004/005/012/019; per-Element SAP and global owners
  → verified Root/scope/identity and eligible cache/temp classification
  → bounded preview with manifest + expected reclaim
  → independent R2 user approval + current Host grant/Kernel Permit
  → authorized bounded Windows effect + durable journal
  → independent re-observation: free-space change and protected canaries
  → success only if both effect scope and protected invariants verify;
     otherwise BLOCKED/PARTIAL/UNKNOWN + recovery without blind retry
```

**Existing source/test definition anchors** (all at `1224fea4097799467e2c0c454885e680f1f28248`):
- [`packages/vertical-storage/src/plan.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/src/plan.ts) — bounded plan, exact target classification and preview;
- [`packages/vertical-storage/src/execute.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/src/execute.ts) — scoped effect path;
- [`packages/vertical-storage/src/verify.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/src/verify.ts) — postcondition verifier;
- [`packages/vertical-storage/test/plan.test.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/test/plan.test.ts), [`packages/vertical-storage/test/execute.test.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/test/execute.test.ts), [`packages/vertical-storage/test/verify.test.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/test/verify.test.ts) — test definitions, **not claimed as current Windows native PASS**.

Required before eligibility: fresh independent PR #414 source-first exact-SHA review, qualified Element SAP and global invariant composition; Product implementation admission/legally selected DIS Function contract; real Windows test and OS/Host permit/approval receipts. Do not mark I3 achieved merely because the source includes an executor.

### Secondary feasibility studies

- **CA-JOB-02 read-only diagnosis** can be examined first at I1 without touching physical effects. It must clearly separate measurements from inferred causes and maintain B-040 local-only privacy.
- **CA-JOB-06 curated JIT** already has a bounded source-based Provider lifecycle; this is not a general app store/installer.
- **CA-JOB-11 software package management** is a future Product candidate. Current Registry sample and curated Provider JIT do not prove general install/upgrade/uninstall support.
- **CA-JOB-12 partition/format**, **CA-JOB-13 driver/PnP mutation**, and **CA-JOB-15 network configuration** are not admitted. They require separate Product decisions, precise live identities, specialist/native oracles and credible recovery.

## 5. AOT and Runtime boundary

| AOT—stable reviewable knowledge | Runtime—must be re-observed |
|---|---|
| Domain vocabulary and identities; source-backed semantics | Exact disk, file, device, software, user and process identity |
| Windows edition/release applicability rules | Current OS edition/build, servicing state, ACL, permissions |
| Source-pinned risk and protected-asset policy | Current filesystem state, locks, provider status, user-selected scope |
| Function precondition/refusal and postcondition requirements | Current approval, permit, grant, provider trust and revocation |
| Independently reviewed diagnostic decision tree | Current sensor/registry values, I/O effects, journal and poststate |

AOT knowledge cannot issue an approval, invent a Host observation, bind a stale object identity or claim that the operation succeeded.

## 6. Evidence and maturity—no false promotion

The matrix records for **every job**: original demand, Product admission, source/Claim/Element/CQ ownership, AOT/Runtime split, implementation level I0–I4, observed code maturity, preconditions, independently verifiable postconditions, refusal cases, UNKNOWN/recovery and unresolved decisions.

- **Product admitted requirement ≠ implementation authorization.** The frozen v0.3 Product is a requirement boundary; the checkpoint does not approve new source changes.
- **Source observed ≠ native verified.** Code and test definitions are not current real Windows execution receipts.
- **Data validity ≠ SAP qualification.** Cross-reference/JSON validation cannot independently establish domain truth.
- **Preview ≠ effect; exit code 0 ≠ verified poststate.**
- **CQs / candidate Function names ≠ actual DIS ECP/AOT Package.**
- **UNKNOWN is intentional** where evidence, target identity, OS support or effect outcome is incomplete.

## 7. Owner/Reviewer next gates

1. Keep PR #414 at exact HEAD `a18374a18c920d4975e09be649d0a98e5dc87b32` for a truly fresh different Source-First Reviewer; first freeze original Product and source/test, then inspect candidate. Do not self-sign independent PASS.
2. Separately review this matrix's 10 Product parity rows against the actual original PRD §2 and pinned source; repair only evidenced claims, not invented features.
3. Validate and qualify each covered Element's SAP/CQ/global-invariant obligations and changed-source invalidation with real oracles.
4. Reconcile dependency drift: PR #410 has advanced; PR #412 is still based on an earlier #410 head, and PR #414 is stacked on #412. Do not silently rebase/merge.
5. Obtain explicit Product Owner admission before implementing general package management, destructive storage, PnP driver/process/service or network administration; native permission/recovery tests must precede use.
6. After an approved Product + qualified SAP, let DIS define selected Function/Pipeline/ECP and AOT Package. Run real Windows authorization/effect/verification; publish exact-SHA receipts and truthfully report UNKNOWN.
7. Keep project-level progress and decisions in **#411**; devkit #7 only aggregates the project evidence and gate counts.

## 8. Data format and limitations

- All rows are **candidate authored analysis**, not independently reviewed.
- Demand frequency/value, implementation and maintenance cost, current native Environment evidence, real UI E2E, actual DIS Function schemas and Product decisions remain **UNKNOWN / NOT_RUN**.
- The JSON `sourceRefs` use the existing frozen candidate #414 inventory and should be invalidated if its source registry, claims or SAP revision changes.
- Source snapshot claims apply only to the inspected files/versions; no extrapolation to all supported Windows builds or current user machines.
