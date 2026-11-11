# Shun Assistant DKE — First Functional Closure Readiness R1

**Output label:** `SHUN_ASSISTANT_DKE_JOB02_JOB03_FIRST_FUNCTION_CLOSURE_READINESS_R1`  
**Main Issue:** [#411](https://github.com/kaicreator-mm/shun-assistant/issues/411)  
**Implementation branch:** `dke/demand-function-closure-r0` / Draft [PR #415](https://github.com/kaicreator-mm/shun-assistant/pull/415), stacked on knowledge Draft [PR #414](https://github.com/kaicreator-mm/shun-assistant/pull/414).  
**Original source baseline:** `version/v0.3.0@1224fea4097799467e2c0c454885e680f1f28248` (read-only historical snapshot, not current Release certification).  
**Original demand matrix:** `DEMAND_TO_FUNCTION_CLOSURE_R0.json` Git Blob `eb00c3ac99ced49a95d0a1ff06d216f4d4cf9a69`.  
**Machine-readable evidence and falsifiers:** [FUNCTION_CLOSURE_READINESS_R1.json](./FUNCTION_CLOSURE_READINESS_R1.json).  
**Status:** `AUTHOR_SOURCE_ANALYSIS_NOT_INDEPENDENTLY_QUALIFIED`. No new Product admission, runtime code, SAP qualification, actual DIS/AOT Package, native Host effect or functional closure.

## 1. Why this is next

The R0 matrix already derives 10 frozen Product §2 parity obligations and 5 future candidate research jobs. Structural Source/Claim/Element/CQ links and 22 prior Node CLI validator tests are **not** a substitute for proving a real Function's outcome.

R1 selects two adjacent tasks with the highest source-grounded feasibility and the clearest incremental validation path:

- **CA-JOB-02 — Windows readonly diagnosis (I1 target):** no effects, privacy-minimal `OBSERVED_ONLY`, valid Windows-native observations; the first safe observation-to-user-result qualification candidate.
- **CA-JOB-03 — bounded storage cleanup (I3 target):** can serve as the first *conditional* effect closure only after scope, human approval, K/Host authority, poststate and recovery are independently proven. Existing source implements important portions, but the full composed Product journey is not currently verified.

These are **target** levels, not a claim that the Product implementation has already passed I1/I3. Product/L1 freeze still has `IMPLEMENTATION_AUTHORIZED=NO` for the described checkpoint; future general software, partition, driver, process, network administration remain NOT_ADMITTED.

## 2. Source-pinned observations and truthful limits

### System observation: CA-JOB-02

- [`packages/vertical-system/src/index.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-system/src/index.ts#L34), Blob `7f687a10f216fc9c792cb689942da792ee8e8d88`: `collectWindowsSystemInventory()` requires `win32`; system disk bytes come from `statfsSync('C:\\')` through `trustedDiskRoot()`, not a demonstrated cross-machine discovery of actual Windows system volume.
- [`packages/vertical-system/src/diagnostics.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-system/src/diagnostics.ts#L40), Blob `79cd145dbcd212968846fad39f7e7f68e21923a2`: `collectWindowsReadonlyDiagnosis()` reports `OBSERVED_ONLY`, `localOnly`, `externalDisclosures=[]`; thresholds are read-only signals with `effect: NONE` and `SINGLE_SNAPSHOT_NO_ROOT_CAUSE_OR_SPEEDUP_CLAIM`.
- [`packages/vertical-system/src/windows-runtime.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-system/src/windows-runtime.ts#L1), Blob `1f425854b688a1981b4f3c28cd4de39bb5cc6288`: fixed bounded process/startup facts; no general process management or arbitrary request-driven commands.

**Qualification obligation:** real Windows observation must establish exactly which volume was measured, avoid attributing `C:\\` to a different system root, and never promote measured pressure to a definite root cause or success claim. A UI screenshot, fixture or Node unit test alone cannot prove that the current customer's Windows host was measured.

### Storage effect: CA-JOB-03

- [`packages/vertical-storage/src/scope.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/src/scope.ts#L28), [`packages/vertical-storage/src/plan.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/src/plan.ts#L64): bounded declared scope, disposable classification and hashed preview proposals.
- [`packages/vertical-storage/src/diagnose.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/src/diagnose.ts#L98): the scoped storage vertical owns its own runtime orchestration, approval/controller and per-action execution. It measures a growth-source directory after action; this is not the same thing as independently proving a change in *volume* free space.
- [`packages/vertical-storage/src/execute.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/src/execute.ts#L90): effect execution requires current grant presentation and records journal phases; its execution receipts deliberately set `postStateVerified:false`, deferring semantic completion to the separate verifier. An uncertain prior execution is reconciled before retry.
- [`packages/vertical-storage/src/verify.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/src/verify.ts#L137), Blob `1552f9e5b84209af37cd1ddcfd6e1291a7c1572f`: independent semantic verifier protects fingerprinted assets and compares claimed gross bytes with journal `EXEC_DONE` bytes. **However** `targets-within-scope` at lines 243–251 checks only that `oracleInputs.scopeRoots` is a nonempty array; it does not match the journal's actual paths to those roots. The gross-byte check at lines 197–214 does not establish actual independent *volume free-space delta*.
- [`packages/vertical-storage/test/verify.test.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/vertical-storage/test/verify.test.ts#L72), Blob `c7c1babb707ef8d0a67565da504a31c9dfad8c51`: source fixture's `writeProvenJournal` records a synthetic `f.bin`, while the positive control supplies `['C:\\\\scope']` as scope and expects `PASS`. This illustrates the verifier's structural positive case; it is **not** proof that the actual privileged executor can delete an out-of-scope file.
- [`packages/domain-host/src/windows/effect-host.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/domain-host/src/windows/effect-host.ts#L230): generic K→C trusted Host adapter requires K Permit, independent Shun ActionController, OS currentness, and treats unverified effects as nonterminal. This source does **not**, by itself, prove that the above vertical-storage path is wired as the selected Production Function.
- [`apps/control-api/src/server.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/apps/control-api/src/server.ts#L740), [`packages/domain-computer/src/computer/folder-observation.ts`](https://github.com/kaicreator-mm/shun-assistant/blob/1224fea4097799467e2c0c454885e680f1f28248/packages/domain-computer/src/computer/folder-observation.ts#L1): selected-root effect/proposal and read-only folder adapters exist, and authority-bearing paths/grants are Host-owned. Routes/adapters alone do not prove the exact path from UI user action through storage cleanup to fully verified poststate.

The R0 phrase **“Re-observed free-space delta” is a required future independent oracle, not a capability already proven by this source snapshot.** The observed algorithm can justify a *journal-based gross deletion tally*, subject to validation, but **must not present that tally as measured physical free-space increase**.

## 3. Six concrete R1 gate findings

| Finding | Job | Candidate severity | Nature | Current gate |
|---|---|---|---|---|
| `CLOSURE-R1-SYS-01` | CA-JOB-02 | P2_CANDIDATE | SOURCE_CONFIRMED_APPLICABILITY_LIMIT | NEEDS_NATIVE_ORACLE_AND_SCOPE_REVIEW |
| `CLOSURE-R1-SYS-02` | CA-JOB-02 | P2_CANDIDATE | SOURCE_CONFIRMED_READONLY_LIMIT | ADMISSIBLE_KNOWLEDGE_CANDIDATE_NOT_FUNCTION_CLOSED |
| `CLOSURE-R1-STG-01` | CA-JOB-03 | P1_CANDIDATE_FOR_INDEPENDENT_REVIEW | SOURCE_CONFIRMED_VERIFIER_CHECK_WEAKNESS | REVIEW_REQUIRED_NO_UNAUTHORIZED_RUNTIME_PATCH |
| `CLOSURE-R1-STG-02` | CA-JOB-03 | P2_CANDIDATE | SOURCE_CONFIRMED_MEASUREMENT_NON_EQUIVALENCE | NEEDS_INDEPENDENT_MEASUREMENT_DESIGN |
| `CLOSURE-R1-STG-03` | CA-JOB-03 | P1_CANDIDATE_FOR_INDEPENDENT_REVIEW | CROSS_COMPONENT_COMPOSITION_GAP | DIS_AND_PRODUCT_ADMISSION_PENDING |
| `CLOSURE-R1-STG-04` | CA-JOB-03 | P2_CANDIDATE | SOURCE_CONFIRMED_EFFECT_RECEIPT_BOUNDARY | COMPOSITION_ORACLE_UNVERIFIED |

P1/P2 labels here are **author-severity candidates for a future independent reviewer**, not independently accepted defects. In particular, the scope-verifier weakness is confirmed in the *verifier's code path*, while the executor has separate containment checks; do not claim an observed out-of-scope Windows deletion.

## 4. Required explicit negative oracles

| Oracle ID | Falsification | Required outcome | Actual |
|---|---|---|---|
| `ORACLE-SYSROOT-1` | Windows system root is not `C:\\` | avoid falsely identifying C: as current system volume; refuse/UNKNOWN or correct trusted observation | NOT_RUN |
| `ORACLE-SCOPE-1` | ScopeRoots nonempty, but trusted journal contains path outside the exact approved action scope | independent scope verification must not PASS | NOT_RUN |
| `ORACLE-GROSS-1` | 100 bytes journaled, volume free-space change does not match | truthful gross-vs-volume delta distinction; no false “freed 100 bytes” user claim | NOT_RUN |
| `ORACLE-KHOST-1` | `SUCCEEDED` executor terminal with `postStateVerified:false` | K/Host cannot claim fully verified final completion | NOT_RUN |

For `ORACLE-SCOPE-1`, a synthetic journal test is an **Oracle negative test**, not an exploit claim. If the contract intentionally delegates exact-scope validation solely to the privileged executor, that semantic decision requires an explicit Source/Domain Owner judgment, with a different claimed postcondition; never keep the text “independently verified scope” if no independent scope verification is actually performed.

## 5. Minimal Delivery-First validation plan

**Step A: Read-only, no effects.** Under the existing frozen scope, verify one genuine CA-JOB-02 Windows observation and truthful, local-only, user-visible result. Record OS edition/build, selected system root and measured volume identity, original executable revision, runtime inputs, actual refusal/UNKNOWN negatives and source pins. Avoid unnecessary privileged Windows operations.

**Step B: Validate knowledge and independent Oracles.** Obtain a different Source-First Reviewer for PR #414 and PR #415 at their *actual latest* Exact-SHAs. Evaluate R1 four negative oracles against the same original source. Keep the 17 Element/58 SAP obligation state `NOT_QUALIFIED` unless true qualification evidence exists.

**Step C: Conditional bounded effect.** After explicit Product/Task admission plus a qualified SAP and DIS contract, trace selected-root case ID and exact plan/Host authorization through K Permit, storage executor, journal, independent target/protected-asset/free-space poststate and truthful UI history. Run a safe native Windows end-to-end test with explicit non-destructive fixtures and necessary consent. A low-level vertical PASS is not an integrated Function PASS.

**Step D: Close through evidence, not documentation.** Register the actual `FunctionID/contractVersion`, exact AOT Package source/qualification, typed outcomes and Native receipts; if any source/authority/target changes, invalidate the affected obligations and requalify. Fail closed on `UNKNOWN`, `PARTIAL` and postcondition mismatch.

## 6. What this R1 does *not* claim

- No new Product scope/admission, runtime source modification, Windows effect permission or device mutation.
- No confirmed Native Host effect execution, Product UI parity, selected DIS Function/ECP, AOT Package or verified increase in disk free space.
- No independent Source-First technical Review/PASS, Source Owner adjudication, qualified SAP, or change in devkit #7 K4/K5.
- The findings are pinned **to the original historical source revision**. A newer runtime branch may differ and must be re-inspected at its exact commit before concluding the current shipped application has the same behavior.
- The R0 Node 22/22 validation receipt applies to its previous exact PR HEAD and files. An additional R1 documentation commit does not upgrade semantic gates or silently constitute fresh exact-HEAD test execution.

**Priority:** close `CA-JOB-02` native read-only observation first, while asking the independent reviewer to resolve the `CA-JOB-03` verifier/scope and volume-delta claims before any real cleanup Function is admitted.
