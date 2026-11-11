# Performance Optimization and Memory Performance — DKE Extension R0

**Output label:** `SHUN_ASSISTANT_DKE_PERFORMANCE_MEMORY_EXTENSION_R0`  
**Owner:** [project DKE main Issue #411](https://github.com/kaicreator-mm/shun-assistant/issues/411)  
**Stack:** PR #414 knowledge model `22a929ce1fbb5cdb5b2819cd3e98e71bbf21085a` → PR #415 demand/closure model `406605ae0d931440338b398d29c2a6dcf4674c80` → this extension PR.  
**Original code baseline:** `version/v0.3.0@1224fea4097799467e2c0c454885e680f1f28248`.

## 1. Decision

Add `CA-PERFORMANCE-OPTIMIZATION` as a new Root child and `CA-MEMORY-PERFORMANCE` as its first nested child. Memory performance is the first full DKE → DIS → AOT-candidate → Runtime research demo.

This is a **knowledge and research-demo extension**, not an amendment to the frozen v0.3 Product. The Product Freeze still states `IMPLEMENTATION_AUTHORIZED=NO`, `SOURCE_SCAFFOLD=NOT_AUTHORIZED`, `L2_FREEZE=NO`, `TASK_DAG_FREEZE=NO`. No general optimizer, process termination, service control, cache clearing, working-set trimming, pagefile tuning, registry change or hardware mutation is admitted.

## 2. Why this is a separate Element

`CA-SYSTEM-OBSERVATION` owns bounded raw system facts. `CA-PROCESS-SERVICE` owns process/service identity and lifecycle. `CA-HARDWARE-DEVICE`, `CA-STORAGE` and `CA-SOFTWARE-LIFECYCLE` own their domain objects. The new Element owns cross-domain performance reasoning: bottleneck hypotheses, safe optimization choices, baseline comparability, trade-offs and verified user-visible outcome.

The memory child owns the memory-specific semantics: Working Set, Private Bytes/PrivateUsage, system Commit/Commit Limit, Available memory, pagefile/paging, page faults, kernel pools, cache/standby, compressed memory, process identity and leak hypotheses.

## 3. Source-first baseline: what Shun actually has

At original v0.3.0 source commit:

- `packages/vertical-system/src/internal/windows-pressure.ts` — Blob `becb976b39ef6da760d451ca8ac7f9af474dc679`: fixed read-only PowerShell command returns at most eight process names and `WorkingSet64` values, local-only; no PID, command line, user or path.
- `packages/vertical-system/test/windows-pressure.test.ts` — Blob `a103a959cecf7fe67f8a626ee6b1a25b9eeeb91b`: definitions cover bounded sorted facts, malformed/injected fields, non-Windows refusal and no process mutation command.
- `packages/vertical-system/src/diagnostics.ts` — Blob `79cd145dbcd212968846fad39f7e7f68e21923a2`: single-snapshot advisory projection; a low-free-memory signal maps to `REVIEW_APPLICATIONS`, effect `NONE`.
- `packages/vertical-system/src/windows-runtime.ts` — Blob `1f425854b688a1981b4f3c28cd4de39bb5cc6288`: fixed PowerShell executable, timeout and bounded output; exports the top-memory collector.
- `packages/vertical-system/test/diagnostics.test.ts` — Blob `b163404542bc73c1fedb9a56fd8b9edf39436896`: source test definitions, not evidence that native Windows tests ran.

**Critical integration gap:** the top-eight memory collector exists but is not included in `collectWindowsReadonlyDiagnosis()`'s report. It reports Working Set only; it does not provide PrivateUsage/Private Bytes, Commit/Commit Limit, pagefile/paging rates, pool metrics, stable process instance identity or a time series. Current data cannot prove a leak, causal root process, reclaimable amount or speedup.

## 4. Correct memory semantics

The AOT candidate must preserve these non-equivalences:

| Metric | Meaning | Not equivalent to |
|---|---|---|
| Available Physical Memory | RAM currently available to satisfy demand | Free list only |
| Process Working Set | Pages currently resident in physical memory; can include shared pages | Private Bytes or unique physical ownership |
| PrivateUsage / Private Bytes | Process private committed memory | Current resident RAM |
| System Committed Bytes | Total system commit charge | Physical RAM in use |
| Commit Limit | Commit capacity backed by RAM + pagefiles | Current pagefile usage |
| PageFaultCount | Cumulative process page-fault count | Hard-page-fault rate |
| Paged/Nonpaged Pool | Kernel pool usage | User-process Working Set |

Working Set is a snapshot of resident pageable pages; shared pages and soft/hard page-fault distinctions matter. Process counters expose additional fields such as PrivateUsage, pool usage and PageFaultCount. Performance counters are administrative/diagnostic collection, not high-frequency profilers; Microsoft's guidance says they are not designed for collection more than once per second. Pagefile/commit semantics must not be reduced to "RAM used".

Windows file cache/standby is normal memory-manager behavior. The assistant must not classify it as junk or clear it by default. Microsoft Server tuning thresholds are not universal Windows Client thresholds and are not compiled as generic rules.

## 5. Functional closure target

The first Demo is **Memory Performance Advisor**, not an automatic memory cleaner:

```text
User goal
  → DKE Element / Claim / CQ / SAP
  → DIS typed Functions and ECP candidate
  → AOT stable memory-semantics candidate
  → Runtime read-only Windows observation
  → typed pressure assessment
  → advisory optimization plan
  → honest UNKNOWN / no-effect outcome
```

The Runtime may show a bounded ranking of top Working Sets, but default output aliases process names. No PID, command line, user, environment or path is collected. Current low-free-memory signal is preserved as a legacy heuristic, not promoted to confirmed pressure.

An improvement comparison requires a trusted same-host/same-workload comparator plus a user-relevant latency/throughput metric and independent post-state. A free-memory increase alone is not a speedup. The first native demo does not mutate the OS; it closes the read-only observe → assess → plan journey. The comparison Function is specified and fixture-tested, but real improvement verification remains UNKNOWN until a comparable workload receipt exists.

## 6. SAP and qualification

This extension adds 2 Elements, 7 Claims, 7 semantic Relations, 6 Global Invariants, 11 CQs, and 2 SAP profiles with 12 independent obligation contracts. Every obligation has its own positive, negative and UNKNOWN falsifier and remains `NOT_RUN / NOT_QUALIFIED`.

No author-side structure check can certify semantic truth. Fresh independent Source-First review must freeze Product and original Code/Test first, then review this exact extension. Windows native execution and controlled workload oracles are separate receipts.

## 7. AOT vs Runtime

AOT candidate may contain: metric definitions, source-pinned Windows memory-manager semantics, non-equivalence rules, safe diagnostic decision tree, falsifiers, risk taxonomy and invalidation triggers.

Runtime-only: current OS/build/API availability, current memory/commit/pagefile/pool values, process instances, timestamps, workload identity, permissions, approval, Host identity and actual performance results.

Never compile: current process list/PID, user paths, credentials, host memory values, approvals, permits or execution receipts.

## 8. Next gates

1. Fresh independent Source-First review of this extension and its exact source pins.
2. Complete the research-only DIS contract and AOT candidate; do not promote either to a production Function/Package.
3. Run pure deterministic analyzer tests on a supported local Node runtime.
4. Run the existing vertical-system pressure/diagnostics tests and the read-only Demo on real Windows; record exact HEAD, OS build, Node version, commands and exit codes. Do not post raw process names to GitHub.
5. Only after separate Product admission and SAP qualification may a later task study reversible process/app actions. No cache/pagefile/service/driver/hardware mutation is part of this Demo.

## 9. Machine-readable companion

- [Extension model](./PERFORMANCE_MEMORY_EXTENSION_R0.json)
- [Demand candidate CA-JOB-16](./PERFORMANCE_MEMORY_DEMAND_EXTENSION_R0.json)
- Demo contracts and research harness: `docs/dke/demos/memory-performance-r0/`
