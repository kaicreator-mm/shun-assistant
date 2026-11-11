# Memory Performance — DKE → DIS → AOT → Runtime Demo R0

**Mode:** research-only, read-only, local-only.  
**Product feature:** no.  
**OS effects:** none.  
**Native Windows execution:** pending local validation.

## Pipeline

1. **DKE:** `CA-PERFORMANCE-OPTIMIZATION` → `CA-MEMORY-PERFORMANCE`, 7 Claims, 11 CQs, 6 invariants and 12 SAP obligations. All remain candidate / NOT_QUALIFIED.
2. **DIS:** [typed Function contracts](./DIS_FUNCTION_CONTRACT_R0.json): `computer.memory.observe`, `computer.memory.assess`, `computer.memory.plan`, optional `computer.memory.compare`. This is a contract candidate, not a qualified Function/ECP.
3. **AOT:** [memory semantics candidate](./AOT_MEMORY_KNOWLEDGE_CANDIDATE_R0.json) contains stable metric definitions, source-pinned decision rules and invalidation metadata only. It is loaded only by this research harness; it is not a production Package.
4. **Runtime:** [runner](./run-windows-memory-demo.mjs) calls existing Shun read-only Windows collectors, then the pure analyzer. It emits a typed local JSON report and advisory-only plan.

## Run

From the repository root, on a Windows host:

```powershell
node --test docs/dke/demos/memory-performance-r0/memory-analysis.test.mjs
node docs/dke/implementation/verify-performance-memory-extension-r0.mjs
node docs/dke/demos/memory-performance-r0/run-windows-memory-demo.mjs
```

The runner does not write files, access the network, invoke arbitrary commands, kill processes, stop services, clear caches, change pagefiles or modify hardware. It calls only the existing fixed Windows collectors.

By default process names are replaced with local aliases. `--show-local-process-names` is an explicit local-only opt-in; do not post raw process names to GitHub.

## Important interpretation

- Existing `LOW_FREE_MEMORY` is a legacy single-snapshot heuristic, not a universal pressure threshold.
- Existing process values are `WorkingSet64` only, not Private Bytes or process commit.
- Top-eight ranking is not causal attribution and does not establish a leak.
- No legacy signal does not prove the system is healthy.
- Memory available increase alone is not a performance improvement.
- `computer.memory.compare` returns UNKNOWN unless a trusted same-host/same-workload comparator receipt and P95 response-time evidence exist. The unit-test fixture can only produce an `IMPROVEMENT_CANDIDATE`, never a verified speedup.

## Local validation receipt

Record: exact branch HEAD, working tree, Windows edition/release/build, architecture, Node version, actual command lines and exit codes, test counts, runner outcome, and whether the two collectors returned OBSERVED or UNKNOWN. Do not upload raw process names, PIDs, paths or other local data. No Native PASS is claimed until the local command has actually run.
