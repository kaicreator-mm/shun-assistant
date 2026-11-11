# CA-JOB-16 — Memory Performance Diagnosis and Guided Optimization Planning

**Admission:** `FUTURE_CANDIDATE_NOT_ADMITTED`  
**Target:** `I2` read-only diagnosis/advisory plan only.  
**Current source:** bounded total/free memory and top-eight `WorkingSet64`; no private bytes, system commit, paging rates, stable process identity or time series.  
**Product implementation authorization:** `NOT_AUTHORIZED_BY_FROZEN_PRODUCT_CHECKPOINT`.

This is one candidate demand extension, not an eleventh frozen Product parity requirement. It is not added to the frozen D0 job count or the Product/L1 contract.

## User outcome

Explain possible memory pressure without conflating memory metrics, identify bounded top Working Set contributors, provide a safe and understandable advisory plan, and state exactly what additional evidence is required before calling a leak, root cause or improvement.

## AOT / Runtime boundary

AOT: metric semantics, Windows memory-manager rules, decision/falsifier tree, risk and verification contracts.

Runtime: current OS/build, memory and process measurements, stable process identity, sample times, workload comparability, user permissions and actual outcome metrics.

## Candidate DIS pipeline

`computer.memory.observe/0.1` → `computer.memory.assess/0.1` → `computer.memory.plan/0.1`; optional `computer.memory.compare/0.1` only with trusted comparable-workload evidence.

## Non-goals

No process termination, service control, startup mutation, cache/standby clearing, working-set trimming, pagefile change, registry edit, driver/hardware tuning or automatic optimization.

## Acceptance

The native Runtime demo must return accurate local-only typed evidence or UNKNOWN, never a false root cause, and prove zero effects. An actual optimization claim is not closed until a trusted same-workload pre/post receipt includes a user-relevant outcome metric.
