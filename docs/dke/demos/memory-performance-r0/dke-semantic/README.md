# Memory Performance — DKE Semantic Qualification Demo R2

**OUTPUT_LABEL:** `SHUN_ASSISTANT_DKE_MEMORY_SEMANTIC_QUALIFICATION_R2`  
**Owner:** [shun-assistant #411](https://github.com/kaicreator-mm/shun-assistant/issues/411)  
**Working Draft:** [PR #416](https://github.com/kaicreator-mm/shun-assistant/pull/416)  
**Status:** author candidate, **not** independent SAP-qualified or eligible for production DIS/AOT.

This is an **independent DKE research-demo surface**, not a rebranding of the four-layer integration demo. It can validate knowledge semantics and change impact using deterministic fixtures without calling Windows or running Shun's OS effects.

## What was added

The R0 memory dossier already defines 2 Elements, 7 Claims, 11 CQs and 12 SAP obligations. R2 adds a versioned source-first *overlay*, without rewriting the earlier exact-SHA evidence:

- 5 additional candidate Claims (`CA-CLM-025..029`).
- 5 CQs (`CQ-CA-032..036`), each with a positive, negative and UNKNOWN.
- 5 additional SAP obligations; **17 candidate obligations** are now in scope for the Performance/Memory and Global-Currentness extension (12 R0 + 5 R2).
- Two official Microsoft Learn source locators: `PROCESS_MEMORY_COUNTERS_EX2` applicability and WPA scenario Reference Set semantics. These URLs are **not immutable source Blobs**. Runtime Windows edition/build, API presence and collection conditions remain separate.
- 16 CQ semantic oracles × 3 polarities = **48 deterministic fixtures** including the original 11 CQs and new 5.
- 7 source-change impact tests with positive inclusion and negative over-invalidation requirements.
- A fail-closed DKE → DIS gate manifest for four candidate Function contracts.
- Seven further **unadmitted** performance knowledge-research topics, recorded separately under `docs/dke/implementation/PERFORMANCE_KNOWLEDGE_EXPANSION_R2.json`: CPU, storage I/O, startup/background, application performance, thermal/power, GPU, network.

## Explicitly corrected memory knowledge and counterexamples

| Topic | Bounded knowledge | Counterexample / UNKNOWN |
|---|---|---|
| Private Working Set | `PROCESS_MEMORY_COUNTERS_EX2.PrivateWorkingSetSize` is not `PrivateUsage`. Its OS/build and update requirements apply. | Unsupported target or missing counter → UNKNOWN, never extrapolate `WorkingSet64`. |
| Diagnostic counters | Performance Counters are not high-frequency profilers and process counter instance names may be nonunique. | 100ms polling or matching a name across process restarts cannot prove a leak. |
| Page faults | `PageFaultCount` is cumulative and includes faults that are not hard disk reads. | Without a separate hard-fault counter and time interval, hard-fault rate UNKNOWN. |
| Reference Sets | A scenario's memory references are different from instant per-process Working Set; WPR collection can perturb system performance. | Do not collect intrusive traces without explicit authorization or call it passive monitoring. |
| Timestamp provenance | Analysis time and Host-attested sampling time are distinct. | Caller-supplied `observedAt` must not be represented as verified sampling time. |

Official source anchors:
- https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex2
- https://learn.microsoft.com/en-us/windows/win32/perfctrs/about-performance-counters
- https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex
- https://learn.microsoft.com/en-us/windows/win32/memory/working-set
- https://learn.microsoft.com/en-us/windows-hardware/test/wpt/wpa-reference-set

**New source content has not been independently frozen or SAP-qualified**. It requires a truly different Source-First Reviewer, especially for Windows update/API applicability.

## Source ownership and recursion

```text
CA-ROOT
  └─ CA-PERFORMANCE-OPTIMIZATION
       └─ CA-MEMORY-PERFORMANCE
```

Existing `CA-SYSTEM-OBSERVATION` owns raw measurements, `CA-PROCESS-SERVICE` owns process identity/lifecycle, and `CA-AOT-KNOWLEDGE` owns stable precomputation and invalidation. Global `CA-GLOBAL-CURRENTNESS` owns whether sampledAt is Host-attested.

The new topics **are not 7 more Elements**. Split only when distinct semantic owners, independent CQ/SAP oracles, and a meaningful evolution boundary exist. Metric names are not a sufficient reason to split.

## DKE-only qualification experiments

1. Original Product/Code/Test and public Microsoft source semantics first; freeze Stage-0 before reading this author's candidate or historical repair analysis.
2. Validate each Claim's actual source, OS version applicability, epistemic status and falsifier.
3. For each of 16 CQs, execute one positive, one negative and one UNKNOWN case against the deterministic semantic evaluator. This checks machine-consistency and obvious false positives; *it does not establish independent semantic truth*.
4. Change one source at a time. Check its Claim/CQ/Relation/Global-Invariant/SAP/AOT-rule/DIS-contract reverse-impact closure. Inspect justified cross-domain effects but avoid whole-graph invalidation without dependency proof.
5. Confirm DKE Gate A can advance only on actual independent semantic evidence. Gate B can advance only after Gate A, Product decisions (if necessary), native Oracle readiness and explicit Function/ECP obligations.
6. Record actual Git HEAD/Blobs and honest Node test/independent review receipts. Do not infer PASS from the presence of files.

## Commands

From the repository root:

```bash
node docs/dke/demos/memory-performance-r0/dke-semantic/verify-memory-dke-r2.mjs
node --test docs/dke/demos/memory-performance-r0/dke-semantic/verify-memory-dke-r2.test.mjs
```

Use a Node runtime with the required language/API support; **no arbitrary minimum version floor**. The standalone R2 validator does not require Windows. Its exact file pins are in the validator source and any changed source requires an explicit re-pin and independent review.

## Deliverable files

| File | Role |
|---|---|
| `SOURCE_FIRST_KNOWLEDGE_DELTA_R2.json` | 5 bounded Claims, sources, new CQs and SAP obligations |
| `SEMANTIC_ORACLES_R2.json` | 48 positive/negative/UNKNOWN evidence challenges |
| `EVOLUTION_IMPACT_R2.json` | Seven source-change scenarios and bounded reverse-impact checks |
| `DKE_TO_DIS_HANDOFF_R2.json` | Selected Function dependencies and qualification blocking gates |
| `memory-dke-evaluator-r2.mjs` | Pure semantic and impact candidate evaluator |
| `verify-memory-dke-r2.mjs` | Exact-blob mechanical verification |
| `verify-memory-dke-r2.test.mjs` | Source lock and negative/UNKNOWN regression definitions |

## Current gate disposition

- **Gate A — Knowledge Qualified:** BLOCKED, independent Source-First review of R2 and missing native metric oracles.
- **Gate B — DIS Handoff Ready:** BLOCKED, Gate A incomplete; do not promote any ECP, Function or production AOT Package.
- **Runtime:** Existing R0 source has a native Windows *read-only* receipt at a previous SHA, not evidence of new PrivateWorkingSetSize, WPR Reference Sets or sampling-time attestation.
- **Original PR #416 independent findings:** P1 AOT semantic-rule provenance and P2 available/free naming and timestamp provenance remain separate repair obligations unless a different reviewer confirms resolution at a new Exact-SHA. R2 documents missing semantics; it does **not** quietly mark those runtime code defects repaired.
- **Actual optimization effect:** EXCLUDED. No automatic process termination, cache clearing, pagefile or hardware changes.

**Next action:** independent reviewer checks source/applicability, negative oracles and reverse-impact ownership before authoring any qualification; then repair only confirmed P0/P1/P2 under the same PR and rerun the exact-HEAD tests.
