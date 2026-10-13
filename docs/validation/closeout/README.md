# Shun v0.1 — Version Closeout (T11)

Authority: Issue #22 (T11), Program Controller #10, frozen DAG
`docs/planning/task-dag-v0.1.md@00fce240fa24fcaedd94d7f5f35f985fbc61a676`.

This directory is the durable T11 closeout record. It is documentation-only;
every load-bearing claim points at independently re-verifiable evidence
(tenant-run logs sealed under SHA-256, GitHub issue terminal IDs, CI run IDs).

## Candidate identity

```ini
CANDIDATE_SHA=2313ba2773dac7aa535570e22760147d9b383b65
CANDIDATE_TREE=cd9c4c772df707a1f36cf78c59c8f2d07e26dd6d
CANDIDATE_COMMIT=Merge PR #77: real Windows C003 control and recovery safety
BASELINE_MAIN=2313ba2 (mirror main == candidate; zero open PRs at closeout)
T10_TERMINAL=#21 comment 6151025323 (PASS_WITH_QUALIFICATIONS)
```

## Evidence index

| Artifact | Location | Seal |
|---|---|---|
| T11 full gates (lint/typecheck/test, exact SHA) | `_tmp/t11-closer/{lint,typecheck,test}.log` (workspace evidence root) | `evidence-sha256.txt` |
| Gate exit codes | `_tmp/t11-closer/exitcodes.txt` | `evidence-sha256.txt` |
| Install smoke | `_tmp/t11-closer/install.log` | `evidence-sha256.txt` |
| Runtime smoke server log | `_tmp/t11-closer/smoke-server2.log` | `evidence-sha256.txt` |
| T10 whole-matrix host evidence (9 rows, 138 files) | `_tmp/t10-final-winval/` | manifest sha256 `5245316d…ed423` (recomputed match, review terminal) |
| T10 UAC Row-7 delta (6 secure-desktop decisions) | `_tmp/t10-final-winval/uac/` | manifest sha256 `c4a6e8b2…8b31a` (recomputed match) |
| T10 fresh independent review terminal | Issue #21 comment 6150849661 | GitHub |
| CI at candidate SHA | GitHub Actions runs 38397967665 (contracts), 38397967948 (vertical-storage) | live API verified 2026-10-13 |

## Verdict summary

```ini
T11_FULL_REGRESSION=PASS (fresh run @candidate: lint 0 / typecheck 0 / test 0; 1266 passed, 3 skipped, 0 failed; integration 3/3 files)
T11_CRITICAL_JOURNEYS=PASS_BY_REFERENCE (T10 whole-matrix terminal, independently reviewed)
T11_PACKAGE_INSTALL_UNINSTALL_SMOKE=PASS (see packaging-smoke.md)
T11_HIDDEN_VALIDATION=NOT_APPLICABLE_AS_SEPARATE_LANE (sealed T09 oracles; see below)
T11_CANDIDATE_FREEZE=2313ba2773dac7aa535570e22760147d9b383b65
T11_RELEASE_QUALIFICATION=QUALIFIED_WITH_QUALIFICATIONS (see v0.1-closeout.md)
RELEASE=NOT_CLAIMED (no release artifact or publication is made by this closeout)
```

## Hidden validation disposition

T09 produced sealed benchmark fixtures and an independent semantic oracle
(`tests/fixtures/**`, `tests/oracles/**`, `tests/harness/**`); the private gold
was never disclosed to builders or validators. T10 exercised those sealed
oracles on the real host (B-037 831/831, B-039 30/30, B-040 17/17 with external
egress observer). There is no additional hidden-validation lane mandated by the
frozen DAG beyond T09+T10; this closeout therefore records
`HIDDEN_VALIDATION=NOT_APPLICABLE_AS_SEPARATE_LANE` rather than inventing a new
gate. The hidden oracle remains sealed and unread by this closeout.

## T10 qualification carry-overs (tracked, not silently dropped)

- **P1 (test-only, nonblocking):** `packages/executor-windows/test/evidence/real-uac.evidence.test.ts` is stale against protected-anchor/program-pin hardening; excluded from the default gate by `vitest.config.ts`. Follow-up: port `prep-elevated-v2.mts` + `pinProgram(node.exe)` provisioning into the checked-in harness after source freeze. No runtime safety guard may be weakened.
- **P2-1:** B-038 N5b assertion redesign (safety invariants + at most one non-zero-deletion winner) and preservation of first-run journals.
- **P2-2:** B-040 zero-leak proof bound restated at ~640ms effective TCP cadence, TCP-only, DNS via client-cache diff.
- **P2-3:** extend the T10 evidence manifest to cited raw monitor/journal files or state the curation boundary explicitly.
- **E2 consent-timeout variant:** NOT_RUN; accepted via the frozen refusal-surface wording (decline or timeout → `UAC_DECLINED`, empty journal, `NOT_STARTED`).
