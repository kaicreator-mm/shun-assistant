# Shun v0.1 — Post-T11 release evidence reconciliation

Scope: **documentation-only successor** to PR #78's historical T11 closeout. It does not alter the frozen product candidate or retroactively rewrite signed/hashed host evidence. The Controller owns the final release decision.

## Immutable identity

| Role | Exact commit/tree |
| --- | --- |
| Frozen executable source candidate | `2313ba2773dac7aa535570e22760147d9b383b65` |
| Frozen source Git tree | `cd9c4c772df707a1f36cf78c59c8f2d07e26dd6d` |
| Original docs-only closeout | PR #78, merge `c766efd0d7452e72a8a726dd782ec95b8ff4bc63` |

Tagging a later docs-only baseline MUST explicitly refer back to the pinned executable source candidate. New source code would invalidate freeze; a documentation-only successor does not change previously qualified executable bytes.

## Later evidence received after the original closeout

| Gate | New independent evidence | Disposition |
| --- | --- | --- |
| T10 Windows + fresh review | Shun #21 comments `6148650270`, `6150083379`, `6150849661`, Controller `6151025323` | 9/9 PASS **with qualifications** |
| T11 full regression + docs review | Shun #22 `6151348464`, `6151368686` | 1266 passed, 3 skipped, 0 failed; 3/3 integration; docs-only PR #78 merged |
| Frozen-source **git archive** release smoke | Shun #22 `6152408374` | `shun-assistant-2313ba2.tar` SHA-256 `d0ff4f830945aea0d26691a9760fa595d6a59fd51e5ecb24aa054b61800df932`; two archives byte-identical; extracted 513/513 blobs match; frozen pnpm install, lint/typecheck/test, actual UI/API and C001/C002/C003 loops, protected canaries and isolated teardown PASS |
| Package evidence integrity | Shun #22 `6152408374` | Host reports 8,997-file `PKGVAL-SEALS.txt` SHA-256 `4c2b6d4c016fc7952e7e598d58c03ab9015746c33cae48ea73c6b6a4c769bba1`; still requires independent raw-file audit before release tag |
| Independent **hidden pack** | Shun #22 `6152779818`; private `kaicreator-mm/hidden-validation#56` and result blob `3ec23fc07389cac9fb12289b013427b054652018` at `c393d16` | PASS **60/60**, nine coverage families, 0 failed/blocked/not-run, same candidate commit/tree. Private cases, gold and scoring do not belong in this repository |

### Supersession of original closeout text

PR #78's `docs/validation/closeout/README.md` and `v0.1-closeout.md` state `HIDDEN_VALIDATION=NOT_APPLICABLE_AS_SEPARATE_LANE` **as of that early terminal**. Later a genuinely independent private pack was built and executed at the frozen source. For **current release qualification**, the more recent evidence above supersedes the older not-applicable disposition: **HIDDEN_VALIDATION=PASS_60_OF_60**, NOT `NOT_APPLICABLE`. The older signed historical decision remains available for traceability.

Likewise, the original packaging-smoke document covered a private clean-checkout demo install only. The later full **source-archive** terminal additionally covers byte-for-byte archive identity, extracted-package full regression, production real-storage UI, native WinGet lifecycle and provider cleanup, semantic oracles and removal of the isolated install directory. It does **not** create or claim an MSI/MSIX/EXE installer; v0.1's accepted deliverable is an immutable executable **source** proof bundle.

## Explicit unresolved bounds

1. **UAC:** The extracted-archive packaging run's *additional* human secure-desktop E1/E5 lane was NOT_RUN; the same frozen production source previously passed six actual operator consent/refusal prompts in T10 #21. The package's fail-closed anchor and filtered-token refusal paths were separately rerun. Do not mislabel package E1/E5 as executed or weaken UAC protections.
2. **Network privacy:** The package observer covers TCP/UDP IPv4/IPv6 using externally observed socket-table polling (typical ~30–45ms, worst recorded 1.63s) and reports zero collector-owned socket rows. Kernel WFP/ETW and the disabled DNS-Client event log were NOT_RUN; hidden egress tests use in-process interception, not kernel capture. Absolute or continuous zero-egress is **not proven**. The release decision must accept this bounded assurance explicitly or request a targeted privileged capture.
3. **Earlier T10 debt:** stale checked-in real-UAC evidence harness (test-only, excluded from default CI); B038 N5b strict one-winner claim not proven; T10 raw-monitor/journal manifest coverage incomplete; separate E2 consent-timeout not run (human decline satisfies frozen E2 decline-or-timeout wording).
4. **New packaging evidence review:** The 8,997-file raw host archive/log seal is reported by its validator, but no separate **fresh independent raw package-evidence audit** is recorded yet; the original T11 independent review predates this later archive. Release Controller must obtain such an audit or record an explicit standards-compliant waiver, not silently re-label historical T11 review.

## Controller release gate

```ini
TASK_DAG=12_OF_12_CLOSED
SOURCE_CANDIDATE=2313ba2773dac7aa535570e22760147d9b383b65
CANDIDATE_TREE=cd9c4c772df707a1f36cf78c59c8f2d07e26dd6d
PACKAGE_ARCHIVE=VALIDATOR_REPORTED_PASS
HIDDEN_VALIDATION=PASS_60_OF_60
POST_PACKAGE_INDEPENDENT_RAW_EVIDENCE_REVIEW=PENDING
KERNEL_EGRESS_TRACE=NOT_RUN_EXTRA_COVERAGE
PACKAGED_UAC_POSITIVE=NOT_RUN_CARRIED_FROM_T10_SOURCE_IDENTITY
RELEASE_DECISION=PENDING_CONTROLLER_QUALIFICATION
RELEASE_TAG=NOT_CREATED
```

No `Release PASS`, Git tag, repository release or published binary is implied by this addendum. Preserve the exact archive bytes, evidence seals and candidate SHA when a future qualification terminal authorizes a tag.
