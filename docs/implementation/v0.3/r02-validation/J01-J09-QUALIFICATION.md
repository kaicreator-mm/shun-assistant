# R02 production qualification plan — J01–J09

**Status:** Zero-paid/zero-physical subset EXECUTED on real Windows Node 24 (`R02-VALIDATION-RECEIPT.md`); J02/J03/J05/J09 real journeys EXECUTED under `OWNER_SHUN_V030_R02_J02030509_DISPOSITION_APPROVE` (`AUTHORIZED-REAL-JOURNEYS-RECEIPT.md`). Post-R02-E integration (`47ecf345…`), the affected J07/J08 rows were targeted-requalified on real Windows Node 24.21.0 AND 26.13.0 (`R02-V-POST-R02E-REQUALIFICATION-RECEIPT.md`, generation 2); J01–J06/J09 evidence retained under the demonstrated exact source-path/environment equivalence. This matrix is **not** an R03 PASS or a release certificate.

**Post-R02-E integrated currentness:** J07 and J08 are both overall **UNKNOWN** for the positive selected-production-BUILD path. Their proven sub-results and the explicit limitations are listed below; fixture or demo-mode evidence is not promoted to a production PASS.

The selected release candidate for R02 must be the exact future merged `version/v0.3.0` commit containing all repair PRs, **not** historical `b97fad...`, planning merge `91420ed...`, or T11's fixture-built Kernel.

| Journey | True production acceptance | Evidence required | Current status |
|---|---|---|---|
| J01 Read-only support and B-040 | Real Windows Chinese OS caption, System32 fixed collector, localOnly and zero egress | Node>=24 Windows, exact SHA, host locale, output and canary negatives | **PASS (R02-VALIDATION-RECEIPT)** |
| J02 Plan/ActionController/Windows effect | One K-issued Permit and independent explicit human R2 precede effect; terminal poststate verified | Signed authorization, live Windows safe fixture, Journal and conflict/replay receipts | **PASS (real effect, authorized)** |
| J03 DeepSeek CN/EN remote interpretation | Exact disclosed bytes and consent, single sender/ledger/deadline; no auto-grant | Paid API credential/cost and real redacted receipts | **PASS (2 real paid completions, authorized; 7/8 ceiling)** |
| J04 Model-free recipe replay | Same immutable Case/scope, no model, selected K path and restart | Real Win storage and deterministic K/Host journals | **PASS (K-fence, receipt)** |
| J05 Signed Provider JIT | Approved production curator roots, signed bytes, cold/offline and recovery | Physical Windows install/cache/signature and rollback evidence | **PASS (real signed first-use, authorized)** |
| J06 Kernel UNKNOWN/recovery | Real selected public v0.10.3 SDK K, durable K doc CAS, never blind retry | Exact selected BUILD digest and crash/restart/UNKNOWN refusal | **PASS (receipt)** |
| J07 CN/EN UI/Control API | Actual installed Windows UI connects selected API and Guided/Host, truthful 200/202/409/422/503 | Real loopback browser interaction both locales, logs | **UNKNOWN (post-R02-E positive selected-BUILD production startup not activated)**. PROVEN sub-results: exact shipping command runner smoke in **T08 DEMO ONLY** mode; actual UI static asset served over loopback HTTP (**GET only; no browser interaction or CN/EN UI workflow**); hostile Host refusal, truthful 503s, loopback-only binding, and real-storage missing-trust no-listener negative on Node 24.21.0 + 26.13.0. Historical pre-integration PASS is not reattributed to the integrated production path. |
| J08 Guided Step/Outcome | Trusted operator Host Case, current selected scope, single persisted consumption, 409 replay, no auto-grant | Real Windows SQLite restart and new Host observation currentness | **UNKNOWN (positive post-R02-E production ProgramData trust path not executed)**. PROVEN sub-results: TEST_FIXTURE-only trust composition via `createProductionGuidedService` with a `DemoShunBackend` HTTP harness over real SQLite and loopback HTTP; refusal/replay/restart/stale-observation cases, anchor-swap and database-binding negatives. No production BUILD activation or positive fixed-ProgramData trust provisioning is claimed; historical pre-integration PASS remains historical only. |
| J09 Feedback/Shadow | Real Host outcome receipt, redacted opt-in candidate, separate promotion approval | Versioned BUILD and documented Shadow/provenance evidence | **PASS (real durable store; future-BUILD promotion stays an operator decision)** |

**No scope expansion:** No GitHub Actions, paid DeepSeek or physical Windows side effects without additional independent authorization. All positive/negative data must point to the identical runtime selected BUILD and real product startup; fake T11 facades, Vitest mock only or downloaded unsigned Provider packages are NOT positive evidence.

## Pending exact-SHA acceptance checklist

1. Full Woodpecker **actual** Node>=24 lint/typecheck/nested T00–T12/R02 suite exits and injected failure produces nonzero.
2. `version/v0.3.0` exact SHA, tree, public DomainHarness `v0.10.3` Git tag/SDK package SHA256, BUILD subjectDigest, selected K/S/B/C module IDs and Host principal.
3. Real Windows startup `SHUN_CONTROL_MODE=real-storage` with valid operator-pinned files and persisted Trusted Guided Case; no fake Seed/blank implicit approval.
4. Fail closed: K/Host unknown, invalid currentness, missing selected Case, forged issuer, external import mismatch, stale signed provider, cross-Case/locale and historical evidence rewrite.
5. Separate recording of real test commands, platform, Node version, exit status and artifacts. Never call UNKNOWN a PASS.

**Review and release:** Deferred until all implementation repairs are complete per Owner. This file is a validation plan, not R03 self-approval, Merge eligibility, or release consent.
