# R03C Provider-global / Meta shared production wiring (v0.3.0)

Owner-approved single-integrator wiring for the two Host-global lanes
(Issue #288, write set frozen at 12 paths; this document is one of them).
Baseline: combined exact source `85150b55a05986203d2600324684fe6e2158af97`
(#285 + #287 + #289 ancestry + #303). Predecessor contracts are authoritative:
#285 (Meta store), #287 (Provider Host-global ledger/UAC), #289 (signed
privilege descriptor), #303 (public package surface).

## Topology (no second Kernel, dispatcher, sender, database or authority)

```
Browser/operator ──HTTP──► control-api (trusted composition only)
                                │
  ┌─────────────────────────────┼───────────────────────────────────┐
  │ Provider lane (Host-global) │ Meta lane (current-Case scoped)   │
  │                             │                                   │
  │ POST /api/v03/provider/     │ POST /api/v03/meta/shared-query  │
  │   prepare  (no Case/refs)   │  {caseId, currentnessRef,        │
  │ POST /api/v03/provider/     │   approvalRef, capabilityId,     │
  │   confirm  {requestRef}     │   taskClass?, limit?}            │
  │                             │                                   │
  ▼                             ▼                                   ▼
Host: staged shun-provider-host          Host: reference-authenticated
  prepareProviderFirstUse()                journey admission (live Case
  confirmProviderFirstUse(requestRef)      step + Host-issued ref pair)
  (durable ledger, one-time                targetCaseRef := caseId
   requestRef, TTL)                        (never caller-chosen)
  │                             │                                   │
  ▼                             ▼                                   ▼
Selected V10 DomainApp facade.send()  ── SAME selected K, ONE writer ──
  │                             │                                   │
  ▼ intent: submitProviderFirstUse      ▼ intent: querySharedExperiences
    instanceKey: provider-global          instanceKey: <current caseId>
    input: {requestRef}                   input: {targetCaseRef,
                                               capabilityId, taskClass?,
                                               limit?}
  │                             │
  ▼ external Effect Permit      ▼ INTERNAL effect (no Permit minted,
    gate (K-issued)               zero external dispatch)
  │                             │
  ▼ capability provider         ▼ capability meta-memory
    (externalEffect:true)         (externalEffect:false)
  │                             │
  ▼ shun-provider-host          ▼ shun-meta-host (wrapping install)
    providerFirstUse({requestRef})  querySharedExperiences(input)
    signed-privilege enforcement    ──► HostMetaShadowStore (#285 store)
    + pre-pinned UAC backend        fail-closed validation/currentness/
    (#287/#289, Host-owned)         revocation; advisoryOnly data
```

## Provider lane contract

1. `prepare` is Host-only and Case-free: no Guided Case, Case ID,
   `currentnessRef` or `approvalRef` is consulted, stored or accepted. The
   Host stages the pinned verified artifact, mints the one-time
   `requestRef` (`provider-request-<uuid>`, 5-minute TTL, exactly one
   pending request) and returns the exact closed preview. For a signed-USER
   descriptor the preview carries no `elevatedAction`; ELEVATED previews
   carry only the pre-pinned installer action/grant/plan/ProgramPin summary
   (no secrets; #287 generation-5).
2. `confirm` consumes PREPARED→APPROVED exactly once in the durable ledger.
   A malformed, wrong, expired or replayed `requestRef` refuses with **zero**
   Kernel sends and zero provider activation. The confirm body is validated
   to be exactly one bounded `requestRef` — no `intentType`, `instanceKey`,
   `taskId`, `path`, `args` or `privilege` field is accepted from any caller.
3. After confirmation the trusted composition submits the FIXED Business
   Intent through the selected V10 facade: `intentType: submitProviderFirstUse`,
   `instanceKey: provider-global`, `input: {requestRef}`. It does not route
   through the Case-scoped `createJourneySubmits.admit()` path, and
   `queryAuthority` (K `query`/`subscribe` authorization only, per
   DomainHarness #1465) is never consulted for send admission — the route
   works with no Case selected at all.
4. Privilege authority is the curator-signed `requiredPrivilege` from #289:
   omitted/USER stays unprivileged and refuses an ELEVATED operator action
   configuration; ELEVATED requires the signed CLI descriptor plus the exact
   pre-pinned action/grant/plan/ProgramPin through the existing UAC backend.
   Host configuration cannot override the signed descriptor (enforced inside
   the #287 Host binding, which remains the single authority).
5. The legacy Case-scoped `POST /api/v03/provider/first-use` journey route is
   superseded: it now refuses closed with `PROVIDER_ROUTE_SUPERSEDED` and
   directs callers to prepare/confirm (the K intent consumes only
   `{requestRef}`; the old `{taskId}` shape is no longer admitted).

## Meta lane contract

1. The shared-experience query is a read-only Business **read intent** over
   the same selected V10 `facade.send()` route used by the other journeys,
   with Case-scoped reference authentication (live Guided step +
   Host-issued pair). It is NOT a K snapshot `query()`/`subscribe()` and
   performs no direct SQLite/SQL access — the selected K owns intent
   admission and dispatch.
2. The intent invokes a separate BUILD-selected read-only C module
   (`shun.capability.meta-memory`, `externalEffect: false`): the kernel
   dispatches the sealed handler in-process with zero Permit minting and
   zero external dispatch. Feedback writes stay in the separate effectful
   `capability-meta` module; nothing in this lane touches it.
3. Query inputs match the #285 store contract exactly: `targetCaseRef`
   (injected by the trusted composition as the admitted current Case —
   the caller can never choose a target Case), `capabilityId`, optional
   `taskClass` and a bounded `limit` (1..20; store default 10/max 20). The
   unsupported `tags` filter does not exist at any layer; unknown or
   free-text fields refuse at the gateway with zero K sends.
4. Results are privacy-minimized verified experience records marked
   `advisoryOnly: true`, with source-Case provenance only. The source Case
   is never an equality gate against the target Case. No Permit, grant,
   approval, executable action, policy mutation or Shadow promotion is
   minted; a query writes nothing to the durable store and never calls a
   paid/cloud LLM.
5. Stale, superseded, expired-consent and revoked experience rows are
   excluded by the store's own currentness/revocation revalidation
   (`declaration_seq` ordering; opt-out immediately revokes and never
   resurrects).

## Multi-Case Host provisioning (boot)

`provisionMetaFromHostFile` (in `composition-journeys.ts`, used by
`main.ts`) keeps the operator-pinned hash-pinning discipline and accepts
exactly one of two file forms:

- legacy: `{ "receipt": {...}, "consent": {...} }` (unchanged behavior);
- batch (R03C): `{ "cases": [ { "receipt": {...}, "consent": {...} }, ... ] }`
  with a bound of **16** cases — enough to seed more than one source Case
  into the SAME local DB at boot.

The whole file is sha256-pinned (`SHUN_V03_META_CASE_SHA256`); every record
must carry the minimal receipt/consent shape and the durable store
re-validates strictly on write. Digest mismatch, malformed entries, a file
mixing both forms, and over-bound batches all refuse closed at boot.

## Build/manifest admission

- New Domain Packages: `shun.business.meta-memory@v0.3.0` (B,
  `intent:querySharedExperiences`) and `shun.capability.meta-memory@v0.3.0`
  (C, `capabilityId: meta-memory`, `externalEffect: false`). The repaired
  `shun.business.provider@v0.3.0` now binds `payloadFromInput:
  {requestRef}`; V8 Qualified ABI identifiers (`v08-business-abi/1`,
  `v08-capability-abi/1`) are unchanged (#303 naming policy).
- A manifest declaring `submitProviderFirstUse` or `querySharedExperiences`
  must bind the frozen capability family (`provider` / `meta-memory`) and
  must be backed by the real journey binding configuration — the production
  composition refuses boot otherwise, and a route pointing either intent at
  another capability refuses as authority forgery.
- Module budget unchanged: 4–10 modules per trusted build (kernel/standard
  singletons mandatory). A build carrying goal + provider + meta-feedback +
  meta-memory pairs fits within the budget.

## Staged consumer bindings (ensure-consumer)

`tests/integration/v03/r02-a-build/ensure-consumer.mjs` stages the real Host
sources through identity-pinned shim packages so the composing process and
the sealed capability share ONE module instance:

- `shun-provider-host` (v2) additionally exports the Host-only
  `prepareProviderFirstUse`, `confirmProviderFirstUse`,
  `readProviderFirstUseRequest` and `closeTrustedProviderBinding`.
- `shun-meta-host` (v2) wraps `installTrustedMetaBinding` to capture the
  exact `HostMetaShadowStore` instance and exports a read-only
  `querySharedExperiences` over it; the #285 store remains the sole
  authority (validation, currentness, revocation all live inside it).

## Qualification

- `tests/integration/v03/r03c-provider-global/provider-global-route.test.ts`
  — real HTTP prepare/confirm over the production composition: no-Case
  prepare, closed preview, one-pending rule, fixed-intent confirm, replay/
  malformed refusal with zero executions, no raw stdout.
- `tests/integration/v03/r03c-meta-shared/meta-shared-production.test.ts`
  — real HTTP cross-Case/same-Case retrieval through the K to the Host
  store, exact input contract (tags refused), advisory-only results, zero
  LLM calls, revocation exclusion, and the multi-Case provisioning matrix
  (legacy/batch/tamper/malformed/both-forms/over-bound).
