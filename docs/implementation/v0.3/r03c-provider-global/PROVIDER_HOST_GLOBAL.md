# R03C-PROVIDER-GLOBAL-UAC — Host-global Provider first-use implementation notes

Issue #287 · Execution Pack `.agent/execution/R03C-PROVIDER-GLOBAL-UAC/MANIFEST.yaml@23019ee4f7afdce7b5051cc4555ea054b97bca5f` · LOCAL_BUILDER r1 · baseline `be2e81722a70ee3d0bd5634bc83d97d733c20b78`.

## What this Task delivers

1. **`packages/domain-host/src/provider/provider-first-use-ledger.ts` (new)** — durable, Case-independent request ledger (`provider_first_use_requests` SQLite table) stored under the operator-owned Provider cache root. Host-issued random `requestRef`, exact bounded preview (provider identity, binding, digest, publisher key, privilege scope, reason, expected changes, and — for ELEVATED only — the installer program/args/side-effect class), 5-minute TTL, bounded receipts, and the one-way state machine:

   ```text
   PREPARED -> APPROVED -> RUNNING -> COMPLETED | REFUSED | UNKNOWN
       |           |          |
       +-> EXPIRED +->EXPIRED +-> UNKNOWN (process-restart sweep)
   ```

   At construction any abandoned `RUNNING` becomes `UNKNOWN` (`PROCESS_RESTARTED_WITH_UNCERTAIN_OUTCOME`) and unconfirmed `PREPARED`/`APPROVED` rows become `EXPIRED`. Nothing is ever auto-replayed.

2. **`packages/domain-host/src/provider/provider-host-binding.ts` (rewritten flow)** — the trusted seam now serves the Host-global request flow:
   - `prepareProviderFirstUse()` (async) first stages the PINNED verified artifact into the operator cache root (the real verifier→stager chain; a confirmed run can then only execute exactly these verified bytes), then builds the bounded preview from the pinned identity alone (no Guided Case, no caller identity) and creates the `PREPARED` request.
   - `confirmProviderFirstUse(requestRef)` is the explicit human confirmation (`PREPARED → APPROVED`, exactly once).
   - `providerFirstUse({ requestRef })` is the K capability: the payload carries **only** `requestRef` (anything else → `PROVIDER_INPUT_REFUSED` before the ledger is touched); `APPROVED → RUNNING` happens exactly once before any execution; terminal receipts are recorded `COMPLETED`/`REFUSED`, and an interrupted activation is recorded `UNKNOWN` (no blind retry).
   - The privilege scope is **operator-pinned Host configuration** at this baseline (the signed `requiredPrivilege` field arrives with the #289 contract through the #288 Integrator): `elevatedAction` present = ELEVATED, absent = USER. ELEVATED is refused outright for non-CLI artifacts, and `prepare()` refuses every request unless the ONE pre-provisioned `provider-global` installer action resolves with current grant/plan/authority in the authority store — so a drifted or missing provisioned action can never issue a request at all.

3. **`packages/domain-host/src/windows/effect-host-binding.ts` (extended)** — reuses the EXISTING `PrivilegedWindowsExecutionBackend` and its pinned one-shot UAC relay (no second RunAs helper): `previewTrustedElevatedAction()` resolves the ONE operator-provisioned `provider-global` `windows.proc.exec`/`windows.proc.contextCheck` installer action from the durable authority store (exact `actionRef`/`planRef`/`grantRef`, current grant/plan/authority via `validateGrantPresentation`, secret-shaped arguments filtered out) and `executeTrustedElevatedAction()` executes it, mapping `SUCCEEDED → COMPLETED`, definitive failures (`REFUSED`/`UAC_DECLINED`/`CANCELLED`/`FAILED`/`TIMED_OUT`) → `REFUSED`, and every uncertain boundary → `UNKNOWN`. ProgramPin verification stays inside the existing backend (read-only preflight; no runtime pin creation/rotation).

## Test seams

`installTrustedProviderBinding` accepts optional `fetchArtifact` and `process` overrides (production defaults remain the real fetch and `BoundedSpawnProcess`) so the qualification suite exercises the real verifier→stager→activator chain with in-memory fixture bytes and a capturing spawn port — zero network, zero real child processes.

## Explicitly out of scope / not done here

- Control API routes, DomainApp activation modules and UI exposure — owned by the single R03C Integrator (#288).
- Real installer execution, persistent system change, ProgramPin provisioning/rotation — separate Owner authorization; LOCAL validation may exercise only a pre-pinned read-only identity probe through the real relay path.
- No `main`/`version/v0.2.0` mutation, no merge/tag/release, no paid LLM, no cloud sync.
