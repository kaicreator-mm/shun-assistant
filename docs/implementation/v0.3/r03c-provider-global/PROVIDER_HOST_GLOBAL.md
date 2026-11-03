# R03C-PROVIDER-GLOBAL-UAC — Host-global Provider first-use implementation notes

Issue #287 · Execution Pack `.agent/execution/R03C-PROVIDER-GLOBAL-UAC-RECEIPT-ALLOWLIST/MANIFEST.yaml@ba149aa594f9507913157f79e14a4c49873815cb` · LOCAL_BUILDER generation 3 · baseline source `fe7a8614521d9a4b4222d89a2b31c6c0b9031e1c`.

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

`installTrustedProviderBinding` accepts optional `fetchArtifact`, `process` and `hostFacts` overrides (production defaults remain the real fetch, `BoundedSpawnProcess` and real host facts) so the qualification suite exercises the real verifier→stager→activator chain with in-memory fixture bytes, a capturing spawn port and the pinned `windows-x64` host facts — zero network, zero real child processes, on any CI host.

## Generation-3 privacy hardening (P1 + P2 repair)

Closing PR #302 findings `R03C-PROVIDER-P1-RAW-PROVIDER-OUTPUT-PERSISTED` (comment 6595168881) and `R03C-PROVIDER-P2-UNVALIDATED-DURABLE-RECEIPT` (comment 6595125211), same six-path write set:

- **Raw provider output eliminated** — `envelopeFrom()` no longer copies `result.stdout`/`result.stderr` into the returned capability envelope, and the terminal receipt never stores provider text. The VERSION_PROBE is reduced to a **strictly parsed version token** (last whitespace token of the first line, kept only when exactly version-shaped; otherwise only `probeVersionParsed:false` is recorded) plus the Host-pinned binding/artifact digest; the FILE_SEARCH canary is reduced to the **enum** `MATCHED | NOT_MATCHED | UNCLEAR`. A secret-shaped stdout regression proves the secret is absent from both the returned envelope and the raw `receipt_json` in SQLite.
- **Closed-world preview** — `validatePreview` enforces the exact key set of the preview (8 keys; 9 with `elevatedAction`) AND of the nested `elevatedAction` (4 keys); caller-supplied extra properties are refused on `prepare` and again on every `decodeRow` read.
- **Closed-world receipt schema shared by write and read** — `finish()` refuses any receipt outside the allowlisted flat key set (`outcome`, `code`, `bindingId`, `artifactSha256`, `probeVersion`, `probeVersionParsed`, `canaryResult`, `elevatedTerminal`, `exitCode`, `timedOut`, `durationMs`) or whose `outcome` disagrees with the terminal status; `decodeRow()` re-validates the persisted JSON with the same validator, so legacy/unknown/malformed shapes fail closed on read. Serialized length stays as a bounded additional guard, never the only one.
- **Privileged receipt allowlist projection** — `effect-host-binding.ts` exports `projectPrivilegedReceipt`, reducing the privileged backend `ExecutionReceipt` to `terminal` classification + bounded exit/timeout/duration facts; `outputRefs`, `stdoutRef`, `stderrRef`, `environmentId`, absolute paths, raw output and arbitrary nesting are structurally dropped before anything is persisted or returned.
- The PREPARED → APPROVED → RUNNING one-way state machine, restart RUNNING→UNKNOWN sweep (`PROCESS_RESTARTED_WITH_UNCERTAIN_OUTCOME`, now in the new receipt shape) and EXPIRED handling are unchanged.

## Explicitly out of scope / not done here

- Control API routes, DomainApp activation modules and UI exposure — owned by the single R03C Integrator (#288).
- Real installer execution, persistent system change, ProgramPin provisioning/rotation — separate Owner authorization; LOCAL validation may exercise only a pre-pinned read-only identity probe through the real relay path.
- No `main`/`version/v0.2.0` mutation, no merge/tag/release, no paid LLM, no cloud sync.
