# U-06 Research Demo — Evidence record

Research demo for kaicreator-mm/shun-assistant issue #5 (UNKNOWN `U-06`).
Run on the local disposable Windows agent host. All 22 cases PASS.

## Host environment

| item | value |
| --- | --- |
| OS | Windows 11 25H2, build 10.0.26200.9457 |
| account | NILAR\15549 — member of local `Administrators`, running with filtered (non-elevated) token |
| UAC | EnableLUA=1, ConsentPromptBehaviorAdmin=5 (prompt for consent), PromptOnSecureDesktop=1 |
| tooling | PowerShell 5.1.26100.9444, winget 1.29.380, Node v24.21.0 |
| elevation probes | writing `C:\Windows\<dir>` and `HKLM:\SOFTWARE\<key>` denied for the filtered token → elevation-gated fixtures are genuine on this host; `Register-ScheduledTask -RunLevel Highest` from the filtered token → Access Denied → no unattended elevation side channel exists here |

Method: typed `AuthorizedAction` envelope as a JSON file on disk (never
command text); PowerShell one-shot helper validates **inside** the
privileged boundary in this order — schema/op enum → planHash
re-computation → approval binding + expiry → declared scope → privilege
consistency — then journals phases, executes, writes an ExecutionReceipt,
exits. `planHash = sha256(canonical-json(plan))`; the privileged side
re-computes the hash with an independent PowerShell implementation
(cross-language agreement with the Node builder).

## Positive evidence

| case | result |
| --- | --- |
| D1-a/b/c | `OK_STRUCTURED` — OS/build, service query, package inventory via typed argv, single-line JSON on stdout, clean stderr, exit codes (raw JSON in `evidence/local/summary.json`) |
| D2-a | `COMPLETED_VERIFIED` — `evidence/d2/`: UAC consent → elevated helper (receipt `elevated=true`, `terminal=OK`, `planHash=5545c6c15bf8b41064c117df568e846a9c8887b0d001dfa2531dee0943a84385`, approvalId `appr-6a2df3076c55`) executed an 8-step HKLM lifecycle (create → set planHash/approver/timestamp → in-helper verify → **delete → verify-gone**) under approval bound to that exact planHash; non-elevated post-state verification confirmed zero residue |
| D3-a | `COMPLETED_VERIFIED` — `evidence/d3/`: 6-step winget lifecycle through the same plan-bound elevated helper: inventory → `install 7zip.7zip --version 26.04 --scope machine` → verify installed (registry uninstall entry + `winget list`: `7-Zip 26.04 (x64 edition) 7zip.7zip 26.04.00.0 winget`) → uninstall → verify gone. Installer captured from the official source, winget output: `Downloading https://www.7-zip.org/a/7z2604-x64.msi` / `Successfully verified installer hash`. No third-party mirror. |

## Negative evidence (`D4`)

| case | expected | result |
| --- | --- | --- |
| D4-1 unknown op (`shell.exec`) | refuse | `REFUSED` — "unknown op … no arbitrary shell endpoint" |
| D4-2 plan mutated after approval | refuse | `REFUSED` at planHash phase; fixture absent |
| D4-3 path outside declared scope (fresh valid approval) | refuse | `REFUSED` at scope phase, before any effect |
| D4-4 shell metacharacters `; & $ ( ) % ^ !` in filename and content | literal pass-through | `COMPLETED_VERIFIED` — file created and content read back byte-exact (typed envelope, no shell) |
| D4-4b NTFS-illegal char (`\|`) in typed path | structured refusal | `REFUSED` — fail-closed scope-validation error, no crash, no side effect |
| D4-5 expired approval | refuse | `REFUSED` |
| D4-6 forged `authorizationRef.approvalId` | refuse | `REFUSED` |
| D4-7 UAC declined | helper never starts | `UAC_DECLINED` — genuine secure-desktop refusal (124 s ≈ the 120 s UAC auto-cancel window), journal empty, no process started (`evidence/decline/`) |
| D1-d/e/f | stderr separation / timeout / cancel | `FAILED_STDERR_SEPARATE`, `TIMED_OUT` (launcher tree-kill), `CANCELLED` (cooperative cancel sentinel honored between phases) |

`D2-b` (also negative): the approved plan was mutated **after** approval and
pushed through the real elevated helper — Action Controller pre-check rejects
(`plan hash mismatch (plan tampered)`) and, when launched anyway with UAC
consent, the privileged helper independently refuses at its own planHash
re-computation (`REFUSED`, exit 2, journal `RECEIVED→VALIDATED→REFUSED→
RECEIPT_WRITTEN`, fixture absent — `evidence/d2tamper/`). Editing the plan
invalidates the authorization across the privilege boundary.

## Recovery / evidence classification (`D5`)

Journal phases: `RECEIVED → VALIDATED → PLANHASH_OK → APPROVAL_OK → SCOPE_OK
→ ELEVATION_OK → EXEC_BEGIN → (EXEC_START → EXEC_DONE)×n → RECEIPT_WRITTEN`.
No side effect can precede the `EXEC_START` of its step (all validation
phases run first), which makes the outcomes decidable:

| case | scenario | classification |
| --- | --- | --- |
| D5-a | hard kill after `EXEC_START`, before side effect | `EXECUTED_PARTIALLY_RESOLVED_BY_VERIFICATION` (post-state: nothing executed) |
| D5-b | hard kill after step-0 effect, before step-1 | `EXECUTED_PARTIALLY_RESOLVED_BY_VERIFICATION` (A present, B absent → partial execution proven, recovery required) |
| D5-c | same + torn journal append | tolerant replay — torn line isolated as `TORN_LINE`, earlier phases intact (`evidence/local/raw-d5c-torn.journal.jsonl`) |
| D5-d | same as B **without** post-state verification | `MAY_HAVE_EXECUTED_UNCERTAIN` — the honest residual outcome |
| D5-e | kill after final `EXEC_DONE`, before receipt | `EXECUTED_RECEIPT_LOST` — post-state verification resolves |

Four-way distinction without any broker:

- **definitely not started** — no `RECEIVED` (or UAC declined before spawn);
- **failed before side effect** — journal stops before first `EXEC_START`;
- **may have executed / uncertain** — kill inside a step's
  `[EXEC_START, EXEC_DONE)` window; resolvable by post-state verification
  whenever the action declares verifiable expected state;
- **completed and verified** — `RECEIPT_WRITTEN` + independent post-state check.

A persistent broker cannot shrink the uncertain window to zero either (a
broker crashes between dispatching work and recording the outcome just the
same), so the one-shot model loses nothing here — it only moves where the
journal lives.

## Architectural findings

1. **The hypothesis holds.** A one-shot elevated helper preserved the whole
   contract: `AuthorizedAction` (typed envelope) → structured execution →
   journal → `ExecutionReceipt` → post-state verification, for both
   non-elevated and elevated operations, with plan-bound authorization
   enforced inside the privileged boundary.
2. **Authorization binding is enforceable at the privileged side**, not only
   at the controller: the helper's independent planHash re-computation
   refused the tampered plan even with a syntactically valid envelope
   (D2-b). Cross-language canonicalization agreement (Node ↔ PowerShell) is
   part of the evidence that plan identity is representation-stable.
3. **Cross-privilege cancellation must be cooperative.** A non-elevated
   parent cannot force-kill an elevated child (Access Denied); the helper
   must therefore enforce its own deadline (per-step checks + exe-level
   `WaitForExit(timeout)` + kill) and poll a cancel sentinel between phases.
   The launcher-side timeout remains last-resort for non-elevated children
   only. This is a real constraint for `LocalWindowsBackend` design.
4. **Interactive UAC consent is not automatable** (secure desktop by
   design) — demonstrated, not assumed: the decline path yields a structured
   `UAC_DECLINED` with the helper provably never started. An agent runtime
   needs a policy-governed elevation channel (interactive consent, or a
   pre-authorized mechanism such as an elevated scheduler entry). That is a
   Shun **policy/authorization** seam, orthogonal to the executor seam: the
   one-shot helper is agnostic to how elevation is obtained.
5. **Fail-closed receipts are mandatory.** Early runs exposed two crash
   paths (scope-validation exception on illegal path characters; a
   transient registry-view error right after winget uninstall). Both were
   hardened so any validation/execution exception produces a structured
   `REFUSED`/`FAILED` receipt — a crash without receipt would break D5's
   four-way distinction. The final run set is crash-free.

## Known limitations

- Throw-away harness: PowerShell 5.1 + Node, zero external dependencies;
  canonical-JSON/SHA-256 is deliberately duplicated across the boundary for
  the experiment. Not production code, per issue #5.
- Single host, single account, zh-CN locale; no VM snapshot/rollback.
- One transient crash (registry view settling immediately after
  `winget uninstall`) was observed in an intermediate D3 run before the
  fail-closed hardening; the committed final D3 run is PASS.
- `winget list` output is human-oriented text; machine-readable inventory
  needs a different winget API surface (out of demo scope).
- Elevated positives required a human clicking consent on the secure
  desktop (3 prompts); consent-dependent evidence is inherently
  interactive on this host.

## Terminal

```ini
RESEARCH_DEMO=U-06
RESULT=PASS
ARCHITECTURE_DISPOSITION=ONE_SHOT_ELEVATED_HELPER_SUFFICIENT
```

Evidence basis: 22/22 cases PASS — D1 6× structured execution, D2 elevated
plan-bound lifecycle + tamper refusal, D3 official winget package lifecycle,
D4 8× negative paths (including genuine UAC refusal), D5 5× recovery
classification. Raw committed artifacts in `evidence/`; exact demo commit
SHA recorded in the issue #5 terminal comment.
