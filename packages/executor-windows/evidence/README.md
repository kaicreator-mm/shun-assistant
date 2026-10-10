# Evidence — Issue #15 required set (real Windows 11 / UAC)

All runs on host `Nilar`, Windows 11 build 10.0.26300.9457, filtered
(non-elevated) admin token, UAC fully enforced (`EnableLUA=1`,
`ConsentPromptBehaviorAdmin=5`, `PromptOnSecureDesktop=1`) — same posture as
the frozen U-06 evidence. Run date: 2026-10-10.

| Case | Evidence dir | Required evidence item | Result |
| --- | --- | --- | --- |
| E1 | `E1-uac-positive-hklm/` | real UAC positive | two consented elevated runs: HKLM `SOFTWARE\ShunT04Evidence\probe` create+setValue → `SUCCEEDED` / `COMPLETED_VERIFIED` (postStateVerified=true via reconcile of declared expectedState), then delete → `SUCCEEDED` / `COMPLETED_VERIFIED`; key proven removed |
| E2 | `E2-uac-refused/` | real UAC negative / refused UAC | secure-desktop consent declined → relay HRESULT `0x80131509` → `UAC_DECLINED`, empty journal (helper provably never started), classification `NOT_STARTED` |
| E3 | `E3-kill-uncertain/` | process kill / uncertain | helper killed by external `taskkill /F` inside the step's effect window → no receipt, journal stops at `EXEC_START` → `MAY_HAVE_EXECUTED_UNCERTAIN`, terminal `UNCERTAIN` |
| E4 | `E4-kill-reconciled/` | uncertain reconciliation | helper killed after the declared side effect landed (marker file written by the killed step's child) → reconcile-first against declared `expectedState` → resolved `COMPLETED_VERIFIED`, `resolvedByPostState=true` |
| E5 | `E5-metachars-elevated/` | typed metacharacters | hostile parameter payload (`& | ; %PATH% " < > $() backtick`, CJK, `DEL /S /Q C:\`) written elevated and verified byte-exact — no shell exists anywhere on the path |

Plus negative/boundary evidence captured by the always-on test suite (95
tests, no elevation needed): plan tamper (`GRANT_PLAN_MISMATCH` inside the
helper), forged/self-declared grant (`GRANT_NOT_AUTHENTIC`), stale authority
(`GRANT_AUTHORITY_STALE`), superseded/revoked policy, revoked grant,
unresolvable currentness (missing AND corrupt), expired grant, helper path
substitution (launcher pin check AND helper self-check), launcher I/O escape
from the pinned workspace root, scope escape before any effect, NTFS-illegal
characters, junction/reparse-point rejection, cancel sentinel, helper-side
deadline, torn-journal replay and the full §9.4 classification matrix.

Each case directory contains the exact journal / receipt / relay artifacts of
the run plus a `summary.json`. Reproduce with:

```bash
pnpm test:evidence   # SHUN_EXECUTOR_EVIDENCE=1 required; human at console needed
```
