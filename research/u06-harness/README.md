# U-06 Research Demo — Windows local executor / elevation seam

Executable architecture evidence for kaicreator-mm/shun-assistant issue #5
(parent L2 #4, UNKNOWN `U-06`, disposition `EXECUTABLE_DEMO_REQUIRED`).

**This is a throw-away research harness, not a production implementation.**
It must not be merged into the Shun mainline (issue #5 explicitly forbids
wholesale adoption); the product of this branch is the evidence, not the code.

## Architecture question

Can a P0 `LocalWindowsBackend` preserve the Shun contract

```text
AuthorizedAction → structured ordinary/elevated Windows execution
→ cancellation/failure semantics → ExecutionReceipt
```

with a **one-shot child/elevated helper**, or is a persistent privileged
broker required?

## What the harness does

Node.js orchestrator (`run-demo.mjs`) + two PowerShell helpers:

- `helpers/obs.ps1` — D1 non-elevated read-only observation (typed
  parameters, JSON stdout, stderr diagnostics).
- `helpers/action-helper.ps1` — privileged **one-shot** helper: reads a
  single `AuthorizedAction` envelope file (typed JSON on disk, never shell
  text), re-validates everything inside the privileged boundary
  (schema → planHash re-computation → approval binding → declared scope →
  privilege consistency), appends a side-effect journal, executes the
  declared typed steps, writes one `ExecutionReceipt`, exits. No listening
  channel, no reuse, no arbitrary shell endpoint.
- `helpers/elevate-relay.ps1` — performs the single `Start-Process -Verb
  RunAs` and relays UAC consent/decline through a JSON file.

`lib/plan.mjs` builds L2 §4.5–4.7-shaped `ActionPlan` / `AuthorizedAction` /
approval records; `planHash = sha256(canonical-json(plan))` with the planHash
key absent. The privileged helper re-computes the hash with an independent
PowerShell implementation — the demo therefore also proves the plan identity
is stable across representations/languages.

## Running

```bash
node run-demo.mjs local     # D1 + non-elevated D4 negatives + D5 (no UAC)
node run-demo.mjs decline   # one UAC prompt — click NO (or let it time out)
node run-demo.mjs d2        # UAC — HKLM fixture create→verify→delete lifecycle
node run-demo.mjs d2tamper  # UAC — plan mutated after approval must refuse
node run-demo.mjs d3        # UAC — winget 7zip.7zip install/uninstall lifecycle
node run-demo.mjs summary   # aggregate a run directory
```

Raw run artifacts land in `C:\xDev\kAiCreator\_tmp\u06-demo\<run>\`.
Committed copies of the evidence of the terminal run live in `evidence/`.

## Terminal

See `EVIDENCE.md` — `ONE_SHOT_ELEVATED_HELPER_SUFFICIENT` (RESULT=PASS),
recorded on issue #5 with the exact demo commit SHA.
