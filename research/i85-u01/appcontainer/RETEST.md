# U01 Windows minimal retest protocol (research-only; NOT production)

## Source / scope
Use the exact tip of `research/i85-appcontainer-preflight-safety`, record the **full 40-character HEAD** via `git rev-parse HEAD` before testing. This supersedes only the erroneous AppContainer *probe* and makes a reachable TCP target mandatory. It does NOT replace the earlier seven negative planner-seam tests, or prove a real LOCAL model exists. Do not merge this research branch into `version/v0.2.0`.

## One-shot Windows execution
1. Fresh detached worktree at the exact pinned branch HEAD. Use a newly created **disposable local disk directory** for all staging and output. Copy trusted locally pinned `node.exe` and `child-probe.js` into that stage. **Never run `run-ac.ps1` against the Git checkout, home directory or user content**: it grants AppContainer SID and ALL APPLICATION PACKAGES ACLs on the child script's parent directory. Delete the entire disposable staging directory afterward (or prove all ACLs were restored).
2. Collect actual `C:\Windows\System32\whoami.exe /groups /fo csv /nh`, `whoami /priv`, Windows build, edition, `Get-FileHash` of Node and probes. A UAC-filtered Administrators-member token is NOT a true standard-user account.
3. Choose an **owned, known reachable IPv4 interface** and port for an independent controlled TCP sink, ideally a second lab machine on the LAN. On that machine run:
   `node controlled-sink.cjs <owned-ip> <port>`
   The script binds only that IP and prints `ready` and connection events. On the Windows test host, a **normal unsandboxed TCP client** must connect to the SAME IP:port and the sink must log its connection. Example:
   `node -e "const s=require('node:net').connect({host:'<owned-ip>',port:<port>},()=>{console.log('POSITIVE_CONNECTED');s.destroy()});s.on('error',e=>{console.error(e);process.exitCode=1})"`
   If the positive control fails, mark `CONTROL_DESTINATION_UNREACHABLE`; any subsequent refusal is NOT an egress PASS. Do not use an unreachable TEST-NET address as the oracle.
4. Also run a plain loopback sink on `127.0.0.1:<loopback-port>` for diagnostic comparison. Invoke (from Windows PowerShell with no elevation):
   ```powershell
   powershell.exe -NoProfile -File <checkout>\research\i85-u01\appcontainer\run-ac.ps1 `
     -NodeExe <disposable-stage>\node.exe `
     -ChildScript <disposable-stage>\child-probe.js `
     -OutFile <disposable-stage>\probe.json `
     -LocalPort <loopback-port> `
     -ControlHost <owned-ip> -ControlPort <port> `
     -ContainerName shunu01-<fresh-unique-name>
   ```
   Observe child PID/token (including AppContainer SID and `TokenIsAppContainer` via Windows OS API), process outcome, JSON `controlled` and `loopback` statuses, independent sink logs and OS process-network tracing. `run-ac.ps1` returning 0 only means a *probe process exited with a fresh result*, NEVER that network denial or OS isolation passed.
5. Compare the unsandboxed `CONNECTED` with sandboxed outcome. A sandbox connection to the controlled sink means `OS_NO_EGRESS=FAIL`. A sandboxed refusal alone is insufficient: establish genuine AppContainer security token, proper process ownership, an enforceable capability-less network restriction, and independent network observation. Loopback is normally restricted too; **do not enable a broad loopback exemption** to force the test to pass. If isolation cannot be attributed to OS policy, `OS_NO_EGRESS=BLOCKED`.
6. Use `verify-cleanup.ps1` and inspect process handles / SID profile cleanup. Explicitly report any undeleted AppContainer profile and do not claim cleanup PASS from launcher exit status. Retain SHA manifest and privacy-minimized logs.

Only **after** confirmed `APPCONTAINER_LAUNCH=PASS` and `OS_NO_EGRESS=PASS`, request explicit user authorization to provision/use a trusted local model (the former host had none). If approved, exercise two actual offline local inferences in the proved network-disabled process/IPC boundary, with binary/model/hash pins. Do not install silently or grant general network capabilities.

## Required output in Issue #85
```ini
TESTED_RESEARCH_HEAD=<40-character SHA>
WINDOWS_HOST=<edition/build/arch/token class>
APPCONTAINER_LAUNCH=PASS|FAIL|BLOCKED
OS_NO_EGRESS=PASS|FAIL|BLOCKED
REAL_LOCAL_INFERENCE=PASS|BLOCKED
UNSANDBOXED_CONTROL=CONNECTED|FAILED
SANDBOX_CONTROL=CONNECTED|ERROR|TIMEOUT|NOT_LAUNCHED
INDEPENDENT_OBSERVER=<instrument and evidence hash>
CLEANUP=PASS|FAIL
OVERALL_U01=PASS|BLOCKED|FAIL
```
Do not upgrade #85 to PASS unless **all three** actual acceptance legs are demonstrated. A static source fix is not a Windows execution result. No re-runs of #86 or #87.
