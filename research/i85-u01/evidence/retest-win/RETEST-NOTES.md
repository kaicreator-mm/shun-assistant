# i85-U01 retest launcher repair notes (research-only changes, no production code)

Baseline `research/i85-appcontainer-preflight-safety@bcab812` could not execute as-is:

1. **run-ac.ps1 was syntactically corrupted at cb60caf**: the param block was split
   across the file with the body duplicated (new body first, then the old param tail
   + old body again). PowerShell parser confirmed errors (missing ')', unterminated
   string). Repaired by reconstructing the intended single script: full param set
   (NodeExe/ChildScript/OutFile/LocalPort/ControlHost/ControlPort/ContainerName),
   new body (ACL gates exit 19/20, evidence JSON validation exit 21), old duplicate
   removed.

2. **Attribute-list marshaling (observed CreateProcessW ERROR_INVALID_PARAMETER 87)**:
   UpdateProcThreadAttribute only RECORDS the lpValue pointer; the value is
   dereferenced later by CreateProcessW. PowerShell `[ref]$struct` marshaling uses a
   temporary that does not survive between the two calls, so the attribute list went
   dangling (87). Even with AllocHGlobal persistence on the PS side the launch stayed
   at 87, so the entire native sequence (InitializeProcThreadAttributeList ->
   UpdateProcThreadAttribute -> CreateProcessW -> token query -> wait/exit) was moved
   into one Add-Type C# method (`AcProbe.LaunchProbe`). After that the launch
   succeeded first try.

3. **Size-query semantics**: first InitializeProcThreadAttributeList(NULL,1,0,&size)
   call always returns FALSE + ERROR_INSUFFICIENT_BUFFER(122); must not be treated
   as failure (initial C# port returned rc=1 on it).

4. **RETEST step 4 token observation added**: TokenIsAppContainer (class 29) and
   TokenAppContainerSid (class 31) via OpenProcessToken/GetTokenInformation on the
   child process handle — required by RETEST ("including AppContainer SID and
   TokenIsAppContainer via Windows OS API"), absent from the baseline launcher.

5. **Node realpath staging**: inside the AppContainer, node's realpathSync lstat's
   every path component from the drive root; lstat('C:\') = EPERM (filesystem
   isolation). Solved by staging on a `subst X:` drive mapped to the disposable
   stage directory, keeping the whole resolution chain inside the ACLed dir. subst
   is a per-logon-session mapping: no ACL or registry change, removed after run.

All changes confined to research/i85-u01/appcontainer/run-ac.ps1 (launcher hardening
for executability + required observation), plus new research-only artifacts
(nettrace.ps1 observer, evidence under research/i85-u01/evidence/retest-win/).
child-probe.js and controlled-sink.cjs executed unmodified (hashes recorded).
No production source touched; no #86/#87 scope re-run.
