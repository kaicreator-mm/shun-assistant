# i85-U01 Windows retest host facts (2026-10-14, unelevated session)

## OS / host
- ProductName (registry): Windows 10 Pro / DisplayVersion 26H2 / Build 26300.9457 (AMD64)
- PowerShell 5.1.26100.9444
- Run token: UAC-filtered Administrators-member, integrity Medium (S-1-16-8192);
  BUILTIN\Administrators (S-1-5-32-544) present "Group used for deny only" — NOT a
  true standard-user account (same host-fact class as the corrected #85 comment).
  Privileges in token: SeShutdown/SeChangeNotify/SeUndock/SeIncreaseWorkingSet/SeTimeZone
  (all Se* admin privileges filtered out; non-elevated).
- whoami /groups /fo csv /nh captured via C:\Windows\System32\whoami.exe (MSYS whoami
  swallows /groups; known false-negative source).

## Binaries (SHA256)
- node.exe v24.21.0 (copied from fnm into disposable stage): BA4E6D110E8C1592A1ECD390F6B05F3DA124B13871A5BE62B341A07A853C6C32
- child-probe.js: 1AA873BBB1FB1AA25CC2664C9B65FB2B92F7FCE1A4CD23714F937C2ED455C3E3
- controlled-sink.cjs: 293D11C6146A02284B41E192281D27D72C46ACEBCB9E9618A4C2A1FCFA226DD5
- run-ac.ps1 as executed: repaired from bcab812 (see RETEST-NOTES.md); committed at
  this task branch.

## Network endpoints (own host interfaces)
- Controlled sink: 192.168.100.245:63801 (WLAN interface, real LAN IPv4, OS-assigned
  free port; NOT loopback, NOT TEST-NET). Sink process pid 34244.
- Loopback sink (diagnostic): 127.0.0.1:63802, pid 31808.
- Positive control (unsandboxed node client, same host): POSITIVE_CONNECTED rc=0;
  sink logged accepted sequence=1 at 2026-10-14T09:14:45.737Z (17:14:45 +08:00).

## Staging
- Disposable stage: C:\xDev\kAiCreator\_tmp\i85-rt1\stage{,2} — icacls granted
  ALL APPLICATION PACKAGES RX + per-run container SID M on the stage dir ONLY.
- subst X: -> stage2 used so node's realpathSync chain stays inside the ACLed
  directory (node lstat('C:\') EPERM inside AppContainer otherwise — itself
  evidence of filesystem isolation). subst removed after run; stage deleted.

## Probe runs (container shunu01-rt1a..f, all profiles deleted, verify-cleanup 0/0)
- rt1a/rt1b: CreateProcessW failed 87 (dangling attribute lpValue from PowerShell
  [ref] marshaling) — diagnosed, launcher hardened to C#-side launch.
- rt1c: PS literal [uint32]0xFFFFFFFF quirk (parse-time cast error, no launch).
- rt1d: size-query InitializeProcThreadAttributeList misread as error (122) — fixed.
- rt1e: launch OK pid 17504, TokenIsAppContainer=1, but node child died EPERM
  lstat C:\ (realpath chain) — staging moved to subst drive.
- rt1f (FINAL): launch rc=0 pid 29232; child-token isAppContainer=1,
  appContainerSid=S-1-15-2-2271455942-2295063338-1415680664-2632229433-2062655370-91685238-1551000773
  (== profile SID); child exit 0; probe JSON written:
  loopback 127.0.0.1:63802 -> ERROR/ETIMEDOUT 318ms;
  controlled 192.168.100.245:63801 -> TIMEOUT 6003ms (no connect).
- Independent observer (nettrace, 100ms Get-NetTCPConnection poller): pid 29232
  socket persistently SynSent 192.168.100.245:63601 -> 192.168.100.245:63801 for
  the full 6s window, never Established; sinks accepted zero sandbox connections.

## Verdicts (per RETEST.md)
- APPCONTAINER_LAUNCH=PASS (real AppContainer token via OS API + child ran to exit 0)
- OS_NO_EGRESS=PASS (unsandboxed CONNECTED vs sandboxed SynSent->TIMEOUT at the SAME
  reachable sink; independent sink logs + connection-state observer; capability-less
  token; no loopback exemption granted — loopback also denied)
- CLEANUP=PASS (no shunu01* profiles in registry/Packages; subst removed; stages deleted)
