# B-038 evidence — Loop B trusted JIT software lifecycle (T06)

- Host: Windows 10.0.26300 x64, privilege FILTERED_ADMIN
- Run dir: evidence/b038-run-20261010
- Result: 7 PASS / 0 FAIL / 1 SKIPPED

| Scenario | Status | Detail |
| --- | --- | --- |
| S1 B-038 trusted acquisition/use/verify + RETAIN (winget official source) | PASS | jq 1.8.2 from winget (hash a6fc67fedaf9128a3309a1e2ebb8b986aeccf70122ee46d2cb4849e423f0c627) — retained, task verified (23s) |
| S1b B-038 verified-use R2 removal, durable JIT policy (dispose jq) | PASS | removed 1.8.2; residue candidates 2, unknownOrProtectedDeleted=false (8s) |
| S2 B-038 install/use/verify/remove with residue classification (ripgrep) | PASS | ripgrep 15.2.0 removed; residue classes PROGRAM_OWNED (37s) |
| S3 B-038 user-asset canary inside deletion scope ⇒ USER_ASSET_AT_RISK, asset intact | PASS | removal blocked (removal blocked: user-created/protected paths inside the deletion scope must be resolved by a human first: C:\Users\15549\AppData\Local\Microsoft\WinGet\Packages\BurntSushi.ripgrep.MSVC_Microsoft.Winget.Source_8wekyb3d8bbwe\b038-user-canary.txt, C:\Users\15549\AppData\Local\Microsoft\WinGet\Packages\BurntSushi.ripgrep.MSVC_Microsoft.Winget.Source_8wekyb3d8bbwe\BurntSushi.ripgrep.MSVC_Microsoft.Winget.Source_8wekyb3d8bbwe.db); canary intact; provider disposed after canary cleanup (35s) |
| S4 B-038 interrupted removal ⇒ journal MAY_HAVE_EXECUTED_UNCERTAIN ⇒ reconcile-first REMOVED | PASS | removed 15.2.0; privileged journal torn at EXEC_START=true; reconcile resolved to REMOVED (44s) |
| S5 B-038 unknown provenance ⇒ typed refusal before any install | PASS | refused: [PACKAGE_UNKNOWN] Shun.Evidence.NoSuchPackage.7f3a is not in the official winget source (0s) |
| S6 B-038 stale policy grant ⇒ GRANT_POLICY_STALE at the boundary, no side effect | PASS | boundary refused the presentation; journal stopped before EXEC_START; nothing installed (1s) |
| S7 B-038 elevation refused non-interactively ⇒ UAC_DECLINED / NOT_STARTED (Notepad++ machine scope) | SKIPPED | UAC silently granted the machine-scope install on this host — a declined-elevation negative cannot be produced here (UAC_DECLINED semantics stay covered by the port-level test suite); install attempt artifacts are in journals/ |

Store records and privileged journals are under this run directory.