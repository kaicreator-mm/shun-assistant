# T05 #106 — real Windows Build Host evidence: production native addon activation (Sharp)

- Baseline: version/v0.2.0@e263f3dc133ca2b664e8a9de2ee6995ccbeacf72
- Host: win32 10.0.26300 x64, node v24.21.0 (ABI 137)
- Package: @img/sharp-win32-x64@0.35.5, tarball sha256=16a804181ddd258ca6fe7079b2faa0c0356654c9db3d93ab0a80ec5e5161c3d4, npm SRI sha512-x76eH0vEiHlcMQu8Y8IenntaACtddpT6W0wmXtWrnKcnKI7ME5DdgqhAD6SEWOEl1v2zDvkZDhFA9KnURwpfqg==
- Addon: sharp-win32-x64-0.35.5.node sha256=971048779f9c8598df14641dfc03c625885c93f473a788e65ca2deb50d0b083e (443904 bytes)
- Closure: libvips-42.dll@06dab07cc386…, libvips-cpp-8.18.7.dll@25001dbd0530…
- Run: 2026-10-17T20-29-25 (UTC); events.ndjson carries the full incremental log

## Verdict

- Production native activation matrix: PASS (24 scenarios)
- Child surface: ONE pinned-runtime Node child per activation, fixed bootstrap source,
  one bounded payload, scrubbed env (no PATH), exec-dir cwd, hard timeout, capped output;
  the loader process itself never dlopens provider bytes.
- T11 Release readiness: NOT claimed by this run.

## Scenarios

- [PASS] HOST host facts (OS, integrity, symlink privilege, node) — os=win32 10.0.26300 x64 node=v24.21.0 symlinkPriv=false elevated=false (0.3s)
- [PASS] PREP anchor @img/sharp-win32-x64 via npm registry SRI, extract .node + DLL closure — sharp@0.35.5 tarball=16a804181ddd258c… addon=971048779f9c8598… dlls=2 (3.6s)
- [PASS] DEPCACHE provision verified dependency bytes into the digest cache — 2 deps cached under digest names (0.1s)
- [PASS] STAGE production stager fetches the pinned .node bytes — digest=971048779f9c8598… bytes=443904 (0.1s)
- [PASS] PREFLIGHT merged preflight admits the native artifact — state=PREFLIGHT_ONLY digest=971048779f9c8598… (0.0s)
- [PASS] ACTIVATE-METADATA runNativeAddon ADDON_METADATA: real child dlopens pinned sharp + libvips closure — exports=13 abi=137 (1.4s)
- [PASS] ACTIVATE-IMAGE runNativeAddon IMAGE_METADATA: real sharp metadata over a seeded PNG — width=8 height=2 format=png (0.9s)
- [PASS] OFFLINE-REPLAY offline cache replay: 0 downloads, activation still works — cache replay ok, downloads=0, exports=13 (0.8s)
- [PASS] RESTART fresh subprocess re-verifies from durable cache and activates — fresh process: exports=13 abi=137 (1.4s)
- [PASS] NEG-TAMPER-MAIN tampered cached .node refuses closed, recovers after restore — tampered→ARTIFACT_NOT_VERIFIED zero spawn; restored→EXECUTED (one fresh run) (1.0s)
- [PASS] NEG-CATALOG unsigned, forged-key and downgrade descriptors refuse before exec — unsigned=CATALOG_SIGNATURE_INVALID forged=CATALOG_SIGNATURE_INVALID downgrade=CATALOG_SCOPE_DRIFT spawns=0 (0.0s)
- [PASS] NEG-ABI host ABI drift refuses closed before any child — hostAbi=999 vs artifact=137 → ABI_MISMATCH zero spawn (0.0s)
- [PASS] NEG-DEP missing and tampered dependency cache bytes refuse closed — missing/tampered dep → DEPENDENCIES_UNVERIFIED zero spawn; restored → EXECUTED (one fresh run) (2.1s)
- [PASS] NEG-IMPORT undeclared non-system import refuses (synthetic PE fixture) — evil_overlay.dll undeclared → DEPENDENCIES_UNVERIFIED zero spawn (0.0s)
- [PASS] NEG-DEP-COLLISION dependency name colliding with a system DLL refuses — KERNEL32.DLL as a curated dep name → DEPENDENCIES_UNVERIFIED zero spawn (0.0s)
- [PASS] NEG-OPERAND unseeded and absolute IMAGE_METADATA operands refuse pre-authority — unseeded + absolute operands → RUN_REQUEST_INVALID, zero spawn (0.0s)
- [PASS] NEG-REVOCATION-EPOCH host revocation-epoch bump voids activation before exec — epoch 1→2 → AUTHORITY_STALE zero spawn; restored → EXECUTED (0.9s)
- [PASS] NEG-GRANT-REVOKED revoked grant refuses; re-issue restores — revokeGrant → AUTHORITY_STALE zero spawn; re-issue → EXECUTED (0.9s)
- [PASS] NEG-TOCTOU ActionController denial between admission and exec voids activation — reads=2 (admission + immediately-before-exec), second denial → zero spawn (0.6s)
- [PASS] NEG-SWAP staged .node byte swap after verification refuses at the last boundary — staged .node swapped post-verify → EXECUTABLE_IDENTITY_DRIFT zero spawn; fresh run → EXECUTED (1.6s)
- [PASS] NEG-INTERRUPT killed child surfaces honestly as timedOut; next run recovers — child killed at 1ms → EXECUTED timedOut=true exit=-1; recovery → exports=13 (1.7s)
- [PASS] R1-F03-GRANT-BINDING effect grant bound to ADDON_METADATA refuses IMAGE_METADATA — ADDON_METADATA grant vs IMAGE_METADATA invocation → EFFECT_NOT_AUTHORIZED zero spawn (0.7s)
- [PASS] DACL private cache root DACL/owner: owner-only write surface — owner=<HOST>\<USER> (current user), wide-write ACEs=0, rules=5 (1.0s)
- [PASS] CANARY user-owned files unchanged across the whole run — 3 canaries byte-identical (0.0s)

## Honest scope

- Positive-path HTTPS origin is a local fixture serving byte-exact package content;
  trust anchors are the curator Ed25519 signature over pinned digests, the npm registry
  SRI anchor recorded in PREP, and the ActionController grant state (LocalAuthority HMAC
  substrate) — all provisioned by this trusted composition, never by request input.
- Dependency bytes are provisioned into the digest-named cache from the SRI-anchored
  tarball extraction (DEPCACHE provenance event); activation re-verifies every dep digest
  on every read and PE-parses the whole import graph (system∪declared closure).
- The documented Windows same-privilege verification→spawn TOCTOU residual (P2 in the
  CLI review) applies to the native seam as well: detection-at-the-last-check, not
  stat→close→spawn atomicity, is claimed.
