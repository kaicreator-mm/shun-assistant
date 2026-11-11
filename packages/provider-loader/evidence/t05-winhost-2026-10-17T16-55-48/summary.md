# T05 #106 + R1 #145 F01–F04 delta — real Windows Build Host evidence

- Baseline: PR #144 HEAD 9f4e1f3372497f031bc8ed68c822976934a20c77 (delta applies the R1 repair contract)
- Host: win32 10.0.26300 x64, node v24.21.0 (ABI 137)
- ripgrep: 14.1.1 official MSVC release, zip sha256=d0f534024c42afd6cb4d38907c25cd2b249b79bbe6cc1dbee8e3e37c2b6e25a1
- Run: 2026-10-17T16-55-48 (UTC); events.ndjson carries the full incremental log

## Verdict

- CLI activation matrix: PASS (29 scenarios)
- R1 #145 F01–F05 delta canaries: PASS (6 scenarios)
- Native addon (Sharp): PASS — sharp-win32-x64@0.35.5 sha256=16a804181ddd258c… SRI-anchored+staged+ABI=137+dlopen OK; production native activation stays fail-closed (ACTIVATION_KIND_UNSUPPORTED) (7.3s)
- Native production activation stays fail-closed (ACTIVATION_KIND_UNSUPPORTED);
  the Sharp row is an ABI probe only and is NOT a native activation result.
- T11 Release readiness: NOT claimed by this run

## Scenarios

- [PASS] HOST host facts (OS, integrity, symlink privilege, node) — os=win32 10.0.26300 x64 node=v24.21.0 symlinkPriv=false elevated=false (0.3s)
- [PASS] PREP download official ripgrep release and pin exact bytes — zip=d0f534024c42afd6… rg.exe=f162b54de2adfc72… bytes=5407744 wingetAnchor=UNAVAILABLE (3.2s)
- [PASS] STAGE production stager fetches fixture origin and pins digest — digest=f162b54de2adfc72… bytes=5407744 (0.5s)
- [PASS] PREFLIGHT merged CuratedProviderPreflight admits the staged artifact — state=PREFLIGHT_ONLY digest=f162b54de2adfc72… (0.0s)
- [PASS] ACTIVATE-VERSION activation executes pinned rg.exe --version — stdout="ripgrep 14.1.1 (rev 4649aa9700)" exit=0 (0.7s)
- [PASS] ACTIVATE-SEARCH activation runs a real ripgrep search in its sandbox — match="2:the needle is here" exit=0 (0.7s)
- [PASS] NEG-PATH-SUBSTITUTION hostile PATH entry cannot substitute the pinned provider — pinned cache executable won; ambush rg.exe never spawned (0.6s)
- [PASS] OFFLINE-REPLAY offline cache replay: 0 downloads, activation still works — cache replay ok, downloads=0, exit=0 (0.8s)
- [PASS] NEG-OFFLINE-EMPTY offline + empty cache refuses closed (no download attempt) — OFFLINE at stage; ARTIFACT_NOT_VERIFIED at activation; 0 spawns 0 fetches (0.0s)
- [PASS] RESTART fresh subprocess re-verifies from durable cache and executes — fresh process: ripgrep 14.1.1 (rev 4649aa9700) env=[SystemDrive,SystemRoot] (1.3s)
- [PASS] NEG-TAMPER-CACHE tampered cached bytes refuse closed, recovery after restore — tampered→ARTIFACT_NOT_VERIFIED zero spawn; restored→EXECUTED (1.3s)
- [PASS] NEG-CATALOG unsigned, forged-key and downgrade descriptors refuse before exec — unsigned=CATALOG_SIGNATURE_INVALID forged=CATALOG_SIGNATURE_INVALID downgrade=CATALOG_SCOPE_DRIFT spawns=0 (0.0s)
- [PASS] NEG-REDIRECT redirect origins refuse: fixture 302 and real github.com 302 — fixture 302 → REDIRECT_REFUSED; real github.com release 302 → REDIRECT_REFUSED (0.7s)
- [PASS] NEG-CORRUPT-DOWNLOAD corrupted bytes over the wire refuse with hash mismatch — ARTIFACT_HASH_MISMATCH, cache stays empty, activation zero-spawn (0.1s)
- [PASS] NEG-REVOCATION-EPOCH host revocation-epoch bump voids activation before exec — epoch 1→2 → AUTHORITY_STALE zero spawn; restored → EXECUTED (0.6s)
- [PASS] NEG-POLICY-REVOKED revoked authorization policy voids activation (real grant substrate) — revokePolicy() → AUTHORITY_STALE zero spawn (0.0s)
- [PASS] NEG-CONSENT-REFUSED unresolvable currentness refuses activation (consent denied) — corruptCurrentness(consent refused) → AUTHORITY_STALE zero spawn (0.0s)
- [PASS] NEG-GRANT-REVOKED revoked grant refuses activation; fresh grant restores it — revokeGrant → AUTHORITY_STALE zero spawn; re-issue → EXECUTED (0.7s)
- [PASS] NEG-TOCTOU ActionController denial between admission and exec voids activation — reads=2 (admission + immediately-before-exec), second denial → zero spawn (0.3s)
- [PASS] NEG-INTERRUPT interrupted staging (socket destroyed) fails closed and recovers — SOURCE_UNAVAILABLE, no artifact cached; main cache still EXECUTES (2.5s)
- [PASS] NEG-ENTRYPOINT path-traversal entrypoint refuses and materializes nothing — ENTRYPOINT_INVALID; no evil.exe under cache (files before=0) (0.0s)
- [PASS] R1-F01-PRE-CANARY ripgrep --pre is INEXPRESSIBLE: request refused pre-spawn, helper marker absent — RUN_REQUEST_INVALID / 0 helper spawns / marker absent; real rg search still works (1.0s)
- [PASS] R1-F02-OUTSIDE-CANARY outside-root operand refuses closed: no spawn, no outside read — absolute/UNC/drive/.. operands → RUN_REQUEST_INVALID, 0 spawns, outside bytes intact (0.9s)
- [PASS] R1-F03-INVOCATION-BINDING a --version grant does NOT authorize a different invocation (zero spawn) — version-grant + search-request → EFFECT_NOT_AUTHORIZED zero spawn; bound grant → EXECUTED (1.1s)
- [PASS] R1-F04-EXE-SWAP staged EXE bytes swapped after verify → EXECUTABLE_IDENTITY_DRIFT, 0 spawns — post-verify swap → EXECUTABLE_IDENTITY_DRIFT 0 spawns; next run EXECUTED (pinned rg) (1.2s)
- [PASS] R1-F04-REPARSE junction canaries: operand redirect and unanchored cache root refuse closed — operand junction → SANDBOX_UNSAFE; junctioned cache root → ACTIVATION_CACHE_UNAVAILABLE; 0 spawns (0.4s)
- [PASS] R1-F05-REVOKE-AT-SEAM revocation flip at the spawn seam → effect gate refuses, 0 process invocations — epoch flip at seam → AUTHORITY_STALE 0 spawns; last-boundary gate ran exactly once (0.9s)
- [PASS] CANARY user-owned canary files unchanged across the entire run — 3 canaries intact (temp + user profile + cwd) (0.0s)
- [PASS] SHARP native addon ABI probe: @img/sharp-win32-x64 real dlopen in isolated child — sharp-win32-x64@0.35.5 sha256=16a804181ddd258c… SRI-anchored+staged+ABI=137+dlopen OK; production native activation stays fail-closed (ACTIVATION_KIND_UNSUPPORTED) (7.3s)

## Honest scope

- Fixture origin is a local HTTPS server (NODE_EXTRA_CA_CERTS trust anchor) serving
  byte-exact official release content; github.com itself 302-redirects, which the
  product refuses by design — proven live in NEG-REDIRECT against the real URL.
- Trust anchors are the curator Ed25519 signature over the pinned digest and the
  ActionController grant state (LocalAuthority HMAC substrate), both provisioned
  by this trusted composition, never by request input. The invocation-scoped
  authorizeRunEffect port re-validates the full grant presentation AND binds the
  exact op/argv/scope roots fresh at the last boundary (R1 #145 F03).
- Execution argv is host-derived from a closed-world typed operation; --pre,
  config/pattern files and outside-root operands are INEXPRESSIBLE, not
  blacklisted (R1 #145 F01/F02).
- The staged executable lives in a fresh per-run random directory under a
  reparse-free anchored chain; identity (dev/ino via the staging handle +
  on-disk lstat) and the full digest are re-verified at the LAST boundary
  before the spawn seam — deletion, symlink/junction swap and byte
  overwrite are all refused with zero spawns (R1 #145 F04, proven live in
  R1-F04-EXE-SWAP and R1-F04-REPARSE). Residual risk (measured, not
  claimed away): the runtime opens files with FILE_SHARE_DELETE, so no
  user-mode handle blocks a same-privilege writer, and the sub-millisecond
  window between the final identity re-check and CreateProcess image open
  cannot be closed without kernel/exclusive-share primitives; this run
  claims detection-at-the-last-check, not stat→close→spawn atomicity.
- Revocation/policy moves observable at the spawn seam are caught by the final
  invocation-scoped gate with zero process invocations (R1 #145 F05).
