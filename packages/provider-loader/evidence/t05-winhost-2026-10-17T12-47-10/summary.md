# T05 #106 — real Windows Build Host evidence (trusted ripgrep CLI activation)

- Baseline: version/v0.2.0@5e0bb2ba4b0f3409247e0f300950b84381d32661
- Host: win32 10.0.26300 x64, node v24.21.0 (ABI 137)
- ripgrep: 14.1.1 official MSVC release, zip sha256=d0f534024c42afd6cb4d38907c25cd2b249b79bbe6cc1dbee8e3e37c2b6e25a1
- Run: 2026-10-17T12-47-10 (UTC); events.ndjson carries the full incremental log

## Verdict

- CLI activation matrix: PASS (23 scenarios)
- Native addon (Sharp): PASS — sharp-win32-x64@0.35.5 sha256=16a804181ddd258c… SRI-anchored+staged+ABI=137+dlopen OK; production native activation stays fail-closed (ACTIVATION_KIND_UNSUPPORTED) (24.7s)
- T11 Release readiness: NOT claimed by this run

## Scenarios

- [PASS] HOST host facts (OS, integrity, symlink privilege, node) — os=win32 10.0.26300 x64 node=v24.21.0 symlinkPriv=false elevated=false (0.3s)
- [PASS] PREP download official ripgrep release and pin exact bytes — zip=d0f534024c42afd6… rg.exe=f162b54de2adfc72… bytes=5407744 wingetAnchor=UNAVAILABLE (4.4s)
- [PASS] STAGE production stager fetches fixture origin and pins digest — digest=f162b54de2adfc72… bytes=5407744 (0.6s)
- [PASS] PREFLIGHT merged CuratedProviderPreflight admits the staged artifact — state=PREFLIGHT_ONLY digest=f162b54de2adfc72… (0.0s)
- [PASS] ACTIVATE-VERSION activation executes pinned rg.exe --version — stdout="ripgrep 14.1.1 (rev 4649aa9700)" exit=0 (0.8s)
- [PASS] ACTIVATE-SEARCH activation runs a real ripgrep search in its sandbox — match="2:the needle is here" exit=0 (0.8s)
- [PASS] NEG-PATH-SUBSTITUTION hostile PATH entry cannot substitute the pinned provider — pinned cache executable won; ambush rg.exe never spawned (0.7s)
- [PASS] OFFLINE-REPLAY offline cache replay: 0 downloads, activation still works — cache replay ok, downloads=0, exit=0 (0.7s)
- [PASS] NEG-OFFLINE-EMPTY offline + empty cache refuses closed (no download attempt) — OFFLINE at stage; ARTIFACT_NOT_VERIFIED at activation; 0 spawns 0 fetches (0.0s)
- [PASS] RESTART fresh subprocess re-verifies from durable cache and executes — fresh process: ripgrep 14.1.1 (rev 4649aa9700) env=[SystemDrive,SystemRoot] (1.3s)
- [PASS] NEG-TAMPER-CACHE tampered cached bytes refuse closed, recovery after restore — tampered→ARTIFACT_NOT_VERIFIED zero spawn; restored→EXECUTED (1.4s)
- [PASS] NEG-CATALOG unsigned, forged-key and downgrade descriptors refuse before exec — unsigned=CATALOG_SIGNATURE_INVALID forged=CATALOG_SIGNATURE_INVALID downgrade=CATALOG_SCOPE_DRIFT spawns=0 (0.0s)
- [PASS] NEG-REDIRECT redirect origins refuse: fixture 302 and real github.com 302 — fixture 302 → REDIRECT_REFUSED; real github.com release 302 → REDIRECT_REFUSED (0.3s)
- [PASS] NEG-CORRUPT-DOWNLOAD corrupted bytes over the wire refuse with hash mismatch — ARTIFACT_HASH_MISMATCH, cache stays empty, activation zero-spawn (0.1s)
- [PASS] NEG-REVOCATION-EPOCH host revocation-epoch bump voids activation before exec — epoch 1→2 → AUTHORITY_STALE zero spawn; restored → EXECUTED (0.8s)
- [PASS] NEG-POLICY-REVOKED revoked authorization policy voids activation (real grant substrate) — revokePolicy() → AUTHORITY_STALE zero spawn (0.0s)
- [PASS] NEG-CONSENT-REFUSED unresolvable currentness refuses activation (consent denied) — corruptCurrentness(consent refused) → AUTHORITY_STALE zero spawn (0.0s)
- [PASS] NEG-GRANT-REVOKED revoked grant refuses activation; fresh grant restores it — revokeGrant → AUTHORITY_STALE zero spawn; re-issue → EXECUTED (0.7s)
- [PASS] NEG-TOCTOU ActionController denial between admission and exec voids activation — reads=2 (admission + immediately-before-exec), second denial → zero spawn (0.4s)
- [PASS] NEG-INTERRUPT interrupted staging (socket destroyed) fails closed and recovers — SOURCE_UNAVAILABLE, no artifact cached; main cache still EXECUTES (2.5s)
- [PASS] NEG-ENTRYPOINT path-traversal entrypoint refuses and materializes nothing — ENTRYPOINT_INVALID; no evil.exe under cache (files before=1) (0.0s)
- [PASS] CANARY user-owned canary files unchanged across the entire run — 3 canaries intact (temp + user profile + cwd) (0.0s)
- [PASS] SHARP native addon ABI probe: @img/sharp-win32-x64 real dlopen in isolated child — sharp-win32-x64@0.35.5 sha256=16a804181ddd258c… SRI-anchored+staged+ABI=137+dlopen OK; production native activation stays fail-closed (ACTIVATION_KIND_UNSUPPORTED) (24.7s)

## Honest scope

- Fixture origin is a local HTTPS server (NODE_EXTRA_CA_CERTS trust anchor) serving
  byte-exact official release content; github.com itself 302-redirects, which the
  product refuses by design — proven live in NEG-REDIRECT against the real URL.
- Trust anchors are the curator Ed25519 signature over the pinned digest and the
  ActionController (LocalAuthority) grant state, both provisioned by this trusted
  composition, never by request input.
- Native addon activation in product code stays fail-closed (ACTIVATION_KIND_UNSUPPORTED);
  the Sharp row is a separate real-host ABI probe, not production native activation.
