# v0.3 Provider Trust, Key Custody and Offline Recovery

## Production trust anchor

The Curator public key, keyId and scope bindings are pre-provisioned by trusted Windows Host configuration. The Goal, Planner, browser, remote catalog and unverified metadata are not trust-anchor sources.

- Curator signing **private keys never ship** in repository files, packages, build logs or a client installer.
- Embed only authorized production public key fingerprints and approved rotation chain; test fixture keys are not production roots.
- Verify signed Provider/Capability identity, platform, version, catalog revision, exact artifact SHA-256 and every declared dependency. Any mismatch fails closed.
- On compromise, fence the catalog and related execution, approve a replacement trust root, rotate catalog/revision and revoke the old root. No silent fallback.
- Handle secrets, model data and diagnostic receipts with least privilege and minimum retention.

## Offline mode

Offline reuse requires a provenance-bound cache with a valid signature, pinned trust root, exact bytes and compatibility checks. A cache miss must return typed UNAVAILABLE, not use an arbitrary URL, second downloader or unverified native executable. Missing Host authority never becomes an implicit grant.

## Pending production qualification

A genuine Windows startup, production key provisioning, offline JIT recovery, binary packaging, locale encoding and end-to-end migrations remain UNKNOWN without exact-SHA physical evidence.
