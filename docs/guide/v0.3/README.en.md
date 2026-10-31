# Shun Assistant v0.3.0 Operator Guide (English)

> **Status: R02 repair work-in-progress. Not release-qualified on real Windows/Woodpecker.**

## Prerequisites and startup

- Windows 10/11, Node.js **24 or newer**, pnpm 10.34.5. No Ubuntu/WSL dependency.
- Check out the exact approved monorepo SHA. Use `corepack enable` and `pnpm install --frozen-lockfile`.
- Loopback UI: `http://127.0.0.1:7788`. `pnpm --filter @shun/control-api dev` starts the current development surface. Demo is simulated and proves no real v0.3 Kernel/Host production journey.
- Real-storage mode (`SHUN_CONTROL_MODE=real-storage`) requires trusted workspace, SQLite, registry revision/public key and Host authorization secret configuration. Missing authoritative configuration must fail closed. Never promote test credentials.
- The BUILD/Guided/HTTP UI journey is **not operationally qualified** until the same production startup artifact is wired and tested end to end.

## Authority boundaries

- A read-only support context has a strict minimal projection and remains local; this does not automatically imply no independently configured remote-model traffic.
- AI Planner proposals are untrusted data: goal/object/root/privacy/currentness are bound by trusted Host state.
- Guided form acknowledgement, cloud disclosure consent, ActionController human approval and Kernel effect Permit are **independent** authorities. None grants another.
- UNKNOWN, timeout and post-send ambiguous states must never trigger blind retries. Reconcile trusted Journal and Host state first.
- Provider artifacts require curator signatures, pinned production trust roots and exact-byte digest verification. UI/model inputs cannot configure trusted keys or executables.
- No API keys, private keys, user data, arbitrary commands or raw system output in logs, CI artifacts or GitHub Issues.

## Recovery and rollback

1. Record exact app SHA, current SQLite/Journal revision and signed Provider catalog identity; stop the local control server.
2. Back up protected state under the user's privacy/retention policy. Do not run cleanup during ambiguous outcomes.
3. If Kernel/ActionController is UNKNOWN, query trusted durable receipts read-only and fence the Case before any replacement operation.
4. Roll back only through a reviewed compatible migration; do not combine mismatched Journal or effect executors.
5. A qualified Windows installer, safe auto-update and automated rollback are **not yet proven**.

## SDK and qualification

DomainHarness v0.10.3 is selected from immutable Git Tag `v0.10.3`, not an assumed public npm publication. Build only documented public SDK workspaces and verify immutable package digests. See [Provider custody](../../provider/v0.3/TRUST.en.md).

Real Windows Node>=24 and Woodpecker exact-SHA evidence is required for J01–J09. Mark unexecuted real-model/physical OS steps UNKNOWN or OWNER_DEFERRED, not PASS.
