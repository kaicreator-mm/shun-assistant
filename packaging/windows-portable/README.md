# Shun Assistant v0.2 — P02 Windows Core portable staging

This is **a source-only staging script, not a completed or qualified installer**.
It is deliberately kept separate from the P01 signed-manifest PR and P03
physical Windows Standard User acceptance. P02 is a concern inside Task T09
[#111](https://github.com/kaicreator-mm/shun-assistant/issues/111).

## Build on an existing Windows x64 Node 24 host

A builder machine needs Node.js 24, pnpm and the normal checkout development
dependencies, plus the **reviewed committed** Rust native binaries. The end
user does not need pnpm or a separately installed Node.js.

```powershell
node --version # v24.x
pnpm install --frozen-lockfile
node packaging/windows-portable/build.mjs "$env:TEMP\shun-v02-stage-clean"
node packaging/windows-portable/smoke.mjs "$env:TEMP\shun-v02-stage-clean"
```

The stage directory must be absent or empty. The command refuses non-Windows
hosts, a non-x64 process, wrong Node major, missing native artifacts, and
mismatched signed-consent broker/addon hashes. It uses the already installed
`esbuild` workspace dependency to compile the TypeScript application into one
Node24 ESM bundle, **not a runtime source tree with workspace links**.

Expected staged layout:

```text
node.exe                     (copied from the Node24 build host)
app/native/control.mjs       (esbuild entry bundle)
app/native/impl/shun_win32_impl.node
app/native/host/shun_consent_host.node
app/native/broker/shun-consent-broker.exe
control-ui/public/**        (static UI)
shun-core.cmd                (REAL mode, trusted environment required)
shun-demo-smoke.cmd          (explicit demo-only offline smoke)
BUILD-NOT-A-RELEASE.txt
```

Putting the compiled entry at `app/native/control.mjs` intentionally preserves
the reviewed relative `createRequire('../native/...')` native addon lookups
and the default `../../control-ui/public` static web UI lookup. This is a
*staging design hypothesis* until proven by a Windows physical Host run — the
code cannot claim all dynamic imports, ABI dependencies or application paths
will work until that host evidence is collected.

`shun-demo-smoke.cmd` starts the unchanged product's clearly labeled demo
surface in offline-only mode; it is useful for a deterministic local smoke
test, but **is not an accepted real-storage or executor journey**.
`shun-core.cmd` explicitly selects `real-storage` and must be provided the
existing operator-controlled `SHUN_REAL_STORAGE_*`, registry, secret and
state configuration by a trusted bootstrap. It must refuse to run when that
configuration is absent; the build does not silently create grants or signing
keys, install a system service, or provision a privileged account.

## Separate mandatory acceptance

1. **P01 signed distribution provenance:** after its independent review,
   sign the complete staged payload with the operator-held external private
   key and verify against the externally trusted public SPKI pin. A signed
   file manifest is *not* Windows Authenticode, OS trust or a safe launcher by
   itself. **Never package the signing private key.**
2. **P02 real stage on Windows x64:** exact repository SHA, Node24 version,
   native artifact identities, esbuild build exit, result digests; try portable
   offline demo smoke with all Node/pnpm absent from PATH, inspect the app and
   static UI, then test the real-storage startup refusal without signed
   operator config. Record exact redacted outputs. Do not call merely passing
   GitHub CI "portable launch proof."
3. **P03 actual packaging and persistence:** a genuine unprivileged **Standard
   User** account and physical Windows Home + Pro; fixed-local-disk SQLite WAL,
   owned state, user canaries surviving reinstall/upgrade/uninstall, no
   unapproved Provider download and correct runtime permission boundaries.
   Node.js redistribution license / third-party notices and any Windows
   executable signing must be resolved before distributing an artifact.
4. **T11 final RQ:** actual human consent, hidden negatives, full regression
   and independent qualification; a test instrument clicking a real dialog
   does not substitute for a physical human action.

No `main` merge and no T09 closure on this script alone. If a bundle fails to
resolve a native addon or behaves as a demo rather than real product, record
the **single concrete incompatibility** and repair the minimal P02 packaging
path, not the frozen T08 source or authority contracts without a new concern.
