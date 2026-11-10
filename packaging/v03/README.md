# v0.3 Windows Portable Distribution (operator build)

This directory builds the v0.3.0 signed Windows portable user distribution
(#407). It reuses the audited v0.2 T09 mechanisms byte-identically — the
Ed25519 full-directory signed manifest with out-of-band SPKI pin
(`scripts/package-v02/manifest.mjs`, PR #202/#204) and the state-preserving
per-user lifecycle (`packaging/windows-portable/lifecycle.mjs`) — and adds the
real v0.3 closure: the trusted DomainHarness BUILD envelope assembled by the
operator script, the installed public SDK consumer (runtime imports resolve
from it), pinned native consent broker/host binaries, the actual R04 desktop
UI, and an embedded Node24 runtime. The end user installs and runs without
Node, pnpm or a repository checkout.

## Build (operator Windows x64 host, Node 24)

```bash
node packaging/v03/stage.mjs <absolute-empty-stage-dir>
```

The stage builder refuses anything but a pinned closure: native binaries must
match the `artifacts.ts` SHA-256 pins, the four public SDK tarballs must match
the committed `SHA256SUMS.txt` receipts, and the BUILD envelope is assembled
by the real `scripts/v03-ci/assemble-trusted-build.mjs` from the pinned kernel
and standard sources plus the reviewed Shun business/capability modules. The
output directory is UNSIGNED and carries `BUILD-NOT-A-RELEASE.txt`.

Layout produced (relative to the stage root):

| Path | Content |
| --- | --- |
| `node.exe` | Node 24 x64 runtime (build-host `process.execPath`) |
| `app/native/control.mjs` | esbuild bundle of `apps/control-api/src/main.ts` |
| `app/native/{broker,host,impl}/` | pinned native consent broker exe, host addon, win32 impl |
| `app/native/shun_folder_picker.node` | separately SHA-pinned Windows Shell folder picker; launcher enables the state/data SQLite-backed Host route |
| `app/native/tools/` | bundled Guided trust bootstrap + registry issuer CLIs |
| `sdk-consumer/` | installed public DomainHarness SDK + four trusted Host binding packages |
| `operator/` | trusted BUILD envelope + receipt, Guided Case + build spec/sources |
| `control-ui/public/` | actual R04 desktop UI (incl. `v03/desktop.js`) |
| `packaging/windows-portable/lifecycle.mjs`, `scripts/package-v02/manifest.mjs` | audited verifier + lifecycle, byte-identical |
| `tools/shun-provision.mjs`, `tools/shun-launch.mjs` | generated per-user provisioner and launcher |
| `Shun-Install.cmd`, `Shun-FirstRun.cmd`, `Shun-Run.cmd`, `Shun-Uninstall.cmd`, `shun-core.cmd` | user entries |
| `BUILD-ID.json` | build id, binary digests, SDK package digests |

### Why the bundled CLIs sit three directories deep

`bootstrap-guided-localappdata` derives its forbidden workspace scope as
`resolve(<script dir>, '../../..')`. In the repository that is the repository
root; in the bundle the scripts live at `app/native/tools/` so the derived
scope is exactly the replaceable Core — keeping the per-user guided database
under `ShunAssistant/state` outside the refused scope at any other depth the
rule would silently re-scope and refuse every first run.

## Sign (operator host, private key never enters the bundle)

```bash
node scripts/package-v02/manifest.mjs sign <stage-dir> <operator-private.pem>
```

Distribute the signed directory (e.g. zipped) through an authenticated
channel together with `operator-public.pem` and the SPKI pin
(`publicKeyFingerprint`). The verifier, public key and pin must reach the
user out-of-band: a signature inside the bundle can never attest a modified
verifier, so the download page itself is part of the trust chain.

## Qualification (operator host, before any release)

```bash
node packaging/v03/smoke.mjs <signed-stage-dir>
```

The driver signs a copy with a generated test authority and proves, inside a
disposable isolated profile: verify + tamper/extra-file/wrong-pin/wrong-key/
junction refusals, per-user install, visible SETUP_REQUIRED fail-closed first
run, consented provisioning (idempotent), real production boot with the R04
UI bytes, byte-stable upgrade, and uninstall retaining user state with no
listener. Zero paid calls: the cloud lane is forced off and the DeepSeek
credential is stripped before every child spawn.

## End-user flow

See `docs/guide/v0.3/README.zh-CN.md` / `README.en.md`. Install and ordinary
launches need no administrator rights and no UAC; every user-owned file lives
under `%LOCALAPPDATA%\ShunAssistant\state` and
`%LOCALAPPDATA%\Shun\{authority,secrets}` and survives upgrade and uninstall.
