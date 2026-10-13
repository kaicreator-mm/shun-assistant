# T11 Packaging / Install / Uninstall Smoke

**Scope note (honest bound):** Shun v0.1 is a private pnpm workspace
(`"private": true` on every package and app) with no distribution installer
and no npm-publish target. "Packaging" for this candidate therefore means
**reproducible workspace installation from the frozen lockfile**; "install"
means a clean-checkout install plus a loopback runtime boot; "uninstall" means
clean teardown of that environment. Provider-removal and storage-clean
*authority* semantics are product runtime concerns already evidenced under T10
(Loop B R11 removal chain 13/13 + durable 5/5, Loop C clean vertical 30/30);
they are not re-run here. No claim about an installer or published artifact is
made or implied.

All steps ran on the real Windows 11 host (10.0.26300 x64), Node v24.21.0
(fnm), pnpm 10.34.5, at exact candidate SHA `2313ba2773dac7aa535570e22760147d9b383b65`.

## 1. Clean-checkout install (frozen lockfile)

```bash
git clone <local mirror of candidate> clean-clone
cd clean-clone && git checkout 2313ba2773dac7aa535570e22760147d9b383b65
pnpm install --frozen-lockfile --registry=http://localhost:14873
```

- `INSTALL_EXIT=0`; resolution 71/71 from cache, 2.3s, no lockfile mutation.
- Evidence: `_tmp/t11-closer/install.log` (sha256 `5ad9f4ab…a2622`).

## 2. Runtime smoke (install → run on loopback)

```bash
node --experimental-transform-types apps/control-api/src/main.ts   # demo mode, default port 7788
curl http://127.0.0.1:7788/api/health
```

- Server booted from the clean install; `GET /api/health` → HTTP 200 with
  `{ ok: true, api: "shun.control-api/0.1", localOnly: true, simulated: true,
  policy: ACTIVE pol-snap-2026-10-10-a }`.
- Unknown route probe `GET /api/plans` → HTTP 404 typed `NOT_FOUND` error
  (typed error surface; no stack/internal leak).
- Evidence: `_tmp/t11-closer/smoke-server2.log` (sha256 `5090595a…f3a3ec`);
  full payload captured in the run log.

## 3. Uninstall / teardown smoke

- Server process terminated (`taskkill /F`, pid recorded in run log);
  post-teardown `netstat` shows **no listener on 127.0.0.1:7788**
  (verified twice, including a second boot/kill cycle).
- Clean-install directory `clean-clone/` deleted in full; demo mode holds no
  durable state outside the workspace, and no protected location was touched
  (no HKLM writes, no files outside `_tmp` and the disposable clone).

## Verdict

```ini
CLEAN_INSTALL_FROZEN_LOCKFILE=PASS
RUNTIME_BOOT_LOOPBACK=PASS
TEARDOWN_NO_RESIDUE=PASS (no listener, no stray process, disposable env removed)
PACKAGE_INSTALL_UNINSTALL_SMOKE=PASS (within the private-workspace meaning stated above)
```
