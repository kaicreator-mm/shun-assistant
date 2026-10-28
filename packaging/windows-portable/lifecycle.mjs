// T09 P03: portable Core installation / replacement / removal.
// User-owned state is deliberately OUTSIDE the replaceable Core directory.
// This script must be launched from a trusted bootstrap/runtime. A file signed
// manifest does not authenticate the executing script or the OS launcher.
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  renameSync,
  rmSync,
} from 'node:fs';
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyBundle } from '../../scripts/package-v02/manifest.mjs';

function refuse() {
  throw new Error('SHUN_PORTABLE_LIFECYCLE_REFUSED');
}

function assertPlainDirectory(path) {
  if (!existsSync(path)) return;
  const stats = lstatSync(path);
  if (!stats.isDirectory() || stats.isSymbolicLink()) refuse();
}

function assertContained(parent, child) {
  const rel = relative(parent, child);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) refuse();
}

export function perUserLayout(localAppData) {
  if (!localAppData || !isAbsolute(localAppData)) refuse();
  const path = resolve(localAppData);
  const root = join(path, 'ShunAssistant');
  return { root, core: join(root, 'core'), state: join(root, 'state') };
}

/** Mandatory for actual Windows CLI, distinct from portable-path tests. */
function assertLocalFixedDrive(localAppData) {
  if (process.platform !== 'win32') refuse();
  const base = resolve(localAppData);
  const drive = parse(base).root;
  if (!/^[A-Za-z]:\\$/.test(drive) || base.startsWith('\\\\')) refuse();
  // The Windows OS reports DriveType=3 for a local fixed disk. Merely using
  // LOCALAPPDATA or checking a drive letter does not prove a network/mapped
  // storage root is safe for SQLite WAL. This is a one-shot installer gate.
  const query = `$d=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${drive.slice(0, 2)}'"; if($null -eq $d -or $d.DriveType -ne 3){exit 1}`;
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', query], {
    timeout: 8000,
    windowsHide: true,
    encoding: 'utf8',
  });
  if (result.error || result.status !== 0) refuse();
  assertPlainDirectory(base);
}

function ensureLayout(layout) {
  assertPlainDirectory(dirname(layout.root));
  assertPlainDirectory(layout.root);
  assertPlainDirectory(layout.core);
  assertPlainDirectory(layout.state);
  mkdirSync(layout.root, { recursive: true });
  mkdirSync(layout.state, { recursive: true });
}

/**
 * P01's signature is checked BEFORE copying anything to the current user
 * profile. The entire newly copied tree is checked again before activation.
 * The operator public key and pinned fingerprint come from outside the bundle.
 */
export function installSignedCore({ stageDir, publicKeyPath, trustedSpkiPin, layout }) {
  const source = resolve(stageDir);
  const src = lstatSync(source);
  if (!src.isDirectory() || src.isSymbolicLink()) refuse();
  if (!layout || !layout.root || !layout.core || !layout.state) refuse();
  const root = resolve(layout.root);
  assertContained(root, resolve(layout.core));
  assertContained(root, resolve(layout.state));
  // The staging tree and the installed app root must be disjoint; never
  // recursively copy a directory into itself (or replace a staging parent).
  const sourceFromRoot = relative(root, source);
  const rootFromSource = relative(source, root);
  const within = (relativePath) =>
    relativePath === '' || (relativePath !== '..' &&
      !relativePath.startsWith(`..${sep}`) && !isAbsolute(relativePath));
  if (within(sourceFromRoot) || within(rootFromSource)) refuse();

  verifyBundle(source, publicKeyPath, trustedSpkiPin);
  // A self-contained Core staging artifact must be runnable without user
  // installing Node/pnpm or any optional Provider/model.
  for (const path of [
    'node.exe',
    'app/native/control.mjs',
    'app/native/broker/shun-consent-broker.exe',
    'app/native/host/shun_consent_host.node',
    'app/native/impl/shun_win32_impl.node',
    'shun-core.cmd',
  ]) {
    const required = join(source, path);
    if (!existsSync(required) || !lstatSync(required).isFile()) refuse();
  }
  ensureLayout(layout);
  const next = join(root, `core.next-${randomUUID()}`);
  const backup = join(root, `core.old-${randomUUID()}`);
  let movedOld = false;
  let installed = false;
  try {
    cpSync(source, next, { recursive: true, force: false, errorOnExist: true, dereference: false });
    verifyBundle(next, publicKeyPath, trustedSpkiPin);
    if (existsSync(layout.core)) {
      assertPlainDirectory(layout.core);
      renameSync(layout.core, backup);
      movedOld = true;
    }
    renameSync(next, layout.core);
    installed = true;
  } catch {
    // A failed replacement retains the old Core and all user state.
    if (movedOld && !existsSync(layout.core)) renameSync(backup, layout.core);
    refuse();
  } finally {
    if (existsSync(next)) rmSync(next, { recursive: true, force: true });
  }
  if (installed && movedOld) rmSync(backup, { recursive: true, force: true });
  return { operation: movedOld ? 'UPGRADE' : 'INSTALL', statePreserved: true, signed: true };
}

/** Removes only the Shun-owned replaceable Core, never user/other data. */
export function uninstallCore({ layout }) {
  if (!layout || !layout.root || !layout.core || !layout.state) refuse();
  assertContained(resolve(layout.root), resolve(layout.core));
  assertContained(resolve(layout.root), resolve(layout.state));
  assertPlainDirectory(layout.root);
  assertPlainDirectory(layout.state);
  if (existsSync(layout.core)) {
    assertPlainDirectory(layout.core);
    rmSync(layout.core, { recursive: true, force: false });
  }
  return { operation: 'UNINSTALL_CORE_ONLY', statePreserved: true };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const [operation, ...params] = process.argv.slice(2);
    if (!process.env.LOCALAPPDATA) refuse();
    assertLocalFixedDrive(process.env.LOCALAPPDATA);
    const layout = perUserLayout(process.env.LOCALAPPDATA);
    if (operation === 'install' && params.length === 3) {
      console.log(JSON.stringify(installSignedCore({
        stageDir: params[0],
        publicKeyPath: params[1],
        trustedSpkiPin: params[2],
        layout,
      })));
    } else if (operation === 'uninstall' && params.length === 0) {
      console.log(JSON.stringify(uninstallCore({ layout })));
    } else {
      refuse();
    }
  } catch {
    // Never print private paths, key material, local profile or user-canary data.
    console.error('SHUN_PORTABLE_LIFECYCLE_REFUSED');
    process.exitCode = 1;
  }
}
