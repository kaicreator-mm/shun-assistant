// v0.3 portable offline qualification driver (#407). Runs on the Windows
// x64 Node24 operator host against an UNSIGNED stage directory produced by
// packaging/v03/stage.mjs. Proves the full chain without touching any real
// user profile: sign (generated test authority) → verify → deterministic
// negatives → per-user install into a DISPOSABLE isolated profile → consented
// first-run provisioning → real production Guided boot with visible R04 UI
// bytes → upgrade with state/canary preservation → uninstall retaining user
// state with no listener. Zero paid calls (cloud lane forced off and the
// DeepSeek credential stripped before every child spawn).
//
//   node packaging/v03/smoke.mjs <absolute-stage-dir>
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createConnection, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { publicKeyFingerprint, signBundle, verifyBundle } from '../../scripts/package-v02/manifest.mjs';
import { perUserLayout } from '../windows-portable/lifecycle.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const steps = [];
function step(name, ok, detail = '') {
  steps.push({ name, ok, detail: detail.slice(0, 400) });
  console.log(
    `SMOKE_STEP ${name}=${ok ? 'OK' : 'FAIL'}${detail ? ' :: ' + detail.slice(0, 400).replace(/\r?\n/g, ' ') : ''}`,
  );
  if (!ok) throw new Error(`SMOKE_FAILED_AT:${name}`);
}
function refuse(reason) {
  throw new Error(`SHUN_V03_SMOKE_REFUSED:${reason}`);
}
function refuses(fn) {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}

async function freePort() {
  const probe = createServer();
  await new Promise((ready) => probe.listen(0, '127.0.0.1', ready));
  const address = probe.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  await new Promise((closed) => probe.close(() => closed()));
  return port;
}

function sanitizedEnv(overrides = {}) {
  const env = { ...process.env, ...overrides };
  env.SHUN_CLOUD_ENABLED = '0';
  delete env.DEEPSEEK_API_KEY;
  delete env.SHUN_CLOUD_LEDGER_FILE;
  delete env.SHUN_CLOUD_AUTHORITY_FILE;
  delete env.SHUN_CLOUD_PUBLIC_KEY_FILE;
  delete env.SHUN_CLOUD_PUBLIC_KEY_SPKI_SHA256;
  return env;
}

function collect(child) {
  let out = '';
  child.stdout?.on('data', (chunk) => (out += chunk.toString('utf8')));
  child.stderr?.on('data', (chunk) => (out += chunk.toString('utf8')));
  return { text: () => out };
}

async function waitForHttp(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`);
      if (response.status === 200) return true;
    } catch {
      /* not listening yet */
    }
    await delay(400);
  }
  return false;
}

function portRefusesConnection(port) {
  return new Promise((resolved) => {
    const conn = createConnection({ port, host: '127.0.0.1' });
    conn.once('connect', () => {
      conn.destroy();
      resolved(false);
    });
    conn.once('error', () => resolved(true));
  });
}

async function portRefusesEventually(port, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await portRefusesConnection(port)) return true;
    await delay(150);
  }
  return false;
}

async function waitForExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return { code: child.exitCode, signal: child.signalCode };
  }
  return new Promise((resolved) => {
    const timer = setTimeout(() => resolved('TIMEOUT'), timeoutMs);
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      resolved({ code, signal });
    });
  });
}

/** Bounded Windows tree kill of a spawned launcher tree (taskkill /T /F). */
function killTree(pid) {
  if (process.platform !== 'win32') {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      try {
        process.kill(pid, 'SIGKILL');
      } catch {
        /* already gone */
      }
    }
    return;
  }
  spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', timeout: 15_000 });
}

function whoamiUserSid() {
  try {
    const out = execFileSync(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'whoami.exe'), [
      '/user',
      '/fo',
      'csv',
      '/nh',
    ]);
    for (const line of String(out).split(/\r?\n/)) {
      const fields = line.trim().split(',').map((f) => f.replace(/^"|"$/g, '').trim());
      const sid = fields[fields.length - 1] ?? '';
      if (/^S-1-\d+(-\d+)+$/.test(sid)) return sid;
    }
  } catch {
    /* fall through */
  }
  return undefined;
}

/** Disposable isolated profile shaped like the startup-runner R04 fixture. */
function isolatedProfile() {
  const root = mkdtempSync(join(tmpdir(), 'shun-v030-smoke-profile-'));
  const localAppData = join(root, 'AppData', 'Local');
  mkdirSync(localAppData, { recursive: true });
  if (process.platform === 'win32') {
    const icacls = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'icacls.exe');
    const grants = [
      '*S-1-5-18:(OI)(CI)F',
      '*S-1-5-32-544:(OI)(CI)F',
      `*${whoamiUserSid() ?? 'S-1-5-18'}:(OI)(CI)F`,
    ];
    execFileSync(icacls, [root, '/grant', ...grants], { windowsHide: true, timeout: 30_000 });
    execFileSync(icacls, [root, '/inheritance:r'], { windowsHide: true, timeout: 30_000 });
  }
  return { root, localAppData, env: { USERPROFILE: root, LOCALAPPDATA: localAppData } };
}

/** Whole-tree copy of a signed bundle, envelope included. */
function copyBundle(src, dst) {
  mkdirSync(dst, { recursive: true });
  for (const name of readdirSync(src)) {
    cpSync(join(src, name), join(dst, name), {
      recursive: true,
      dereference: false,
      force: false,
      errorOnExist: true,
    });
  }
}

async function main(stageArg) {
  if (process.platform !== 'win32' || Number(process.versions.node.split('.')[0]) !== 24) {
    refuse('WINDOWS_X64_NODE24_HOST_REQUIRED');
  }
  const stageRoot = resolve(stageArg);
  if (!existsSync(join(stageRoot, 'BUILD-ID.json'))) refuse('STAGE_DIR_NOT_A_V03_STAGE');
  const nodeExe = join(stageRoot, 'node.exe');
  const lifecycle = join(stageRoot, 'packaging/windows-portable/lifecycle.mjs');

  const work = mkdtempSync(join(tmpdir(), 'shun-v030-smoke-'));
  const profile = isolatedProfile();
  const layout = perUserLayout(profile.localAppData);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicKeyFile = join(work, 'smoke-authority-public.pem');
  const privateKeyFile = join(work, 'smoke-authority-private.pem');
  writeFileSync(publicKeyFile, publicKey.export({ type: 'spki', format: 'pem' }));
  writeFileSync(privateKeyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const pin = publicKeyFingerprint(publicKey);

  try {
    // 1. Sign the staged bundle with a generated test authority and verify.
    signBundle(stageRoot, privateKeyFile);
    const verified = verifyBundle(stageRoot, publicKeyFile, pin);
    step('sign-verify', verified.entries > 0 && verified.signerSpkiSha256 === pin, `entries=${verified.entries}`);

    // 2. Deterministic negatives on full copies of the signed bundle.
    const tampered = join(work, 'tampered');
    copyBundle(stageRoot, tampered);
    const victim = join(tampered, 'BUILD-NOT-A-RELEASE.txt');
    writeFileSync(victim, readFileSync(victim, 'utf8') + 'x');
    step('negative-tamper', refuses(() => verifyBundle(tampered, publicKeyFile, pin)));

    const extra = join(work, 'extra');
    copyBundle(stageRoot, extra);
    writeFileSync(join(extra, 'smuggled.txt'), 'x');
    step('negative-extra-file', refuses(() => verifyBundle(extra, publicKeyFile, pin)));

    const wrongPin = 'a'.repeat(64);
    step('negative-wrong-pin', refuses(() => verifyBundle(stageRoot, publicKeyFile, wrongPin)));
    step(
      'negative-wrong-key',
      refuses(() => {
        const other = generateKeyPairSync('ed25519');
        const otherPublic = join(work, 'other-public.pem');
        writeFileSync(otherPublic, other.publicKey.export({ type: 'spki', format: 'pem' }));
        verifyBundle(stageRoot, otherPublic, pin);
      }),
    );
    // A junction inside a signed bundle copy must be refused (reparse class).
    const junctionRoot = join(work, 'junction');
    copyBundle(stageRoot, junctionRoot);
    let junctionMade = false;
    try {
      symlinkSync(junctionRoot, join(junctionRoot, 'operator', 'junction-probe'), 'junction');
      junctionMade = true;
    } catch {
      // Junction creation unavailable: reparse class stays covered by the
      // manifest verifier's own unit tests.
    }
    if (junctionMade) {
      step('negative-junction', refuses(() => verifyBundle(junctionRoot, publicKeyFile, pin)));
    } else {
      step('negative-junction', true, 'junction creation unavailable on host; covered by manifest unit tests');
    }

    // 3. Install into the disposable profile through the audited lifecycle.
    const install = spawnSync(nodeExe, [lifecycle, 'install', stageRoot, publicKeyFile, pin], {
      encoding: 'utf8',
      env: sanitizedEnv(profile.env),
      timeout: 300_000,
    });
    if (install.status !== 0) {
      step('install-signed-core', false, String(install.stdout || install.stderr));
    }
    const installReceipt = JSON.parse(install.stdout);
    step(
      'install-signed-core',
      installReceipt.operation === 'INSTALL' &&
        installReceipt.statePreserved === true &&
        installReceipt.signed === true,
      JSON.stringify(installReceipt),
    );

    const core = layout.core;
    const state = layout.state;
    for (const required of [
      join(core, 'node.exe'),
      join(core, 'app/native/control.mjs'),
      join(core, 'app/native/shun_folder_picker.node'),
      join(core, 'sdk-consumer/node_modules/@kaicreator/domain-harness-build'),
      join(core, 'operator/v03-build.json'),
      join(core, 'operator/guided-case.json'),
      join(core, 'tools/shun-provision.mjs'),
      join(core, 'tools/shun-launch.mjs'),
      join(core, 'app/native/tools/bootstrap-guided-localappdata.mjs'),
      join(core, 'app/native/tools/issue-registry-currentness.mjs'),
      join(core, 'control-ui/public/v03/desktop.js'),
      join(core, 'packaging/windows-portable/lifecycle.mjs'),
    ]) {
      if (!existsSync(required)) step('installed-closure', false, `missing ${required}`);
    }
    step('installed-closure', true);
    const id = JSON.parse(readFileSync(join(core, 'BUILD-ID.json'), 'utf8'));
    const installedPickerDigest = createHash('sha256')
      .update(readFileSync(join(core, 'app/native/shun_folder_picker.node')))
      .digest('hex');
    step('folder-picker-signed-closure', id.digests.folderPicker === installedPickerDigest);

    // 4. Before first-run provisioning the real launcher must fail closed
    //    with the visible setup-required guidance (no listener, no DEMO).
    const port = await freePort();
    const preSetup = spawn(
      nodeExe,
      [join(core, 'tools/shun-launch.mjs')],
      {
        env: sanitizedEnv({ ...profile.env, SHUN_CONTROL_PORT: String(port) }),
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const preOut = collect(preSetup);
    const preExit = await waitForExit(preSetup, 60_000);
    step(
      'first-run-setup-required',
      preExit !== 'TIMEOUT' &&
        preExit.code !== 0 &&
        preOut.text().includes('SETUP_REQUIRED') &&
        preOut.text().includes('Shun-FirstRun.cmd') &&
        !(await waitForHttp(port, 1_000)),
      preOut.text(),
    );

    // 5. Consented per-user first-run provisioning (Guided trust + registry
    //    authority + controller secrets) must succeed and be idempotent.
    const provision = spawnSync(nodeExe, [join(core, 'tools/shun-provision.mjs')], {
      encoding: 'utf8',
      env: sanitizedEnv(profile.env),
      timeout: 300_000,
    });
    if (provision.status !== 0) {
      step('first-run-provision', false, String(provision.stdout || provision.stderr));
    }
    step('first-run-provision', provision.stdout.includes('PROVISION_RESULT=CREATED'), provision.stdout);
    const provisionAgain = spawnSync(nodeExe, [join(core, 'tools/shun-provision.mjs')], {
      encoding: 'utf8',
      env: sanitizedEnv(profile.env),
      timeout: 300_000,
    });
    step(
      'first-run-provision-idempotent',
      provisionAgain.status === 0 &&
        provisionAgain.stdout.includes('PROVISION_RESULT=ALREADY_COMPLETE') &&
        provisionAgain.stdout.includes('guided=ALREADY_COMPLETE') &&
        provisionAgain.stdout.includes('registry=ALREADY_PRESENT'),
      provisionAgain.stdout,
    );
    for (const required of [
      join(state, 'config/launch.json'),
      join(state, 'secrets/storage-registry/registry-private.pem'),
      join(state, 'secrets/storage-registry/registry-public.pem'),
      join(state, 'secrets/controller/issuance.secret'),
      join(state, 'secrets/controller/integrity.secret'),
      join(profile.localAppData, 'Shun/authority/guided-provenance/trust-anchor.json'),
      join(profile.localAppData, 'Shun/authority/guided-provenance-trust-pin.json'),
      join(profile.localAppData, 'Shun/secrets/guided-issuer/issuer-private.pem'),
      join(state, 'workspace/protected'),
    ]) {
      if (!existsSync(required)) step('provisioned-state', false, `missing ${required}`);
    }
    step('provisioned-state', true);

    // User-owned canaries + trust material snapshots for upgrade/uninstall.
    const canaryDir = join(state, 'workspace/protected');
    writeFileSync(join(canaryDir, 'user-canary.txt'), 'user-owned-state-canary-v1\n');
    const anchorPath = join(profile.localAppData, 'Shun/authority/guided-provenance/trust-anchor.json');
    const pinPath = join(profile.localAppData, 'Shun/authority/guided-provenance-trust-pin.json');
    const guidedSecretPath = join(
      profile.localAppData,
      'Shun/secrets/guided-issuer/issuer-private.pem',
    );
    const registryPrivatePath = join(state, 'secrets/storage-registry/registry-private.pem');
    const anchorBefore = readFileSync(anchorPath);
    const pinBefore = readFileSync(pinPath);
    const guidedSecretBefore = readFileSync(guidedSecretPath);
    const registryPrivateBefore = readFileSync(registryPrivatePath);

    // 6. Real production boot from the installed Core: REAL banner, activated
    //    DomainHarness, positive Guided state, byte-identical R04 desktop.js.
    const bootPort = await freePort();
    const server = spawn(
      nodeExe,
      [join(core, 'tools/shun-launch.mjs')],
      {
        env: sanitizedEnv({ ...profile.env, SHUN_CONTROL_PORT: String(bootPort) }),
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const serverOut = collect(server);
    try {
      const up = await waitForHttp(bootPort, 120_000);
      const text = serverOut.text();
      step('folder-selection-host-active', up && text.includes('v0.3 folder-selection startup recovery:'));
      step(
        'production-boot',
        up &&
          text.includes('Shun control surface (REAL bounded C-003)') &&
          text.includes('v0.3 public DomainHarness activated') &&
          !text.includes('T08 DEMO ONLY'),
        text,
      );
      const guidedState = await fetch(`http://127.0.0.1:${bootPort}/api/v03/guided/state`, {
        headers: { host: `127.0.0.1:${bootPort}` },
      });
      const guidedBody = await guidedState.text();
      const parsed = JSON.parse(guidedBody);
      step(
        'guided-state-positive',
        guidedState.status === 200 &&
          parsed?.currentStep?.templateRef?.artifactId !== undefined &&
          parsed?.journey !== undefined,
        guidedBody.slice(0, 200),
      );
      const desktop = await fetch(`http://127.0.0.1:${bootPort}/v03/desktop.js`);
      const served = Buffer.from(await desktop.arrayBuffer());
      const onDisk = readFileSync(join(core, 'control-ui/public/v03/desktop.js'));
      step('r04-desktop-ui-bytes', desktop.status === 200 && served.equals(onDisk));
      const index = await fetch(`http://127.0.0.1:${bootPort}/v03/index.html`);
      step('r04-desktop-page', index.status === 200);
    } finally {
      killTree(server.pid);
      await waitForExit(server, 20_000);
      const refused = await portRefusesEventually(bootPort);
      if (!refused) console.error('SMOKE cleanup: port still accepting after tree kill');
    }

    // 7. Upgrade: re-sign the SAME stage bytes (byte-identical bundle) and
    //    install over the existing Core. State, secrets and canaries must be
    //    preserved untouched; the operation must report UPGRADE.
    signBundle(stageRoot, privateKeyFile);
    const upgrade = spawnSync(nodeExe, [lifecycle, 'install', stageRoot, publicKeyFile, pin], {
      encoding: 'utf8',
      env: sanitizedEnv(profile.env),
      timeout: 300_000,
    });
    if (upgrade.status !== 0) {
      step('upgrade-preserves-state', false, String(upgrade.stdout || upgrade.stderr));
    }
    const upgradeReceipt = JSON.parse(upgrade.stdout);
    step(
      'upgrade-preserves-state',
      upgradeReceipt.operation === 'UPGRADE' &&
        upgradeReceipt.statePreserved === true &&
        readFileSync(anchorPath).equals(anchorBefore) &&
        readFileSync(pinPath).equals(pinBefore) &&
        readFileSync(guidedSecretPath).equals(guidedSecretBefore) &&
        readFileSync(registryPrivatePath).equals(registryPrivateBefore) &&
        readFileSync(join(canaryDir, 'user-canary.txt'), 'utf8') === 'user-owned-state-canary-v1\n',
      JSON.stringify(upgradeReceipt),
    );

    // 8. Post-upgrade production boot still works from the replaced Core.
    const portAfterUpgrade = await freePort();
    const server2 = spawn(
      nodeExe,
      [join(core, 'tools/shun-launch.mjs')],
      {
        env: sanitizedEnv({ ...profile.env, SHUN_CONTROL_PORT: String(portAfterUpgrade) }),
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    const out2 = collect(server2);
    try {
      const up2 = await waitForHttp(portAfterUpgrade, 120_000);
      step('post-upgrade-boot', up2 && out2.text().includes('v0.3 public DomainHarness activated'), out2.text());
    } finally {
      killTree(server2.pid);
      await waitForExit(server2, 20_000);
      await portRefusesEventually(portAfterUpgrade);
    }

    // 9. Uninstall removes ONLY the replaceable Core; user state, per-user
    //    trust and secrets survive; no listener remains.
    const uninstall = spawnSync(nodeExe, [lifecycle, 'uninstall'], {
      encoding: 'utf8',
      env: sanitizedEnv(profile.env),
      timeout: 120_000,
    });
    if (uninstall.status !== 0) {
      step('uninstall-retains-state', false, String(uninstall.stdout || uninstall.stderr));
    }
    const uninstallReceipt = JSON.parse(uninstall.stdout);
    step(
      'uninstall-retains-state',
      uninstallReceipt.operation === 'UNINSTALL_CORE_ONLY' &&
        uninstallReceipt.statePreserved === true &&
        !existsSync(core) &&
        existsSync(state) &&
        existsSync(anchorPath) &&
        existsSync(guidedSecretPath) &&
        existsSync(registryPrivatePath) &&
        readFileSync(join(canaryDir, 'user-canary.txt'), 'utf8') === 'user-owned-state-canary-v1\n',
      JSON.stringify(uninstallReceipt),
    );

    console.log(`SMOKE_RESULT=PASS steps=${steps.length}`);
    for (const s of steps) console.log(`SMOKE_RECEIPT ${s.name}=${s.ok ? 'OK' : 'FAIL'} ${s.detail}`);
  } finally {
    rmSync(work, { recursive: true, force: true });
    rmSync(profile.root, { recursive: true, force: true });
  }
}

void here;

try {
  const [stageArg] = process.argv.slice(2);
  if (!stageArg) refuse('USAGE_STAGE_PATH_ONLY');
  await main(stageArg);
} catch (error) {
  console.error(String(error?.message ?? error));
  console.log('SMOKE_RESULT=FAIL');
  for (const s of steps) console.log(`SMOKE_RECEIPT ${s.name}=${s.ok ? 'OK' : 'FAIL'} ${s.detail}`);
  process.exitCode = 1;
}
