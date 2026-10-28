// T09 P02 — stage the Core-only portable Windows payload from a prepared
// Node24 Windows checkout. This produces an UNSIGNED staging directory.
// Operator signing, offline bootstrap and Standard User tests are separate
// mandatory acceptance gates; this script does not silently grant authority.
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import {
  copyFileSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../..');
const native = join(repo, 'apps/control-api/native');
const RUNTIME_NODE_MAJOR = 24;

function fail(reason) {
  throw new Error(`SHUN_PORTABLE_STAGE_REFUSED:${reason}`);
}

function requireFile(path) {
  if (!existsSync(path)) fail('REQUIRED_SOURCE_MISSING');
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) fail('REQUIRED_SOURCE_NOT_REGULAR');
  return path;
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function pinnedDigest(name) {
  const text = readFileSync(join(native, 'artifacts.ts'), 'utf8');
  const match = text.match(new RegExp(`export const ${name}\\s*=\\s*['"]([0-9a-f]{64})['"]`));
  if (!match) fail('NATIVE_PIN_UNAVAILABLE');
  return match[1];
}

async function stage(target) {
  if (process.platform !== 'win32' || process.arch !== 'x64') fail('WINDOWS_X64_REQUIRED');
  if (Number(process.versions.node.split('.')[0]) !== RUNTIME_NODE_MAJOR) {
    fail('NODE24_BUILD_HOST_REQUIRED');
  }
  if (!target) fail('EXPLICIT_STAGE_PATH_REQUIRED');
  const stageRoot = resolve(target);
  if (stageRoot === repo || stageRoot === here) fail('STAGE_PATH_INVALID');
  // Prevent accidental deletion of a prior build or user-owned directory.
  if (existsSync(stageRoot)) {
    if (!lstatSync(stageRoot).isDirectory() || readdirSync(stageRoot).length) {
      fail('STAGE_MUST_BE_AN_EMPTY_DIRECTORY');
    }
  } else {
    mkdirSync(stageRoot, { recursive: true });
  }

  const exe = requireFile(process.execPath);
  const broker = requireFile(join(native, 'broker/shun-consent-broker.exe'));
  const host = requireFile(join(native, 'host/shun_consent_host.node'));
  const win32 = requireFile(
    join(repo, 'packages/recipe-runtime/native/impl/shun_win32_impl.node'),
  );
  // Validate the reviewed binary identities before staging; don't silently
  // accept an unreviewed rebuilt native addon with a different hash.
  if (sha256(broker) !== pinnedDigest('CONSENT_BROKER_EXE_SHA256')) {
    fail('BROKER_PIN_MISMATCH');
  }
  if (sha256(host) !== pinnedDigest('CONSENT_HOST_ADDON_SHA256')) {
    fail('ADDON_PIN_MISMATCH');
  }

  // esbuild is already a reviewed workspace dependency, not a new bundler
  // requirement; the end user has neither pnpm nor node_modules.
  const buildRequire = createRequire(join(repo, 'packages/executor-windows/package.json'));
  const { build } = buildRequire('esbuild');
  const appRoot = join(stageRoot, 'app/native');
  mkdirSync(appRoot, { recursive: true });
  const appBundle = join(appRoot, 'control.mjs');
  await build({
    entryPoints: [join(repo, 'apps/control-api/src/main.ts')],
    outfile: appBundle,
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node24',
    packages: 'bundle',
    logLevel: 'warning',
    // Some transitive CJS packages may require Node builtins. The native
    // addon itself is resolved with createRequire(import.meta.url).
    banner: {
      js: "import { createRequire as __shunCreateRequire } from 'node:module'; const require = __shunCreateRequire(import.meta.url);",
    },
  });

  // Placement deliberately preserves the relative require('../native/*')
  // paths of native/index.ts and recipe-runtime/src/scoped-file-search.ts
  // when they have been bundled into app/native/control.mjs.
  const binaries = [
    [broker, 'app/native/broker/shun-consent-broker.exe'],
    [host, 'app/native/host/shun_consent_host.node'],
    [win32, 'app/native/impl/shun_win32_impl.node'],
  ];
  for (const [src, relativePath] of binaries) {
    const dst = join(stageRoot, relativePath);
    mkdirSync(dirname(dst), { recursive: true });
    copyFileSync(src, dst);
  }
  copyFileSync(exe, join(stageRoot, 'node.exe'));
  cpSync(
    join(repo, 'apps/control-ui/public'),
    join(stageRoot, 'control-ui/public'),
    { recursive: true, errorOnExist: true, force: false, dereference: false },
  );

  // The production launcher requires operator-provisioned trusted config;
  // default-deny authorization must never become a "demo as real" fallback.
  writeFileSync(
    join(stageRoot, 'shun-core.cmd'),
    '@echo off\r\nsetlocal\r\nset "SHUN_CONTROL_MODE=real-storage"\r\n"%~dp0node.exe" "%~dp0app\\native\\control.mjs"\r\nexit /b %ERRORLEVEL%\r\n',
  );
  // Clearly marked offline smoke path only — not the real product authority.
  writeFileSync(
    join(stageRoot, 'shun-demo-smoke.cmd'),
    '@echo off\r\nsetlocal\r\nset "SHUN_CONTROL_MODE=demo"\r\nset "SHUN_CLOUD_ENABLED=0"\r\n"%~dp0node.exe" "%~dp0app\\native\\control.mjs"\r\nexit /b %ERRORLEVEL%\r\n',
  );
  writeFileSync(
    join(stageRoot, 'BUILD-NOT-A-RELEASE.txt'),
    'UNSIGNED T09 P02 Windows staging output. Must be operator-signed, independently reviewed and qualified under a genuine Standard User on Windows Home and Pro. Do not ship this directory directly.\r\n',
  );
  return {
    kind: 'SHUN_T09_P02_UNSIGNED_STAGE',
    nodeVersion: process.version,
    binaryDigests: {
      node: sha256(join(stageRoot, 'node.exe')),
      consentBroker: sha256(join(stageRoot, 'app/native/broker/shun-consent-broker.exe')),
      consentHost: sha256(join(stageRoot, 'app/native/host/shun_consent_host.node')),
      win32: sha256(join(stageRoot, 'app/native/impl/shun_win32_impl.node')),
    },
    appBundleDigest: sha256(appBundle),
    uiFiles: readdirSync(join(stageRoot, 'control-ui/public')).length,
    signed: false,
    launchQualified: false,
  };
}

try {
  const args = process.argv.slice(2);
  if (args.length !== 1) fail('USAGE_STAGE_PATH_ONLY');
  console.log(JSON.stringify(await stage(args[0]), null, 2));
} catch (error) {
  const code = String(error?.message ?? '').startsWith('SHUN_PORTABLE_STAGE_REFUSED:')
    ? error.message
    : 'SHUN_PORTABLE_STAGE_REFUSED:BUILD_FAILED';
  console.error(code);
  process.exitCode = 1;
}
