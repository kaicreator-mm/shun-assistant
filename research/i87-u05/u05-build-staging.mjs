// Phase 1: build the portable staging tree under _tmp/i87-u05/staging.
// - esbuild bundle apps/control-api/src/main.ts -> staging/server.mjs
// - copy apps/control-ui/public -> staging/app-ui
// - copy pinned node.exe -> staging/runtime/node.exe (record SHA256)
// - write staging/launch.cmd
// - walk staging -> staging/manifest.json (every file, size + sha256, totals)
import { cp, mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import * as path from 'node:path';
import {
  ev,
  sha256File,
  writeJson,
  rmrf,
  WORKTREE,
  TMP_ROOT,
} from './u05-lib.mjs';

const require = createRequire(import.meta.url);
const ESBUILD_ENTRY = path.join(
  WORKTREE,
  'node_modules',
  '.pnpm',
  'esbuild@0.25.12',
  'node_modules',
  'esbuild',
  'lib',
  'main.js',
);

const staging = path.join(TMP_ROOT, 'staging');
const nodeSrc = process.env.U05_NODE_EXE; // resolved by caller via fnm

async function main() {
  await ev('build.start', 'RUN', { staging, nodeSrc });
  await rmrf(staging);
  await mkdir(path.join(staging, 'runtime'), { recursive: true });
  await mkdir(path.join(staging, 'app-ui'), { recursive: true });

  // 1. esbuild bundle
  const esbuild = require(ESBUILD_ENTRY);
  const entry = path.join(WORKTREE, 'apps', 'control-api', 'src', 'main.ts');
  const result = await esbuild.build({
    entryPoints: [entry],
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node24',
    outfile: path.join(staging, 'server.mjs'),
    sourcemap: false,
    logLevel: 'warning',
    absWorkingDir: WORKTREE,
  });
  const bundleStat = await stat(path.join(staging, 'server.mjs'));
  await ev('build.esbuild', 'OK', {
    entry,
    errors: result.errors,
    warnings: result.warnings,
    bundleBytes: bundleStat.size,
  });

  // 2. control-ui public
  await cp(path.join(WORKTREE, 'apps', 'control-ui', 'public'), path.join(staging, 'app-ui'), {
    recursive: true,
  });
  await ev('build.ui', 'OK', { from: 'apps/control-ui/public', to: 'staging/app-ui' });

  // 3. pinned runtime
  await cp(nodeSrc, path.join(staging, 'runtime', 'node.exe'));
  const nodeSrcSha = await sha256File(nodeSrc);
  const nodeCopySha = await sha256File(path.join(staging, 'runtime', 'node.exe'));
  if (nodeSrcSha !== nodeCopySha) throw new Error('node.exe copy sha mismatch');
  const nodeBytes = (await stat(path.join(staging, 'runtime', 'node.exe'))).size;
  await ev('build.runtime', 'OK', {
    source: nodeSrc,
    sha256: nodeCopySha,
    bytes: nodeBytes,
    pinned: true,
    note: 'runtime node.exe is explicitly bundled; no host Node is required',
  });

  // 4. launch.cmd — %~dp0 keeps it location-independent (works from any copied
  // path). Output is redirected BY cmd into the caller-provided log file so
  // capture does not depend on inherited handle lifetimes.
  const launch = [
    '@echo off',
    'rem Shun portable launcher (U05 pilot). Runs the bundled pinned runtime',
    'rem against the bundled server bundle. Requires the trusted environment',
    'rem variables documented in manifest.json to be present in the caller.',
    'setlocal',
    'set "HERE=%~dp0"',
    'if not exist "%HERE%runtime\\node.exe" (',
    '  echo [shun] bundled runtime missing 1>&2 & exit /b 2',
    ')',
    'if not exist "%HERE%server.mjs" (',
    '  echo [shun] server bundle missing 1>&2 & exit /b 2',
    ')',
    'if defined SHUN_SERVER_LOG (',
    '  "%HERE%runtime\\node.exe" "%HERE%server.mjs" >> "%SHUN_SERVER_LOG%" 2>&1',
    ') else (',
    '  "%HERE%runtime\\node.exe" "%HERE%server.mjs"',
    ')',
    'endlocal',
    '',
  ].join('\r\n');
  await writeFile(path.join(staging, 'launch.cmd'), launch, 'utf8');
  await ev('build.launchcmd', 'OK', { note: 'no requireAdministrator, no manifest, plain cmd' });

  // 5. manifest: every file in staging (manifest.json excluded from itself)
  const files = [];
  async function walk(dir, rel) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const relChild = rel ? `${rel}/${e.name}` : e.name;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) await walk(full, relChild);
      else if (e.isFile()) {
        const s = await stat(full);
        files.push({ path: relChild, size: s.size, sha256: await sha256File(full) });
      }
    }
  }
  await walk(staging, '');
  files.sort((a, b) => a.path.localeCompare(b.path));
  const totalBytes = files.reduce((a, f) => a + f.size, 0);
  const manifest = {
    kind: 'shun-portable-staging-manifest',
    issue: 'i87-u05',
    baselineSha: 'd812ca2f5d5e48dd637c5580cb4c30ecf4116663',
    generatedAt: new Date().toISOString(),
    pinnedRuntime: { file: 'runtime/node.exe', sha256: nodeCopySha, bytes: nodeBytes },
    note: 'Every file actually shipped in the staging tree is listed with size and sha256. manifest.json itself is excluded (self-reference).',
    totals: { files: files.length, bytes: totalBytes },
    files,
  };
  await writeJson(path.join(staging, 'manifest.json'), manifest);
  await ev('build.manifest', 'OK', {
    files: files.length,
    totalBytes,
    file: 'staging/manifest.json',
  });
  console.log(
    JSON.stringify({ ok: true, files: files.length, totalBytes, nodeSha: nodeCopySha }, null, 2),
  );
}

main().catch(async (err) => {
  await ev('build', 'FAIL', { error: String(err && err.stack ? err.stack : err) });
  console.error(err);
  process.exit(1);
});
