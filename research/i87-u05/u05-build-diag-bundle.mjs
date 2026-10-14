// Build the research-only diagnostic bundle (identical to the product bundle
// except the swallowed #execute error is logged to stderr).
import { mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ev, WORKTREE, TMP_ROOT } from './u05-lib.mjs';

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ESBUILD_ENTRY = path.join(WORKTREE, 'node_modules', '.pnpm', 'esbuild@0.25.12', 'node_modules', 'esbuild', 'lib', 'main.js');

const staging = path.join(TMP_ROOT, 'staging-diag');
await mkdir(staging, { recursive: true });
const esbuild = require(ESBUILD_ENTRY);
const pkg = (name) => path.join(WORKTREE, 'packages', name, 'src', 'index.ts');
await esbuild.build({
  entryPoints: [path.join(HERE, 'diag-src', 'main.ts')],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  outfile: path.join(staging, 'server-diag.mjs'),
  sourcemap: false,
  logLevel: 'warning',
  absWorkingDir: WORKTREE,
  alias: {
    '@shun/contracts': pkg('contracts'),
    '@shun/resolver': pkg('resolver'),
    '@shun/authorization': pkg('authorization'),
    '@shun/store': pkg('store'),
    '@shun/vertical-storage': pkg('vertical-storage'),
    zod: require.resolve('zod', { paths: [path.join(WORKTREE, 'apps', 'control-api')] }),
  },
});
await ev('diag.bundle', 'OK', { staging, note: 'research-only; one console.error added' });
console.log(JSON.stringify({ ok: true, staging }));
