// All nested v0.3 task qualification suites are mandatory; the old runner
// only enumerated top-level .test.mjs and silently skipped every Vitest suite.
import { existsSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const here = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = resolve(here, '../..');
const v03 = join(here, 'v03');
const vitest = join(workspaceRoot, 'packages/vertical-support/node_modules/vitest/vitest.mjs');
const suites = [];

function addNative(file) {
  suites.push({
    name: file,
    args: ['--experimental-transform-types', '--test', file],
  });
}

for (const name of readdirSync(here).filter((x) => x.endsWith('.test.mjs')).sort()) {
  addNative(join(here, name));
}

for (const dirName of readdirSync(v03, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort()) {
  const dir = join(v03, dirName);
  const files = readdirSync(dir).sort();
  for (const file of files.filter((name) => name.endsWith('.test.mjs'))) {
    addNative(join(dir, file));
  }
  if (files.some((name) => name.endsWith('.test.ts'))) {
    const config = join(dir, 'vitest.config.ts');
    if (!existsSync(config)) {
      throw new Error(`V03_TEST_GATE_MISSING_CONFIG: ${dirName}`);
    }
    suites.push({
      name: `${dirName}/vitest`,
      args: [vitest, 'run', '--config', config],
      requiresVitest: true,
    });
  }
}

if (suites.length === 0) {
  console.error('[integration] MANDATORY_SUITES_MISSING');
  process.exit(1);
}
if (suites.some((s) => s.requiresVitest) && !existsSync(vitest)) {
  console.error('[integration] VITEST_NOT_INSTALLED; fail closed');
  process.exit(1);
}

let passed = 0;
for (const suite of suites) {
  console.log(`[integration] RUN ${suite.name}`);
  const result = spawnSync(process.execPath, suite.args, {
    cwd: workspaceRoot,
    stdio: 'inherit',
    env: process.env,
  });
  if (result.error || result.status !== 0) {
    console.error(`[integration] FAIL ${suite.name}: ${result.error?.message ?? result.status ?? 'no exit'}`);
    process.exit(result.status && result.status > 0 ? result.status : 1);
  }
  passed++;
}
console.log(`[integration] PASS ${passed}/${suites.length} suites`);
