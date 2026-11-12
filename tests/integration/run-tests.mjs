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

// VITEST-WORKER RPC STARVATION TRANSIENT (2026-11-11 Woodpecker #775/#776):
// vitest 3.2.7 hard-codes a 60s birpc timeout (DEFAULT_TIMEOUT = 6e4) on the
// worker→main channel and the pool configs cannot override it. Under heavy
// agent load (11 concurrent full-qualification pipelines on one worker) the
// main thread can starve past that deadline; vitest then records one unhandled
// error and exits nonzero EVEN THOUGH EVERY TEST PASSED. A real test failure
// never carries that marker, so one marker-gated retry keeps the gate
// fail-closed while surviving the starvation transient.
const VITEST_WORKER_RPC_TRANSIENT_MARKER = '[vitest-worker]: Timeout calling';

// Vitest suites run captured instead of inherited so the RPC transient is
// detectable; the full captured trace is still echoed, because this
// deployment retains no server logs and this output is the only post-mortem
// evidence path (see .woodpecker.yml).
function runVitestSuite(suite) {
  const result = spawnSync(process.execPath, suite.args, {
    cwd: workspaceRoot,
    encoding: 'buffer',
    maxBuffer: 128 * 1024 * 1024,
    env: process.env,
  });
  if (result.stdout?.length) process.stdout.write(result.stdout);
  if (result.stderr?.length) process.stderr.write(result.stderr);
  return result;
}

function isVitestWorkerRpcTransient(suite, result) {
  return (
    suite.requiresVitest === true &&
    !result.error &&
    result.status !== 0 &&
    `${result.stdout?.toString() ?? ''}${result.stderr?.toString() ?? ''}`.includes(
      VITEST_WORKER_RPC_TRANSIENT_MARKER,
    )
  );
}

let passed = 0;
for (const suite of suites) {
  console.log(`[integration] RUN ${suite.name}`);
  let result;
  if (suite.requiresVitest) {
    result = runVitestSuite(suite);
    if (isVitestWorkerRpcTransient(suite, result)) {
      console.error(
        `[integration] TRANSIENT ${suite.name}: vitest worker RPC starvation (tests may have all passed); retrying once`,
      );
      result = runVitestSuite(suite);
    }
  } else {
    result = spawnSync(process.execPath, suite.args, {
      cwd: workspaceRoot,
      stdio: 'inherit',
      env: process.env,
    });
  }
  if (result.error || result.status !== 0) {
    console.error(`[integration] FAIL ${suite.name}: ${result.error?.message ?? result.status ?? 'no exit'}`);
    process.exit(result.status && result.status > 0 ? result.status : 1);
  }
  passed++;
}
console.log(`[integration] PASS ${passed}/${suites.length} suites`);
