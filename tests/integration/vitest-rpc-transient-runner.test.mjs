import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const fakeVitest = [
  "import { readFileSync, writeFileSync } from 'node:fs';",
  "const file = process.env.SHUN_RPC_TEST_COUNT;",
  "let n = 0;",
  "try { n = Number(readFileSync(file, 'utf8')); } catch {}",
  "n += 1;",
  "writeFileSync(file, String(n));",
  "const green = ' Test Files  1 passed (1)\\n Tests  24 passed | 3 skipped (27)\\n';",
  "if (n === 1 || process.env.SHUN_RPC_TEST_ALWAYS_FAIL === '1') {",
  "  const count = process.env.SHUN_RPC_TEST_MODE === 'mixed' ? '2 unhandled errors' : '1 unhandled error';",
  "  process.stdout.write(green + 'Vitest caught ' + count + ' during the test run.\\n'",
  "    + 'Error: [vitest-worker]: Timeout calling \"onTaskUpdate\"\\n'",
  "    + (process.env.SHUN_RPC_TEST_MODE === 'mixed' ? 'TypeError: Cannot read currentness\\n' : ''));",
  "  process.exit(1);",
  "}",
  "process.stdout.write(green);",
  "",
  '',
].join('\n');

function executeFixture(mode, alwaysFail = false) {
  const root = mkdtempSync(join(tmpdir(), 'shun-rpc-native-'));
  const integr = join(root, 'tests', 'integration');
  const v03 = join(integr, 'v03', 'fixture');
  const vitest = join(root, 'packages', 'vertical-support', 'node_modules', 'vitest');
  const countFile = join(root, 'spawn-count.txt');
  try {
    mkdirSync(v03, { recursive: true });
    mkdirSync(vitest, { recursive: true });
    copyFileSync(join(here, 'run-tests.mjs'), join(integr, 'run-tests.mjs'));
    copyFileSync(join(here, 'vitest-rpc-transient-guard.mjs'), join(integr, 'vitest-rpc-transient-guard.mjs'));
    writeFileSync(join(v03, 'fixture.test.ts'), '// intentionally stubbed in isolated runner integration\n');
    writeFileSync(join(v03, 'vitest.config.ts'), '// intentionally stubbed configuration\n');
    writeFileSync(join(vitest, 'vitest.mjs'), fakeVitest);
    const run = spawnSync(process.execPath, [join(integr, 'run-tests.mjs')], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, SHUN_RPC_TEST_MODE: mode,
        SHUN_RPC_TEST_ALWAYS_FAIL: alwaysFail ? '1' : '0', SHUN_RPC_TEST_COUNT: countFile },
    });
    const count = Number(readFileSync(countFile, 'utf8'));
    return { status: run.status, stdout: run.stdout, stderr: run.stderr, count, error: run.error };
  } finally { rmSync(root, { recursive: true, force: true }); }
}

test('real integration runner refuses mixed RPC+independent TypeError without retry', () => {
  const run = executeFixture('mixed');
  assert.equal(run.error, undefined);
  assert.equal(run.status, 1);
  assert.equal(run.count, 1);
  assert.match(run.stdout, /TypeError: Cannot read currentness/);
  assert.match(run.stderr, /\[integration\] FAIL/);
  assert.doesNotMatch(run.stderr, /\[integration\] TRANSIENT/);
});
test('real integration runner retries a single verified RPC transient once', () => {
  const run = executeFixture('single');
  assert.equal(run.status, 0);
  assert.equal(run.count, 2);
  assert.match(run.stderr, /\[integration\] TRANSIENT/);
  assert.match(run.stdout, /\[integration\] PASS 1\/1 suites/);
});
test('real integration runner never accepts a second failed RPC attempt', () => {
  const run = executeFixture('single', true);
  assert.equal(run.status, 1);
  assert.equal(run.count, 2);
  assert.match(run.stderr, /\[integration\] FAIL/);
});
