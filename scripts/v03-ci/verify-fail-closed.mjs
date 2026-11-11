/**
 * This exact nested suite must return nonzero with an injected failed test,
 * then pass without injection. CI cannot claim success by skipping nested tests.
 * Does not alter source or committed historic qualification evidence.
 */
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const vitest = resolve(root, 'packages/vertical-support/node_modules/vitest/vitest.mjs');
const config = resolve(root, 'tests/integration/v03/r02-d2-gate/vitest.config.ts');
function run(inject) {
  const result = spawnSync(process.execPath, [vitest, 'run', '--config', config], {
    cwd: root, encoding: 'utf8',
    env: { ...process.env, SHUN_R02_FAULT_INJECT_NESTED: inject ? '1' : '0' },
  });
  if (result.error) throw result.error;
  return result.status;
}
const failExit = run(true);
const cleanExit = run(false);
if (failExit === 0 || cleanExit !== 0) {
  console.error(JSON.stringify({ code: 'NESTED_GATE_FAIL_OPEN', failExit, cleanExit }));
  process.exit(1);
}
console.log(JSON.stringify({ nestedGate: 'PASS', injectedFailExit: failExit, cleanExit }));
