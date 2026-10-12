import { readdirSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const here = dirname(fileURLToPath(import.meta.url));
const tests = readdirSync(here)
  .filter((name) => name.endsWith('.test.mjs'))
  .sort();

if (tests.length === 0) {
  console.log('[t10-integration] NO_TESTS_PRESENT');
  process.exit(0);
}

for (const name of tests) {
  const file = join(here, name);
  console.log(`[t10-integration] RUN ${basename(file)}`);
  const result = spawnSync(
    process.execPath,
    ['--experimental-transform-types', '--test', file],
    {
    cwd: process.cwd(),
    stdio: 'inherit',
      env: process.env,
    },
  );
  if (result.error) {
    console.error(`[t10-integration] SPAWN_FAILED ${name}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(`[t10-integration] FAIL ${name} status=${String(result.status)}`);
    process.exit(result.status ?? 1);
  }
}

console.log(`[t10-integration] PASS ${tests.length} file(s)`);
