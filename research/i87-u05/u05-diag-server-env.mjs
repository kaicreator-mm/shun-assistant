// Run the resolve diagnosis under the server's EXACT restricted environment.
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { capture, readJson, restrictedEnv } from './u05-lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const sandbox = process.argv[2];
const env = await readJson(path.join(sandbox, 'env.json'));
const renv = restrictedEnv({ sandbox, port: 41235, staging: path.join('C:\\xDev\\kAiCreator\\_tmp\\i87-u05', 'staging'), mode: 'real-storage', env });
const res = await capture(
  process.execPath,
  ['--experimental-transform-types', path.join(HERE, 'u05-diag-resolve.mjs'), sandbox],
  { env: renv, timeoutMs: 120_000 },
);
console.log('exit', res.code);
console.log(res.stdout);
if (res.code !== 0) console.log('STDERR:', res.stderr.slice(-2000));
