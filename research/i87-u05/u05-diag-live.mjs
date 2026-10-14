// Boot the diagnostic bundle (2nd instance) and submit a task; then print the
// logged #execute error from the diag server log.
import { readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ev,
  httpJson,
  bootPortable,
  killTree,
  readJson,
  writeJson,
  pickBindablePort,
  capture,
  sleep,
} from './u05-lib.mjs';

const sandbox = 'C:\\xDev\\kAiCreator\\_tmp\\i87-u05\\user-home';
const staging = 'C:\\xDev\\kAiCreator\\_tmp\\i87-u05\\staging-diag';
const HERE = path.dirname(fileURLToPath(import.meta.url));

const env = await readJson(path.join(sandbox, 'env.json'));
const port = await pickBindablePort(41237);
const issue = await capture(process.execPath, [path.join(HERE, 'u05-issue.mjs'), sandbox], {
  timeoutMs: 90_000,
});
if (issue.code !== 0) throw new Error('issue failed');
const boot = await bootPortable({ staging, sandbox, port, mode: 'real-storage', env: { ...env, SHUN_CONTROL_PORT: String(port) } });
await ev('diag.boot', boot.ok ? 'OK' : 'FAIL', { port, nodePid: boot.nodePid });
if (!boot.ok) throw new Error('diag boot failed: ' + boot.serverOutput);

const workspace = env.SHUN_REAL_STORAGE_ROOT;
const taskId = 'u05-diag-' + Date.now();
const submit = await httpJson(port, 'POST', '/api/tasks', {
  taskId,
  goal: 'bounded cache cleanup of stale browser cache files',
  objects: [{ kind: 'DIRECTORY', ref: workspace }],
  constraints: {},
  policyContext: {
    privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
    environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
  },
});
await sleep(3000);
const snap = await httpJson(port, 'GET', `/api/tasks/${taskId}`);
const log = await readFile(path.join(sandbox, 'server.log'), 'utf8');
const diagLines = log.split(/\r?\n/).filter((l) => l.includes('[U05-DIAG]'));
await writeJson(path.join(sandbox, 'diag-submit.json'), { taskId, submitStatus: submit.status, state: snap.json?.state, diagLines: diagLines.slice(-6) });
await ev('diag.submit', 'OK', { taskId, state: snap.json?.state, diagLines: diagLines.slice(-4) });
await killTree(boot.nodePid, { force: true });
if (boot.cmdPid) await killTree(boot.cmdPid, { force: true }).catch(() => {});
console.log(JSON.stringify({ taskId, state: snap.json?.state, diagLines: diagLines.slice(-6) }, null, 2));
