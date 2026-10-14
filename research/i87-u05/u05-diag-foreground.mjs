// Foreground diagnostic: run the diag bundle with piped stdio, submit a task,
// print everything the server says (the swallowed #execute error).
import { spawn } from 'node:child_process';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { httpJson, readJson, pickBindablePort, capture, sleep, killTree } from './u05-lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const sandbox = 'C:\\xDev\\kAiCreator\\_tmp\\i87-u05\\user-home';
const nodeExe = 'C:\\xDev\\kAiCreator\\_tmp\\i87-u05\\staging\\runtime\\node.exe';
const server = 'C:\\xDev\\kAiCreator\\_tmp\\i87-u05\\staging-diag\\server-diag.mjs';

const env = await readJson(path.join(sandbox, 'env.json'));
const port = await pickBindablePort(41241);
const issue = await capture(process.execPath, [path.join(HERE, 'u05-issue.mjs'), sandbox], { timeoutMs: 90_000 });
if (issue.code !== 0) throw new Error('issue failed');

const child = spawn(nodeExe, [server], {
  env: {
    ...process.env,
    SHUN_CONTROL_PORT: String(port),
    SHUN_CONTROL_MODE: 'real-storage',
    SHUN_CONTROL_UI_DIR: 'C:\\xDev\\kAiCreator\\_tmp\\i87-u05\\staging\\app-ui',
    ...env,
    SHUN_CONTROL_PORT: String(port),
  },
  stdio: ['ignore', 'pipe', 'pipe'],
  windowsHide: true,
});
const lines = [];
child.stdout.on('data', (d) => lines.push('OUT ' + d.toString('utf8').trim()));
child.stderr.on('data', (d) => lines.push('ERR ' + d.toString('utf8').trim()));

// wait healthy
let healthy = false;
for (let i = 0; i < 400 && !healthy; i++) {
  const h = await httpJson(port, 'GET', '/api/health');
  if (h.status === 200) healthy = true;
  else await sleep(25);
}
lines.push('HEALTHY=' + healthy);
if (healthy) {
  const workspace = env.SHUN_REAL_STORAGE_ROOT;
  const taskId = 'u05-diagfg-' + Date.now();
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
  lines.push('SUBMIT=' + submit.status);
  await sleep(4000);
  const snap = await httpJson(port, 'GET', `/api/tasks/${taskId}`);
  lines.push('STATE=' + snap.json?.state);
}
child.kill();
await sleep(500);
console.log(lines.join('\n'));
