// Probe refusal semantics on the uncertain (post-effect-boundary) task.
import { httpJson, ev, writeJson } from './u05-lib.mjs';

const port = Number(process.argv[2]);
const sandbox = process.argv[3];
const taskId = process.argv[4];

const recovery = await httpJson(port, 'POST', `/api/tasks/${taskId}/recovery`, {});
const retry = await httpJson(port, 'POST', `/api/tasks/${taskId}/retry`, {});
const cancel = await httpJson(port, 'POST', `/api/tasks/${taskId}/cancel`, {});
const out = {
  recoveryRefusal: { status: recovery.status, body: recovery.json },
  retryRefusal: { status: retry.status, body: retry.json },
  cancelAfterAuthorization: { status: cancel.status, body: cancel.json },
};
await writeJson(`${sandbox}/uncertain-refusal.json`, out);
await ev('uncertain.refusals', 'OK', out);
console.log(JSON.stringify(out, null, 2));
