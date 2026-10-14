// Capture task snapshot + preview evidence for a task id on a live server.
import * as path from 'node:path';
import { httpJson, writeJson, ev } from './u05-lib.mjs';

const port = Number(process.argv[2]);
const sandbox = process.argv[3];
const taskId = process.argv[4];

const snap = await httpJson(port, 'GET', `/api/tasks/${taskId}`);
await writeJson(path.join(sandbox, `task-${taskId}-snapshot.json`), snap.json);
const prev = await httpJson(port, 'GET', `/api/tasks/${taskId}/preview`);
await writeJson(path.join(sandbox, `task-${taskId}-preview.json`), prev.json);
await ev('task.evidence.capture', 'OK', {
  taskId,
  state: snap.json?.state,
  verification: snap.json?.verification,
  execution: snap.json?.execution,
  previewStatus: prev.status,
  planHash: prev.json?.planHash,
  actionCount: prev.json?.actions?.length,
});
console.log(
  JSON.stringify(
    {
      state: snap.json?.state,
      verification: snap.json?.verification,
      execution: snap.json?.execution,
      previewPlanHash: prev.json?.planHash,
      previewActions: prev.json?.actions?.length,
    },
    null,
    2,
  ),
);
