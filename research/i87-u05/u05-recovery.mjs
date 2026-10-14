// Recovery scenarios driven against a live staging server:
//   midawait  <staging> <sandbox> <port> <taskId>
//       submit a goal, wait for AWAITING_AUTHORIZATION, then hard-kill the
//       process (taskkill /F /T). Durable row is still RECEIVED -> restart
//       must classify NOT_STARTED (never crossed the effect boundary).
//   mideffect <staging> <sandbox> <port> <taskId> [bulkFiles]
//       approve the plan, watch for state EXECUTING (set right after the
//       durable EFFECT_AUTHORIZED boundary commit), then hard-kill. Restart
//       must classify MAY_HAVE_EXECUTED_UNCERTAIN (conservative uncertainty).
import { writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ev,
  httpJson,
  readJson,
  writeJson,
  sleep,
  capture,
  killTree,
  pidAlive,
} from './u05-lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const staging = process.argv[3];
const sandbox = process.argv[4];
const port = Number(process.argv[5]);
const taskId = process.argv[6];
const bulk = Number(process.argv[7] || 0);
const scenario = process.argv[2];

async function issue() {
  const res = await capture(process.execPath, [path.join(HERE, 'u05-issue.mjs'), sandbox], {
    timeoutMs: 90_000,
  });
  if (res.code !== 0) throw new Error('issue failed: ' + res.stderr);
  return JSON.parse(res.stdout);
}

async function main() {
  const env = await readJson(path.join(sandbox, 'env.json'));
  const workspace = env.SHUN_REAL_STORAGE_ROOT;

  // every scenario needs an eligible cleanup target: refill the cache fixture
  const refill = await capture(process.execPath, [path.join(HERE, 'u05-refill.mjs'), sandbox], {
    timeoutMs: 60_000,
  });
  if (refill.code !== 0) throw new Error('refill failed');

  if (scenario === 'mideffect' && bulk > 0) {
    // bulk up the existing cache target so deletion takes measurable time
    const { mkdir, writeFile: wf } = await import('node:fs/promises');
    await mkdir(path.join(workspace, 'cache', 'bulk'), { recursive: true });
    for (let i = 0; i < bulk; i++) {
      await wf(path.join(workspace, 'cache', 'bulk', `f-${i}.tmp`), 'b'.repeat(8192));
    }
    await ev('recovery.bulk', 'OK', { taskId, bulk });
  }

  const issued = await issue();
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
  if (submit.status !== 201) throw new Error('submit failed: ' + JSON.stringify(submit.json));
  await ev('recovery.submit', 'OK', { scenario, taskId });

  const boot = await readJson(path.join(sandbox, 'boot.json'));

  if (scenario === 'midawait') {
    let state;
    const start = Date.now();
    for (;;) {
      await sleep(40);
      const r = await httpJson(port, 'GET', `/api/tasks/${taskId}`);
      state = r.json?.state;
      if (state === 'AWAITING_AUTHORIZATION') break;
      if (Date.now() - start > 30_000) break;
    }
    if (state !== 'AWAITING_AUTHORIZATION') throw new Error('expected AWAITING_AUTHORIZATION, got ' + state);
    const kill = await killTree(boot.nodePid, { force: true });
    if (boot.cmdPid) await killTree(boot.cmdPid, { force: true }).catch(() => {});
    const alive = await pidAlive(boot.nodePid);
    await ev('recovery.hardkill', alive ? 'FAIL' : 'OK', {
      scenario,
      taskId,
      stateAtKill: state,
      killCode: kill.code,
      aliveAfter: alive,
    });
    console.log(JSON.stringify({ scenario, taskId, stateAtKill: state, killed: !alive }, null, 2));
    return;
  }

  if (scenario === 'mideffect') {
    let snapshot;
    const start = Date.now();
    for (;;) {
      await sleep(40);
      const r = await httpJson(port, 'GET', `/api/tasks/${taskId}`);
      snapshot = r.json;
      if (snapshot?.state === 'AWAITING_AUTHORIZATION') break;
      if (Date.now() - start > 30_000) break;
    }
    if (snapshot?.state !== 'AWAITING_AUTHORIZATION') {
      throw new Error('expected AWAITING_AUTHORIZATION, got ' + snapshot?.state);
    }
    const approvals = await httpJson(port, 'GET', '/api/approvals');
    const approval = (approvals.json?.approvals ?? []).find((a) => a.taskId === taskId);
    if (!approval) throw new Error('no approval');
    // No re-issue here: the effect gate requires the SAME envelope revision
    // that was bound at submit; a re-issue mints a new revision by design.
    const decision = await httpJson(port, 'POST', `/api/approvals/${approval.approvalId}/decision`, {
      approved: true,
      planHash: approval.planHash,
      reason: 'U05 recovery scenario: approve then hard-kill at the effect boundary',
    });
    await ev('recovery.approved', decision.status === 200 ? 'OK' : 'FAIL', { taskId, status: decision.status });
    // poll aggressively for EXECUTING and kill the moment it appears
    let killed = false;
    let stateAtKill;
    const t0 = Date.now();
    for (;;) {
      const r = await httpJson(port, 'GET', `/api/tasks/${taskId}`);
      stateAtKill = r.json?.state;
      if (stateAtKill === 'EXECUTING' || stateAtKill === 'VERIFYING') {
        const kill = await killTree(boot.nodePid, { force: true });
        if (boot.cmdPid) await killTree(boot.cmdPid, { force: true }).catch(() => {});
        killed = !(await pidAlive(boot.nodePid));
        await ev('recovery.hardkill', 'OK', { scenario, taskId, stateAtKill, killCode: kill.code });
        break;
      }
      if (['SUCCEEDED', 'FAILED', 'CANCELLED', 'NEEDS_INTERVENTION'].includes(stateAtKill)) {
        await ev('recovery.hardkill', 'MISS', { scenario, taskId, racedTerminal: stateAtKill });
        break;
      }
      if (Date.now() - t0 > 60_000) break;
    }
    console.log(JSON.stringify({ scenario, taskId, stateAtKill, killed }, null, 2));
    return;
  }

  throw new Error('unknown scenario: ' + scenario);
}

main().catch(async (err) => {
  await ev('recovery.' + scenario, 'FAIL', { error: String(err && err.stack ? err.stack : err) });
  console.error(err);
  process.exit(1);
});
