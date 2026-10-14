// Cold-start timing: N boots of the portable staging via launch.cmd under the
// restricted end-user env, each with a freshly issued currentness envelope.
// Measures spawn -> first HTTP 200 on /api/health. Also fetches / (UI) once.
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ev,
  bootPortable,
  killTree,
  pidAlive,
  httpJson,
  capture,
  readJson,
  writeJson,
  sleep,
  pickBindablePort,
} from './u05-lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const runs = Number(process.argv[2] || 3);
const staging = process.argv[3];
const sandbox = process.argv[4];
const portBase = Number(process.argv[5] || 41239);

async function issue(sandbox) {
  const res = await capture(process.execPath, [path.join(HERE, 'u05-issue.mjs'), sandbox], {
    timeoutMs: 90_000,
  });
  if (res.code !== 0) throw new Error('issue failed: ' + res.stderr);
  return JSON.parse(res.stdout);
}

async function main() {
  const results = [];
  for (let i = 0; i < runs; i++) {
    const port = await pickBindablePort(portBase + i * 3);
    await issue(sandbox);
    const env = await readJson(path.join(sandbox, 'env.json'));
    const t0 = Date.now();
    const boot = await bootPortable({ staging, sandbox, port, mode: 'real-storage', env });
    const run = {
      run: i + 1,
      port,
      bootMsSpawnToFirst200: boot.bootMs,
      totalMsIncludingIssue: Date.now() - t0,
      ok: boot.ok,
      nodePid: boot.nodePid,
    };
    if (boot.ok) {
      const ui = await httpJson(port, 'GET', '/');
      run.uiStatus = ui.status;
      const health = await httpJson(port, 'GET', '/api/health');
      run.healthSimulated = health.json?.simulated;
      run.policyKind = health.json?.policy?.kind;
      await killTree(boot.nodePid, { force: true });
      if (boot.cmdPid) await killTree(boot.cmdPid, { force: true }).catch(() => {});
      await sleep(300);
      run.cleanedUp = !(await pidAlive(boot.nodePid));
    } else {
      run.output = boot.serverOutput?.slice(0, 800);
    }
    results.push(run);
    await ev('coldstart', run.ok ? 'OK' : 'FAIL', run);
  }
  const out = { runs: results };
  await writeJson(path.join(sandbox, 'coldstart.json'), out);
  console.log(JSON.stringify(out, null, 2));
}

main().catch(async (err) => {
  await ev('coldstart', 'FAIL', { error: String(err && err.stack ? err.stack : err) });
  console.error(err);
  process.exit(1);
});
