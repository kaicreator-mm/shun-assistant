// Round driver: subcommands orchestrated from bash.
// where-check | netstat | powercheck | elevation | boot | negatives | task |
// tasks | stop | watch | watchdiff | portfree
import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ev,
  httpJson,
  waitHealthy,
  bootPortable,
  killTree,
  pidAlive,
  netstatFor,
  powerShellJson,
  capture,
  restrictedEnv,
  snapshotTree,
  snapshotDirLevel,
  diffSnapshots,
  writeJson,
  readJson,
  sleep,
  sha256File,
  pickBindablePort,
  WHERE,
  REG,
  WHOAMI,
  TMP_ROOT,
  RESTRICTED_PATH,
  POWERSHELL,
} from './u05-lib.mjs';

function flag(name, def) {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 ? process.argv[i + 1] : def;
}
const cmd = process.argv[2];
const HERE = path.dirname(fileURLToPath(import.meta.url));

async function readBoot(sandbox) {
  return readJson(path.join(sandbox, 'boot.json'));
}

async function main() {
  if (cmd === 'where-check') {
    // prove the restricted end-user env cannot find pnpm/npm/node
    const renv = restrictedEnv({ sandbox: path.join(TMP_ROOT, 'user-home') });
    const out = {};
    for (const tool of ['pnpm', 'npm', 'node', 'npx']) {
      const res = await capture(WHERE, [tool], { env: renv, timeoutMs: 20_000 });
      out[tool] = { code: res.code, stdout: res.stdout.trim(), stderr: res.stderr.trim() };
    }
    out.restrictedPath = RESTRICTED_PATH;
    await ev('env.where', 'OK', out);
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  if (cmd === 'portfree') {
    const port = Number(flag('port'));
    const res = await netstatFor(0);
    const busy = res.all.filter((l) => l.includes(':' + port + ' ') && /LISTENING/.test(l));
    await ev('port.check', 'OK', { port, busy });
    console.log(JSON.stringify({ port, busy, free: busy.length === 0 }));
    process.exit(busy.length === 0 ? 0 : 3);
  }

  if (cmd === 'netstat') {
    const pid = Number(process.argv[3]);
    const tag = process.argv[4] || 'snap';
    const sandbox = flag('sandbox');
    const res = await netstatFor(pid);
    if (sandbox) await writeJson(path.join(sandbox, `netstat-${tag}.json`), res.mine);
    await ev('netstat', 'OK', { pid, tag, lines: res.mine });
    console.log(JSON.stringify(res.mine, null, 2));
    return;
  }

  if (cmd === 'elevation') {
    // host shell privilege facts (standard user evidence)
    const ps =
      `[Security.Principal.WindowsPrincipal]$p=[Security.Principal.WindowsIdentity]::GetCurrent();` +
      `$admin=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);` +
      `@{user=$env:USERNAME; isAdmin=$admin; integrity=$p.Owner.Value} | ConvertTo-Json -Compress`;
    const who = await capture(WHOAMI, ['/groups', '/fo', 'csv', '/nh'], { timeoutMs: 20_000 });
    const label = await capture(WHOAMI, [], { timeoutMs: 10_000 });
    const elevatedSid = /S-1-16-12288/i.test(who.stdout);
    const adminGroupSid = /S-1-5-32-544/i.test(who.stdout);
    const psRes = await powerShellJson(ps);
    await ev('host.privilege', 'OK', {
      whoami: label.stdout.trim(),
      elevatedSidPresent: elevatedSid,
      adminGroupPresent: adminGroupSid,
      groupsCsv: who.stdout.trim().slice(0, 1200),
      powerShell: psRes.value,
    });
    console.log(JSON.stringify({ elevatedSidPresent: elevatedSid, adminGroupPresent: adminGroupSid, powerShell: psRes.value }, null, 2));
    return;
  }

  if (cmd === 'boot') {
    const staging = process.argv[3];
    const sandbox = process.argv[4];
    const wantedPort = Number(process.argv[5]);
    const mode = process.argv[6] || 'real-storage';
    let env = {};
    if (mode === 'real-storage') {
      env = await readJson(path.join(sandbox, 'env.json'));
    }
    // probe-bind first: Windows phantom reservations make netstat unreliable
    const port = await pickBindablePort(wantedPort);
    if (port !== wantedPort) await ev('boot.portmove', 'OK', { wantedPort, port });
    let boot = await bootPortable({ staging, sandbox, port, mode, env });
    let attempts = 1;
    while (!boot.ok && /EADDRINUSE/.test(boot.serverOutput || '') && attempts < 4) {
      await ev('boot.retry', 'RETRY', { port, reason: 'EADDRINUSE', attempts });
      const next = await pickBindablePort(port + 2);
      port = next;
      attempts += 1;
      boot = await bootPortable({ staging, sandbox, port, mode, env });
    }
    if (!boot.ok) {
      await ev('boot', 'FAIL', { staging, sandbox, port, mode, boot: { ...boot, child: undefined, health: undefined }, serverOutput: boot.serverOutput });
      await writeJson(path.join(sandbox, 'boot.json'), { ok: false, port, mode, bootMs: boot.bootMs, output: boot.serverOutput });
      console.error(JSON.stringify({ ok: false, output: boot.serverOutput }, null, 2));
      process.exit(1);
    }
    const record = {
      ok: true,
      port,
      mode,
      cmdPid: boot.cmdPid,
      nodePid: boot.nodePid,
      nodeExecutablePath: boot.nodeExecutablePath,
      nodeCommandLine: boot.nodeCommandLine,
      parentProcessId: boot.parentProcessId,
      bootMs: boot.bootMs,
      health: boot.health.health,
      startedAt: new Date().toISOString(),
      staging,
      sandbox,
      serverLog: boot.serverLog,
    };
    await writeJson(path.join(sandbox, 'boot.json'), record);
    await ev('boot', 'OK', {
      port,
      mode,
      nodePid: boot.nodePid,
      nodeExecutablePath: boot.nodeExecutablePath,
      bootMs: boot.bootMs,
      healthSimulated: boot.health.health?.simulated,
      policy: boot.health.health?.policy,
    });
    console.log(JSON.stringify({ ...record, health: undefined }, null, 2));
    return;
  }

  if (cmd === 'powercheck') {
    const pid = Number(process.argv[3]);
    const staging = process.argv[4];
    const ps =
      `$p=Get-CimInstance Win32_Process -Filter "ProcessId=${pid}";` +
      `$proc=Get-Process -Id ${pid};` +
      `@{path=$p.ExecutablePath;cmd=$p.CommandLine;parent=$p.ParentProcessId;name=$p.Name;startTime=$proc.StartTime.ToString('o')} | ConvertTo-Json -Compress`;
    const res = await powerShellJson(ps);
    const expected = path.join(staging, 'runtime', 'node.exe').toLowerCase();
    const matches = res.ok && String(res.value?.path || '').toLowerCase() === expected;
    await ev('process.identity', matches ? 'OK' : 'FAIL', { pid, expected, actual: res.value, matches });
    console.log(JSON.stringify({ matches, value: res.value }, null, 2));
    process.exit(matches ? 0 : 1);
  }

  if (cmd === 'negatives') {
    const port = Number(process.argv[3]);
    const sandbox = process.argv[4];
    const env = await readJson(path.join(sandbox, 'env.json'));
    const workspace = env.SHUN_REAL_STORAGE_ROOT;
    const policyContext = {
      privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
      environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
    };
    const cases = [
      {
        id: 'image-goal-no-model',
        body: {
          taskId: 'u05-neg-image-1',
          goal: 'resize my holiday pictures with an image model',
          objects: [{ kind: 'DIRECTORY', ref: workspace }],
          constraints: { format: 'JPG' },
          policyContext,
        },
        expectRefuse: true,
      },
      {
        id: 'elevation-goal',
        body: {
          taskId: 'u05-neg-elev-1',
          goal: 'bounded cache cleanup requiring admin rights',
          objects: [{ kind: 'DIRECTORY', ref: workspace }],
          constraints: {},
          policyContext: {
            privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
            environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: true },
          },
        },
        expectRefuse: true,
      },
      {
        id: 'out-of-scope-goal',
        body: {
          taskId: 'u05-neg-scope-1',
          goal: 'bounded cache cleanup of C:\\Windows\\Temp',
          objects: [{ kind: 'DIRECTORY', ref: 'C:\\Windows\\Temp' }],
          constraints: {},
          policyContext,
        },
        expectRefuse: true,
      },
      {
        id: 'protected-canary-target-goal',
        body: {
          taskId: 'u05-neg-canary-1',
          goal: 'bounded cache cleanup including protected-keep',
          objects: [{ kind: 'DIRECTORY', ref: path.join(workspace, 'protected-keep', 'canary.txt') }],
          constraints: {},
          policyContext,
        },
        expectRefuse: true,
      },
    ];
    const results = [];
    for (const c of cases) {
      const res = await httpJson(port, 'POST', '/api/tasks', c.body);
      const refused = res.status >= 400;
      results.push({
        id: c.id,
        status: res.status,
        refused,
        body: res.json ?? res.text?.slice(0, 500),
      });
      await ev('negative.goal', refused ? 'REFUSED' : 'UNEXPECTED_ACCEPT', {
        id: c.id,
        status: res.status,
        body: res.json ?? res.text?.slice(0, 500),
      });
      await sleep(120);
    }
    // honest-missing probes
    const residue = await httpJson(port, 'GET', '/api/tasks/u05-neg-image-1/residue?detail=true');
    const evidence = await httpJson(port, 'GET', '/api/evidence/local:some/ref');
    results.push({ id: 'residue-endpoint-real-backend', status: residue.status, body: residue.json });
    results.push({ id: 'evidence-endpoint-real-backend', status: evidence.status, body: evidence.json });
    await ev('negative.endpoints', 'OK', { residue: residue.status, evidence: evidence.status });
    await writeJson(path.join(sandbox, 'negatives.json'), results);
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  if (cmd === 'task') {
    const staging = process.argv[3];
    const sandbox = process.argv[4];
    const port = Number(process.argv[5]);
    const taskId = process.argv[6];
    const env = await readJson(path.join(sandbox, 'env.json'));
    const workspace = env.SHUN_REAL_STORAGE_ROOT;
    const result = { taskId, steps: [] };

    // 1. fresh issuance right before submit
    const issueRes = await capture(process.execPath, [
      path.join(HERE, 'u05-issue.mjs'),
      sandbox,
    ], { timeoutMs: 90_000 });
    let bindingRev;
    try {
      bindingRev = JSON.parse(issueRes.stdout).revision;
    } catch {}
    result.steps.push({ step: 'issue-before-submit', ok: issueRes.code === 0, revision: bindingRev });
    if (issueRes.code !== 0) throw new Error('issuance failed: ' + issueRes.stderr);

    // 2. submit
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
    result.submit = { status: submit.status, body: submit.json };
    await ev('task.submit', submit.status === 201 ? 'OK' : 'FAIL', { taskId, status: submit.status, body: submit.json });
    if (submit.status !== 201) throw new Error('submit failed');

    // 3. poll to AWAITING_AUTHORIZATION
    let snapshot;
    const pollStart = Date.now();
    for (;;) {
      await sleep(40);
      const r = await httpJson(port, 'GET', `/api/tasks/${taskId}`);
      snapshot = r.json;
      if (snapshot && (snapshot.state === 'AWAITING_AUTHORIZATION' || ['SUCCEEDED', 'FAILED', 'CANCELLED', 'NEEDS_INTERVENTION'].includes(snapshot.state))) break;
      if (Date.now() - pollStart > 30_000) break;
    }
    result.awaitState = snapshot?.state;
    await ev('task.await', 'OK', { taskId, state: snapshot?.state });
    if (snapshot?.state !== 'AWAITING_AUTHORIZATION') {
      await writeJson(path.join(sandbox, `task-${taskId}.json`), { ...result, terminal: snapshot });
      throw new Error('task did not reach AWAITING_AUTHORIZATION: ' + JSON.stringify(snapshot)?.slice(0, 600));
    }

    // 4. preview
    const preview = await httpJson(port, 'GET', `/api/tasks/${taskId}/preview`);
    result.preview = { status: preview.status, body: preview.json };
    await ev('task.preview', preview.status === 200 ? 'OK' : 'FAIL', {
      taskId,
      status: preview.status,
      planHash: preview.json?.planHash,
      actionCount: preview.json?.actions?.length,
      riskStatement: preview.json?.riskStatement,
    });

    // 5. approvals list + decision. Design intent: the single 60s issuance
    // envelope issued before submit must STILL be the current file at the
    // effect gate (revision equality is checked, and any re-issue mints a new
    // observationRevision -> new revision -> refused by design). Approving
    // within the envelope lifetime is the correct operator flow.
    const approvals = await httpJson(port, 'GET', '/api/approvals');
    const approval = (approvals.json?.approvals ?? []).find((a) => a.taskId === taskId);
    result.approval = approval;
    if (!approval) throw new Error('no pending approval for ' + taskId);
    const decision = await httpJson(port, 'POST', `/api/approvals/${approval.approvalId}/decision`, {
      approved: true,
      planHash: approval.planHash,
      reason: 'U05 pilot: human approves the exact previewed bounded cleanup plan',
    });
    result.decision = { status: decision.status, body: decision.json };
    await ev('task.approve', decision.status === 200 ? 'OK' : 'FAIL', { taskId, status: decision.status, body: decision.json });
    if (decision.status !== 200) throw new Error('decision failed');

    // 7. poll to terminal
    let terminal;
    const termStart = Date.now();
    for (;;) {
      await sleep(30);
      const r = await httpJson(port, 'GET', `/api/tasks/${taskId}`);
      terminal = r.json;
      if (terminal && ['SUCCEEDED', 'FAILED', 'CANCELLED', 'NEEDS_INTERVENTION'].includes(terminal.state)) break;
      if (Date.now() - termStart > 90_000) break;
    }
    result.terminal = terminal;
    await ev('task.terminal', terminal?.state === 'SUCCEEDED' ? 'OK' : 'FAIL', {
      taskId,
      state: terminal?.state,
      verification: terminal?.verification,
      execution: terminal?.execution,
      recovery: terminal?.recovery,
    });

    // 8. filesystem truth. Classification is exact-segment based (product
    // policy): only the exact 'cache' segment dir is CACHE-eligible; the
    // lookalike 'npm-cache' and the TEMP-marked 'temp' are conservatively
    // excluded for this run because the backend pins eligibleCategories=['CACHE'].
    const canaries = await readJson(path.join(sandbox, 'canaries.json'));
    const fsTruth = { protected: [], userContent: [], conservativeKept: [], expectGoneGone: 0, expectGoneRemaining: [] };
    for (const c of canaries.protected) {
      const exists = existsSync(c.full);
      const sha = exists ? await sha256File(c.full) : undefined;
      fsTruth.protected.push({ rel: c.rel, exists, shaMatches: sha === c.sha256 });
    }
    for (const c of canaries.userContent) {
      const exists = existsSync(c.full);
      const sha = exists ? await sha256File(c.full) : undefined;
      fsTruth.userContent.push({ rel: c.rel, exists, shaMatches: sha === c.sha256 });
    }
    for (const c of canaries.deletable) {
      const rel = c.rel.replace(/\\/g, '/');
      const gone = !existsSync(c.full);
      if (rel.startsWith('cache/')) {
        if (gone) fsTruth.expectGoneGone += 1;
        else fsTruth.expectGoneRemaining.push(c.rel);
      } else {
        // npm-cache/* (lookalike marker) and temp/* (TEMP category not in
        // eligibleCategories): conservative fail-closed survivors
        fsTruth.conservativeKept.push({ rel: c.rel, stillThere: existsSync(c.full) });
      }
    }
    fsTruth.allProtectedIntact = fsTruth.protected.every((p) => p.exists && p.shaMatches);
    fsTruth.allUserContentIntact = fsTruth.userContent.every((p) => p.exists && p.shaMatches);
    fsTruth.allExpectGoneGone = fsTruth.expectGoneRemaining.length === 0;
    fsTruth.conservativeKeptAll = fsTruth.conservativeKept.every((p) => p.stillThere);
    result.fsTruth = fsTruth;
    await ev('task.poststate', 'OK', { taskId, ...fsTruth });
    await writeJson(path.join(sandbox, `task-${taskId}.json`), result);
    console.log(JSON.stringify({ taskId, state: terminal?.state, fsTruth }, null, 2));
    return;
  }

  if (cmd === 'tasks') {
    const port = Number(process.argv[3]);
    const sandbox = process.argv[4];
    const tag = process.argv[5] || 'all';
    const res = await httpJson(port, 'GET', '/api/tasks');
    await writeJson(path.join(sandbox, `tasks-${tag}.json`), res.json);
    await ev('tasks.list', res.status === 200 ? 'OK' : 'FAIL', { tag, count: res.json?.tasks?.length, states: res.json?.tasks?.map((t) => ({ id: t.taskId, state: t.state, recovery: t.recovery?.classification })) });
    console.log(JSON.stringify(res.json?.tasks?.map((t) => ({ id: t.taskId, state: t.state, recovery: t.recovery })), null, 2));
    return;
  }

  if (cmd === 'stop') {
    const sandbox = process.argv[3];
    const style = process.argv[4] || 'orderly-then-force';
    const boot = await readBoot(sandbox);
    const out = { style, nodePid: boot.nodePid, cmdPid: boot.cmdPid };
    if (style === 'orderly-then-force' && boot.nodePid) {
      const orderly = await killTree(boot.nodePid, { force: false });
      out.orderlyAttempt = { code: orderly.code, stdout: orderly.stdout.trim().slice(0, 300) };
      await ev('stop.orderlyAttempt', 'OK', out.orderlyAttempt);
      await sleep(700);
      out.stillAliveAfterOrderly = await pidAlive(boot.nodePid);
      if (out.stillAliveAfterOrderly) {
        // Windows console node without an in-app signal handler: SIGTERM is
        // simulated by TerminateProcess; record as the honest stop mechanism.
        const res = await killTree(boot.nodePid, { force: true });
        out.forceKill = { code: res.code };
      }
    } else {
      const res = await killTree(boot.nodePid, { force: true });
      out.forceKill = { code: res.code };
    }
    if (boot.cmdPid) await killTree(boot.cmdPid, { force: true }).catch(() => {});
    await sleep(400);
    out.aliveAfter = await pidAlive(boot.nodePid);
    await ev('stop', out.aliveAfter ? 'FAIL' : 'OK', out);
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  if (cmd === 'watch') {
    const sandbox = process.argv[3];
    const staging = process.argv[4];
    const tag = process.argv[5];
    const snap = {
      at: new Date().toISOString(),
      workspace: await snapshotTree(path.join(sandbox, 'workspace')),
      sandboxTop: await snapshotDirLevel(sandbox),
      staging: await snapshotTree(staging),
      tmpDir: await snapshotTree(path.join(sandbox, 'tmp')),
      appdataLevel1: await snapshotDirLevel(process.env.APPDATA),
      regHkcuEnvironment: (await capture(REG, ['query', 'HKCU\\Environment'], { timeoutMs: 20_000 })).stdout,
    };
    await writeJson(path.join(sandbox, `snap-${tag}.json`), snap);
    await ev('watch', 'OK', { tag, workspaceFiles: Object.keys(snap.workspace).length, stagingFiles: Object.keys(snap.staging).length });
    console.log(JSON.stringify({ tag, workspaceFiles: Object.keys(snap.workspace).length, stagingFiles: Object.keys(snap.staging).length }));
    return;
  }

  if (cmd === 'watchdiff') {
    const sandbox = process.argv[3];
    const staging = process.argv[4];
    const tagA = process.argv[5];
    const tagB = process.argv[6];
    const a = await readJson(path.join(sandbox, `snap-${tagA}.json`));
    const b = await readJson(path.join(sandbox, `snap-${tagB}.json`));
    const diff = {
      workspace: diffSnapshots(a.workspace, b.workspace),
      staging: diffSnapshots(a.staging, b.staging),
      sandboxTop: diffSnapshots(a.sandboxTop, b.sandboxTop),
      tmpDir: diffSnapshots(a.tmpDir, b.tmpDir),
      appdataLevel1: diffSnapshots(a.appdataLevel1, b.appdataLevel1),
      regChanged: a.regHkcuEnvironment !== b.regHkcuEnvironment,
      atA: a.at,
      atB: b.at,
    };
    await writeJson(path.join(sandbox, `watchdiff-${tagA}-to-${tagB}.json`), diff);
    await ev('watchdiff', 'OK', {
      tagA,
      tagB,
      stagingDiff: diff.staging,
      sandboxTopDiff: diff.sandboxTop,
      tmpDiff: diff.tmpDir,
      appdataDiff: diff.appdataLevel1,
      regChanged: diff.regChanged,
    });
    console.log(JSON.stringify(diff, null, 2));
    return;
  }

  if (cmd === 'uiprobe') {
    const port = Number(process.argv[3]);
    const sandbox = process.argv[4];
    const tag = process.argv[5] || 'ui';
    const index = await httpJson(port, 'GET', '/');
    const appjs = await httpJson(port, 'GET', '/app.js');
    const out = {
      indexStatus: index.status,
      indexIsHtml: /<!doctype html|<html/i.test(index.text ?? ''),
      indexSnippet: (index.text ?? '').slice(0, 300),
      appJsStatus: appjs.status,
    };
    await writeJson(path.join(sandbox, `uiprobe-${tag}.json`), out);
    await ev('ui.probe', out.indexStatus === 200 && out.appJsStatus === 200 ? 'OK' : 'FAIL', { tag, ...out, indexSnippet: undefined });
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  throw new Error('unknown command: ' + cmd);
}

main().catch(async (err) => {
  await ev('round.' + (cmd ?? '?'), 'FAIL', { error: String(err && err.stack ? err.stack : err) });
  console.error(err);
  process.exit(1);
});
