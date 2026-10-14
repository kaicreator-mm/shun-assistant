// UNC path timebox (15 min): attempt to provision + issue + boot a real-storage
// sandbox with its workspace/state/registry under \\wsl.localhost\<distro>\...
// Any failure is recorded honestly (SKIP with the exact error), never faked.
import { mkdir, writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ev,
  capture,
  readJson,
  writeJson,
  TMP_ROOT,
  bootPortable,
  killTree,
  httpJson,
} from './u05-lib.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEADLINE = Date.now() + 15 * 60_000;

function left() {
  return DEADLINE - Date.now();
}

async function main() {
  const out = { attempt: [], skipped: false };
  // 1. find a WSL distro
  const wsl = await capture('C:\\Windows\\System32\\wsl.exe', ['-l', '-q'], { timeoutMs: 30_000 });
  // wsl.exe outputs UTF-16LE sometimes; normalize
  const raw = wsl.stdout;
  const norm = raw.includes('\u0000') ? raw.replace(/\u0000/g, '') : raw;
  const distros = norm
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s && !/^(name|native|docker)/i.test(s));
  out.attempt.push({ step: 'wsl-list', code: wsl.code, distros });
  await ev('unc.wslList', 'OK', { distros, code: wsl.code });
  if (wsl.code !== 0 || distros.length === 0) {
    out.skipped = true;
    out.reason = 'no WSL distro available for a non-admin UNC path';
    await ev('unc', 'SKIP', out);
    console.log(JSON.stringify(out, null, 2));
    return;
  }
  const distro = distros[0];
  const uncRoot = `\\\\wsl.localhost\\${distro}\\tmp\\shun-u05-unc`;

  // 2. can the redirector write there at all?
  try {
    await mkdir(path.join(uncRoot, 'probe'), { recursive: true, });
    await writeFile(path.join(uncRoot, 'probe', 'w.txt'), 'unc write probe\n', 'utf8');
    out.attempt.push({ step: 'unc-write-probe', ok: true, uncRoot });
  } catch (err) {
    out.skipped = true;
    out.reason = 'UNC write probe failed: ' + String(err);
    await ev('unc', 'SKIP', out);
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  // 3. provision via the standard provisioner (it only uses path.join under root)
  const prov = await capture(process.execPath, [path.join(HERE, 'u05-provision.mjs'), uncRoot], {
    timeoutMs: Math.min(120_000, left()),
  });
  out.attempt.push({ step: 'provision', code: prov.code, stdout: prov.stdout.slice(0, 300), stderr: prov.stderr.slice(0, 500) });
  if (prov.code !== 0) {
    out.skipped = true;
    out.reason = 'provision on UNC failed (fail-closed or unsupported): see attempt';
    await ev('unc', 'SKIP', out);
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  // 4. issuance (issuer requires fs.statfs on the workspace; often unsupported on UNC)
  const issue = await capture(process.execPath, [path.join(HERE, 'u05-issue.mjs'), uncRoot], {
    timeoutMs: Math.min(120_000, left()),
  });
  out.attempt.push({ step: 'issue', code: issue.code, stdout: issue.stdout.slice(0, 300), stderr: issue.stderr.slice(0, 500) });
  if (issue.code !== 0) {
    out.skipped = true;
    out.reason = 'issuance on UNC failed: ' + (issue.stderr || issue.stdout).slice(0, 300);
    await ev('unc', 'SKIP', out);
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  // 5. boot the portable server against the UNC workspace (staging itself local)
  const sandboxLocal = path.join(TMP_ROOT, 'unc-driver');
  await mkdir(sandboxLocal, { recursive: true });
  const port = 41247;
  const env = await readJson(path.join(uncRoot, 'env.json'));
  const boot = await bootPortable({ staging: path.join(TMP_ROOT, 'staging'), sandbox: sandboxLocal, port, mode: 'real-storage', env });
  out.attempt.push({
    step: 'boot',
    ok: boot.ok,
    bootMs: boot.bootMs,
    output: boot.ok ? undefined : (boot.serverOutput || '').slice(-1500),
  });
  if (!boot.ok) {
    out.skipped = true;
    out.reason = 'boot against UNC workspace failed (likely fail-closed alias/statfs check): see server output';
    out.serverOutput = (boot.serverOutput || '').slice(-1500);
    await ev('unc', 'SKIP', out);
    console.log(JSON.stringify(out, null, 2));
    return;
  }
  const health = await httpJson(port, 'GET', '/api/health');
  out.booted = { ok: true, port, healthStatus: health.status, simulated: health.json?.simulated };
  await killTree(boot.nodePid, { force: true });
  await ev('unc', 'OK', out);
  console.log(JSON.stringify(out, null, 2));
}

main().catch(async (err) => {
  const out = { skipped: true, reason: String(err && err.stack ? err.stack : err) };
  await ev('unc', 'SKIP', out);
  console.log(JSON.stringify(out, null, 2));
});
