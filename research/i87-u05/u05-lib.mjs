// i87 U05 shared harness library. One-shot research code, never merged into src.
import { spawn } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { appendFile, mkdir, readFile, writeFile, readdir, stat, lstat, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import * as path from 'node:path';

export const WORKTREE = 'C:\\xDev\\kAiCreator\\shun-assistant\\i87-u05-zc';
export const RESEARCH = path.join(WORKTREE, 'research', 'i87-u05');
export const EVENTS = path.join(RESEARCH, 'events.ndjson');
export const TMP_ROOT = 'C:\\xDev\\kAiCreator\\_tmp\\i87-u05';

const SYSTEM32 = 'C:\\Windows\\System32';
export const POWERSHELL = path.join(SYSTEM32, 'WindowsPowerShell', 'v1.0', 'powershell.exe');
export const CMD = path.join(SYSTEM32, 'cmd.exe');
export const NETSTAT = path.join(SYSTEM32, 'netstat.exe');
export const TASKKILL = path.join(SYSTEM32, 'taskkill.exe');
export const WHOAMI = path.join(SYSTEM32, 'whoami.exe');
export const WHERE = path.join(SYSTEM32, 'where.exe');
export const REG = path.join(SYSTEM32, 'reg.exe');

export const RESTRICTED_PATH = 'C:\\Windows\\System32;C:\\Windows';

export async function ev(step, status, data) {
  const line =
    JSON.stringify({ ts: new Date().toISOString(), step, status, ...(data ? { data } : {}) }) +
    '\n';
  await appendFile(EVENTS, line, 'utf8');
  return line.trim();
}

export async function sha256File(file) {
  const buf = await readFile(file);
  return createHash('sha256').update(buf).digest('hex');
}

export function sha256Buf(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/** Spawn a process, capture stdout/stderr as text, resolve {code, stdout, stderr}. */
export function capture(exe, args, { cwd, env, timeoutMs = 60_000, input } = {}) {
  return new Promise((resolveRun) => {
    const child = spawn(exe, args, {
      cwd,
      env,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill();
      } catch {}
    }, timeoutMs);
    child.stdout.on('data', (d) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d) => (stderr += d.toString('utf8')));
    child.on('error', (err) => {
      clearTimeout(timer);
      resolveRun({ code: -1, stdout, stderr: stderr + String(err), timedOut });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolveRun({ code, stdout, stderr, timedOut });
    });
    if (input !== undefined) child.stdin.end(input);
  });
}

/** httpJson against 127.0.0.1:port with a hard timeout. */
export function httpJson(port, method, reqPath, body, timeoutMs = 15_000) {
  return new Promise((resolveHttp) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const headers = { accept: 'application/json' };
    if (payload !== undefined) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(payload);
      headers.origin = `http://127.0.0.1:${port}`;
    }
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port,
        path: reqPath,
        method,
        headers,
        setHost: true,
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json;
          try {
            json = text ? JSON.parse(text) : undefined;
          } catch {
            json = undefined;
          }
          resolveHttp({ status: res.statusCode, text, json });
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('client timeout')));
    req.on('error', (err) => resolveHttp({ status: 0, text: String(err), json: undefined }));
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

/** Poll until GET /api/health returns 200. Returns {ok, ms, health}. */
export async function waitHealthy(port, timeoutMs = 30_000, opts = {}) {
  const start = Date.now();
  for (;;) {
    const elapsed = Date.now() - start;
    if (elapsed > timeoutMs) return { ok: false, ms: elapsed, health: undefined };
    if (opts.child && opts.child.exitCode !== null) {
      // server process already exited — no point polling the full timeout
      return { ok: false, ms: elapsed, health: undefined, exited: true };
    }
    const res = await httpJson(port, 'GET', '/api/health');
    if (res.status === 200) return { ok: true, ms: elapsed, health: res.json };
    await sleep(25);
  }
}

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** Windows hosts have phantom port reservations (netstat shows nothing, bind
 *  still fails). Probe-bind on 127.0.0.1 right before handing a port over. */
export function probeBindable(port) {
  return new Promise((resolveProbe) => {
    const s = createServer();
    s.once('error', () => resolveProbe(false));
    s.listen(port, '127.0.0.1', () => s.close(() => resolveProbe(true)));
  });
}

export async function pickBindablePort(startPort, maxTries = 12) {
  for (let i = 0; i < maxTries; i++) {
    const p = startPort + i * 2;
    if (await probeBindable(p)) return p;
  }
  throw new Error(`no bindable port found near ${startPort}`);
}

/** Restricted "end-user" environment: PATH shrunk to System32+Windows, TEMP into sandbox. */
export function restrictedEnv({ sandbox, port, staging, mode = 'real-storage', env } = {}) {
  const base = {
    PATH: RESTRICTED_PATH,
    Path: RESTRICTED_PATH,
    PATHEXT: '.COM;.EXE;.BAT;.CMD',
    SystemRoot: 'C:\\Windows',
    windir: 'C:\\Windows',
    SystemDrive: 'C:',
    ComSpec: CMD,
    OS: 'Windows_NT',
    PROCESSOR_ARCHITECTURE: process.env.PROCESSOR_ARCHITECTURE,
    NUMBER_OF_PROCESSORS: process.env.NUMBER_OF_PROCESSORS,
    // user profile stays REAL so any out-of-scope write would land somewhere we snapshot
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA,
    LOCALAPPDATA: process.env.LOCALAPPDATA,
    HOMEDRIVE: process.env.HOMEDRIVE,
    HOMEPATH: process.env.HOMEPATH,
    USERNAME: process.env.USERNAME,
    USERDOMAIN: process.env.USERDOMAIN,
  };
  if (sandbox) {
    base.TEMP = path.join(sandbox, 'tmp');
    base.TMP = path.join(sandbox, 'tmp');
  }
  if (staging) {
    base.SHUN_CONTROL_UI_DIR = path.join(staging, 'app-ui');
  }
  if (port) base.SHUN_CONTROL_PORT = String(port);
  if (mode) base.SHUN_CONTROL_MODE = mode;
  return Object.assign(base, env ?? {});
}

/**
 * Boot the portable server via staging launch.cmd under the restricted env.
 * Resolves the real node PID + ExecutablePath via CIM. Returns boot record.
 */
export async function bootPortable({ staging, sandbox, port, mode = 'real-storage', env }) {
  const launchCmd = path.join(staging, 'launch.cmd');
  const serverLog = path.join(sandbox, 'server.log');
  const start = Date.now();
  const marker = `U05-BOOT-${Date.now()}`;
  await appendFile(serverLog, `\n===== ${marker} boot port=${port} mode=${mode} =====\n`, 'utf8');
  const renv = restrictedEnv({ sandbox, port, staging, mode, env });
  renv.SHUN_SERVER_LOG = serverLog;
  // cwd=staging with a pure-ASCII argv: cmd's command line then contains no
  // unicode characters (cmd's legacy codepage mangles them in argv);
  // %~dp0 resolves the wide-char staging path inside the batch itself. The
  // batch redirects server output into SHUN_SERVER_LOG itself.
  const cmdArgs = ['/d', '/s', '/c', 'launch.cmd'];
  const child = spawn(CMD, cmdArgs, {
    cwd: staging,
    env: renv,
    windowsVerbatimArguments: true,
    windowsHide: true,
    stdio: 'ignore',
  });
  child.unref();
  const health = await waitHealthy(port, 45_000, { child });
  const bootMs = Date.now() - start;
  if (!health.ok) {
    await sleep(300);
    let tail = '';
    try {
      tail = (await readFile(serverLog, 'utf8')).slice(-4000);
    } catch {}
    return {
      ok: false,
      cmdPid: child.pid,
      bootMs,
      health,
      serverOutput: tail,
    };
  }
  // Resolve the real node process serving this port via CIM (match by the
  // staging-owned executable path; the port travels via env, not argv).
  const stagingNorm = String(staging).toLowerCase().replace(/[\\/]+$/, '');
  const ps = `Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -like '*server.mjs*' } | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress`;
  const probe = await capture(POWERSHELL, ['-NoProfile', '-Command', ps], { timeoutMs: 30_000 });
  let procs = [];
  try {
    const parsed = JSON.parse(probe.stdout || '[]');
    procs = Array.isArray(parsed) ? parsed : [parsed];
  } catch {}
  const mine = procs.find(
    (p) =>
      p.ExecutablePath &&
      String(p.ExecutablePath).toLowerCase().replace(/[\\/]+/g, '\\').startsWith(stagingNorm),
  );
  return {
    ok: true,
    cmdPid: child.pid,
    nodePid: mine ? mine.ProcessId : undefined,
    nodeExecutablePath: mine ? mine.ExecutablePath : undefined,
    nodeCommandLine: mine ? mine.CommandLine : undefined,
    parentProcessId: mine ? mine.ParentProcessId : undefined,
    bootMs,
    health,
    childPidNote: 'server runs detached; driver exited',
    serverLog,
    marker,
  };
}

/** Kill the whole process tree of a boot record (or a single pid). */
export async function killTree(pid, { force = true } = {}) {
  if (!pid) return { code: -1, stdout: 'no pid', stderr: '' };
  const args = force ? ['/PID', String(pid), '/F', '/T'] : ['/PID', String(pid), '/T'];
  return capture(TASKKILL, args, { timeoutMs: 20_000 });
}

export async function pidAlive(pid) {
  if (!pid) return false;
  // locale-neutral: tasklist output is localized on zh-CN hosts
  const res = await capture(
    POWERSHELL,
    ['-NoProfile', '-Command', `if (Get-Process -Id ${pid} -ErrorAction SilentlyContinue) { 'ALIVE' } else { 'DEAD' }`],
    { timeoutMs: 20_000 },
  );
  return /ALIVE/.test(res.stdout);
}

/** netstat lines for one pid (or all), recorded as evidence. */
export async function netstatFor(pid) {
  const res = await capture(NETSTAT, ['-ano', '-p', 'tcp'], { timeoutMs: 20_000 });
  const lines = (res.stdout || '').split(/\r?\n/).filter((l) => l.trim());
  const mine = lines.filter((l) => new RegExp(`\\s${pid}\\s*$`).test(l));
  return { all: lines, mine, code: res.code };
}

export async function powerShellJson(ps) {
  const res = await capture(POWERSHELL, ['-NoProfile', '-Command', ps], { timeoutMs: 30_000 });
  try {
    return { ok: true, value: JSON.parse(res.stdout), raw: res };
  } catch {
    return { ok: false, value: undefined, raw: res };
  }
}

/** Recursive file snapshot: relPath -> {size, mtimeMs}. Files only. */
export async function snapshotTree(root, { maxDepth = Infinity } = {}) {
  const out = {};
  async function walk(dir, rel, depth) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (depth < maxDepth) await walk(full, childRel, depth + 1);
      } else if (e.isFile()) {
        try {
          const s = await stat(full);
          out[childRel] = { size: s.size, mtimeMs: s.mtimeMs };
        } catch {}
      }
    }
  }
  await walk(root, '', 0);
  return out;
}

export function diffSnapshots(before, after) {
  const added = [];
  const removed = [];
  const changed = [];
  for (const k of Object.keys(before)) {
    if (!(k in after)) removed.push(k);
    else if (
      before[k].size !== after[k].size ||
      Math.abs(before[k].mtimeMs - after[k].mtimeMs) > 2
    ) {
      changed.push(k);
    }
  }
  for (const k of Object.keys(after)) if (!(k in before)) added.push(k);
  return { added, removed, changed };
}

/** Depth-1 listing of a directory (name -> mtime) for APPDATA-style monitoring. */
export async function snapshotDirLevel(root) {
  const out = {};
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    try {
      const s = await stat(path.join(root, e.name));
      out[e.name] = { mtimeMs: s.mtimeMs, size: s.size };
    } catch {}
  }
  return out;
}

export async function writeJson(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, JSON.stringify(value, null, 2), 'utf8');
}

export async function readJson(file) {
  return JSON.parse(await readFile(file, 'utf8'));
}

export async function rmrf(dir) {
  await rm(dir, { recursive: true, force: true });
}
