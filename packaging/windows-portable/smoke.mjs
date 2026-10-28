// T09 P02 Windows Build Host smoke: verify the staged Node.exe and bundled UI
// boot without a separately installed Node, pnpm, remote model or user state.
// Not a substitute for physical Standard User Home/Pro or real-storage tests.
import { spawn } from 'node:child_process';
import { existsSync, lstatSync } from 'node:fs';
import { resolve, join, delimiter } from 'node:path';

function fail(code) {
  throw new Error(`SHUN_PORTABLE_SMOKE_REFUSED:${code}`);
}

if (process.platform !== 'win32' || process.arch !== 'x64') fail('WIN_X64_ONLY');
const args = process.argv.slice(2);
if (args.length !== 1) fail('STAGE_PATH_REQUIRED');
const root = resolve(args[0]);
const exe = join(root, 'node.exe');
const app = join(root, 'app/native/control.mjs');
const ui = join(root, 'control-ui/public');
for (const file of [exe, app]) {
  if (!existsSync(file) || !lstatSync(file).isFile()) fail('STAGE_FILE_MISSING');
}

// Don't forward operator secrets to a demo process. Don't let a global Node
// install or pnpm on PATH silently satisfy a missing packaged executable.
const env = { ...process.env };
for (const key of Object.keys(env)) {
  if (key.toUpperCase().startsWith('SHUN_') || key.toUpperCase() === 'DEEPSEEK_API_KEY') {
    delete env[key];
  }
}
env.SHUN_CONTROL_MODE = 'demo';
env.SHUN_CLOUD_ENABLED = '0';
env.SHUN_CONTROL_PORT = '0';
env.SHUN_CONTROL_UI_DIR = ui;
const osDir = env.SystemRoot ?? 'C:\\Windows';
for (const name of ['PATH', 'Path']) {
  env[name] = [join(osDir, 'System32'), osDir].join(delimiter);
}

const child = spawn(exe, [app], {
  cwd: root,
  env,
  windowsHide: true,
  stdio: ['ignore', 'pipe', 'pipe'],
});
let captured = '';
let timer;
try {
  const origin = await new Promise((accept, reject) => {
    child.once('error', () => reject(new Error('STAGE_PROCESS_START_REFUSED')));
    child.once('exit', () => reject(new Error('STAGE_PROCESS_EXITED_BEFORE_READY')));
    child.stdout.on('data', (chunk) => {
      captured = (captured + chunk.toString('utf8')).slice(-4096);
      const match = captured.match(
        /Shun control surface \(T08 DEMO ONLY\) on (http:\/\/127\.0\.0\.1:\d+)/,
      );
      if (match) accept(match[1]);
    });
    timer = setTimeout(() => reject(new Error('STAGE_BOOT_TIMEOUT')), 15_000);
  });
  clearTimeout(timer);
  // Local UI GET is sufficient as a product-code boot smoke; no HTTPS,
  // credential, external model or privileged native action is exercised.
  const response = await fetch(`${origin}/`, { signal: AbortSignal.timeout(5_000) });
  const html = await response.text();
  if (response.status !== 200 || !/Shun/i.test(html)) fail('LOCAL_UI_UNAVAILABLE');
  console.log(JSON.stringify({
    kind: 'SHUN_T09_P02_OFFLINE_DEMO_SMOKE',
    nodeExecutable: 'STAGED_NODE_EXE',
    command: 'STAGED_ECMASCRIPT_BUNDLE',
    uiStatus: response.status,
    cloudEnabled: false,
    modelCalls: 0,
    realStorageQualified: false,
    standardUserQualified: false,
    passed: true,
  }));
} catch {
  console.error('SHUN_PORTABLE_SMOKE_REFUSED');
  process.exitCode = 1;
} finally {
  if (timer) clearTimeout(timer);
  child.kill();
}
