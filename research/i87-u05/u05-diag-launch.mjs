// Mirror bootPortable's exact spawn but with piped output to see cmd's failure.
import { spawn } from 'node:child_process';
import { readJson } from './u05-lib.mjs';

const sandbox = 'C:\\xDev\\kAiCreator\\_tmp\\i87-u05\\user-home';
const staging = process.argv[2] ?? 'C:\\xDev\\kAiCreator\\_tmp\\i87-u05\\staging';
const port = Number(process.argv[3] ?? 41255);
const env = await readJson(sandbox + '\\env.json');
const childEnv = {
  PATH: 'C:\\Windows\\System32;C:\\Windows',
  Path: 'C:\\Windows\\System32;C:\\Windows',
  SystemRoot: 'C:\\Windows',
  SystemDrive: 'C:',
  ComSpec: 'C:\\Windows\\System32\\cmd.exe',
  OS: 'Windows_NT',
  TEMP: sandbox + '\\tmp',
  TMP: sandbox + '\\tmp',
  SHUN_CONTROL_PORT: String(port),
  SHUN_CONTROL_MODE: 'real-storage',
  SHUN_CONTROL_UI_DIR: staging + '\\app-ui',
  SHUN_SERVER_LOG: sandbox + '\\server.log',
  ...env,
  SHUN_CONTROL_PORT: String(port),
};
console.log('spawning cmd /c launch.cmd with cwd=', staging);
const child = spawn('C:\\Windows\\System32\\cmd.exe', ['/d', '/s', '/c', 'launch.cmd'], {
  cwd: staging,
  env: childEnv,
  windowsVerbatimArguments: true,
  windowsHide: true,
  stdio: ['ignore', 'pipe', 'pipe'],
});
child.stdout.on('data', (d) => console.log('OUT:', d.toString('utf8').trim()));
child.stderr.on('data', (d) => console.log('ERR:', d.toString('utf8').trim()));
child.on('exit', (code) => {
  console.log('CMD EXIT', code);
  process.exit(0);
});
setTimeout(() => {
  console.log('TIMEOUT-KILL (server apparently still running = good)');
  child.kill();
  process.exit(0);
}, 12_000);
