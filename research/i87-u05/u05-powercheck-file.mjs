// Locale-proof process identity check: PowerShell writes a UTF-8 JSON sidecar
// file (no console codepage involvement), node reads and verifies it.
import { readFileSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { capture, ev, POWERSHELL } from './u05-lib.mjs';

const pid = Number(process.argv[2]);
const staging = process.argv[4] ?? process.argv[3];
const outFile = path.join(process.argv[3] ?? '.', `proc-${pid}.json`);
const target = process.argv[4];

const ps = `
[IO.File]::WriteAllText('${outFile.replace(/\\/g, '\\\\')}',
  (ConvertTo-Json -Compress (@{
    path = (Get-CimInstance Win32_Process -Filter "ProcessId=${pid}").ExecutablePath
    cmd  = (Get-CimInstance Win32_Process -Filter "ProcessId=${pid}").CommandLine
    parent = (Get-CimInstance Win32_Process -Filter "ProcessId=${pid}").ParentProcessId
  })), [System.Text.Encoding]::UTF8)
`;
const res = await capture(POWERSHELL, ['-NoProfile', '-Command', ps], { timeoutMs: 30_000 });
if (res.code !== 0) throw new Error('powershell failed: ' + res.stderr);
const v = JSON.parse(readFileSync(outFile, 'utf8').replace(/^\uFEFF/, ''));
let matches = null;
if (target) {
  const expected = path.join(target, 'runtime', 'node.exe').toLowerCase();
  matches = typeof v.path === 'string' && v.path.toLowerCase() === expected;
}
await ev('process.identity.utf8file', matches === null ? 'INFO' : matches ? 'OK' : 'MISMATCH', {
  pid,
  path: v.path,
  matches,
});
console.log(JSON.stringify({ pid, path: v.path, cmd: v.cmd, parent: v.parent, matches }, null, 2));
