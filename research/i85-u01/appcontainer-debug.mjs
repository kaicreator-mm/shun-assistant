// i85-U01 step 4b appendix — record the real debug output of all three
// AppContainer launcher attempts into the evidence stream, and conclude the
// mechanism exploration honestly: profile creation/deletion works unelevated,
// but UpdateProcThreadAttribute(SECURITY_CAPABILITIES) is rejected with
// ERROR_BAD_LENGTH(24) on this build for every cbSize tried, while the
// PARENT_PROCESS control attribute succeeds — so the isolated child could
// not be launched via this P/Invoke path here.
import { randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EVIDENCE_DIR, ensureDirs, logEvent, logNote } from './lib/runner.mjs';

await ensureDirs();
const scriptDir = fileURLToPath(new URL('.', import.meta.url));
const ps = (name) => resolve(scriptDir, 'appcontainer', name);
const now = () => Date.now().toString();

function runPs(script, args) {
  return new Promise((resolveRun) => {
    execFile(
      'powershell',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script, ...args],
      { timeout: 90_000, windowsHide: true },
      (err, stdout, stderr) => resolveRun({ err: err ? String(err.message) : null, stdout: stdout ?? '', stderr: stderr ?? '' }),
    );
  });
}

const debug = { attempts: [] };

const r1 = await runPs(ps('debug-ac.ps1'), ['-ContainerName', `ShunU01DbgA${randomBytes(3).toString('hex')}${now()}`]);
debug.attempts.push({ id: 'debug-ac (PowerShell-ref marshaling)', stdout: r1.stdout.trim(), stderr: r1.stderr.trim().slice(0, 500), err: r1.err });
await logEvent('S4B-debug-round1', { cmd: 'powershell -File appcontainer/debug-ac.ps1', rc: r1.err ? 1 : 0, stdout: r1.stdout });

const r2 = await runPs(ps('debug-ac2.ps1'), ['-ContainerName', `ShunU01DbgB${randomBytes(3).toString('hex')}${now()}`]);
debug.attempts.push({ id: 'debug-ac2 (pure C# sequence + PARENT_PROCESS control)', stdout: r2.stdout.trim(), stderr: r2.stderr.trim().slice(0, 500), err: r2.err });
await logEvent('S4B-debug-round2', { cmd: 'powershell -File appcontainer/debug-ac2.ps1', rc: r2.err ? 1 : 0, stdout: r2.stdout });

const r3 = await runPs(ps('debug-ac3.ps1'), ['-ContainerName', `ShunU01DbgC${randomBytes(3).toString('hex')}${now()}`]);
debug.attempts.push({ id: 'debug-ac3 (cbSize sweep 24/28/32/40/48)', stdout: r3.stdout.trim(), stderr: r3.stderr.trim().slice(0, 500), err: r3.err });
await logEvent('S4B-debug-round3', { cmd: 'powershell -File appcontainer/debug-ac3.ps1', rc: r3.err ? 1 : 0, stdout: r3.stdout });

debug.conclusion = {
  profileLifecycleWorksUnelevated: true,
  securityCapabilitiesAttributeUpdateFails: true,
  windowsError: 'ERROR_BAD_LENGTH (24)',
  controlAttributeThatSucceeds: 'PROC_THREAD_ATTRIBUTE_PARENT_PROCESS (0x00020000)',
  meaning:
    'The failure is specific to the SECURITY_CAPABILITIES attribute on this Windows build (10.0.26300.9457) and this standard-user token, not to the attribute-list mechanics or PowerShell marshaling (pure C# reproduces it; cbSize sweep 24/28/32/40/48 all rejected). The capability-less AppContainer child therefore could NOT be launched via this P/Invoke path here. Recorded as mechanism ATTEMPTED / NOT DEMONSTRABLE — explicitly not evidence that AppContainer isolation is unavailable on Windows, only that this launcher path failed in this environment.',
};

// Merge an appendix into the orchestrator's evidence file.
const probePath = resolve(EVIDENCE_DIR, 'appcontainer-probe.json');
const probe = JSON.parse(await readFile(probePath, 'utf8'));
probe.debugAppendix = debug;
await writeFile(probePath, `${JSON.stringify(probe, null, 2)}\n`, 'utf8');
await logEvent('S4B-evidence-updated', { cmd: `update ${probePath}`, rc: 0, stdout: 'debugAppendix merged' });
await logNote('S4B-mechanism-verdict', debug.conclusion);
console.log(JSON.stringify(debug, null, 2));
