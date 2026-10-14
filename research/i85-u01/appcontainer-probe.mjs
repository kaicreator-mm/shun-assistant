// i85-U01 step 4b orchestrator — AppContainer isolation mechanism
// exploration (NOT a U01 PASS). Real OS-enforced isolation attempt as a
// NON-ADMIN:
//   control group : plain child process connects the live local listener
//   isolated group: same probe inside an AppContainer with NO capabilities —
//                   loopback and TEST-NET-1 connects are expected to be
//                   blocked by WFP network isolation
// Everything (staging, ACL grants, P/Invoke launch, profile deletion) runs
// for real; the AppContainer profile is deleted in the script's finally block.
import { spawn } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { EVIDENCE_DIR, TMP_ARTIFACTS, ensureDirs, logEvent, logNote } from './lib/runner.mjs';

await ensureDirs();
const scriptDir = fileURLToPath(new URL('.', import.meta.url));
const evidence = { mechanism: 'AppContainer (CreateAppContainerProfile + PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, no capabilities)', steps: {} };

// Live loopback target listener.
const target = await new Promise((resolveServer) => {
  const s = createServer((socket) => socket.end());
  s.listen(0, '127.0.0.1', () => resolveServer({ server: s, port: s.address().port }));
});
evidence.localListenerPort = target.port;
await logNote('S4B-local-listener', { port: target.port });

// --- staging (real files, real ACLs) -----------------------------------------
const stageDir = resolve(TMP_ARTIFACTS, 'ac-stage');
mkdirSync(stageDir, { recursive: true });
const nodeExe = process.execPath;
const stageNode = resolve(stageDir, 'node.exe');
const stageChild = resolve(stageDir, 'child-probe.js');
copyFileSync(nodeExe, stageNode);
copyFileSync(resolve(scriptDir, 'appcontainer', 'child-probe.js'), stageChild);
evidence.steps.staging = { stageDir, nodeExeCopied: existsSync(stageNode), childCopied: existsSync(stageChild) };
await logEvent('S4B-staging', {
  cmd: `copy node.exe + child-probe.js -> ${stageDir}`,
  rc: evidence.steps.staging.nodeExeCopied ? 0 : 1,
  stdout: JSON.stringify(evidence.steps.staging),
});

function runProbe(label, outFile, command, args) {
  return new Promise((resolveRun) => {
    const child = spawn(command, args, { windowsHide: true });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    const timer = setTimeout(() => child.kill('kill'), 120_000);
    child.on('close', async (code) => {
      clearTimeout(timer);
      const resultFile = existsSync(outFile) ? readFileSync(outFile, 'utf8').trim() : null;
      const record = {
        label,
        rc: code,
        outputTail: out.slice(-2000),
        childResultFile: resultFile ? JSON.parse(resultFile) : null,
      };
      await logEvent(`S4B-${label}`, {
        cmd: `${command} ${args.join(' ')}`.slice(0, 300),
        rc: code ?? -1,
        stdout: out,
      });
      resolveRun(record);
    });
  });
}

// --- control group: plain process ---------------------------------------------
const controlOut = resolve(stageDir, 'control-result.json');
evidence.steps.control = await runProbe(
  'control-plain-process',
  controlOut,
  nodeExe,
  [stageChild, String(target.port), controlOut],
);

// --- isolated group: AppContainer ---------------------------------------------
const containerName = `ShunU01Probe${randomBytes(4).toString('hex')}`;
const acOut = resolve(stageDir, 'ac-result.json');
const ps1 = resolve(scriptDir, 'appcontainer', 'run-ac.ps1');
evidence.steps.appContainer = await runProbe(
  'appcontainer-isolated',
  acOut,
  'powershell',
  [
    '-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', ps1,
    '-NodeExe', stageNode,
    '-ChildScript', stageChild,
    '-OutFile', acOut,
    '-LocalPort', String(target.port),
    '-ContainerName', containerName,
  ],
);
evidence.steps.appContainer.containerName = containerName;

// --- verdict -------------------------------------------------------------------
const ac = evidence.steps.appContainer.childResultFile;
const control = evidence.steps.control.childResultFile;
evidence.analysis = {
  controlLoopback: control?.loopback?.outcome ?? 'NO-RESULT-FILE',
  controlTestnet: control?.testnet?.outcome ?? 'NO-RESULT-FILE',
  acChildRan: ac !== null,
  acLoopback: ac?.loopback?.outcome ?? 'NO-RESULT-FILE',
  acLoopbackDetail: ac?.loopback?.detail ?? null,
  acTestnet: ac?.testnet?.outcome ?? 'NO-RESULT-FILE',
  acTestnetDetail: ac?.testnet?.detail ?? null,
};
evidence.verdict = (() => {
  const { steps } = evidence;
  if (!steps.appContainer.childResultFile) {
    return `MECHANISM_ATTEMPT_FAILED: no child result file; launcher output tail: ${steps.appContainer.outputTail.slice(-500)}`;
  }
  if (steps.control.childResultFile?.loopback?.outcome === 'CONNECTED' && steps.appContainer.childResultFile.loopback.outcome !== 'CONNECTED') {
    return 'OS_ISOLATION_DEMONSTRATED_NONADMIN: identical probe connects loopback as a plain process but is blocked inside a capability-less AppContainer — candidate OS-enforced no-network primitive available to a standard user';
  }
  return 'INCONCLUSIVE: inspect S4B evidence (control/ac child results)';
})();
await logNote('S4B-verdict', { verdict: evidence.verdict, analysis: evidence.analysis });

target.server.close();

const outPath = resolve(EVIDENCE_DIR, 'appcontainer-probe.json');
writeFileSync(outPath, `${JSON.stringify(evidence, null, 2)}\n`);
await logEvent('S4B-evidence-written', { cmd: `write ${outPath}`, rc: 0, stdout: outPath });
console.log(JSON.stringify({ verdict: evidence.verdict, analysis: evidence.analysis, launcherTail: evidence.steps.appContainer.outputTail.slice(-800) }, null, 2));
