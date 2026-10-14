// i85-U01 step 1 — host & model fact collection (all real, reproducible).
// Records: Windows version/build, user privilege evidence, Node version/ABI,
// SHA256 of packages/resolver/src/planner-seam.ts at the pinned base tree,
// and an exhaustive LOCAL-LLM absence re-scan (processes, binaries, dirs,
// listening ports, docker images, HTTP probe). Every scan command + output
// tail lands in events.ndjson; full outputs land in the _tmp artifacts dir.
import { existsSync, statSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { resolve } from 'node:path';
import {
  EVIDENCE_DIR,
  ensureDirs,
  logEvent,
  logNote,
  runCmd,
  sha256File,
} from './lib/runner.mjs';

const results = { host: {}, plannerSeam: {}, modelAbsence: [] };

await ensureDirs();

// --- pinned tree identity -------------------------------------------------
const gitHead = await runCmd('S1-git-head', 'git', ['rev-parse', 'HEAD']);
results.baseSha = gitHead.text.trim();
const gitStatus = await runCmd('S1-git-status', 'git', ['status', '--porcelain']);
results.gitStatusAtStart = gitStatus.text.trim().split('\n').filter(Boolean);
const gitDiff = await runCmd('S1-git-diff-tracked', 'git', ['diff', '--stat']);
results.trackedDiffClean = gitDiff.text.trim() === '';

const seamRel = 'packages\\resolver\\src\\planner-seam.ts';
const seamPath = resolve(process.cwd(), seamRel);
results.plannerSeam = {
  path: seamRel,
  sha256: await sha256File(seamPath),
  bytes: existsSync(seamPath) ? statSync(seamPath).size : null,
};
await logNote('S1-planner-seam-sha256', results.plannerSeam);

// --- host facts ------------------------------------------------------------
const ver = await runCmd('S1-windows-ver', 'cmd', ['/c', 'ver'], { fullToTmp: 's1-windows-ver.txt' });
results.host.windowsVerRaw = ver.text.trim();

const cim = await runCmd(
  'S1-win32-os',
  'powershell',
  ['-NoProfile', '-Command',
    "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture | ConvertTo-Json -Compress"],
  { fullToTmp: 's1-win32-os.json' },
);
results.host.win32Os = cim.text.trim();

const whoami = await runCmd('S1-whoami', 'whoami', [], { fullToTmp: 's1-whoami.txt' });
results.host.user = whoami.text.trim();

const groups = await runCmd('S1-whoami-groups', 'whoami', ['/groups'], { fullToTmp: 's1-whoami-groups.txt' });
results.host.inAdministratorsGroup = groups.text.includes('S-1-5-32-544');
results.host.integrityLevelHigh = /\bS-1-16-12288\b/.test(groups.text);

const netSession = await runCmd('S1-net-session', 'net', ['session'], { fullToTmp: 's1-net-session.txt' });
results.host.netSessionRc = netSession.rc;
results.host.netSessionDenied = netSession.rc !== 0;
results.host.privilegeVerdict =
  results.host.inAdministratorsGroup && !results.host.netSessionDenied
    ? 'ELEVATED_ADMIN-capable token in this process'
    : results.host.inAdministratorsGroup
      ? 'FILTERED_ADMIN (Administrators group present, UAC-filtered token: net session denied)'
      : 'STANDARD_USER';

const nodeVer = await runCmd('S1-node-version', 'node', ['-v']);
results.host.nodeVersion = nodeVer.text.trim();
const nodeAbi = await runCmd('S1-node-abi', 'node', ['-p', 'process.versions.modules']);
results.host.nodeAbi = nodeAbi.text.trim();
const nodePath = await runCmd('S1-node-path', 'where', ['node']);
results.host.nodePath = nodePath.text.trim().split('\n')[0] ?? '';

await logNote('S1-host-facts', results.host);

// --- LOCAL LLM absence re-scan --------------------------------------------
const MODEL_PROC_NAMES = [
  'ollama', 'ollama app', 'llama-server', 'llama-cli', 'llama.cpp', 'lmstudio', 'lm-studio',
  'koboldcpp', 'text-generation-webui', 'jan.exe', 'llamasetup', 'gpt4all', 'llamafactory',
];
const MODEL_DIRS = [
  resolve(homedir(), '.ollama'),
  resolve(homedir(), 'AppData', 'Local', 'Ollama'),
  resolve(homedir(), 'AppData', 'Local', 'Programs', 'Ollama'),
  resolve(homedir(), 'AppData', 'Local', 'LM-Studio'),
  resolve(homedir(), 'AppData', 'Roaming', 'LM Studio'),
  resolve(homedir(), '.lmstudio'),
  resolve(homedir(), '.cache', 'lm-studio'),
  resolve(homedir(), 'AppData', 'Roaming', 'gpt4all'),
  resolve(homedir(), 'AppData', 'Local', 'gpt4all'),
  resolve(homedir(), '.jan'),
  'C:\\Program Files\\Ollama',
  'C:\\Program Files (x86)\\Ollama',
  'C:\\Program Files\\LM Studio',
  'C:\\Program Files\\llama.cpp',
  resolve(tmpdir(), 'ollama'),
];
const MODEL_EXE_NAMES = ['ollama.exe', 'llama-server.exe', 'llama-cli.exe', 'lmstudio.exe', 'koboldcpp.exe', 'gpt4all.exe'];
const MODEL_PORTS = ['11434', '8080', '1234', '7860', '5000', '1337', '4891'];

// 1. processes
const tasklist = await runCmd('S1-scan-tasklist', 'tasklist', ['/FO', 'CSV'], { fullToTmp: 's1-tasklist-full.csv' });
const taskLines = tasklist.text.split('\n');
const procHits = taskLines.filter((l) => MODEL_PROC_NAMES.some((n) => l.toLowerCase().includes(n)));
results.modelAbsence.push({
  scan: 'tasklist process-name filter',
  command: 'tasklist /FO CSV (full capture in _tmp/s1-tasklist-full.csv), filtered in harness',
  processesScanned: taskLines.filter((l) => l.includes('","')).length,
  hits: procHits,
  verdict: procHits.length === 0 ? 'ABSENT' : 'PRESENT',
});

// 2. PATH lookup for model binaries
for (const exe of MODEL_EXE_NAMES) {
  const where = await runCmd(`S1-scan-where-${exe}`, 'where', [exe]);
  results.modelAbsence.push({
    scan: `where ${exe}`,
    command: `where ${exe}`,
    hits: where.rc === 0 ? where.text.trim().split('\n') : [],
    rawTail: where.text.trim().slice(0, 200),
    verdict: where.rc === 0 ? 'PRESENT' : 'ABSENT',
  });
}

// 3. install/model directories
for (const dir of MODEL_DIRS) {
  const exists = existsSync(dir);
  results.modelAbsence.push({
    scan: `directory ${dir}`,
    command: `existsSync ${dir}`,
    hits: exists ? [dir] : [],
    verdict: exists ? 'PRESENT' : 'ABSENT',
  });
}

// 4. listening ports
const netstat = await runCmd('S1-scan-netstat', 'netstat', ['-ano', '-p', 'tcp'], { fullToTmp: 's1-netstat-full.txt' });
const listenLines = netstat.text.split('\n').filter((l) => l.toUpperCase().includes('LISTENING'));
const portHits = listenLines.filter((l) => MODEL_PORTS.some((p) => l.trim().split(/\s+/)[1]?.endsWith(`:${p}`)));
results.modelAbsence.push({
  scan: 'netstat listening model-service ports',
  command: 'netstat -ano -p tcp (full capture in _tmp/s1-netstat-full.txt), LISTENING lines filtered in harness',
  listeningLinesTotal: listenLines.length,
  hits: portHits.map((l) => l.trim()),
  verdict: portHits.length === 0 ? 'ABSENT' : 'PRESENT',
});

// 5. docker images
const dockerImages = await runCmd('S1-scan-docker-images', 'docker', ['images', '--format', '{{.Repository}}:{{.Tag}}'], { fullToTmp: 's1-docker-images.txt' });
const imageHits = dockerImages.rc === 0
  ? dockerImages.text.split('\n').filter((l) => /ollama|llama|lm.?studio|vllm|textgen|kobold|gpt4all/i.test(l))
  : [`docker-images-rc=${dockerImages.rc}`, dockerImages.text.trim().slice(0, 200)];
results.modelAbsence.push({
  scan: 'docker images model filter',
  command: 'docker images --format {{.Repository}}:{{.Tag}}',
  hits: imageHits.filter((h) => !h.startsWith('docker-images-rc=')),
  note: imageHits.filter((h) => h.startsWith('docker-images-rc=')).join(' ') || 'docker reachable',
  verdict: imageHits.length === 0 ? 'ABSENT' : imageHits.some((h) => !h.startsWith('docker-images-rc=')) ? 'PRESENT' : 'ABSENT (docker query succeeded, zero matches)',
});

// 6. HTTP probe of the canonical Ollama endpoint (expect connection refused)
const probe = await runCmd(
  'S1-scan-http-11434',
  'node',
  ['-e',
    `fetch('http://127.0.0.1:11434/api/tags',{signal:AbortSignal.timeout(2000)}).then(r=>{console.log('HTTP_STATUS',r.status);process.exit(0)}).catch(e=>{console.log('FETCH_ERR',e.cause?.code??e.name);process.exit(0)})`],
);
results.modelAbsence.push({
  scan: 'HTTP GET http://127.0.0.1:11434/api/tags',
  command: 'node -e fetch with AbortSignal.timeout(2000)',
  output: probe.text.trim(),
  verdict: probe.text.includes('FETCH_ERR') ? 'ABSENT (connection refused)' : probe.text.includes('HTTP_STATUS') ? 'PRESENT' : 'INCONCLUSIVE',
});

await logNote('S1-model-absence-summary', {
  scans: results.modelAbsence.length,
  allAbsent: results.modelAbsence.every((s) => s.verdict.startsWith('ABSENT')),
});

// --- persist evidence JSON ---------------------------------------------------
const factPath = resolve(EVIDENCE_DIR, 'fact-collection.json');
await writeFile(factPath, `${JSON.stringify(results, null, 2)}\n`, 'utf8');
await logEvent('S1-evidence-written', {
  cmd: `write ${factPath}`,
  rc: 0,
  stdout: await sha256File(factPath),
});
console.log(JSON.stringify({ baseSha: results.baseSha, seam: results.plannerSeam, host: results.host, allAbsent: results.modelAbsence.every((s) => s.verdict.startsWith('ABSENT')) }, null, 2));
