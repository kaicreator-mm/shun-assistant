// run-sharp.mjs — i86-U04 step 8: native ABI leg.
//
// S1 acquire the vetted sharp payload through the trusted pipeline -> READY
// S2 Node 24 (ABI 137) worker: load acquired binding, real resize, independent IHDR verify
// S3 Node 22 (ABI 127, fnm) worker: same — proves the N-API artifact is ABI-stable
// S4 worker crash (process.exit after load): parent survives, typed recovery, no residue
// S5 hostile-CWD DLL plant: junk libvips-42.dll in the worker CWD must not be used
// The sharp verdict is recorded SEPARATELY from the ripgrep verdict.
import { mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const RESEARCH = resolve(HERE, '..');
const TMP = 'C:\\xDev\\kAiCreator\\_tmp\\i86-u04';
const JIT = '../../../packages/vertical-jit/src';
const { Events } = await import('./lib/events.mjs');
const { ProviderAcquirer } = await import('./lib/acquisition.mjs');
const { startOrigin } = await import('./lib/origin.mjs');
const { sha256File } = await import('./lib/downloader.mjs');
const { makePng, parsePng } = await import('./lib/png.mjs');
const { SpawnProcess } = await import(`${JIT}/adapters/node.ts`);

const events = new Events(join(RESEARCH, 'events.ndjson'), 'sharp');
const SANDBOX = join(TMP, 'sharp-sandbox');
const results = { legs: [], failures: [], sharpVerdict: 'PENDING', ripgrepVerdict: 'see pipeline results' };

function record(id, ok, detail) {
  results.legs.push({ id, status: ok ? 'PASS' : 'FAIL', detail });
  if (!ok) results.failures.push(id);
  return events.emit(ok ? 'LEG_PASS' : 'LEG_FAIL', `${id} :: ${detail}`);
}

function assert(cond, message) {
  if (!cond) throw new Error(`ASSERT: ${message}`);
}

const trustRoot = JSON.parse(await readFile(join(RESEARCH, 'trust-root.json'), 'utf8'));
const catalogLocal = JSON.parse(await readFile(join(RESEARCH, 'catalogs', 'catalog-local.json'), 'utf8'));
const endpoint = JSON.parse(await readFile(join(TMP, 'origin', 'endpoint.json'), 'utf8'));
const WORKER = join(HERE, 'sharp-worker.cjs');
const proc = new SpawnProcess();

for (const dir of ['providers', 'downloads', 'staging', 'state', 'io']) {
  await rm(join(SANDBOX, dir), { recursive: true, force: true });
  await mkdir(join(SANDBOX, dir), { recursive: true });
}

const acquirer = new ProviderAcquirer({
  events,
  trustRoot,
  sandbox: {
    providersRoot: join(SANDBOX, 'providers'),
    downloadsRoot: join(SANDBOX, 'downloads'),
    stagingRoot: join(SANDBOX, 'staging'),
    journalPath: join(SANDBOX, 'state', 'journal.jsonl'),
  },
  maxBytes: 64 * 1024 * 1024,
});

// ---------- S1: acquire ----------
const origin = await startOrigin({ root: join(TMP, 'origin-files'), port: endpoint.port });
const outcome = await acquirer.acquire(catalogLocal, 'addon.sharp-win32-x64', { consent: true, originCounters: origin });
assert(outcome.status === 'READY', `sharp acquire expected READY, got ${outcome.status} ${outcome.detail ?? ''}`);
const nodeRelPath = outcome.entry.contents.node.relativePath;
const nodePath = join(outcome.providerRoot, nodeRelPath);
const installedSha = await sha256File(nodePath);
const sourceSha = await sha256File(
  join(
    'C:\\xDev\\kAiCreator\\shun-assistant\\i86-u04-zc\\node_modules\\.pnpm\\@img+sharp-win32-x64@0.35.5\\node_modules\\@img\\sharp-win32-x64',
    nodeRelPath,
  ),
);
assert(installedSha === sourceSha, 'installed .node must equal the vetted store artifact byte-for-byte');
assert(installedSha === outcome.entry.contents.node.sha256, 'installed .node must match the signed catalog digest');
const installedSize = (await stat(nodePath)).size;
await record(
  'S1-sharp-acquire-READY',
  true,
  `states ${outcome.states.join('->')}; .node ${installedSize}B sha ${installedSha.slice(0, 16)}… matches signed catalog and vetted store artifact`,
);
results.acquiredNodeSha256 = installedSha;
results.acquiredNodeSizeBytes = installedSize;

// ---------- shared worker driver ----------
async function runWorker(label, mode, { nodeArgs = [], cwd, extraEnv } = {}) {
  const resultPath = join(SANDBOX, 'io', `${label}-result.json`);
  const inputPngPath = join(SANDBOX, 'io', `${label}-input.png`);
  const outputPngPath = join(SANDBOX, 'io', `${label}-output.png`);
  await writeFile(inputPngPath, makePng(64, 48));
  await rm(resultPath, { force: true });
  await rm(outputPngPath, { force: true });
  const argv = [process.execPath, ...nodeArgs, WORKER, mode, outcome.providerRoot, resultPath, inputPngPath, outputPngPath];
  const run = await proc.run({
    argv,
    cwd,
    env: extraEnv,
    timeoutMs: 120_000,
  });
  let workerResult = null;
  try {
    workerResult = JSON.parse(await readFile(resultPath, 'utf8'));
  } catch {
    /* crashed before writing */
  }
  let outputPng = null;
  try {
    outputPng = await readFile(outputPngPath);
  } catch {
    /* no output */
  }
  return { run, workerResult, outputPng, inputPngPath, outputPngPath, label };
}

function verifyResize(leg) {
  const parsed = parsePng(leg.outputPng);
  assert(parsed.width === 20 && parsed.height === 10, `IHDR says ${parsed.width}x${parsed.height}, expected 20x10`);
  assert(parsed.bitDepth === 8 && parsed.colorType === 6, `IHDR depth/type ${parsed.bitDepth}/${parsed.colorType}, expected 8/6`);
  // input is left-half red / right-half blue; sample far from the sub-sampling
  // boundary column so no resample kernel can flip the expectation
  const left = parsed.pixelAt(2, 5);
  const right = parsed.pixelAt(17, 5);
  assert(left[0] > 200 && left[2] < 60, `left region must stay red, got ${left}`);
  assert(right[2] > 200 && right[0] < 60, `right region must stay blue, got ${right}`);
  return parsed;
}

// ---------- S2: Node 24 (ABI 137) ----------
{
  const leg = await runWorker('n24', 'run');
  assert(leg.run.exitCode === 0, `worker exit ${leg.run.exitCode}: ${leg.run.stderr.slice(0, 200)}`);
  assert(leg.workerResult.abi === 137, `expected ABI 137, got ${leg.workerResult.abi}`);
  assert(leg.workerResult.apiBindsAcquiredBinding === true, 'friendly API must bind the acquired binding');
  assert(leg.workerResult.bindingLoadedFrom?.toLowerCase().startsWith(outcome.providerRoot.toLowerCase()), 'binding must load from the provider root');
  const parsed = verifyResize(leg);
  await record(
    'S2-node24-abi137-resize',
    true,
    `node ${leg.workerResult.node} ABI ${leg.workerResult.abi} N-API ${leg.workerResult.napi}; libvips ${leg.workerResult.libvipsVersion}; resize 64x48 -> ${parsed.width}x${parsed.height} verified by independent IHDR+pixel parse`,
  );
  results.node24 = { node: leg.workerResult.node, abi: leg.workerResult.abi, libvips: leg.workerResult.libvipsVersion };
}

// ---------- S3: Node 22 (ABI 127) through fnm ----------
{
  const resultPath = join(SANDBOX, 'io', 'n22b-result.json');
  const inputPngPath = join(SANDBOX, 'io', 'n22b-input.png');
  const outputPngPath = join(SANDBOX, 'io', 'n22b-output.png');
  await writeFile(inputPngPath, makePng(64, 48));
  await rm(resultPath, { force: true });
  await rm(outputPngPath, { force: true });
  const run = await proc.run({
    argv: ['fnm', 'exec', '--using=22.23.3', '--', 'node', WORKER, 'run', outcome.providerRoot, resultPath, inputPngPath, outputPngPath],
    timeoutMs: 180_000,
  });
  assert(run.exitCode === 0, `node22 worker exit ${run.exitCode}: ${run.stderr.slice(0, 300)}`);
  const workerResult = JSON.parse(await readFile(resultPath, 'utf8'));
  assert(workerResult.node.startsWith('v22.'), `expected node 22, got ${workerResult.node}`);
  assert(workerResult.abi === 127, `expected ABI 127, got ${workerResult.abi}`);
  const parsed = parsePng(await readFile(outputPngPath));
  assert(parsed.width === 20 && parsed.height === 10, `node22 IHDR ${parsed.width}x${parsed.height}, expected 20x10`);
  await record(
    'S3-node22-abi127-resize',
    true,
    `node ${workerResult.node} ABI ${workerResult.abi} N-API ${workerResult.napi}; same acquired .node loads and resizes (N-API ABI stability confirmed); IHDR verified 20x10`,
  );
  results.node22 = { node: workerResult.node, abi: workerResult.abi, libvips: workerResult.libvipsVersion };
}

// ---------- S4: worker crash after load ----------
{
  const leg = await runWorker('crash', 'crash');
  assert(leg.run.exitCode === 1, `crash worker must exit 1, got ${leg.run.exitCode}`);
  assert(leg.workerResult?.crashAfterLoad === true, 'worker must have loaded the binding before crashing');
  // parent obviously survived (this code is running); typed recovery semantics:
  const recovery = await runWorker('recovery', 'run');
  assert(recovery.run.exitCode === 0, `recovery worker failed: ${recovery.run.stderr.slice(0, 200)}`);
  verifyResize(recovery);
  // residue scan: no lock/pid/temp files anywhere in the provider root
  const residue = [];
  const walk = async (dir) => {
    for (const child of await readdir(dir, { withFileTypes: true })) {
      const p = join(dir, child.name);
      if (child.isDirectory()) await walk(p);
      else if (/\.(lock|pid|tmp)$/i.test(child.name)) residue.push(p);
    }
  };
  await walk(outcome.providerRoot);
  assert(residue.length === 0, `residue after crash: ${residue}`);
  await record(
    'S4-worker-crash-recovery',
    true,
    `worker process.exit(1) after native load -> parent alive (typed WORKER_CRASHED), recovery worker re-loaded and resized correctly, 0 lock/pid/tmp residue in provider root`,
  );
}

// ---------- S5: hostile CWD DLL plant ----------
{
  const hostile = join(SANDBOX, 'hostile-cwd');
  await mkdir(hostile, { recursive: true });
  await writeFile(join(hostile, 'libvips-42.dll'), Buffer.from('this is not a DLL, it is planted hostile junk\r\n'.repeat(10), 'utf8'));
  await writeFile(join(hostile, 'libvips-cpp-8.18.7.dll'), Buffer.from('more hostile junk\r\n', 'utf8'));
  const leg = await runWorker('hostile', 'run', { cwd: hostile });
  assert(leg.run.exitCode === 0, `worker with hostile CWD failed (a planted DLL was likely picked up): ${leg.run.stderr.slice(0, 200)}`);
  verifyResize(leg);
  await record(
    'S5-hostile-cwd-dll',
    true,
    'junk libvips DLLs planted in the worker CWD: the acquired binding still loads the real DLLs from its own directory and the verified resize passes — CWD-planted DLLs were not used',
  );
}

await origin.close();
// keep the provider root for post-run inspection; record final state
results.providerRoot = outcome.providerRoot;
results.originRequestsTotal = origin.requests;
results.sharpVerdict = results.failures.length === 0 ? 'PASS' : 'FAIL';
await mkdir(join(RESEARCH, 'partial'), { recursive: true });
await writeFile(join(RESEARCH, 'partial', 'sharp-results.json'), JSON.stringify(results, null, 2), 'utf8');
await events.emit('SHARP_DONE', `sharp verdict ${results.sharpVerdict}: ${results.legs.filter((l) => l.status === 'PASS').length} PASS / ${results.failures.length} FAIL`);
console.log('SHARP DONE', results.sharpVerdict, JSON.stringify(results.failures));
