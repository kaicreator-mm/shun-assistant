// collect-results.mjs — merge the three legs' partial results into the final
// research/i86-u04/results.json. Reads only tool-produced files; every number
// comes from real run output.
import { readFile, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import os from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const RESEARCH = resolve(HERE, '..');

function sha256File(path) {
  return new Promise((resolve, reject) => {
    const hasher = createHash('sha256');
    createReadStream(path)
      .on('data', (chunk) => hasher.update(chunk))
      .on('end', () => resolve(hasher.digest('hex')))
      .on('error', reject);
  });
}

const pipeline = JSON.parse(await readFile(join(RESEARCH, 'partial', 'pipeline-results.json'), 'utf8'));
const negatives = JSON.parse(await readFile(join(RESEARCH, 'partial', 'negatives-results.json'), 'utf8'));
const sharp = JSON.parse(await readFile(join(RESEARCH, 'partial', 'sharp-results.json'), 'utf8'));
const trustRoot = JSON.parse(await readFile(join(RESEARCH, 'trust-root.json'), 'utf8'));
const eventsText = await readFile(join(RESEARCH, 'events.ndjson'), 'utf8');
const eventsLines = eventsText.trim().split('\n').length;

const nodeExeSha = await sha256File(process.execPath);
const nodeExeStat = await stat(process.execPath);

const rgLegs = pipeline.legs.filter((l) => l.status === 'PASS').length;
const negLegs = negatives.cases.filter((l) => l.status === 'PASS').length;
const sharpLegs = sharp.legs.filter((l) => l.status === 'PASS').length;

const results = {
  issue: 'kaicreator-mm/shun-assistant #86 — v0.2 L2 U04 minimal trusted Provider JIT payload pilot',
  generatedAt: new Date().toISOString(),
  baseline: 'd812ca2f5d5e48dd637c5580cb4c30ecf4116663 (task/i86-u04-zc)',
  host: {
    os: `${os.type()} ${os.release()} ${os.arch()}`,
    hostname: os.hostname(),
    nodeVersion: process.version,
    nodeAbi: Number(process.versions.modules),
    napiVersion: Number(process.versions.napi),
    nodeExePath: process.execPath,
    nodeExeSha256: nodeExeSha,
    nodeExeBytes: nodeExeStat.size,
  },
  trustRoot: {
    algorithm: trustRoot.algorithm,
    publicKeyFingerprint: trustRoot.publicKeyFingerprint,
    activeCatalogRevision: trustRoot.activeCatalogRevision,
  },
  providers: {
    'cli.ripgrep': {
      verdict: pipeline.failures.length === 0 ? 'PASS' : 'FAIL',
      version: '14.1.1 (ripgrep-14.1.1-x86_64-pc-windows-msvc.zip from github releases)',
      artifactSha256: pipeline.downloadSha256,
      artifactBytes: pipeline.downloadBytes,
      downloadRedirectHops: pipeline.downloadHops,
      rgExeSha256: pipeline.rgExeSha256,
      rgExeBytes: pipeline.rgExeBytes,
      rgVersion: pipeline.rgVersion,
      oracleExpectedMatches: pipeline.oracleExpectedMatches,
      legs: pipeline.legs,
      negatives: negatives.cases,
    },
    'addon.sharp-win32-x64': {
      verdict: sharp.sharpVerdict,
      version: '0.35.5 (@img/sharp-win32-x64, N-API 10 prebuilt)',
      acquiredNodeSha256: sharp.acquiredNodeSha256,
      acquiredNodeBytes: sharp.acquiredNodeSizeBytes,
      node24: sharp.node24,
      node22: sharp.node22,
      legs: sharp.legs,
    },
  },
  counts: {
    pipelineLegsPass: rgLegs,
    pipelineLegsTotal: pipeline.legs.length,
    negativeCasesPass: negLegs,
    negativeCasesTotal: negatives.cases.length,
    sharpLegsPass: sharpLegs,
    sharpLegsTotal: sharp.legs.length,
    eventsNdjsonLines: eventsLines,
  },
  v01Reuse: {
    imported: [
      'SafePowerShellZipExtractor (native handle-relative extractor, per-entry SHA)',
      'PowerShellNativeDeleter (identity-pinned snapshot/removeTreePinned)',
      'SpawnProcess / FileJournal / NodeFilesystem (adapters/node.ts)',
      'classifyFromJournal (journal.ts recovery classification)',
      'effectTimeScopeRefusal (manifest-removal.ts effect-time exclusivity)',
      'AcquisitionError typed failures (ports.ts)',
      'stableDirectoryName naming + exclusive-root creation semantics (managed-portable.ts)',
    ],
    semanticsAdoptedWithoutImport: [
      'consent/authorization phase journaling (RECEIVED→VALIDATED→EXEC_START→EXEC_DONE→RECEIPT_WRITTEN)',
      'fail-closed refusal notes + no-effect journal markers',
      'content-addressed cache is U04-new (v0.1 used winget transport + its own downloadRoot)',
    ],
  },
};

await writeFile(join(RESEARCH, 'results.json'), JSON.stringify(results, null, 2), 'utf8');
console.log('RESULTS WRITTEN', JSON.stringify(results.counts));
console.log('verdicts:', results.providers['cli.ripgrep'].verdict, results.providers['addon.sharp-win32-x64'].verdict);
