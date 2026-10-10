// B-037 reference-benchmark harness for the C-001 vertical (docs/validation/
// benchmark-v0.1.md, B-037): 200 mixed JPG/PNG images, no provider
// preselected, shrink to long edge 1600px preserving capture dates, verified
// by the precommitted SSIM oracle (20 deterministic samples, threshold 0.95),
// plus the missing-Provider, corrupt-input and unsupported-declared fallbacks.
//
// The corpus is generated deterministically (fixed seed, photographic-style
// soft scenes) so any reviewer can reproduce it; only the evidence JSON and
// report are committed. Corpus files live outside the repository.
import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readdir, readFile, rm, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import process from 'node:process';
import type { EnvironmentFacts } from '@shun/contracts';
import sharp from 'sharp';
import { runImageBatchProcess } from '../src/executor.ts';
import { sha256Hex } from '../src/inspect.ts';
import {
  makeSharpImageProvider,
  SHARP_JPEG_QUALITY,
  sharpBindingView,
} from '../src/sharp-engine.ts';

const SEED = 20261010;
const CORPUS_COUNT = 200;
const JPG_COUNT = 120;
const MAX_LONG_EDGE = 1600;
const SSIM_THRESHOLD = 0.95;
const JPG_LONG_EDGE_RANGE: [number, number] = [1800, 3600];
const PNG_LONG_EDGE_RANGE: [number, number] = [1800, 2400];

function args(): { corpusDir: string; evidenceFile: string } {
  const map = new Map<string, string>();
  const argv = process.argv.slice(2);
  for (let i = 0; i + 1 < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (key !== undefined && value !== undefined) {
      map.set(key, value);
    }
  }
  return {
    corpusDir: resolve(map.get('--corpus-dir') ?? join(tmpdir(), 'shun-b037-corpus')),
    evidenceFile: resolve(map.get('--evidence-file') ?? 'evidence/b037/b037-results.json'),
  };
}

function pick<T>(items: readonly T[], index: number): T {
  const value = items[index];
  if (value === undefined) {
    throw new Error(`index ${index} out of range`);
  }
  return value;
}

function makeRand(seed: number): () => number {
  let s = seed >>> 0;
  if (s === 0) {
    s = 0x9e3779b9;
  }
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 4294967296;
  };
}

interface CorpusSpec {
  index: number;
  name: string;
  format: 'JPG' | 'PNG';
  width: number;
  height: number;
  captureDate: string | null;
  grain: number;
  blobCount: number;
  hueShift: number;
}

function buildSpecs(): CorpusSpec[] {
  const rand = makeRand(SEED);
  const aspects: Array<[number, number]> = [
    [3, 2],
    [2, 3],
    [4, 3],
    [3, 4],
    [16, 9],
    [1, 1],
  ];
  const specs: CorpusSpec[] = [];
  for (let i = 0; i < CORPUS_COUNT; i++) {
    const format = i < JPG_COUNT ? 'JPG' : 'PNG';
    const [longEdgeMin, longEdgeMax] = format === 'JPG' ? JPG_LONG_EDGE_RANGE : PNG_LONG_EDGE_RANGE;
    const longEdge = longEdgeMin + Math.floor(rand() * (longEdgeMax - longEdgeMin + 1));
    const aspect = pick(aspects, Math.floor(rand() * aspects.length));
    const width =
      aspect[0] >= aspect[1] ? longEdge : Math.round((longEdge * aspect[0]) / aspect[1]);
    const height =
      aspect[1] > aspect[0] ? longEdge : Math.round((longEdge * aspect[1]) / aspect[0]);
    const hasDate = rand() < (format === 'JPG' ? 0.6 : 0.5);
    const year = 2018 + Math.floor(rand() * 9);
    const month = 1 + Math.floor(rand() * 12);
    const day = 1 + Math.floor(rand() * 28);
    const captureDate = hasDate
      ? `${year}:${String(month).padStart(2, '0')}:${String(day).padStart(2, '0')} ${String(
          Math.floor(rand() * 24),
        ).padStart(2, '0')}:${String(Math.floor(rand() * 60)).padStart(2, '0')}:${String(
          Math.floor(rand() * 60),
        ).padStart(2, '0')}`
      : null;
    specs.push({
      index: i,
      name: `img-${String(i + 1).padStart(4, '0')}.${format === 'JPG' ? 'jpg' : 'png'}`,
      format,
      width,
      height,
      captureDate,
      grain: 3 + Math.floor(rand() * 2), // 3..4: photographic grain level
      blobCount: 3 + Math.floor(rand() * 7),
      hueShift: Math.floor(rand() * 360),
    });
  }
  return specs;
}

function sceneBuffer(spec: CorpusSpec): Buffer {
  const rand = makeRand(SEED + spec.index * 7919);
  const { width, height, grain, blobCount } = spec;
  const buf = Buffer.alloc(width * height * 3);
  const hue = spec.hueShift;
  const blobs = Array.from({ length: blobCount }, () => ({
    cx: rand() * width,
    cy: rand() * height,
    rad: (0.15 + rand() * 0.3) * width,
    color: [30 + rand() * 200, 30 + rand() * 200, 30 + rand() * 200] as const,
  }));
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const i = (y * width + x) * 3;
      let r = 60 + (x / width) * 120;
      let g = 70 + (y / height) * 100;
      let b = 90 + 30 * Math.sin((x + y + hue) / 53);
      for (const blob of blobs) {
        const dx = x - blob.cx;
        const dy = y - blob.cy;
        const d2 = (dx * dx + dy * dy) / (blob.rad * blob.rad);
        if (d2 < 1) {
          const t = 0.35 * (1 - d2) * (1 - d2);
          r += t * (blob.color[0] - r);
          g += t * (blob.color[1] - g);
          b += t * (blob.color[2] - b);
        }
      }
      const n = (rand() - 0.5) * grain * 2;
      buf[i] = Math.max(0, Math.min(255, r + n));
      buf[i + 1] = Math.max(0, Math.min(255, g + n));
      buf[i + 2] = Math.max(0, Math.min(255, b + n));
    }
  }
  return buf;
}

async function generateCorpus(
  corpusDir: string,
  specs: CorpusSpec[],
): Promise<Map<string, string>> {
  await rm(corpusDir, { recursive: true, force: true });
  await mkdir(corpusDir, { recursive: true });
  const hashes = new Map<string, string>();
  for (const spec of specs) {
    const pipeline = sharp(sceneBuffer(spec), {
      raw: { width: spec.width, height: spec.height, channels: 3 },
    });
    const dated = spec.captureDate
      ? pipeline.withMetadata({ exif: { IFD0: { DateTimeOriginal: spec.captureDate } } })
      : pipeline;
    const bytes =
      spec.format === 'JPG'
        ? await dated.jpeg({ quality: 96 }).toBuffer()
        : await dated.png({ compressionLevel: 6 }).toBuffer();
    const path = join(corpusDir, spec.name);
    await writeFile(path, bytes, { flag: 'wx' });
    hashes.set(path, sha256Hex(bytes));
  }
  return hashes;
}

function localWindowsFacts(): EnvironmentFacts {
  return {
    environmentId: `local-windows-${process.platform}-${process.arch}`,
    backendKind: 'LOCAL_WINDOWS',
    os: `${process.platform} ${process.arch}`,
    arch: process.arch.toUpperCase(),
    observationRevision: 'b037-run-0001',
    runtimeCapabilities: ['sharp-i0'],
    privilegeMode: 'STANDARD_USER',
    guiSession: true,
    filesystemCapabilities: ['read', 'write'],
    networkPolicy: 'OFFLINE',
    resources: { cpuCores: 8, memoryMb: 16384, freeDiskMb: 50000 },
  };
}

function c001Input(
  taskId: string,
  corpusDir: string,
  specs: Array<Pick<CorpusSpec, 'name' | 'format'>>,
  outputDir: string,
) {
  return {
    taskId,
    inputFiles: specs.map((s) => ({
      path: join(corpusDir, s.name),
      format: s.format,
    })),
    operation: { kind: 'RESIZE' as const, maxLongEdgePx: MAX_LONG_EDGE },
    metadataPolicy: { preserveCaptureDate: true },
    outputDirectory: outputDir,
    qualityPolicy: { oracle: 'NO_OBVIOUS_DEGRADATION_V1' as const, ssimThreshold: SSIM_THRESHOLD },
    networkUsage: 'LOCAL_ONLY' as const,
  };
}

async function main(): Promise<number> {
  const { corpusDir, evidenceFile } = args();
  const startedAt = new Date().toISOString();
  console.log(`[b037] corpus dir: ${corpusDir}`);

  const specs = buildSpecs();
  const tGen0 = Date.now();
  const manifest = await generateCorpus(corpusDir, specs);
  const genMs = Date.now() - tGen0;
  const manifestLines = [...manifest.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([p, h]) => `${basename(p)} ${h}`);
  const corpusFingerprint = createHash('sha256').update(manifestLines.join('\n')).digest('hex');
  const datedCount = specs.filter((s) => s.captureDate !== null).length;
  console.log(
    `[b037] corpus: ${specs.length} files (${specs.filter((s) => s.format === 'JPG').length} JPG / ${specs.filter((s) => s.format === 'PNG').length} PNG), ${datedCount} with capture date, fingerprint ${corpusFingerprint.slice(0, 16)}…, ${genMs} ms`,
  );

  let codeCommit: string = 'unknown';
  try {
    codeCommit = execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
  } catch {
    /* detached context without git — recorded as unknown */
  }

  // ---- Main journey: no provider preselected; the vertical ranks and selects.
  const scratch = resolve(corpusDir, '..');
  for (const stale of [
    'b037-output',
    'b037-neg-missing',
    'b037-neg-corpus',
    'b037-neg-corrupt-output',
    'b037-neg-lie',
    'b037-neg-lie-output',
  ]) {
    await rm(join(scratch, stale), { recursive: true, force: true });
  }
  const outDir = join(scratch, 'b037-output');
  const tRun0 = Date.now();
  const mainResult = await runImageBatchProcess(c001Input('b037-main', corpusDir, specs, outDir), {
    facts: localWindowsFacts(),
    providers: [makeSharpImageProvider()],
  });
  const runMs = Date.now() - tRun0;
  if (!mainResult.ok) {
    throw new Error(`main journey failed: ${JSON.stringify(mainResult.failure)}`);
  }
  const output = mainResult.output;
  const written = output.records.filter((r) => r.status === 'WRITTEN');
  const rejected = output.records.filter((r) => r.status === 'REJECTED');
  console.log(
    `[b037] main run: binding=${output.selectedBindingId} written=${written.length} rejected=${rejected.length} verification=${output.verification.status} (${runMs} ms)`,
  );
  for (const check of output.verification.checks) {
    console.log(
      `[b037]   check ${check.checkId}: ${check.status}${check.detail ? ` — ${check.detail}` : ''}`,
    );
  }

  const oracleInputs = output.verification.oracleInputs as {
    ssimResults?: Array<{ inputPath: string; status: string; ssim?: number }>;
  };
  const ssimValues = (oracleInputs.ssimResults ?? [])
    .filter((r) => typeof r.ssim === 'number')
    .map((r) => ({ inputPath: basename(r.inputPath), ssim: r.ssim as number }));

  // ---- Independent source preservation re-check (outside the executor).
  const changedSources: string[] = [];
  for (const [path, hash] of manifest) {
    if (!existsSync(path) || sha256Hex(await readFile(path)) !== hash) {
      changedSources.push(basename(path));
    }
  }
  console.log(
    `[b037] source preservation: ${changedSources.length === 0 ? 'all 200 byte-identical' : `CHANGED: ${changedSources.join(', ')}`}`,
  );

  // ---- Negative: missing Provider (nothing registered) must fail closed.
  const negOutMissing = join(scratch, 'b037-neg-missing');
  const missingResult = await runImageBatchProcess(
    c001Input('b037-neg-missing', corpusDir, specs.slice(0, 4), negOutMissing),
    { facts: localWindowsFacts(), providers: [] },
  );
  const missingDirEmpty = !existsSync(negOutMissing) || (await readdir(negOutMissing)).length === 0;
  console.log(
    `[b037] negative missing-provider: ok=${missingResult.ok}${missingResult.ok ? '' : ` code=${missingResult.failure.code}`} dirEmpty=${missingDirEmpty}`,
  );

  // ---- Negative: corrupt input rejects per-record; the rest still verifies.
  const negCorruptSpecs = specs.slice(0, 5);
  const negCorruptDir = join(scratch, 'b037-neg-corpus');
  await rm(negCorruptDir, { recursive: true, force: true });
  await mkdir(negCorruptDir, { recursive: true });
  for (const spec of negCorruptSpecs) {
    await writeFile(join(negCorruptDir, spec.name), await readFile(join(corpusDir, spec.name)));
  }
  const corruptTarget = join(negCorruptDir, pick(negCorruptSpecs, 1).name);
  const corruptSize = (await readFile(corruptTarget)).length;
  await truncate(corruptTarget, Math.floor(corruptSize / 3));
  const negCorruptOut = join(scratch, 'b037-neg-corrupt-output');
  const corruptResult = await runImageBatchProcess(
    c001Input('b037-neg-corrupt', negCorruptDir, negCorruptSpecs, negCorruptOut),
    { facts: localWindowsFacts(), providers: [makeSharpImageProvider()] },
  );
  const corruptRejected = corruptResult.ok
    ? corruptResult.output.records
        .filter((r) => r.status === 'REJECTED')
        .map((r) => r.rejectionCode)
    : [];
  console.log(
    `[b037] negative corrupt-input: ok=${corruptResult.ok} rejected=${corruptRejected.join(',')} verification=${corruptResult.ok ? corruptResult.output.verification.status : '-'}`,
  );

  // ---- Negative: PNG bytes declared as JPG are UNSUPPORTED_INPUT.
  const lieSpec = { name: 'liar.jpg', format: 'JPG' as const };
  const negLieDir = join(scratch, 'b037-neg-lie');
  await rm(negLieDir, { recursive: true, force: true });
  await mkdir(negLieDir, { recursive: true });
  const firstPng = specs.find((s) => s.format === 'PNG');
  if (!firstPng) {
    throw new Error('corpus contains no PNG file');
  }
  const realPng = await readFile(join(corpusDir, firstPng.name));
  await writeFile(join(negLieDir, 'liar.jpg'), realPng, { flag: 'wx' });
  const negLieOut = join(scratch, 'b037-neg-lie-output');
  const lieResult = await runImageBatchProcess(
    c001Input('b037-neg-lie', negLieDir, [lieSpec], negLieOut),
    { facts: localWindowsFacts(), providers: [makeSharpImageProvider()] },
  );
  const lieCode = lieResult.ok ? lieResult.output.records[0]?.rejectionCode : 'run-failed';
  console.log(`[b037] negative unsupported-declared: rejectionCode=${lieCode}`);

  // ---- Verdict + evidence.
  const verdict = {
    mainRunPass:
      output.verification.status === 'PASS' &&
      written.length === CORPUS_COUNT &&
      rejected.length === 0,
    sourcesPreserved: changedSources.length === 0,
    missingProviderFailClosed: !missingResult.ok && missingDirEmpty,
    corruptInputPerRecordReject:
      corruptResult.ok === true && corruptRejected.includes('DECODE_FAILED'),
    unsupportedDeclaredReject: lieCode === 'UNSUPPORTED_INPUT',
  };
  const allPass = Object.values(verdict).every(Boolean);
  console.log(
    `[b037] verdict: ${JSON.stringify(verdict)} => ${allPass ? 'B-037 PASS' : 'B-037 FAIL'}`,
  );

  const binding = sharpBindingView();
  const evidence = {
    benchmark: 'B-037',
    task: 'T05',
    capability: 'image.batch_process (C-001)',
    executedAt: startedAt,
    finishedAt: new Date().toISOString(),
    codeCommit,
    toolchain: {
      node: process.version,
      platform: `${process.platform} ${process.arch}`,
      sharpBinding: binding,
      jpegQuality: SHARP_JPEG_QUALITY,
      metric: 'ssim.js original SSIM, 11x11 Gaussian window, K1 0.01, K2 0.03, no downsampling',
    },
    corpus: {
      seed: SEED,
      count: CORPUS_COUNT,
      jpg: JPG_COUNT,
      png: CORPUS_COUNT - JPG_COUNT,
      withCaptureDate: datedCount,
      longEdgeRange: { JPG: JPG_LONG_EDGE_RANGE, PNG: PNG_LONG_EDGE_RANGE },
      fingerprint: corpusFingerprint,
      generatorRevision: 'gen-corpus-v1 (seeded soft scenes, deterministic)',
    },
    mainRun: {
      taskId: 'b037-main',
      maxLongEdgePx: MAX_LONG_EDGE,
      ssimThreshold: SSIM_THRESHOLD,
      written: written.length,
      rejected: rejected.length,
      selectedBindingId: output.selectedBindingId,
      rankingEvidence: output.rankingEvidence,
      verification: output.verification,
      durationMs: runMs,
      corpusGenerationMs: genMs,
    },
    ssimSamples: ssimValues,
    sourcePreservation: { verified: true, changed: changedSources },
    negatives: {
      missingProvider: {
        outcome: missingResult.ok ? 'unexpected-ok' : missingResult.failure.code,
        detail: missingResult.ok ? '' : missingResult.failure.detail,
        outputDirEmpty: missingDirEmpty,
      },
      corruptInput: {
        rejectionCodes: corruptRejected,
        verification: corruptResult.ok ? corruptResult.output.verification.status : 'RUN_FAILED',
      },
      unsupportedDeclared: { rejectionCode: lieCode },
    },
    verdict,
    allPass,
    note: 'B-037 journey stages goal-parse and shared resolution are upstream concerns (T01/T08); this vertical covers discovery-input, feasible-binding selection, execution, precommitted SSIM oracle verification and the required fallbacks. Multi-provider ranking is exercised with binding doubles in the unit suite; exactly one real I0 provider (sharp) is registered on this machine.',
  };
  await mkdir(join(evidenceFile, '..'), { recursive: true });
  await writeFile(evidenceFile, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
  // The evidence file is a committed artifact inside the linted tree: normalize
  // it with the repo's own biome formatter so `biome check` stays green.
  try {
    execSync(`pnpm exec biome format --write "${evidenceFile}"`, { stdio: 'pipe' });
  } catch {
    console.log('[b037] note: biome formatter unavailable, evidence left as written');
  }
  console.log(`[b037] evidence written: ${evidenceFile}`);

  // Keep the workspace clean: the corpus is deterministically reproducible.
  await rm(corpusDir, { recursive: true, force: true });
  return allPass ? 0 : 1;
}

process.exitCode = await main();
