import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import sharp from 'sharp';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { scaledDims } from '../src/dims.ts';
import { runImageBatchProcess } from '../src/executor.ts';
import { sha256Hex } from '../src/inspect.ts';
import { commitOracle } from '../src/oracle.ts';
import { makeSharpImageProvider } from '../src/sharp-engine.ts';
import { type BatchRecord, type SsimMetric, verifyBatch } from '../src/verifier.ts';
import { type FixtureDir, fixtureDir, jpegBytes, pngBytes, testFacts } from './helpers.ts';

let src: FixtureDir;
let out: FixtureDir;

beforeEach(async () => {
  src = await fixtureDir('shun-verifier-src-');
  out = await fixtureDir('shun-verifier-out-');
});

afterEach(async () => {
  await src.cleanup();
  await out.cleanup();
});

const BOUND = 300;

async function runStandardBatch(): Promise<{
  input: Parameters<typeof verifyBatch>[0]['input'];
  records: BatchRecord[];
}> {
  const a = await src.write(
    'a.jpg',
    await jpegBytes({ width: 900, height: 600, seed: 201, captureDate: '2024:02:03 04:05:06' }),
  );
  const b = await src.write('b.png', await pngBytes({ width: 500, height: 700, seed: 202 }));
  const inputFiles = [
    { path: a, format: 'JPG' as const },
    { path: b, format: 'PNG' as const },
  ];
  const rawInput = {
    taskId: 'task-verify',
    inputFiles,
    operation: { kind: 'RESIZE' as const, maxLongEdgePx: BOUND },
    metadataPolicy: { preserveCaptureDate: true as const },
    outputDirectory: out.path,
    qualityPolicy: { oracle: 'NO_OBVIOUS_DEGRADATION_V1' as const, ssimThreshold: 0.95 },
    networkUsage: 'LOCAL_ONLY' as const,
  };
  const result = await runImageBatchProcess(rawInput, {
    facts: testFacts(),
    providers: [makeSharpImageProvider()],
    oracleWorkDir: join(out.path, 'oracle-kept'),
  });
  if (!result.ok) {
    throw new Error('standard batch unexpectedly failed');
  }
  return { input: rawInput, records: result.output.records };
}

async function freshOracle(input: Parameters<typeof verifyBatch>[0]['input']) {
  const hashes = new Map<string, Awaited<ReturnType<typeof sha256Hex>>>();
  for (const f of input.inputFiles) {
    hashes.set(f.path, sha256Hex(await readFile(f.path)));
  }
  return commitOracle({
    sourceHashes: hashes,
    maxLongEdgePx: input.operation.maxLongEdgePx,
    ssimThreshold: input.qualityPolicy.ssimThreshold,
    workDir: join(out.path, 'oracle-verify'),
  });
}

describe('verifyBatch', () => {
  it('stays honest when the metric cannot be produced (INCOMPLETE, never PASS)', async () => {
    const { input, records } = await runStandardBatch();
    const oracle = await freshOracle(input);
    const deadMetric: SsimMetric = () => null;
    const receipt = await verifyBatch({
      input,
      records,
      oracle,
      sourceHashesBefore: new Map(),
      sourceHashesAfter: new Map(),
      metric: deadMetric,
    });
    const oracleCheck = receipt.checks.find((c) => c.checkId === 'ssim-oracle');
    expect(oracleCheck?.status).toBe('NOT_RUN');
    expect(receipt.status).toBe('INCOMPLETE');
  });

  it('fails the SSIM oracle when an output is visibly degraded', async () => {
    const { input, records } = await runStandardBatch();
    const oracle = await freshOracle(input);
    // Degrade one output in place: blur + brutal recompression.
    const victim = records.find((r) => r.status === 'WRITTEN')?.outputPath;
    if (!victim) {
      throw new Error('no written output to degrade');
    }
    const degraded = await sharp(victim).blur(2).jpeg({ quality: 8 }).toBuffer();
    await writeFile(victim, degraded);

    const before = new Map<string, Awaited<ReturnType<typeof sha256Hex>>>();
    for (const f of input.inputFiles) {
      before.set(f.path, sha256Hex(await readFile(f.path)));
    }
    const receipt = await verifyBatch({
      input,
      records,
      oracle,
      sourceHashesBefore: before,
      sourceHashesAfter: before,
    });
    const oracleCheck = receipt.checks.find((c) => c.checkId === 'ssim-oracle');
    expect(oracleCheck?.status).toBe('FAIL');
    expect(receipt.status).toBe('FAIL');
  });

  it('fails outputs-decodable when a written file is garbage', async () => {
    const { input, records } = await runStandardBatch();
    const oracle = await freshOracle(input);
    const victim = records.find((r) => r.status === 'WRITTEN')?.outputPath;
    if (!victim) {
      throw new Error('no written output to corrupt');
    }
    await writeFile(victim, Buffer.from('definitely not an image'));

    const receipt = await verifyBatch({
      input,
      records,
      oracle,
      sourceHashesBefore: new Map(),
      sourceHashesAfter: new Map(),
      metric: () => 1,
    });
    const decodeCheck = receipt.checks.find((c) => c.checkId === 'outputs-decodable');
    expect(decodeCheck?.status).toBe('FAIL');
    expect(receipt.status).toBe('FAIL');
  });

  it('fails sources-unchanged when an input mutates after execution', async () => {
    const { input, records } = await runStandardBatch();
    const oracle = await freshOracle(input);
    const before = new Map<string, Awaited<ReturnType<typeof sha256Hex>>>();
    for (const f of input.inputFiles) {
      before.set(f.path, sha256Hex(await readFile(f.path)));
    }
    await writeFile(input.inputFiles[0]?.path ?? '', Buffer.from('mutated'));
    const after = new Map<string, Awaited<ReturnType<typeof sha256Hex>>>();
    for (const f of input.inputFiles) {
      after.set(f.path, sha256Hex(await readFile(f.path)));
    }
    const receipt = await verifyBatch({
      input,
      records,
      oracle,
      sourceHashesBefore: before,
      sourceHashesAfter: after,
      metric: () => 1,
    });
    const preserveCheck = receipt.checks.find((c) => c.checkId === 'sources-unchanged');
    expect(preserveCheck?.status).toBe('FAIL');
    expect(receipt.status).toBe('FAIL');
  });

  it('passes all checks on an honest batch executed with the default metric', async () => {
    const { input, records } = await runStandardBatch();
    const oracle = await freshOracle(input);
    const before = new Map<string, Awaited<ReturnType<typeof sha256Hex>>>();
    const after = new Map<string, Awaited<ReturnType<typeof sha256Hex>>>();
    for (const f of input.inputFiles) {
      before.set(f.path, sha256Hex(await readFile(f.path)));
      after.set(f.path, sha256Hex(await readFile(f.path)));
    }
    const receipt = await verifyBatch({
      input,
      records,
      oracle,
      sourceHashesBefore: before,
      sourceHashesAfter: after,
    });
    expect(receipt.status).toBe('PASS');
    expect(receipt.checks.every((c) => c.status === 'PASS')).toBe(true);
    const written = records.find((r) => r.status === 'WRITTEN');
    expect(written?.outputPath).toBeDefined();
    const dims = await sharp(written?.outputPath).metadata();
    expect(Math.max(dims.width ?? 0, dims.height ?? 0)).toBeLessThanOrEqual(
      scaledDims(900, 600, BOUND).width,
    );
  });
});
