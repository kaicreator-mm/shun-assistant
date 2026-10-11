// Negative controls for the T05 safety corrections (Issue #38):
// - VI-P1-04: a precommitted, eligible oracle sample that produces no written
//   output must degrade the receipt — never PASS. The committed oracle
//   promised a quality check that did not run.
// - VI-P2-06: a nonfinite metric value (±Infinity) is metric garbage and must
//   degrade to METRIC_UNAVAILABLE, never count as a perfect score.
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runImageBatchProcess } from '../src/executor.ts';
import { sha256Hex } from '../src/inspect.ts';
import { commitOracle } from '../src/oracle.ts';
import { makeSharpImageProvider } from '../src/sharp-engine.ts';
import { type BatchRecord, type SsimMetric, verifyBatch } from '../src/verifier.ts';
import { type FixtureDir, fixtureDir, jpegBytes, pngBytes, testFacts } from './helpers.ts';

let src: FixtureDir;
let out: FixtureDir;

beforeEach(async () => {
  src = await fixtureDir('shun-oracle-src-');
  out = await fixtureDir('shun-oracle-out-');
});

afterEach(async () => {
  await src.cleanup();
  await out.cleanup();
});

const BOUND = 300;

function c001Input(files: Array<{ path: string; format: 'JPG' | 'PNG' }>) {
  return {
    taskId: 'task-oracle-negative',
    inputFiles: files,
    operation: { kind: 'RESIZE' as const, maxLongEdgePx: BOUND },
    metadataPolicy: { preserveCaptureDate: true as const },
    outputDirectory: out.path,
    qualityPolicy: { oracle: 'NO_OBVIOUS_DEGRADATION_V1' as const, ssimThreshold: 0.95 },
    networkUsage: 'LOCAL_ONLY' as const,
  };
}

const deps = () => ({ facts: testFacts(), providers: [makeSharpImageProvider()] });

describe('committed sample without written output (VI-P1-04)', () => {
  it('never returns PASS when a precommitted sample is rejected at execution', async () => {
    const good = await src.write(
      'good.jpg',
      await jpegBytes({ width: 600, height: 400, seed: 501 }),
    );
    // PNG payload declared as JPG: decodable at precommit (the oracle is
    // format-agnostic), rejected as UNSUPPORTED_INPUT at execution — its
    // committed SSIM check can never run.
    const liar = await src.write(
      'liar.jpg',
      await pngBytes({ width: 600, height: 400, seed: 502 }),
    );
    const result = await runImageBatchProcess(
      c001Input([
        { path: good, format: 'JPG' },
        { path: liar, format: 'JPG' },
      ]),
      deps(),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const byPath = new Map(result.output.records.map((r) => [r.inputPath, r]));
    expect(byPath.get(good)?.status).toBe('WRITTEN');
    expect(byPath.get(liar)?.status).toBe('REJECTED');
    const oracleCheck = result.output.verification.checks.find((c) => c.checkId === 'ssim-oracle');
    expect(oracleCheck?.status).toBe('NOT_RUN');
    expect(result.output.verification.status).toBe('INCOMPLETE');
  });

  it('never returns PASS when the verifier replays a committed sample without a record', async () => {
    const a = await src.write('a.jpg', await jpegBytes({ width: 600, height: 400, seed: 511 }));
    const b = await src.write('b.jpg', await jpegBytes({ width: 600, height: 400, seed: 512 }));
    const input = c001Input([
      { path: a, format: 'JPG' },
      { path: b, format: 'JPG' },
    ]);
    const result = await runImageBatchProcess(input, {
      ...deps(),
      oracleWorkDir: join(out.path, 'oracle-kept'),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const hashes = new Map<string, Awaited<ReturnType<typeof sha256Hex>>>();
    for (const file of input.inputFiles) {
      hashes.set(file.path, sha256Hex(await readFile(file.path)));
    }
    const oracle = await commitOracle({
      sourceHashes: hashes,
      maxLongEdgePx: BOUND,
      ssimThreshold: 0.95,
      workDir: join(out.path, 'oracle-replay'),
    });
    // Replay as if execution had rejected the first record entirely.
    const records: BatchRecord[] = result.output.records.map((r, i) => {
      if (i === 0) {
        return { inputPath: r.inputPath, status: 'REJECTED', rejectionCode: 'UNSUPPORTED_INPUT' };
      }
      return r;
    });
    const receipt = await verifyBatch({
      input,
      records,
      oracle,
      sourceHashesBefore: hashes,
      sourceHashesAfter: hashes,
    });
    const oracleCheck = receipt.checks.find((c) => c.checkId === 'ssim-oracle');
    expect(oracleCheck?.status).toBe('NOT_RUN');
    expect(receipt.status).toBe('INCOMPLETE');
  });
});

describe('nonfinite SSIM values (VI-P2-06)', () => {
  it.each([
    ['+Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('treats %s as metric-unavailable, never as a score', async (_label, bad) => {
    const a = await src.write('a.jpg', await jpegBytes({ width: 600, height: 400, seed: 521 }));
    const input = c001Input([{ path: a, format: 'JPG' }]);
    const result = await runImageBatchProcess(input, {
      ...deps(),
      oracleWorkDir: join(out.path, 'oracle-kept'),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const hashes = new Map<string, Awaited<ReturnType<typeof sha256Hex>>>();
    hashes.set(a, sha256Hex(await readFile(a)));
    const oracle = await commitOracle({
      sourceHashes: hashes,
      maxLongEdgePx: BOUND,
      ssimThreshold: 0.95,
      workDir: join(out.path, 'oracle-infinite'),
    });
    const brokenMetric: SsimMetric = () => bad;
    const receipt = await verifyBatch({
      input,
      records: result.output.records,
      oracle,
      sourceHashesBefore: hashes,
      sourceHashesAfter: hashes,
      metric: brokenMetric,
    });
    const oracleCheck = receipt.checks.find((c) => c.checkId === 'ssim-oracle');
    expect(oracleCheck?.status).toBe('NOT_RUN');
    expect(receipt.status).toBe('INCOMPLETE');
    expect((receipt.oracleInputs as { metricAvailable?: boolean }).metricAvailable).toBe(false);
  });
});
