// Semantic verifier for C-001 image.batch_process (Product contracts
// "Semantic verification" 1..5, plus source preservation). Re-derives post
// state from the files on disk and replays the precommitted oracle; it never
// trusts the executor's in-memory view. Execution success without this
// verification can never become Task PASS (L2 §4.7).
import { readFile } from 'node:fs/promises';
import type {
  ImageBatchProcessInput,
  ImageBatchProcessOutput,
  Sha256Hex,
  VerificationReceipt,
  VerificationStatus,
} from '@shun/contracts';
import { ssim as ssimLib } from 'ssim.js';
import { decodeRgbaBytes, inspectBytes, type RgbaPixels } from './inspect.ts';
import { type CommittedOracle, SSIM_OPTIONS } from './oracle.ts';

export const VERIFIER_ID = 'verifier.image-c001';
export const VERIFIER_REVISION = 'v0.1';

/** Keep in sync with the ssim.js entry in package.json. */
export const SSIM_JS_VERSION = '3.5.0';

export const METRIC_IDENTITY = `ssim.js@${SSIM_JS_VERSION} original/11x11/gauss`;

export type BatchRecord = ImageBatchProcessOutput['records'][number];

/**
 * Injected metric seam. Returns null when the metric cannot be produced —
 * which must degrade the receipt to a non-PASS status, never skip the bar.
 */
export type SsimMetric = (a: RgbaPixels, b: RgbaPixels) => number | null;

export function makeSsimJsMetric(): SsimMetric {
  return (a, b) => {
    try {
      return ssimLib(a, b, SSIM_OPTIONS).mssim;
    } catch {
      return null;
    }
  };
}

interface CheckResult {
  checkId: string;
  status: 'PASS' | 'FAIL' | 'NOT_RUN' | 'SKIPPED';
  detail?: string;
}

export interface VerifyBatchArgs {
  input: ImageBatchProcessInput;
  records: readonly BatchRecord[];
  oracle: CommittedOracle;
  sourceHashesBefore: ReadonlyMap<string, Sha256Hex>;
  sourceHashesAfter: ReadonlyMap<string, Sha256Hex>;
  metric?: SsimMetric;
}

interface DecodedOutput {
  inputPath: string;
  outputPath: string;
  width: number;
  height: number;
  captureDate: string | null;
}

async function decodeWrittenOutputs(records: readonly BatchRecord[]): Promise<{
  decoded: DecodedOutput[];
  failures: string[];
}> {
  const decoded: DecodedOutput[] = [];
  const failures: string[] = [];
  for (const record of records) {
    if (record.status !== 'WRITTEN' || !record.outputPath) {
      continue;
    }
    try {
      const bytes = await readFile(record.outputPath);
      const facts = await inspectBytes(bytes);
      decoded.push({
        inputPath: record.inputPath,
        outputPath: record.outputPath,
        width: facts.width,
        height: facts.height,
        captureDate: facts.captureDate,
      });
    } catch (cause) {
      failures.push(
        `${record.outputPath}: not decodable (${cause instanceof Error ? cause.message : String(cause)})`,
      );
    }
  }
  return { decoded, failures };
}

function sortedPaths(paths: readonly string[]): string[] {
  return [...paths].sort();
}

export async function verifyBatch(args: VerifyBatchArgs): Promise<VerificationReceipt> {
  const metric = args.metric ?? makeSsimJsMetric();
  const checks: CheckResult[] = [];
  const bound = args.input.operation.maxLongEdgePx;

  // 1. count conservation: exactly one record per declared input.
  const inputPaths = args.input.inputFiles.map((f) => f.path);
  const recordPaths = args.records.map((r) => r.inputPath);
  const countOk =
    args.records.length === inputPaths.length &&
    JSON.stringify(sortedPaths(inputPaths)) === JSON.stringify(sortedPaths(recordPaths));
  checks.push({
    checkId: 'count-conservation',
    status: countOk ? 'PASS' : 'FAIL',
    detail: `${args.records.length} records vs ${inputPaths.length} inputs`,
  });

  // 2. every written output decodes.
  const { decoded, failures: decodeFailures } = await decodeWrittenOutputs(args.records);
  checks.push({
    checkId: 'outputs-decodable',
    status: decodeFailures.length === 0 ? 'PASS' : 'FAIL',
    detail:
      decodeFailures.length > 0 ? decodeFailures.join('; ') : `${decoded.length} output(s) decoded`,
  });

  // 3. longest edge within the requested bound.
  const edgeFailures = decoded
    .filter((d) => Math.max(d.width, d.height) > bound)
    .map((d) => `${d.outputPath}: ${Math.max(d.width, d.height)}px > ${bound}px`);
  checks.push({
    checkId: 'long-edge-bound',
    status: edgeFailures.length === 0 ? 'PASS' : 'FAIL',
    detail:
      edgeFailures.length > 0
        ? edgeFailures.join('; ')
        : `bound ${bound}px held for ${decoded.length} output(s)`,
  });

  // 4. capture date preserved when the input carried one.
  const dateFailures: string[] = [];
  for (const output of decoded) {
    let inputDate: string | null = null;
    try {
      inputDate = (await inspectBytes(await readFile(output.inputPath))).captureDate;
    } catch (cause) {
      dateFailures.push(
        `${output.inputPath}: input unreadable during verification (${cause instanceof Error ? cause.message : String(cause)})`,
      );
      continue;
    }
    if (inputDate !== null && output.captureDate !== inputDate) {
      dateFailures.push(
        `${output.inputPath}: capture date "${inputDate}" not preserved in ${output.outputPath} (got ${output.captureDate ?? 'none'})`,
      );
    }
  }
  checks.push({
    checkId: 'capture-date-preserved',
    status: dateFailures.length === 0 ? 'PASS' : 'FAIL',
    detail:
      dateFailures.length > 0 ? dateFailures.join('; ') : 'capture dates preserved where present',
  });

  // 5. precommitted SSIM oracle over the committed samples.
  const ssimResults: Array<{
    inputPath: string;
    status: 'PASS' | 'FAIL' | 'SKIPPED' | 'METRIC_UNAVAILABLE';
    ssim?: number;
    detail?: string;
  }> = [];
  let evaluated = 0;
  let metricUnavailable = 0;
  let ssimFailed = 0;
  let minSsim = Number.POSITIVE_INFINITY;
  for (const sample of args.oracle.samples) {
    const record = args.records.find((r) => r.inputPath === sample.inputPath);
    if (
      !sample.eligible ||
      !sample.referencePath ||
      record?.status !== 'WRITTEN' ||
      !record.outputPath
    ) {
      ssimResults.push({
        inputPath: sample.inputPath,
        status: 'SKIPPED',
        detail: sample.eligible ? 'no output for this sample' : sample.detail,
      });
      continue;
    }
    evaluated += 1;
    try {
      const [outPx, refPx] = await Promise.all([
        decodeRgbaBytes(await readFile(record.outputPath)),
        decodeRgbaBytes(await readFile(sample.referencePath)),
      ]);
      if (outPx.width !== refPx.width || outPx.height !== refPx.height) {
        ssimFailed += 1;
        ssimResults.push({
          inputPath: sample.inputPath,
          status: 'FAIL',
          detail: `dimension mismatch: output ${outPx.width}x${outPx.height} vs reference ${refPx.width}x${refPx.height}`,
        });
        continue;
      }
      const value = metric(outPx, refPx);
      if (value === null || Number.isNaN(value)) {
        metricUnavailable += 1;
        ssimResults.push({ inputPath: sample.inputPath, status: 'METRIC_UNAVAILABLE' });
        continue;
      }
      minSsim = Math.min(minSsim, value);
      const pass = value >= args.oracle.ssimThreshold;
      if (!pass) {
        ssimFailed += 1;
      }
      ssimResults.push({
        inputPath: sample.inputPath,
        status: pass ? 'PASS' : 'FAIL',
        ssim: value,
      });
    } catch (cause) {
      ssimFailed += 1;
      ssimResults.push({
        inputPath: sample.inputPath,
        status: 'FAIL',
        detail: `oracle comparison failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      });
    }
  }
  let oracleStatus: CheckResult['status'];
  let oracleDetail: string;
  if (evaluated === 0) {
    oracleStatus = 'NOT_RUN';
    oracleDetail = 'no eligible sample produced an output';
  } else if (metricUnavailable > 0) {
    oracleStatus = 'NOT_RUN';
    oracleDetail = `metric unavailable for ${metricUnavailable}/${evaluated} evaluated samples — no PASS-equivalent status`;
  } else {
    oracleStatus = ssimFailed > 0 ? 'FAIL' : 'PASS';
    oracleDetail =
      ssimFailed > 0
        ? `${ssimFailed}/${evaluated} sample(s) below ${args.oracle.ssimThreshold}`
        : `min SSIM ${minSsim.toFixed(5)} >= ${args.oracle.ssimThreshold} over ${evaluated} sample(s)`;
  }
  checks.push({ checkId: 'ssim-oracle', status: oracleStatus, detail: oracleDetail });

  // 6. original preservation: every input byte-identical after the run.
  const changed: string[] = [];
  const allPaths = new Set([...args.sourceHashesBefore.keys(), ...args.sourceHashesAfter.keys()]);
  for (const path of allPaths) {
    const before = args.sourceHashesBefore.get(path);
    const after = args.sourceHashesAfter.get(path);
    if (before !== after) {
      changed.push(`${path}: ${before ?? 'missing'} -> ${after ?? 'missing'}`);
    }
  }
  checks.push({
    checkId: 'sources-unchanged',
    status: changed.length === 0 ? 'PASS' : 'FAIL',
    detail:
      changed.length > 0
        ? changed.join('; ')
        : `${args.sourceHashesBefore.size} source(s) byte-identical`,
  });

  const hasFail = checks.some((c) => c.status === 'FAIL');
  const hasNotRun = checks.some((c) => c.status === 'NOT_RUN');
  const status: VerificationStatus = hasFail ? 'FAIL' : hasNotRun ? 'INCOMPLETE' : 'PASS';

  return {
    taskId: args.input.taskId,
    verifierId: VERIFIER_ID,
    verifierRevision: VERIFIER_REVISION,
    status,
    checks,
    oracleInputs: {
      oracle: args.oracle,
      ssimResults,
      metricIdentity: METRIC_IDENTITY,
      metricAvailable: metricUnavailable === 0,
    },
    evidenceRefs: [
      `oracle://${args.input.taskId}/committed-oracle`,
      `oracle://${args.input.taskId}/ssim-results`,
    ],
  };
}
