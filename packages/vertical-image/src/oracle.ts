// Precommitted quality oracle for C-001 (Product contracts, "quality oracle
// is precommitted before execution"): the sampled inputs, the lossless
// reference resizes and the SSIM bar are all fixed BEFORE the provider runs.
// The executor cannot see, tune or extend the oracle after outputs exist;
// the verifier only replays the committed oracle against the written files.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Sha256Hex } from '@shun/contracts';
import sharp from 'sharp';
import { scaledDims } from './dims.ts';
import { inspectBytes, sha256Hex } from './inspect.ts';

export const ORACLE_REVISION = 'oracle-c001-v0.1';

/** Wang et al. (2004) SSIM: 11x11 Gaussian window, sigma 1.5, K1 0.01, K2 0.03. */
export const SSIM_OPTIONS = {
  windowSize: 11,
  k1: 0.01,
  k2: 0.03,
  ssim: 'original',
  downsample: false,
  rgb2grayVersion: 'original',
  bitDepth: 8,
} as const;

export const MAX_ORACLE_SAMPLES = 20;

export interface OracleSample {
  inputPath: string;
  sourceSha256: Sha256Hex;
  /** false = source undecodable at precommit; execution rejects it anyway. */
  eligible: boolean;
  /** Lossless reference resize at the exact expected output dimensions. */
  referencePath?: string;
  referenceSha256?: Sha256Hex;
  referenceWidth?: number;
  referenceHeight?: number;
  detail?: string;
}

export interface CommittedOracle {
  oracleRevision: string;
  metric: 'SSIM';
  ssimOptions: typeof SSIM_OPTIONS;
  ssimThreshold: number;
  maxSamples: number;
  samples: OracleSample[];
}

/**
 * Deterministic sample pick: ascending source SHA-256 (path as tiebreak),
 * capped at MAX_ORACLE_SAMPLES. Inputs with fewer files than the cap use all.
 */
export function selectSampleEntries(
  sourceHashes: ReadonlyMap<string, Sha256Hex>,
  max: number = MAX_ORACLE_SAMPLES,
): Array<{ inputPath: string; sourceSha256: Sha256Hex }> {
  return [...sourceHashes.entries()]
    .map(([inputPath, sourceSha256]) => ({ inputPath, sourceSha256 }))
    .sort((a, b) => {
      if (a.sourceSha256 !== b.sourceSha256) {
        return a.sourceSha256 < b.sourceSha256 ? -1 : 1;
      }
      if (a.inputPath !== b.inputPath) {
        return a.inputPath < b.inputPath ? -1 : 1;
      }
      return 0;
    })
    .slice(0, max);
}

export interface CommitOracleArgs {
  sourceHashes: ReadonlyMap<string, Sha256Hex>;
  maxLongEdgePx: number;
  ssimThreshold: number;
  /** Directory (private to the oracle) that receives the lossless references. */
  workDir: string;
}

/**
 * Freezes the oracle: picks the samples by ascending source SHA-256 and
 * generates the lossless PNG reference resize for every decodable sample
 * source, at the exact output dimensions execution is required to produce
 * (shared scaledDims math). Read-only on inputs.
 */
export async function commitOracle(args: CommitOracleArgs): Promise<CommittedOracle> {
  await mkdir(args.workDir, { recursive: true });
  const entries = selectSampleEntries(args.sourceHashes);
  const samples: OracleSample[] = [];
  for (const [index, entry] of entries.entries()) {
    const sample: OracleSample = {
      inputPath: entry.inputPath,
      sourceSha256: entry.sourceSha256,
      eligible: false,
    };
    try {
      const bytes = await readFile(entry.inputPath);
      const facts = await inspectBytes(bytes);
      const dims = scaledDims(facts.width, facts.height, args.maxLongEdgePx);
      const referencePath = oracleReferencePath(args.workDir, index);
      const reference = await sharp(bytes, { failOn: 'error' })
        .rotate()
        .resize(dims.width, dims.height, { fit: 'fill', kernel: 'lanczos3' })
        .png({ compressionLevel: 9 })
        .toBuffer();
      await writeFile(referencePath, reference, { flag: 'wx' });
      sample.eligible = true;
      sample.referencePath = referencePath;
      sample.referenceSha256 = sha256Hex(reference);
      sample.referenceWidth = dims.width;
      sample.referenceHeight = dims.height;
    } catch (cause) {
      sample.detail = `source undecodable at precommit: ${cause instanceof Error ? cause.message : String(cause)}`;
    }
    samples.push(sample);
  }
  return {
    oracleRevision: ORACLE_REVISION,
    metric: 'SSIM',
    ssimOptions: SSIM_OPTIONS,
    ssimThreshold: args.ssimThreshold,
    maxSamples: MAX_ORACLE_SAMPLES,
    samples,
  };
}

/** Oracle working directory layout helper. */
export function oracleReferencePath(workDir: string, index: number): string {
  return join(workDir, `reference-${index}.png`);
}
