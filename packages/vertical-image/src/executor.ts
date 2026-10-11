// C-001 image.batch_process vertical orchestration: contract parse -> safety
// prechecks -> binding selection -> precommitted oracle -> execution ->
// source re-hash -> semantic verification -> schema-valid output.
//
// Task-level resolution outcomes (no trusted provider, no feasible binding,
// blocked output location) are typed failures returned before any write.
// Per-input problems become explicit REJECTED records; original inputs are
// never modified and failed outputs are removed again.
import { readdirSync } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import {
  type EnvironmentFacts,
  type ImageBatchFailure,
  ImageBatchProcessInputSchema,
  type ImageBatchProcessOutput,
  type Sha256Hex,
  ShunContractError,
} from '@shun/contracts';
import { scaledDims } from './dims.ts';
import { inspectBytes, sha256Hex } from './inspect.ts';
import { type CommittedOracle, commitOracle } from './oracle.ts';
import { type ImageFormat, type ImageProvider, ImageProviderError } from './provider.ts';
import {
  type BindingCandidate,
  type BindingSelection,
  feasiblePool,
  selectBinding,
} from './selector.ts';
import type { BatchRecord, SsimMetric } from './verifier.ts';
import { verifyBatch } from './verifier.ts';

export interface BatchTaskFailure {
  code: Extract<
    ResolutionFailure,
    'NO_TRUSTED_PROVIDER' | 'NO_FEASIBLE_BINDING' | 'POLICY_BLOCKED'
  >;
  detail: string;
  rankingEvidence?: ImageBatchProcessOutput['rankingEvidence'];
}

type ResolutionFailure = import('@shun/contracts').ResolutionFailure;

export type BatchRunResult =
  | { ok: true; output: ImageBatchProcessOutput; diagnostics: Record<string, string> }
  | { ok: false; failure: BatchTaskFailure };

export interface RunDeps {
  facts: EnvironmentFacts;
  providers: readonly ImageProvider[];
  /** Overrides registration/availability; defaults to every provider registered. */
  candidates?: readonly BindingCandidate[];
  preferredBindingId?: string;
  /** Oracle scratch dir; defaults to a private temp dir removed after verify. */
  oracleWorkDir?: string;
  metric?: SsimMetric;
}

interface ExecutionRejection {
  code: ImageBatchFailure;
  detail: string;
}

function reject(inputPath: string, code: ImageBatchFailure): BatchRecord {
  return { inputPath, status: 'REJECTED', rejectionCode: code };
}

/**
 * Canonical (symlink/junction-resolved) form of `path`. For a path that does
 * not exist yet, canonicalizes the nearest existing ancestor and appends the
 * remaining segments — so an alias planted on a parent directory is still
 * unmasked before anything is created through it.
 */
async function canonicalPath(path: string): Promise<string> {
  try {
    return await realpath(path);
  } catch {
    const parent = dirname(path);
    if (parent === path) {
      return path;
    }
    return join(await canonicalPath(parent), basename(path));
  }
}

function rejectPolicyBlocked(detail: string): BatchRunResult {
  return { ok: false, failure: { code: 'POLICY_BLOCKED', detail } };
}

export async function runImageBatchProcess(
  rawInput: unknown,
  deps: RunDeps,
): Promise<BatchRunResult> {
  const parsed = ImageBatchProcessInputSchema.safeParse(rawInput);
  if (!parsed.success) {
    throw new ShunContractError(
      'SCHEMA_VIOLATION',
      'invalid C-001 image.batch_process input',
      parsed.error.issues,
    );
  }
  const input = parsed.data;
  const diagnostics: Record<string, string> = {};

  // Safety precheck: the output location must differ from every input dir.
  // Comparison is on canonical (link-resolved) paths — a symlink/junction
  // alias of an input directory must not slip through lexical resolve().
  const outputDir = resolve(input.outputDirectory);
  const outputDirReal = await canonicalPath(outputDir);
  const inputDirs = [...new Set(input.inputFiles.map((f) => resolve(dirname(f.path))))];
  for (const inputDir of inputDirs) {
    if ((await canonicalPath(inputDir)) === outputDirReal) {
      return rejectPolicyBlocked(
        `outputDirectory ${outputDir} aliases input directory ${inputDir} (canonical paths must differ)`,
      );
    }
  }

  // Collision detection happens BEFORE any write: duplicates inside the batch
  // (case-insensitive) and pre-existing targets both reject up front. Existing
  // targets are detected by listing the output directory and comparing entry
  // names case-insensitively — relying on the filesystem's case behavior (e.g.
  // existsSync) would detect A.JPG vs a.jpg on Windows but silently miss it on
  // case-sensitive POSIX filesystems.
  const existingTargets = new Map<string, string>();
  try {
    for (const name of readdirSync(outputDir)) {
      existingTargets.set(name.toLowerCase(), join(outputDir, name));
    }
  } catch {
    // Output directory does not exist yet: nothing can collide with it.
  }

  const preRejected = new Map<string, string>();
  const seenBasenames = new Set<string>();
  for (const file of input.inputFiles) {
    const key = basename(file.path).toLowerCase();
    if (seenBasenames.has(key)) {
      preRejected.set(file.path, 'duplicate output name within the batch');
      continue;
    }
    seenBasenames.add(key);
    const existing = existingTargets.get(key);
    if (existing) {
      preRejected.set(file.path, `target already exists: ${existing}`);
    }
  }

  const records: BatchRecord[] = [];
  for (const [path, detail] of preRejected) {
    diagnostics[path] = detail;
    records.push(reject(path, 'OUTPUT_COLLISION'));
  }

  const active = input.inputFiles.filter((f) => !preRejected.has(f.path));

  // Binding selection over the registered candidates.
  const candidates =
    deps.candidates ?? deps.providers.map((p) => ({ binding: p.binding, registered: true }));
  const requiredFormats = [...new Set<ImageFormat>(active.map((f) => f.format))];
  const selection: BindingSelection = selectBinding(
    candidates,
    deps.facts,
    requiredFormats,
    deps.preferredBindingId,
  );
  if (selection.selected === null) {
    const code =
      selection.outcome === 'SELECTED' ? ('NO_FEASIBLE_BINDING' as const) : selection.outcome;
    return {
      ok: false,
      failure: {
        code,
        detail: selection.rankingEvidence.reasons.join('; '),
        rankingEvidence: selection.rankingEvidence,
      },
    };
  }

  try {
    await mkdir(outputDir, { recursive: true });
  } catch (cause) {
    return {
      ok: false,
      failure: {
        code: 'POLICY_BLOCKED',
        detail: `output directory ${outputDir} could not be created: ${cause instanceof Error ? cause.message : String(cause)}`,
      },
    };
  }

  // The output path may have been a not-yet-existing symlink/junction before
  // mkdir: recursive mkdir succeeds on it and writes would flow through the
  // alias. Re-canonicalize AFTER creation and re-check before any write.
  const outputDirAfterMkdir = await canonicalPath(outputDir);
  for (const inputDir of inputDirs) {
    if ((await canonicalPath(inputDir)) === outputDirAfterMkdir) {
      return rejectPolicyBlocked(
        `outputDirectory ${outputDir} resolves to input directory ${inputDir} after creation (canonical paths must differ)`,
      );
    }
  }

  // Read + hash every input once (before execution) for the oracle and for
  // the post-run preservation check. Unreadable inputs reject individually.
  const sourceBytes = new Map<string, Buffer>();
  const sourceHashesBefore = new Map<string, Sha256Hex>();
  const executionRejections = new Map<string, ExecutionRejection>();
  for (const file of input.inputFiles) {
    try {
      const bytes = await readFile(file.path);
      sourceBytes.set(file.path, bytes);
      sourceHashesBefore.set(file.path, sha256Hex(bytes));
    } catch (cause) {
      const detail = `input unreadable: ${cause instanceof Error ? cause.message : String(cause)}`;
      executionRejections.set(file.path, { code: 'DECODE_FAILED', detail });
      diagnostics[file.path] = detail;
    }
  }

  // Precommit the oracle BEFORE any provider runs.
  const ownsWorkDir = deps.oracleWorkDir === undefined;
  const workDir = deps.oracleWorkDir ?? (await mkdtemp(join(tmpdir(), 'shun-image-oracle-')));
  const oracle: CommittedOracle = await commitOracle({
    sourceHashes: sourceHashesBefore,
    maxLongEdgePx: input.operation.maxLongEdgePx,
    ssimThreshold: input.qualityPolicy.ssimThreshold,
    workDir,
  });

  for (const file of input.inputFiles) {
    if (preRejected.has(file.path)) {
      continue;
    }
    const execRejection = executionRejections.get(file.path);
    if (execRejection) {
      records.push(reject(file.path, execRejection.code));
      continue;
    }
    const bytes = sourceBytes.get(file.path);
    if (!bytes) {
      records.push(reject(file.path, 'DECODE_FAILED'));
      continue;
    }
    const picked = pickProvider(deps.providers, selection, candidates, deps.facts, file.format);
    if (!picked) {
      records.push(reject(file.path, 'UNSUPPORTED_INPUT'));
      diagnostics[file.path] = 'no registered provider supports this format';
      continue;
    }
    const targetPath = join(outputDir, basename(file.path));
    await executeOne(
      file.path,
      bytes,
      file.format,
      picked.provider,
      targetPath,
      input.operation.maxLongEdgePx,
      records,
      diagnostics,
    );
    // A record routed away from the selected binding must disclose the real
    // executing binding in the receipt — never let the batch claim the
    // selected binding produced outputs it did not produce.
    if (picked.viaFallback) {
      const record = records.find((r) => r.inputPath === file.path);
      if (record?.status === 'WRITTEN') {
        const fallbackBindingId = picked.provider.binding.bindingId;
        diagnostics[file.path] =
          `executed via binding ${fallbackBindingId} (selected binding ${selection.selected?.bindingId ?? 'none'} does not support ${file.format})`;
        selection.rankingEvidence.reasons.push(
          `record ${file.path} executed via fallback binding ${fallbackBindingId} (selected binding does not support ${file.format})`,
        );
      }
    }
  }

  // Post-state: re-hash every input (preservation covers all inputs, not only
  // the successfully processed ones).
  const sourceHashesAfter = new Map<string, Sha256Hex>();
  for (const file of input.inputFiles) {
    try {
      sourceHashesAfter.set(file.path, sha256Hex(await readFile(file.path)));
    } catch {
      sourceHashesAfter.set(file.path, SENTINEL_MISSING);
    }
  }

  const verification = await verifyBatch({
    input,
    records,
    oracle,
    sourceHashesBefore,
    sourceHashesAfter,
    metric: deps.metric,
  });

  if (ownsWorkDir) {
    await rm(workDir, { recursive: true, force: true });
  }

  const output: ImageBatchProcessOutput = {
    taskId: input.taskId,
    records,
    selectedBindingId: selection.selected.bindingId,
    rankingEvidence: selection.rankingEvidence,
    verification,
  };
  return { ok: true, output, diagnostics };
}

/** A hash no real file can have: marks an input that vanished mid-run. */
const SENTINEL_MISSING: Sha256Hex =
  'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

/**
 * Filesystem identity of a path, captured without following links. Cleanup is
 * only allowed on a path whose live identity still matches the captured one —
 * the executor never unlinks a file a provider (or a racing actor) created
 * outside its own verified write.
 */
interface FileIdentity {
  dev: number;
  ino: number;
}

async function captureIdentity(path: string): Promise<FileIdentity> {
  const stat = await lstat(path);
  return { dev: stat.dev, ino: stat.ino };
}

async function removeIfIdentityMatches(path: string, identity: FileIdentity): Promise<void> {
  try {
    if (
      await captureIdentity(path).then(
        (live) => live.dev === identity.dev && live.ino === identity.ino,
      )
    ) {
      await rm(path, { force: true });
    }
  } catch {
    // Vanished (or unreadable) between capture and cleanup: nothing of ours to
    // remove, and never the caller's business to force it.
  }
}

async function executeOne(
  inputPath: string,
  bytes: Buffer,
  format: ImageFormat,
  provider: ImageProvider,
  targetPath: string,
  maxLongEdgePx: number,
  records: BatchRecord[],
  diagnostics: Record<string, string>,
): Promise<void> {
  // Ownership is only established after the provider reports success AND the
  // file's identity at the target is captured; everything the executor removes
  // must be that same file.
  let owned: FileIdentity | null = null;
  try {
    const facts = await inspectBytes(bytes).catch((cause: unknown) => {
      throw new ImageProviderError(
        'DECODE_FAILED',
        provider.binding.bindingId,
        `source did not decode: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    });
    const targetDims = scaledDims(facts.width, facts.height, maxLongEdgePx);
    await provider.resizeTo({ bytes, declaredFormat: format, targetDims, targetPath });
    owned = await captureIdentity(targetPath);
    // Post-write self-check against the file actually on disk.
    const outputFacts = await inspectBytes(await readFile(targetPath));
    const dimsOk =
      outputFacts.width === targetDims.width && outputFacts.height === targetDims.height;
    const dateOk = facts.captureDate === null || outputFacts.captureDate === facts.captureDate;
    if (!dimsOk) {
      await removeIfIdentityMatches(targetPath, owned);
      records.push(reject(inputPath, 'OUTPUT_VERIFY_FAILED'));
      diagnostics[inputPath] =
        `written dims ${outputFacts.width}x${outputFacts.height} != target ${targetDims.width}x${targetDims.height}`;
      return;
    }
    if (!dateOk) {
      await removeIfIdentityMatches(targetPath, owned);
      records.push(reject(inputPath, 'METADATA_LOST'));
      diagnostics[inputPath] = `capture date "${facts.captureDate}" lost on write`;
      return;
    }
    records.push({ inputPath, status: 'WRITTEN', outputPath: targetPath });
  } catch (cause) {
    const code =
      cause instanceof Error &&
      'code' in cause &&
      typeof (cause as { code?: unknown }).code === 'string' &&
      ['DECODE_FAILED', 'UNSUPPORTED_INPUT', 'OUTPUT_COLLISION', 'OUTPUT_VERIFY_FAILED'].includes(
        (cause as { code: string }).code,
      )
        ? (cause as { code: ImageBatchFailure }).code
        : 'OUTPUT_VERIFY_FAILED';
    diagnostics[inputPath] = cause instanceof Error ? cause.message : String(cause);
    // A provider that threw may have collided with (or raced) a file it did
    // not create — only ever clean up a path whose identity we verified.
    if (owned) {
      await removeIfIdentityMatches(targetPath, owned);
    }
    records.push(reject(inputPath, code));
  }
}

function pickProvider(
  providers: readonly ImageProvider[],
  selection: BindingSelection,
  candidates: readonly BindingCandidate[],
  facts: EnvironmentFacts,
  format: ImageFormat,
): { provider: ImageProvider; viaFallback: boolean } | null {
  if (selection.selected === null) {
    return null;
  }
  const primary = providers.find((p) => p.binding.bindingId === selection.selected?.bindingId);
  if (primary && !primary.binding.unsupportedFormats.includes(format)) {
    return { provider: primary, viaFallback: false };
  }
  // Format fallback is only allowed through the same registered, feasible pool
  // the selection drew from — never an arbitrary provider in the process.
  for (const binding of feasiblePool(candidates, facts)) {
    if (binding.bindingId === selection.selected?.bindingId) {
      continue;
    }
    if (binding.unsupportedFormats.includes(format)) {
      continue;
    }
    const provider = providers.find((p) => p.binding.bindingId === binding.bindingId);
    if (provider) {
      return { provider, viaFallback: true };
    }
  }
  return null;
}
