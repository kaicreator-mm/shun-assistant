// Benchmark-only envelope entry (L2 §4.2): the hidden harness truth — the
// synthetic growth injector reference and the precommitted protected-asset
// baseline hashes — is consumed EXCLUSIVELY here and reduced to a pure
// production input plus verifier baselines. The production diagnose path
// structurally rejects these fields (strict schema), and this module never
// interprets `growthFixture.injectorRef`: it is harness truth, opaque to the
// diagnoser.
import {
  type StorageBenchmarkInput,
  StorageBenchmarkInputSchema,
  type StorageDiagnoseInput,
} from '@shun/contracts';
import {
  runStorageDiagnose,
  type StorageDiagnoseResult,
  type StorageDiagnoseRuntime,
} from './diagnose.ts';

export interface BenchmarkRunOutcome extends StorageDiagnoseResult {
  /** The production-shaped input the benchmark envelope was reduced to. */
  productionInput: StorageDiagnoseInput;
}

/**
 * Run Loop C under the benchmark envelope. The envelope's `protectedAssets`
 * carry precommitted `baselineSha256` canaries: they become verifier
 * baselines (hidden truth checked AFTER the action), never production input
 * fields and never visible to attribution/plan/execute.
 */
export async function runStorageDiagnoseBenchmark(
  runtime: StorageDiagnoseRuntime,
  rawBenchmarkInput: unknown,
): Promise<BenchmarkRunOutcome> {
  const benchmark: StorageBenchmarkInput = StorageBenchmarkInputSchema.parse(rawBenchmarkInput);

  const productionInput: StorageDiagnoseInput = {
    taskId: benchmark.taskId,
    targetVolume: benchmark.targetVolume,
    protectedAssets: benchmark.protectedAssets.map((a) => ({ path: a.path })),
    cleanupPolicy: benchmark.cleanupPolicy,
  };

  const result = await runStorageDiagnose(
    { ...runtime, benchmarkBaselines: toBaselineMap(benchmark) },
    productionInput,
  );
  return { ...result, productionInput };
}

/**
 * Baselines keyed by canonical path: the verifier compares against these
 * precommitted hashes (hidden canary truth) instead of the production
 * pre-action snapshot. Path canonicalization happens at verification time on
 * the resolved realpath.
 */
function toBaselineMap(benchmark: StorageBenchmarkInput): Record<string, string> {
  return Object.fromEntries(benchmark.protectedAssets.map((a) => [a.path, a.baselineSha256]));
}
