// Fail-closed classification of a single known Vitest 3.x worker-RPC transient.
// All-green test counts alone do not rule out additional unhandled exceptions.
export const VITEST_WORKER_RPC_TRANSIENT_MARKER = '[vitest-worker]: Timeout calling';
const EXPECTED_RPC_ERROR = 'Error: [vitest-worker]: Timeout calling "onTaskUpdate"';

export function isVitestWorkerRpcTransient(suite, result) {
  if (suite?.requiresVitest !== true || result?.error ||
      result?.status !== 1 || result.signal) return false;

  const output = ((result.stdout?.toString() ?? '') + '\n' + (result.stderr?.toString() ?? ''))
    .replace(/\x1b\[[0-9;]*m/g, '');
  const lines = output.split(/\r?\n/).map((line) => line.trim());
  const fileSummaries = lines.filter((line) => /^Test Files\s+/.test(line));
  const testSummaries = lines.filter((line) => /^Tests\s+/.test(line));
  if (fileSummaries.length !== 1 || testSummaries.length !== 1 ||
      !/^Test Files\s+[1-9]\d* passed\b/.test(fileSummaries[0]) ||
      !/^Tests\s+[1-9]\d* passed\b/.test(testSummaries[0]) ||
      /\b\d+\s+failed\b/i.test(output)) return false;

  // Vitest can report green tests and two *independent* unhandled failures.
  // Only one explicitly counted unhandled error with one exact RPC error
  // header is retryable; missing/truncated/multiple/unknown errors fail closed.
  const unhandledCounts = lines.filter((line) => /\bVitest caught \d+ unhandled errors? during the test run\.?/i.test(line));
  if (unhandledCounts.length !== 1 ||
      !/\bVitest caught 1 unhandled error during the test run\.?/i.test(unhandledCounts[0])) return false;

  const diagnostics = lines.filter((line) => /^(?:Error|[A-Za-z]+Error|Exception):\s/.test(line));
  if (diagnostics.length !== 1 || diagnostics[0] !== EXPECTED_RPC_ERROR) return false;
  if (output.split(VITEST_WORKER_RPC_TRANSIENT_MARKER).length !== 2) return false;

  const errorSections = lines.filter((line) => /(?:^|\s)Unhandled Error(?:\s|$)/.test(line) && !/Unhandled Errors/.test(line));
  return errorSections.length <= 1;
}
