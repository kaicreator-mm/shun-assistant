// Narrowly classify the Vitest 3.x worker-RPC starvation transient.
// A real failed test can coexist with an RPC timeout: never retry a run
// unless the first run contains an explicit all-green Vitest summary.
export const VITEST_WORKER_RPC_TRANSIENT_MARKER = '[vitest-worker]: Timeout calling';

export function isVitestWorkerRpcTransient(suite, result) {
  if (suite?.requiresVitest !== true || result?.error ||
      !Number.isInteger(result?.status) || result.status <= 0 || result.signal) {
    return false;
  }
  const output = `${result.stdout?.toString() ?? ''}\n${result.stderr?.toString() ?? ''}`
    .replace(/\x1b\[[0-9;]*m/g, '');
  if (!output.includes(VITEST_WORKER_RPC_TRANSIENT_MARKER)) return false;

  const lines = output.split(/\r?\n/).map((line) => line.trim());
  const fileSummaries = lines.filter((line) => /^Test Files\s+/.test(line));
  const testSummaries = lines.filter((line) => /^Tests\s+/.test(line));
  return fileSummaries.length === 1 && testSummaries.length === 1 &&
    /^Test Files\s+[1-9]\d* passed\b/.test(fileSummaries[0]) &&
    /^Tests\s+[1-9]\d* passed\b/.test(testSummaries[0]) &&
    !/\b\d+\s+failed\b/i.test(output);
}
