// v0.2 readonly Windows local system snapshot. NO script, shell, registry
// mutation, process enumeration or user document content collection.
// Frozen Product #96, L2 #101, Task DAG #102 T06.
import { statfsSync } from 'node:fs';
import { availableParallelism, cpus, freemem, totalmem, uptime } from 'node:os';
import {
  collectSystemInventoryWithTrustedHost,
  type SystemInventoryHost,
} from './internal/collector.ts';

export type ReadonlySystemSnapshot = Readonly<{
  schema: 'shun.system-inventory.v02';
  localOnly: true;
  externalDisclosures: readonly [];
  provenance: 'node:os+node:fs:statfs';
  platform: 'win32';
  cpuLogicalCount: number;
  memoryTotalBytes: number;
  memoryFreeBytes: number;
  diskTotalBytes: number;
  diskFreeBytes: number;
  uptimeSeconds: number;
}>;

export type SystemReadRefusal =
  | 'WINDOWS_REQUIRED'
  | 'SYSTEM_OBSERVATION_UNAVAILABLE'
  | 'SYSTEM_OBSERVATION_INVALID';

export type SystemInventoryResult =
  | { ok: true; snapshot: ReadonlySystemSnapshot }
  | { ok: false; code: SystemReadRefusal };

/** Only allows fixed system-drive root, not an env-controlled arbitrary path. */
function trustedDiskRoot(): string {
  return 'C:\\';
}

/** Public API: accepts NO injected host, shell command, filesystem root or options. */
export function collectWindowsSystemInventory(): SystemInventoryResult {
  if (process.platform !== 'win32') return { ok: false, code: 'WINDOWS_REQUIRED' };
  const host: SystemInventoryHost = {
    availableParallelism,
    cpuCount: () => cpus().length,
    totalMemory: totalmem,
    freeMemory: freemem,
    uptime,
    diskTotals: () => {
      const disk = statfsSync(trustedDiskRoot(), { bigint: true });
      const block = disk.bsize;
      const total = disk.blocks * block;
      const free = disk.bavail * block;
      if (total > BigInt(Number.MAX_SAFE_INTEGER) || free > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error('SYSTEM_OBSERVATION_INVALID');
      }
      return { total: Number(total), free: Number(free) };
    },
  };
  return collectSystemInventoryWithTrustedHost(host, process.platform);
}

/** Advisory only. NO mutation, automatic cleanup or unbounded path disclosure. */
export type SafeSystemSuggestion =
  | { kind: 'LOW_DISK_SPACE'; effect: 'NONE'; action: 'REVIEW_STORAGE' }
  | { kind: 'LOW_FREE_MEMORY'; effect: 'NONE'; action: 'REVIEW_APPLICATIONS' };

export function suggestReadonlyOptimizations(
  result: SystemInventoryResult,
): readonly SafeSystemSuggestion[] {
  if (!result.ok) return [];
  const { memoryFreeBytes, memoryTotalBytes, diskFreeBytes, diskTotalBytes } = result.snapshot;
  const suggestions: SafeSystemSuggestion[] = [];
  if (diskFreeBytes / diskTotalBytes < 0.1) {
    suggestions.push({ kind: 'LOW_DISK_SPACE', effect: 'NONE', action: 'REVIEW_STORAGE' });
  }
  if (memoryFreeBytes / memoryTotalBytes < 0.1) {
    suggestions.push({ kind: 'LOW_FREE_MEMORY', effect: 'NONE', action: 'REVIEW_APPLICATIONS' });
  }
  return suggestions;
}

export {
  collectWindowsReadonlyDiagnosis,
  type DiagnosticReport,
  type DiagnosticResult,
} from './diagnostics.ts';
export type { RuntimeCountRefusal, RuntimeCountResult } from './internal/windows-counts.ts';
// Public host-only process/startup counts; no names, paths or script arguments.
export type { ProcessPressureRefusal, TopMemoryProcessResult } from './internal/windows-pressure.ts';
export { collectWindowsRuntimeCounts, collectWindowsTopMemoryProcesses } from './windows-runtime.ts';
