// T06: deterministic, privacy-minimal read-only Windows diagnosis projection.
// This file NEVER authorizes cleanup, touches user data or claims root cause.
import type { RuntimeCountResult } from './internal/windows-counts.ts';
import {
  collectWindowsSystemInventory,
  type SystemInventoryResult,
} from './index.ts';
import { collectWindowsRuntimeCounts } from './windows-runtime.ts';

export type DiagnosisRefusal =
  | 'WINDOWS_REQUIRED'
  | 'OBSERVATION_UNAVAILABLE'
  | 'OBSERVATION_INVALID';

export type DiagnosticReport = Readonly<{
  schema: 'shun.windows-diagnostic-report.v02';
  status: 'OBSERVED_ONLY';
  localOnly: true;
  externalDisclosures: readonly [];
  evidence: Readonly<{
    cpuLogicalCount: number;
    memoryTotalBytes: number;
    memoryFreeBytes: number;
    diskTotalBytes: number;
    diskFreeBytes: number;
    processCount: number;
    startupEntryCount: number;
    inventoryProvenance: 'node:os+node:fs:statfs';
    runtimeProvenance: 'fixed-readonly-powershell';
  }>;
  signals: readonly ('LOW_DISK_SPACE' | 'LOW_FREE_MEMORY')[];
  advice: readonly Readonly<{
    action: 'REVIEW_STORAGE' | 'REVIEW_APPLICATIONS';
    effect: 'NONE';
  }>[];
  limitation: 'SINGLE_SNAPSHOT_NO_ROOT_CAUSE_OR_SPEEDUP_CLAIM';
}>;

export type DiagnosticResult =
  | { ok: true; report: DiagnosticReport }
  | { ok: false; code: DiagnosisRefusal };

function validBytes(total: number, free: number): boolean {
  return (
    Number.isSafeInteger(total) &&
    Number.isSafeInteger(free) &&
    total > 0 &&
    free >= 0 &&
    free <= total
  );
}

/**
 * Testable pure projection, NOT an authority port. Only the zero-argument
 * public collector below can produce actual Windows host observations.
 */
export function projectReadonlyDiagnosis(
  inventory: SystemInventoryResult,
  runtime: RuntimeCountResult,
): DiagnosticResult {
  if (!inventory.ok || !runtime.ok) {
    return {
      ok: false,
      code: inventory.ok && !runtime.ok && runtime.code === 'WINDOWS_REQUIRED'
        ? 'WINDOWS_REQUIRED'
        : !inventory.ok && inventory.code === 'WINDOWS_REQUIRED'
          ? 'WINDOWS_REQUIRED'
          : 'OBSERVATION_UNAVAILABLE',
    };
  }
  const a = inventory.snapshot;
  const b = runtime.facts;
  if (
    a.schema !== 'shun.system-inventory.v02' ||
    b.schema !== 'shun.windows-runtime-counts.v02' ||
    a.platform !== 'win32' ||
    a.localOnly !== true ||
    b.localOnly !== true ||
    a.provenance !== 'node:os+node:fs:statfs' ||
    b.provenance !== 'fixed-readonly-powershell' ||
    a.externalDisclosures.length !== 0 ||
    b.externalDisclosures.length !== 0 ||
    !Number.isSafeInteger(a.cpuLogicalCount) ||
    a.cpuLogicalCount < 1 ||
    !validBytes(a.memoryTotalBytes, a.memoryFreeBytes) ||
    !validBytes(a.diskTotalBytes, a.diskFreeBytes) ||
    !Number.isSafeInteger(b.processCount) ||
    !Number.isSafeInteger(b.startupEntryCount) ||
    b.processCount < 0 ||
    b.startupEntryCount < 0
  ) {
    return { ok: false, code: 'OBSERVATION_INVALID' };
  }
  const signals: ('LOW_DISK_SPACE' | 'LOW_FREE_MEMORY')[] = [];
  const advice: { action: 'REVIEW_STORAGE' | 'REVIEW_APPLICATIONS'; effect: 'NONE' }[] = [];
  if (a.diskFreeBytes / a.diskTotalBytes < 0.1) {
    signals.push('LOW_DISK_SPACE');
    advice.push({ action: 'REVIEW_STORAGE', effect: 'NONE' });
  }
  if (a.memoryFreeBytes / a.memoryTotalBytes < 0.1) {
    signals.push('LOW_FREE_MEMORY');
    advice.push({ action: 'REVIEW_APPLICATIONS', effect: 'NONE' });
  }
  return {
    ok: true,
    report: {
      schema: 'shun.windows-diagnostic-report.v02',
      status: 'OBSERVED_ONLY',
      localOnly: true,
      externalDisclosures: [],
      evidence: {
        cpuLogicalCount: a.cpuLogicalCount,
        memoryTotalBytes: a.memoryTotalBytes,
        memoryFreeBytes: a.memoryFreeBytes,
        diskTotalBytes: a.diskTotalBytes,
        diskFreeBytes: a.diskFreeBytes,
        processCount: b.processCount,
        startupEntryCount: b.startupEntryCount,
        inventoryProvenance: a.provenance,
        runtimeProvenance: b.provenance,
      },
      signals,
      advice,
      limitation: 'SINGLE_SNAPSHOT_NO_ROOT_CAUSE_OR_SPEEDUP_CLAIM',
    },
  };
}

/** Public entrypoint accepts no caller-injected host/data, never changes OS. */
export function collectWindowsReadonlyDiagnosis(): DiagnosticResult {
  if (process.platform !== 'win32') return { ok: false, code: 'WINDOWS_REQUIRED' };
  try {
    return projectReadonlyDiagnosis(
      collectWindowsSystemInventory(),
      collectWindowsRuntimeCounts(),
    );
  } catch {
    return { ok: false, code: 'OBSERVATION_UNAVAILABLE' };
  }
}
