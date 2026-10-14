// Private deterministic OS observation adapter, not exported by @shun/vertical-system.
// Its injected fake host is test-only. Public callers use collectWindowsSystemInventory().
import type { SystemInventoryResult } from '../index.ts';

export interface SystemInventoryHost {
  availableParallelism(): number;
  cpuCount(): number;
  totalMemory(): number;
  freeMemory(): number;
  uptime(): number;
  diskTotals(): { total: number; free: number };
}

function safeInteger(n: number, positive: boolean): boolean {
  return Number.isSafeInteger(n) && (positive ? n > 0 : n >= 0);
}

/** Internal deterministic test seam; never exposed by the public host API. */
export function collectSystemInventoryWithTrustedHost(
  host: SystemInventoryHost,
  platform: string,
): SystemInventoryResult {
  if (platform !== 'win32') return { ok: false, code: 'WINDOWS_REQUIRED' };
  let cpuLogicalCount: number;
  let memoryTotalBytes: number;
  let memoryFreeBytes: number;
  let diskTotalBytes: number;
  let diskFreeBytes: number;
  let uptimeSeconds: number;
  try {
    cpuLogicalCount = Math.max(host.availableParallelism(), host.cpuCount());
    memoryTotalBytes = host.totalMemory();
    memoryFreeBytes = host.freeMemory();
    const disk = host.diskTotals();
    diskTotalBytes = disk.total;
    diskFreeBytes = disk.free;
    uptimeSeconds = Math.floor(host.uptime());
  } catch {
    return { ok: false, code: 'SYSTEM_OBSERVATION_UNAVAILABLE' };
  }
  if (
    !safeInteger(cpuLogicalCount, true) ||
    cpuLogicalCount > 4096 ||
    !safeInteger(memoryTotalBytes, true) ||
    !safeInteger(memoryFreeBytes, false) ||
    memoryFreeBytes > memoryTotalBytes ||
    !safeInteger(diskTotalBytes, true) ||
    !safeInteger(diskFreeBytes, false) ||
    diskFreeBytes > diskTotalBytes ||
    !safeInteger(uptimeSeconds, false)
  )
    return { ok: false, code: 'SYSTEM_OBSERVATION_INVALID' };
  return {
    ok: true,
    snapshot: {
      schema: 'shun.system-inventory.v02',
      localOnly: true,
      externalDisclosures: [],
      provenance: 'node:os+node:fs:statfs',
      platform: 'win32',
      cpuLogicalCount,
      memoryTotalBytes,
      memoryFreeBytes,
      diskTotalBytes,
      diskFreeBytes,
      uptimeSeconds,
    },
  };
}
