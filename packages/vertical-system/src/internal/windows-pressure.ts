// T06 fixed read-only, local-only Windows process memory-pressure evidence.
// Never collect argv, users, paths, PIDs or process environment.
export const TOP_MEMORY_PROCESS_COMMAND =
  "$ErrorActionPreference='Stop'; @(Get-Process -ErrorAction Stop | Sort-Object WorkingSet64 -Descending | Select-Object -First 8 -Property Name,WorkingSet64) | ConvertTo-Json -Compress -Depth 3";

export type ProcessPressureRefusal =
  | 'WINDOWS_REQUIRED'
  | 'PROCESS_FACTS_UNAVAILABLE'
  | 'PROCESS_FACTS_INVALID';

export type TopMemoryProcessResult =
  | {
      ok: true;
      facts: Readonly<{
        schema: 'shun.windows-top-memory.v02';
        status: 'OBSERVED_ONLY';
        localOnly: true;
        externalDisclosures: readonly [];
        metric: 'RESIDENT_MEMORY_BYTES_AT_SNAPSHOT';
        top: readonly Readonly<{ name: string; residentBytes: number }>[];
        interpretation: 'MEMORY_ONLY_NO_CPU_OR_ROOT_CAUSE_INFERENCE';
        provenance: 'fixed-readonly-powershell';
      }>;
    }
  | { ok: false; code: ProcessPressureRefusal };

type FixedPowerShellRunner = (script: string) => string;

export function observeTopMemoryProcessesWithHost(
  runner: FixedPowerShellRunner,
  platform: string,
): TopMemoryProcessResult {
  if (platform !== 'win32') return { ok: false, code: 'WINDOWS_REQUIRED' };
  let raw: string;
  try {
    raw = runner(TOP_MEMORY_PROCESS_COMMAND);
  } catch {
    return { ok: false, code: 'PROCESS_FACTS_UNAVAILABLE' };
  }
  if (typeof raw !== 'string' || raw.length > 8192 || raw.trim().length === 0) {
    return { ok: false, code: 'PROCESS_FACTS_INVALID' };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return { ok: false, code: 'PROCESS_FACTS_INVALID' };
  }
  const entries: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
  if (entries.length < 1 || entries.length > 8) {
    return { ok: false, code: 'PROCESS_FACTS_INVALID' };
  }
  const top: { name: string; residentBytes: number }[] = [];
  let previous = Number.MAX_SAFE_INTEGER;
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return { ok: false, code: 'PROCESS_FACTS_INVALID' };
    }
    const record = entry as Record<string, unknown>;
    if (
      Object.keys(record).length !== 2 ||
      !Object.hasOwn(record, 'Name') ||
      !Object.hasOwn(record, 'WorkingSet64')
    ) {
      return { ok: false, code: 'PROCESS_FACTS_INVALID' };
    }
    // Only executable basenames are emitted. Even these can be sensitive:
    // local-only means never automatically attach this to DeepSeek prompts.
    const name = record.Name;
    const bytes = record.WorkingSet64;
    if (
      typeof name !== 'string' ||
      name.length < 1 ||
      name.length > 64 ||
      !/^[\p{L}\p{N}_. ()-]+$/u.test(name) ||
      typeof bytes !== 'number' ||
      !Number.isSafeInteger(bytes) ||
      bytes < 0 ||
      bytes > previous
    ) {
      return { ok: false, code: 'PROCESS_FACTS_INVALID' };
    }
    previous = bytes;
    top.push({ name, residentBytes: bytes });
  }
  return {
    ok: true,
    facts: {
      schema: 'shun.windows-top-memory.v02',
      status: 'OBSERVED_ONLY',
      localOnly: true,
      externalDisclosures: [],
      metric: 'RESIDENT_MEMORY_BYTES_AT_SNAPSHOT',
      top,
      interpretation: 'MEMORY_ONLY_NO_CPU_OR_ROOT_CAUSE_INFERENCE',
      provenance: 'fixed-readonly-powershell',
    },
  };
}
