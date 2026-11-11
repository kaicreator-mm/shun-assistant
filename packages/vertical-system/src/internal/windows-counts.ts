// Internal deterministic fixed-command host adapter. Never export as public API.
export type RuntimeCountRefusal =
  | 'WINDOWS_REQUIRED'
  | 'PROCESS_FACTS_UNAVAILABLE'
  | 'STARTUP_FACTS_UNAVAILABLE'
  | 'SYSTEM_OBSERVATION_INVALID';

export type RuntimeCountResult =
  | {
      ok: true;
      facts: Readonly<{
        schema: 'shun.windows-runtime-counts.v02';
        localOnly: true;
        externalDisclosures: readonly [];
        processCount: number;
        startupEntryCount: number;
        provenance: 'fixed-readonly-powershell';
      }>;
    }
  | { ok: false; code: RuntimeCountRefusal };

// Every command is a fixed literal; no user paths, filters, argv or model text.
export const PROCESS_COUNT_COMMAND =
  "$ErrorActionPreference='Stop'; (Get-Process -ErrorAction Stop | Measure-Object).Count";
export const STARTUP_COUNT_COMMAND =
  "$ErrorActionPreference='Stop'; (Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction Stop | Measure-Object).Count";

export type FixedReadRunner = (script: string) => string;

function strictCount(raw: string): number | null {
  const text = raw.trim();
  if (!/^(0|[1-9][0-9]{0,5})$/.test(text)) return null;
  const count = Number(text);
  return Number.isSafeInteger(count) && count < 100000 ? count : null;
}

/** Only an internal/test-port may inject the runner; no public host override. */
export function observeRuntimeCountsWithHost(
  runner: FixedReadRunner,
  platform: string,
): RuntimeCountResult {
  if (platform !== 'win32') return { ok: false, code: 'WINDOWS_REQUIRED' };
  let processCount: number | null;
  try {
    processCount = strictCount(runner(PROCESS_COUNT_COMMAND));
  } catch {
    return { ok: false, code: 'PROCESS_FACTS_UNAVAILABLE' };
  }
  if (processCount === null) return { ok: false, code: 'SYSTEM_OBSERVATION_INVALID' };
  let startupEntryCount: number | null;
  try {
    startupEntryCount = strictCount(runner(STARTUP_COUNT_COMMAND));
  } catch {
    return { ok: false, code: 'STARTUP_FACTS_UNAVAILABLE' };
  }
  if (startupEntryCount === null) return { ok: false, code: 'SYSTEM_OBSERVATION_INVALID' };
  return {
    ok: true,
    facts: {
      schema: 'shun.windows-runtime-counts.v02',
      localOnly: true,
      externalDisclosures: [],
      processCount,
      startupEntryCount,
      provenance: 'fixed-readonly-powershell',
    },
  };
}
