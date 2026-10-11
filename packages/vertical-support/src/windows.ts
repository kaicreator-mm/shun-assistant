import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { minimizeSupportContext } from './minimize.ts';
import type { SupportContextResult } from './schema.ts';

const execFile = promisify(execFileCallback);
const SYSTEM_POWERSHELL =
  String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`;

export interface WindowsCollectorDeps {
  execFile?: (
    file: string,
    args: readonly string[],
    options: { windowsHide: boolean; timeout: number; encoding: 'utf8' },
  ) => Promise<{ stdout: string; stderr?: string }>;
}

function collectionError(code: 'EXECUTION' | 'STDERR' | 'INVALID_JSON' | 'INVALID_OBSERVATION'): Error {
  return new Error(`SUPPORT_COLLECTION_FAILED: ${code}`);
}

/**
 * Real Windows R0 collector. It executes only fixed local PowerShell/CIM
 * queries through the pinned System32 executable path and has no URL/network/
 * client surface. Raw subprocess/parser diagnostics never cross this boundary.
 */
export async function collectWindowsSupportContext(
  deps: WindowsCollectorDeps = {},
): Promise<SupportContextResult> {
  if (process.platform !== 'win32' && deps.execFile === undefined) {
    throw new Error('WINDOWS_REQUIRED: support-context collection is local-Windows only');
  }

  const run = deps.execFile ?? execFile;
  const script = [
    "$ErrorActionPreference='Stop'",
    '$os=Get-CimInstance Win32_OperatingSystem',
    '$cs=Get-CimInstance Win32_ComputerSystem',
    '$u=Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1',
    "$last=if($null -eq $u){'UNKNOWN'}elseif($null -ne $u.InstalledOn){$u.InstalledOn.ToString('o')}else{$u.HotFixID}",
    '[pscustomobject]@{os=@{name=[string]$os.Caption;build=[string]$os.BuildNumber};device=@{model=[string]$cs.Model};updates=@{last_check=[string]$last}} | ConvertTo-Json -Compress -Depth 5',
  ].join(';');

  let result: { stdout: string; stderr?: string };
  try {
    result = await run(
      SYSTEM_POWERSHELL,
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { windowsHide: true, timeout: 30_000, encoding: 'utf8' },
    );
  } catch {
    throw collectionError('EXECUTION');
  }
  if (result.stderr?.trim()) {
    throw collectionError('STDERR');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout.trim()) as unknown;
  } catch {
    throw collectionError('INVALID_JSON');
  }

  try {
    return minimizeSupportContext(parsed);
  } catch {
    throw collectionError('INVALID_OBSERVATION');
  }
}
