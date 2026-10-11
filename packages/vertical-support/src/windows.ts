import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { minimizeSupportContext } from './minimize.ts';
import type { SupportContextResult } from './schema.ts';

const execFile = promisify(execFileCallback);
const SYSTEM_ROOT = String.raw`C:\Windows`;
const SYSTEM_POWERSHELL =
  String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`;
const TRUSTED_ENV: Readonly<Record<string, string>> = Object.freeze({
  SystemRoot: SYSTEM_ROOT,
  WINDIR: SYSTEM_ROOT,
  PATH: String.raw`C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0`,
  PSModulePath: String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\Modules`,
  ComSpec: String.raw`C:\Windows\System32\cmd.exe`,
  TEMP: String.raw`C:\Windows\Temp`,
  TMP: String.raw`C:\Windows\Temp`,
});

export interface WindowsCollectorDeps {
  execFile?: (
    file: string,
    args: readonly string[],
    options: {
      windowsHide: boolean;
      timeout: number;
      encoding: 'utf8';
      env: Readonly<Record<string, string>>;
    },
  ) => Promise<{ stdout: string; stderr?: string }>;
}

function collectionError(
  code: 'EXECUTION' | 'STDERR' | 'INVALID_JSON' | 'INVALID_OBSERVATION',
): Error {
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
    '$os=CimCmdlets\\Get-CimInstance Win32_OperatingSystem',
    '$cs=CimCmdlets\\Get-CimInstance Win32_ComputerSystem',
    '$u=Microsoft.PowerShell.Management\\Get-HotFix | Microsoft.PowerShell.Utility\\Sort-Object InstalledOn -Descending | Microsoft.PowerShell.Utility\\Select-Object -First 1',
    "$last=if($null -eq $u){'UNKNOWN'}elseif($null -ne $u.InstalledOn){$u.InstalledOn.ToString('o')}else{$u.HotFixID}",
    '[pscustomobject]@{os=@{name=[string]$os.Caption;build=[string]$os.BuildNumber};device=@{model=[string]$cs.Model};updates=@{last_check=[string]$last}} | Microsoft.PowerShell.Utility\\ConvertTo-Json -Compress -Depth 5',
  ].join(';');

  let result: { stdout: string; stderr?: string };
  try {
    result = await run(SYSTEM_POWERSHELL, ['-NoProfile', '-NonInteractive', '-Command', script], {
      windowsHide: true,
      timeout: 30_000,
      encoding: 'utf8',
      env: TRUSTED_ENV,
    });
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
