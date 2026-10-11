import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { minimizeSupportContext } from './minimize.ts';
import type { SupportContextResult } from './schema.ts';

const execFile = promisify(execFileCallback);

export interface WindowsCollectorDeps {
  execFile?: (
    file: string,
    args: readonly string[],
    options: { windowsHide: boolean; timeout: number; encoding: 'utf8' },
  ) => Promise<{ stdout: string; stderr?: string }>;
}

/**
 * Real Windows R0 collector. It executes only fixed local PowerShell/CIM
 * queries and has no URL/network/client surface. Collection itself is already
 * allowlisted to the three B-040 report sections; minimization runs again
 * before the value leaves this module.
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

  const result = await run(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', script],
    { windowsHide: true, timeout: 30_000, encoding: 'utf8' },
  );
  if (result.stderr?.trim()) {
    throw new Error(`SUPPORT_COLLECTION_FAILED: PowerShell stderr: ${result.stderr.trim()}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(result.stdout.trim()) as unknown;
  } catch (error) {
    throw new Error(
      `SUPPORT_COLLECTION_FAILED: invalid structured PowerShell output: ${String(error)}`,
    );
  }
  return minimizeSupportContext(parsed);
}
