// Windows process/startup COUNT facts only. Never disclose names, paths or commands.
// No privilege escalation, mutation, PowerShell expression from request, or network.
import { execFileSync } from 'node:child_process';
import { win32 } from 'node:path';
import {
  observeRuntimeCountsWithHost,
  type RuntimeCountResult,
} from './internal/windows-counts.ts';

const COMMAND_TIMEOUT_MS = 5000;

/** Never resolve powershell.exe through mutable PATH or the current directory. */
function trustedPowerShellExe(): string | null {
  const root = process.env.SystemRoot;
  if (!root || !/^[A-Za-z]:\\\\Windows\\?$/i.test(root)) return null;
  return win32.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

/** No options/input: trusted product fixed PowerShell script and bounded output. */
export function collectWindowsRuntimeCounts(): RuntimeCountResult {
  if (process.platform !== 'win32') return { ok: false, code: 'WINDOWS_REQUIRED' };
  const executable = trustedPowerShellExe();
  if (!executable) return { ok: false, code: 'PROCESS_FACTS_UNAVAILABLE' };
  return observeRuntimeCountsWithHost(
    (script) =>
      execFileSync(executable, ['-NoProfile', '-NonInteractive', '-Command', script], {
        encoding: 'utf8',
        timeout: COMMAND_TIMEOUT_MS,
        maxBuffer: 1024,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'ignore'],
      }),
    process.platform,
  );
}
