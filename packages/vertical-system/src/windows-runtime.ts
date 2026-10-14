// Windows process/startup COUNT facts only. Never disclose names, paths or commands.
// No privilege escalation, mutation, PowerShell expression from request, or network.
import { execFileSync } from 'node:child_process';
import {
  observeRuntimeCountsWithHost,
  type RuntimeCountResult,
} from './internal/windows-counts.ts';

const COMMAND_TIMEOUT_MS = 5000;

/** No options/input: trusted product fixed PowerShell script and bounded output. */
export function collectWindowsRuntimeCounts(): RuntimeCountResult {
  if (process.platform !== 'win32') return { ok: false, code: 'WINDOWS_REQUIRED' };
  return observeRuntimeCountsWithHost(
    (script) =>
      execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
        encoding: 'utf8',
        timeout: COMMAND_TIMEOUT_MS,
        maxBuffer: 1024,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'ignore'],
      }),
    process.platform,
  );
}
