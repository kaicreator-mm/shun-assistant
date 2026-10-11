import { execFile as execFileCallback } from 'node:child_process';
import { promisify } from 'node:util';
import { collectWindowsSupportContextWithTrustedRunner } from './internal/windows-runner.ts';
import type { SupportContextResult } from './schema.ts';

const execFile = promisify(execFileCallback);

/**
 * Public frozen B-040 collector.
 *
 * There is deliberately no dependency-injection parameter. Every public call
 * enforces the real host platform and uses the internal trusted Node runner.
 * Extra JavaScript arguments are ignored by the language and cannot replace
 * the execution path.
 */
export async function collectWindowsSupportContext(): Promise<SupportContextResult> {
  if (process.platform !== 'win32') {
    throw new Error('WINDOWS_REQUIRED: support-context collection is local-Windows only');
  }
  return collectWindowsSupportContextWithTrustedRunner(execFile, process.platform);
}
