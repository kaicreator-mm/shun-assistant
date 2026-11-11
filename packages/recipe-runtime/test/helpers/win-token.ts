// Physical host-evidence suites are operator-gated: they are only valid and
// only run under a non-elevated UAC-filtered token on a real host. CI runner
// images may present an elevated (High integrity) token, in which case the
// physical suites skip with an explicit marker — CI is source/ABI regression
// only (see .github/workflows/executor-windows.yml).
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

export type WindowsTokenIntegrity = 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export function windowsTokenIntegrity(): WindowsTokenIntegrity {
  if (process.platform !== 'win32') return 'UNKNOWN';
  const out = spawnSync(
    join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'whoami.exe'),
    ['/groups'],
    { encoding: 'utf8', timeout: 15_000 },
  );
  if (out.status !== 0) return 'UNKNOWN';
  const text = out.stdout ?? '';
  if (text.includes('S-1-16-12288')) return 'HIGH';
  if (text.includes('S-1-16-8192')) return 'MEDIUM';
  if (text.includes('S-1-16-4096')) return 'LOW';
  return 'UNKNOWN';
}

/**
 * Whether the physical host falsifier suites should execute in this session.
 * Never mutates anything; the explicit skip marker is logged here so an
 * all-skipped CI run stays explainable in evidence.
 */
export function physicalHostSuiteActive(): boolean {
  const integrity = windowsTokenIntegrity();
  if (integrity === 'HIGH') {
    console.log(
      'E2E_PHYSICAL_SUITE=SKIPPED_ELEVATED_TOKEN (physical evidence runs are operator-gated locally, never on CI)',
    );
    return false;
  }
  return true;
}
