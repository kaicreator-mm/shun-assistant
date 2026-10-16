// T06 machine-wide installed software: bounded, read-only LOCAL-only sample.
// Never executes installers, reads user hives, or discloses paths/commands.
export const SOFTWARE_COMMAND =
  "$ErrorActionPreference='Stop'; $p=@('Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); @(Get-ItemProperty -Path $p -ErrorAction Stop | Where-Object { $_.DisplayName -is [string] -and $_.DisplayName.Trim().Length -gt 0 } | Sort-Object DisplayName | Select-Object -First 64 -Property DisplayName,DisplayVersion) | ConvertTo-Json -Compress -Depth 3";

export type SoftwareReportResult =
  | {
      ok: true;
      report: Readonly<{
        schema: 'shun.windows-software.v02';
        status: 'OBSERVED_ONLY';
        localOnly: true;
        automaticCloudDisclosure: false;
        externalDisclosures: readonly [];
        scope: 'HKLM_UNINSTALL_SAMPLE';
        completeness: 'BOUNDED_NOT_EXHAUSTIVE';
        entries: readonly Readonly<{ name: string; version: string | null }>[];
      }>;
    }
  | {
      ok: false;
      code: 'WINDOWS_REQUIRED' | 'SOFTWARE_FACTS_UNAVAILABLE' | 'SOFTWARE_FACTS_INVALID';
    };

export function observeInstalledSoftwareWithHost(
  runner: (script: string) => string,
  platform: string,
): SoftwareReportResult {
  if (platform !== 'win32') return { ok: false, code: 'WINDOWS_REQUIRED' };
  let raw: string;
  try {
    raw = runner(SOFTWARE_COMMAND);
  } catch {
    return { ok: false, code: 'SOFTWARE_FACTS_UNAVAILABLE' };
  }
  if (typeof raw !== 'string' || !raw.trim() || raw.length > 16384) {
    return { ok: false, code: 'SOFTWARE_FACTS_INVALID' };
  }
  try {
    const parsed: unknown = JSON.parse(raw) as unknown;
    const rows: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
    if (rows.length > 64) return { ok: false, code: 'SOFTWARE_FACTS_INVALID' };
    const entries: { name: string; version: string | null }[] = [];
    for (const row of rows) {
      if (!row || typeof row !== 'object' || Array.isArray(row)) {
        return { ok: false, code: 'SOFTWARE_FACTS_INVALID' };
      }
      const record = row as Record<string, unknown>;
      const keys = Object.keys(record);
      const name = record.DisplayName;
      const version = record.DisplayVersion ?? null;
      if (
        keys.length > 2 ||
        keys.some((k) => k !== 'DisplayName' && k !== 'DisplayVersion') ||
        typeof name !== 'string' ||
        name.length < 1 ||
        name.length > 120 ||
        /[\\:@\r\n\t]/u.test(name) ||
        name.startsWith('/') ||
        name.includes('../') ||
        (version !== null &&
          (typeof version !== 'string' || version.length > 64 || /[\\/:@\r\n\t]/u.test(version)))
      ) {
        return { ok: false, code: 'SOFTWARE_FACTS_INVALID' };
      }
      entries.push({ name, version: version as string | null });
    }
    return {
      ok: true,
      report: {
        schema: 'shun.windows-software.v02',
        status: 'OBSERVED_ONLY',
        localOnly: true,
        automaticCloudDisclosure: false,
        externalDisclosures: [],
        scope: 'HKLM_UNINSTALL_SAMPLE',
        completeness: 'BOUNDED_NOT_EXHAUSTIVE',
        entries,
      },
    };
  } catch {
    return { ok: false, code: 'SOFTWARE_FACTS_INVALID' };
  }
}
