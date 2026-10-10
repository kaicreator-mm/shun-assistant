// Windows token elevation detection from `whoami /groups /fo csv` output.
//
// The integrity-level SID is the reliable signal: S-1-16-12288 (High) =
// elevated admin token, S-1-16-8192 (Medium) = filtered token (UAC enforced).
// An unparseable or empty capture fails CLOSED to "not elevated" — privilege
// consistency then refuses any ELEVATED action instead of guessing.
export const INTEGRITY_HIGH_SID = 'S-1-16-12288';
export const INTEGRITY_SYSTEM_SID = 'S-1-16-16384';
export const INTEGRITY_MEDIUM_SID = 'S-1-16-8192';

export function isElevatedToken(whoamiGroupsCsv: string): boolean {
  return (
    whoamiGroupsCsv.includes(INTEGRITY_HIGH_SID) || whoamiGroupsCsv.includes(INTEGRITY_SYSTEM_SID)
  );
}

export function isFilteredToken(whoamiGroupsCsv: string): boolean {
  return !isElevatedToken(whoamiGroupsCsv);
}
