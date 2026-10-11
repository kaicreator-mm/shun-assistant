// Privileged-path environment sterilization (N-R2-1, P1).
//
// The launcher process runs with an environment a same-user attacker fully
// controls (the module header of system-exe.ts states the model: "the
// launcher ... UNTRUSTED and fully controls our inherited environment"). If
// that environment crosses a privileged spawn boundary, one UAC consent is
// total compromise: NODE_OPTIONS=--require=C:\attacker\pwn.js injects
// attacker JS into the PINED elevated node.exe before any helper self-check
// runs — every pin still verifies, because the process itself is already
// attacker-controlled. It would also defeat the C06 externalized-key
// deployment seam from inside the elevated boundary.
//
// Fix shape: every spawn on the privileged path passes an EXPLICIT MINIMAL
// environment built by privilegedSpawnEnv() — an ALLOWLIST of the variables
// Windows/PowerShell/node need to initialize, copied from the current
// process. Everything else (NODE_* interpreter directives in particular, and
// every unrecognized variable an attacker may have planted) never crosses.
// The relay re-scrubs defensively on top (belt-and-braces, pinned script).
//
// Honest boundary: the allowlist is an allowlist, not a sandbox — variables
// ON it come from the same untrusted environment. They are limited to names
// that Windows/PowerShell/node treat as inert OS configuration (paths of
// machine locations, temp dirs, CPU facts); no name on the list is
// interpreted as code or module resolution by the elevated node interpreter
// (NODE_OPTIONS/NODE_PATH and friends are structurally excluded: any key
// matching /^node$/i is dropped even if a future edit adds it to the list).

const PRIVILEGED_ENV_ALLOWLIST: readonly string[] = [
  // Windows CRT / .NET initialization (PowerShell fails to start without
  // SystemRoot on some hosts) and path basics.
  'SystemRoot',
  'windir',
  'SystemDrive',
  'ComSpec',
  'PATHEXT',
  'PATH',
  'Path',
  // Temp resolution for the relay/child (PS writes, .NET temp).
  'TEMP',
  'TMP',
  // Inert OS facts some runtimes consult at init.
  'OS',
  'NUMBER_OF_PROCESSORS',
  'PROCESSOR_ARCHITECTURE',
  'PROCESSOR_IDENTIFIER',
  'PROCESSOR_LEVEL',
  'PROCESSOR_REVISION',
  // Identity/home basics (never interpreted as code by the child).
  'COMPUTERNAME',
  'USERDOMAIN',
  'USERNAME',
  'USERPROFILE',
  'HOMEDRIVE',
  'HOMEPATH',
];

/**
 * Build the minimal environment for a privileged-path child: only
 * allowlisted names are copied from `source` (default: the current process
 * environment); everything else — unrecognized keys and, structurally, every
 * NODE_* interpreter directive — is dropped. Fail-safe by construction: an
 * allowlist cannot leak a variable that is not on it.
 */
export function privilegedSpawnEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  const allowed = new Set(PRIVILEGED_ENV_ALLOWLIST.map((name) => name.toLowerCase()));
  for (const [name, value] of Object.entries(source)) {
    if (value === undefined) continue;
    // Structural exclusion: no Node interpreter directive ever crosses the
    // privileged boundary, regardless of any future allowlist edit.
    if (/^node/i.test(name)) continue;
    if (!allowed.has(name.toLowerCase())) continue;
    env[name] = value;
  }
  // Normalize the Windows path variable to its canonical casing so PS/dll
  // resolution sees exactly one PATH entry.
  if (env.Path !== undefined || env.PATH !== undefined) {
    const merged = env.Path ?? env.PATH;
    delete env.PATH;
    delete env.Path;
    if (merged !== undefined) env.Path = merged;
  }
  return env;
}
