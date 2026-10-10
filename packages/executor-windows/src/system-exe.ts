// SystemRoot-anchored system executables. Anything the executor or the
// privileged helper spawns MUST be resolved against SystemRoot, never against
// PATH: an attacker-controlled launcher spawns both and can prepend its own
// directory to PATH, so an unanchored 'whoami.exe' (or reg.exe/powershell.exe/
// taskkill.exe) would let it forge token/elevation observations. Same
// convention as reg.exe/powershell.exe/taskkill.exe spawns elsewhere.
import { join } from 'node:path';

function systemRoot(): string {
  return process.env.SystemRoot ?? 'C:\\Windows';
}

/** <SystemRoot>\System32\whoami.exe — the token-state probe. */
export function systemWhoamiExe(): string {
  return join(systemRoot(), 'System32', 'whoami.exe');
}
