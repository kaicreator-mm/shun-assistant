// N-2 — windows.proc.exec program BYTE identity (the C12 audit's actual
// target). The plan hash binds the program PATH string only, the grant-scope
// preflight deliberately exempts the program path (frozen contracts: the
// program is "plan-pinned infrastructure" — but only its PATH was ever
// pinned), and the interpreter merely statSync+spawn: bytes swapped at the
// same path after the grant would run elevated untouched.
//
// Division of labor:
//   - pinProgram: LAUNCHER-side preflight, before any UAC work — canonical
//     real path + measured sha256 recorded in the authority store. A missing
//     or non-file program refuses here (no UAC prompt burned).
//   - verifyPinnedProgram: HELPER-side, PRE-JOURNAL (privileged boundary
//     re-verifies, never on the launcher's say-so §4.6.1) — the same
//     canonicalization + measurement, then a REQUIRED matching pin: no pin,
//     unreadable file, or byte change ⇒ refusal with nothing written.
//
// Scope honesty: this gates the PRIVILEGED surface (the elevated helper and
// its launcher preflight). The unprivileged in-process backend executes as
// the same user without elevation — no privilege gain is possible there, and
// its program identity remains plan-path-pinned as before.
//
// Honest boundary (documented, not hidden): bytes swapped BEFORE the launcher
// preflight are pinned AS-SWAPPED — the pin attests what was measured at
// provisioning time and the measured identity is recorded in the journal
// evidence. Winning that race requires writing the program file AND the
// authority store as the same user: the C06 open boundary, escalated; nothing
// in this module claims to close it.

import { createHash } from 'node:crypto';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { type ProgramPin, readProgramPin, sha256File, writeProgramPin } from './trusted-store.ts';

export type ProgramIdentityCheck =
  | { ok: true; canonicalPath: string; programSha256: string }
  | { ok: false; reason: string };

/**
 * Canonical (real) path of a program file. Reparse points resolve here, so
 * the pin key is the byte-identity anchor independent of lexical aliases.
 * The program must exist and be a regular file — a privileged proc.exec
 * target is pinned before it is ever spawned.
 */
export function canonicalProgramPath(
  programPath: string,
): { ok: true; canonicalPath: string } | { ok: false; reason: string } {
  const st = statSync(programPath, { throwIfNoEntry: false });
  if (!st) return { ok: false, reason: `program does not exist: ${programPath}` };
  if (!st.isFile()) return { ok: false, reason: `program is not a regular file: ${programPath}` };
  try {
    return { ok: true, canonicalPath: realpathSync(programPath) };
  } catch (e) {
    return {
      ok: false,
      reason: `program path does not resolve to a real path: ${programPath} (${e instanceof Error ? e.message : String(e)})`,
    };
  }
}

/**
 * LAUNCHER preflight: measure the program's bytes and record the identity
 * pin (keyed by canonical path). Re-pins on every privileged launch — an
 * intentional program update is picked up by the NEXT launch's preflight,
 * never by a mid-flight swap.
 */
export function pinProgram(
  authorityDir: string,
  programPath: string,
): { ok: true; canonicalPath: string; programSha256: string } | { ok: false; reason: string } {
  const canonical = canonicalProgramPath(programPath);
  if (!canonical.ok) return canonical;
  let programSha256: string;
  try {
    programSha256 = sha256File(canonical.canonicalPath);
  } catch (e) {
    return {
      ok: false,
      reason: `program unreadable at preflight: ${canonical.canonicalPath} (${e instanceof Error ? e.message : String(e)})`,
    };
  }
  const pin: ProgramPin = {
    schemaVersion: 'shun.executor-windows.program-pin/1',
    programPath: canonical.canonicalPath,
    programSha256,
    pinnedAt: new Date().toISOString(),
  };
  writeProgramPin(authorityDir, pin);
  return { ok: true, canonicalPath: canonical.canonicalPath, programSha256 };
}

/**
 * HELPER-side verification, run PRE-JOURNAL inside the privileged boundary:
 * re-canonicalize, re-measure, and REQUIRE a matching pin. No pin for the
 * path = unpinned = refused; any byte change after pinning = refused. A
 * refusal here writes NOTHING (the journal has not opened yet).
 */
export function verifyPinnedProgram(
  authorityDir: string,
  programPath: string,
): ProgramIdentityCheck {
  const canonical = canonicalProgramPath(programPath);
  if (!canonical.ok) return canonical;
  const pin = readProgramPin(authorityDir, canonical.canonicalPath);
  if (!pin) {
    return {
      ok: false,
      reason: `no program identity pin for ${canonical.canonicalPath} — refusing to execute an unpinned program elevated (fail closed)`,
    };
  }
  let measured: string;
  try {
    measured = createHash('sha256').update(readFileSync(canonical.canonicalPath)).digest('hex');
  } catch (e) {
    return {
      ok: false,
      reason: `program unreadable inside the privileged boundary: ${canonical.canonicalPath} (${e instanceof Error ? e.message : String(e)})`,
    };
  }
  if (measured !== pin.programSha256) {
    return {
      ok: false,
      reason: `program identity mismatch for ${canonical.canonicalPath}: measured sha256 ${measured} != pinned ${pin.programSha256} — bytes replaced after pinning, refusing elevated execution (fail closed)`,
    };
  }
  return { ok: true, canonicalPath: canonical.canonicalPath, programSha256: measured };
}
