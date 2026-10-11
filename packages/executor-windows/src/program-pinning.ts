// N-2 — windows.proc.exec program BYTE identity (the C12 audit's actual
// target). The plan hash binds the program PATH string only, the grant-scope
// preflight deliberately exempts the program path (frozen contracts: the
// program is "plan-pinned infrastructure" — but only its PATH was ever
// pinned), and the interpreter merely statSync+spawn: bytes swapped at the
// same path after the grant would run elevated untouched.
//
// Division of labor after C06 R5:
//   - pinProgram: TRUSTED PROVISIONING / authority-event helper only. A normal
//     runtime launcher MUST NOT call it because the protected anchor is
//     read-only to that token.
//   - verifyPinnedProgram: runtime launcher AND HELPER pre-journal check — both
//     canonicalize/re-measure and REQUIRE an already-provisioned matching pin.
//     No pin or byte change => refusal with no privileged effect.
//
// Scope honesty: this gates the PRIVILEGED surface (the elevated helper and
// its launcher preflight). The unprivileged in-process backend executes as
// the same user without elevation — no privilege gain is possible there, and
// its program identity remains plan-path-pinned as before.
//
// Honest boundary: pin creation/rotation is an explicit trusted provisioning
// event. Runtime code only verifies the protected record. Replacing program
// bytes after provisioning is detected both before UAC and inside the helper.

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
 * TRUSTED PROVISIONING helper: measure the program's bytes and record the
 * identity pin (keyed by canonical path). Production runtime launchers never
 * call this against the elevated-only anchor; updates require an authority
 * event/provisioning step.
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
