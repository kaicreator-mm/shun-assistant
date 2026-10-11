// File-backed reference substrate for the privileged boundary's trusted
// inputs (L2 §4.6.1 L3 latitude): current authority/policy/revocation state,
// grant integrity, the pinned helper identity and the trusted plan source.
//
// Layout (one directory, the "authority store"):
//   current-authority.json   CurrentAuthorityState — CURRENT | UNRESOLVABLE
//   grant-hmac.key           base64 32-byte HMAC key (authority-held)
//   helper-pin.json          pinned helper/relay identity + revision
//   system-tools.json        pinned binary identity of the system tools (N-1)
//   programs/<pathHash>.json pinned byte identity per proc.exec program (N-2)
//   plans/<planHash>.json    ActionPlan records (trusted plan source)
//
// Trust anchors, not security theater: on a single-user Windows host the
// store is protected by user-profile ACLs, and the HELPER resolves this
// directory from a build-time constant — never from the envelope, argv or
// environment an attacker-controlled launcher could influence (§4.6.1: the
// privileged boundary re-verifies against trusted state "never on the
// caller's say-so"). Moving or re-keying the store is an explicit authority
// event: it changes the helper bundle (build-time constant) and therefore
// requires a helper re-pin, exactly like any other helper revision.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  type ActionPlan,
  ActionPlanSchema,
  type AuthorizationGrant,
  AuthorizationGrantSchema,
  type CurrentAuthorityState,
  CurrentAuthorityStateSchema,
  canonicalJson,
  type GrantIntegrity,
} from '@shun/contracts';
import { z } from 'zod';

export const HELPER_PIN_SCHEMA_VERSION = 'shun.executor-windows.helper-pin/1';

export const HelperPinSchema = z.strictObject({
  schemaVersion: z.literal(HELPER_PIN_SCHEMA_VERSION),
  helperRevision: z.string().min(1),
  /** SHA-256 of the helper bundle file content (lowercase hex). */
  helperSha256: z.string().regex(/^[0-9a-f]{64}$/),
  /** SHA-256 of the elevation relay script content (lowercase hex). */
  relaySha256: z.string().regex(/^[0-9a-f]{64}$/),
  /**
   * SHA-256 of the node.exe interpreter the helper runs on (lowercase hex,
   * C12). The launcher chooses the interpreter path and an attacker-run
   * launcher could point it at its own node; without this pin the bundle
   * hash would be measured theater — a substituted interpreter can ignore
   * the bundle entirely. An interpreter update is an authority event: it
   * changes this pin exactly like a helper revision.
   */
  nodeExeSha256: z.string().regex(/^[0-9a-f]{64}$/),
  /**
   * The only directory root inside which the helper accepts its I/O channel
   * paths (journal/receipt/cancel/evidence). The helper runs elevated: an
   * unbounded journal/receipt path from the launcher would be an elevated
   * arbitrary-write primitive, so the anchor lives in the authority pin.
   */
  workspaceRoot: z.string().min(1),
  pinnedAt: z.string().min(1),
  note: z.string().min(1).optional(),
});
export type HelperPin = z.infer<typeof HelperPinSchema>;

export const SYSTEM_TOOLS_PIN_SCHEMA_VERSION = 'shun.executor-windows.system-tools-pin/1';

/**
 * Pinned BINARY IDENTITY of the security-relevant Windows system tools
 * (N-1): whoami.exe decides whether a token counts as elevated, reg.exe both
 * answers the C13 fixed-point probe and performs registry mutations, and
 * powershell.exe is the very host the UAC relay elevates. The C13 fixed
 * point proves nothing about WHICH BYTES answered (a self-written reg.exe in
 * a planted root can re-report itself), so authority provisioning records
 * the real tools' sha256 at the same trusted moment as the helper pin and
 * resolution (src/system-exe.ts) verifies candidates against it — missing
 * record, missing digest, or any mismatch fails closed.
 *
 * Honest boundary: a real binary COPIED elsewhere passes identity (equal
 * bytes); the machine-evidence path defeats copies by construction. The
 * record itself is same-user writable — the C06 ESCALATED boundary applies.
 */
export const SystemToolsPinSchema = z.strictObject({
  schemaVersion: z.literal(SYSTEM_TOOLS_PIN_SCHEMA_VERSION),
  /** SHA-256 of <SystemRoot>\System32\whoami.exe (lowercase hex). */
  whoamiSha256: z.string().regex(/^[0-9a-f]{64}$/),
  /** SHA-256 of <SystemRoot>\System32\reg.exe (lowercase hex). */
  regSha256: z.string().regex(/^[0-9a-f]{64}$/),
  /** SHA-256 of <SystemRoot>\System32\WindowsPowerShell\v1.0\powershell.exe (lowercase hex). */
  powershellSha256: z.string().regex(/^[0-9a-f]{64}$/),
  /** SHA-256 of <SystemRoot>\System32\taskkill.exe (lowercase hex). */
  taskkillSha256: z.string().regex(/^[0-9a-f]{64}$/),
  pinnedAt: z.string().min(1),
});
export type SystemToolsPin = z.infer<typeof SystemToolsPinSchema>;

/** Reads + parses the system-tools pin. Any absence/corruption fails closed (undefined). */
export function readSystemToolsPin(authorityDir: string): SystemToolsPin | undefined {
  const file = join(authorityDir, 'system-tools.json');
  if (!existsSync(file)) return undefined;
  try {
    return SystemToolsPinSchema.parse(JSON.parse(readFileSync(file, 'utf8')));
  } catch {
    return undefined;
  }
}

/** Authority-side provisioning write — same trusted moment as writeHelperPin. */
export function writeSystemToolsPin(authorityDir: string, pin: SystemToolsPin): void {
  mkdirSync(authorityDir, { recursive: true });
  writeFileSync(
    join(authorityDir, 'system-tools.json'),
    `${JSON.stringify(pin, null, 2)}\n`,
    'utf8',
  );
}

export const PROGRAM_PIN_SCHEMA_VERSION = 'shun.executor-windows.program-pin/1';

/**
 * Pinned BYTE IDENTITY of a windows.proc.exec program (N-2, the C12 audit's
 * actual target). The plan hash binds the program PATH string only, so bytes
 * swapped at the same path after the grant would otherwise run elevated
 * untouched. The launcher preflights every privileged proc.exec step —
 * canonical real path + measured sha256 recorded here — and the privileged
 * helper re-measures pre-journal: NO pin for the path, or any byte change
 * after pinning, refuses the run (fail closed). An interpreter update of a
 * program is exactly such a byte change and must be re-pinned by a fresh
 * launch-side measurement.
 *
 * Honest boundary: bytes swapped BEFORE the launcher's preflight are pinned
 * AS-SWAPPED (the pin attests what was measured at provisioning time; the
 * measured identity lands in the journal evidence). That race is a same-user
 * attack on the authority store itself — the C06 ESCALATED boundary.
 */
export const ProgramPinSchema = z.strictObject({
  schemaVersion: z.literal(PROGRAM_PIN_SCHEMA_VERSION),
  /** The canonical (real) program path this pin is keyed by. */
  programPath: z.string().min(1),
  /** SHA-256 of the program file content at pin time (lowercase hex). */
  programSha256: z.string().regex(/^[0-9a-f]{64}$/),
  pinnedAt: z.string().min(1),
});
export type ProgramPin = z.infer<typeof ProgramPinSchema>;

/** Deterministic store key: the lowercased canonical path, digested. */
export function programPinKey(canonicalProgramPath: string): string {
  return createHash('sha256').update(canonicalProgramPath.toLowerCase(), 'utf8').digest('hex');
}

/** Reads the pin for one canonical program path; absence/corruption fails closed (undefined). */
export function readProgramPin(
  authorityDir: string,
  canonicalPath: string,
): ProgramPin | undefined {
  const file = join(authorityDir, 'programs', `${programPinKey(canonicalPath)}.json`);
  if (!existsSync(file)) return undefined;
  try {
    return ProgramPinSchema.parse(JSON.parse(readFileSync(file, 'utf8')));
  } catch {
    return undefined;
  }
}

/** Launcher-side preflight write (per privileged proc.exec launch). */
export function writeProgramPin(authorityDir: string, pin: ProgramPin): void {
  const dir = join(authorityDir, 'programs');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, `${programPinKey(pin.programPath)}.json`),
    `${JSON.stringify(pin, null, 2)}\n`,
    'utf8',
  );
}

export function sha256File(file: string): string {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

export function sha256Text(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** Reads + parses the pin. Any absence/corruption fails closed (undefined), never a default pin. */
export function readHelperPin(authorityDir: string): HelperPin | undefined {
  const file = join(authorityDir, 'helper-pin.json');
  if (!existsSync(file)) return undefined;
  try {
    return HelperPinSchema.parse(JSON.parse(readFileSync(file, 'utf8')));
  } catch {
    return undefined;
  }
}

/** Authority-side write of a pin — an explicit authority event, never called by the executor. */
export function writeHelperPin(authorityDir: string, pin: HelperPin): void {
  mkdirSync(authorityDir, { recursive: true });
  writeFileSync(join(authorityDir, 'helper-pin.json'), `${JSON.stringify(pin, null, 2)}\n`, 'utf8');
}

/**
 * Currentness source (L2 §4.6.1): missing, unreadable or corrupt records
 * resolve to UNRESOLVABLE — never to "authentic therefore current".
 */
export class FileCurrentnessSource {
  private readonly file: string;

  constructor(file: string) {
    this.file = file;
  }

  read(): CurrentAuthorityState {
    let raw: string;
    try {
      raw = readFileSync(this.file, 'utf8');
    } catch (e) {
      return { kind: 'UNRESOLVABLE', reason: `current-authority record unreadable: ${message(e)}` };
    }
    try {
      return CurrentAuthorityStateSchema.parse(JSON.parse(raw));
    } catch (e) {
      return { kind: 'UNRESOLVABLE', reason: `current-authority record corrupt: ${message(e)}` };
    }
  }
}

export function writeCurrentAuthority(authorityDir: string, state: CurrentAuthorityState): void {
  mkdirSync(authorityDir, { recursive: true });
  writeFileSync(
    join(authorityDir, 'current-authority.json'),
    `${JSON.stringify(state, null, 2)}\n`,
    'utf8',
  );
}

// ---- HMAC grant integrity (L3 latitude: one of the three frozen schemes). ----

export function generateGrantHmacKey(): string {
  return randomBytes(32).toString('base64');
}

export function writeGrantHmacKey(authorityDir: string, keyBase64: string): void {
  mkdirSync(authorityDir, { recursive: true });
  writeFileSync(join(authorityDir, 'grant-hmac.key'), `${keyBase64}\n`, 'utf8');
}

/**
 * C06 — HMAC key location (the grant-integrity trust anchor). Default: the
 * key sits co-located in the authority store, which on a single-user Windows
 * host is writable (and readable) by the very user whose grants it protects:
 * a same-user attacker can rewrite grants AND re-sign them with the readable
 * key — the residual hole that only an independently protected trust
 * principal closes (see ESCALATED in the T04 report). What CAN be hardened
 * in scope is key EXTERNALIZATION: a deployment may move the key to a
 * protected path (ACL'd to Administrators/SYSTEM, or held by the privileged
 * authority service) and pass it in via the build define. The helper then
 * ignores any store-located key, so a rewritten grant record or a swapped
 * co-located key fails HMAC verification and the privileged boundary refuses
 * (fail closed) instead of accepting the tampered anchor.
 */
export function resolveGrantHmacKeyFile(authorityDir: string, overridePath?: string): string {
  const trimmed = overridePath?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : join(authorityDir, 'grant-hmac.key');
}

function hmacOf(keyBase64: string, grant: AuthorizationGrant): string {
  const { integrity: _omit, ...payload } = grant;
  return createHmac('sha256', Buffer.from(keyBase64, 'base64'))
    .update(canonicalJson(payload), 'utf8')
    .digest('base64');
}

/** Authority-side: derive the integrity envelope for a freshly issued grant. */
export function signGrantWithHmac(keyBase64: string, grant: AuthorizationGrant): GrantIntegrity {
  return { scheme: 'HMAC_SHA256', value: hmacOf(keyBase64, grant) };
}

/**
 * Privileged-side verifier for `validateGrantPresentation`. `keyFile` names
 * the HMAC key explicitly (resolve via resolveGrantHmacKeyFile). Deliberately
 * returns false on ANY substrate failure (missing/unreadable/corrupt key
 * file): an unverifiable envelope is an unauthentic grant, and the boundary
 * never degrades to "presented, therefore fine".
 */
export function hmacGrantIntegrityVerifier(keyFile: string) {
  return (grant: AuthorizationGrant, envelope: GrantIntegrity): boolean => {
    if (envelope.scheme !== 'HMAC_SHA256') return false;
    let keyBase64: string;
    try {
      keyBase64 = readFileSync(keyFile, 'utf8').trim();
      if (keyBase64.length === 0) return false;
    } catch {
      return false;
    }
    const expected = hmacOf(keyBase64, grant);
    // Constant-time compare; both values are base64 of 32 raw bytes.
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(envelope.value, 'utf8');
    return a.length === b.length && timingSafeEqual(a, b);
  };
}

// ---- Trusted plan source (launcher side envelope assembly). ----

export class FilePlanSource {
  private readonly plansDir: string;

  constructor(plansDir: string) {
    this.plansDir = plansDir;
  }

  byPlanHash(planHash: string): ActionPlan | undefined {
    const file = join(this.plansDir, `${planHash}.json`);
    if (!existsSync(file)) return undefined;
    try {
      const plan = ActionPlanSchema.parse(JSON.parse(readFileSync(file, 'utf8')));
      return plan;
    } catch {
      return undefined;
    }
  }
}

export function writePlanRecord(plansDir: string, plan: ActionPlan): void {
  mkdirSync(plansDir, { recursive: true });
  writeFileSync(
    join(plansDir, `${plan.planHash}.json`),
    `${JSON.stringify(plan, null, 2)}\n`,
    'utf8',
  );
}

// ---- Trusted grant source (unprivileged backend: EnvironmentBackend
// receives only the AuthorizedAction, so the grant is fetched from the
// authority store by authorizationRef, never from the caller). ----

export class FileGrantSource {
  private readonly grantsDir: string;

  constructor(grantsDir: string) {
    this.grantsDir = grantsDir;
  }

  byGrantId(grantId: string): AuthorizationGrant | undefined {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(grantId)) return undefined;
    const file = join(this.grantsDir, `${grantId}.json`);
    if (!existsSync(file)) return undefined;
    try {
      return AuthorizationGrantSchema.parse(JSON.parse(readFileSync(file, 'utf8')));
    } catch {
      return undefined;
    }
  }
}

export function writeGrantRecord(grantsDir: string, grant: AuthorizationGrant): void {
  mkdirSync(grantsDir, { recursive: true });
  writeFileSync(
    join(grantsDir, `${grant.grantId}.json`),
    `${JSON.stringify(grant, null, 2)}\n`,
    'utf8',
  );
}

function message(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
