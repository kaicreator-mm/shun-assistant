// File-backed reference substrate for the privileged boundary's trusted
// inputs (L2 §4.6.1 L3 latitude): current authority/policy/revocation state,
// grant integrity, the pinned helper identity and the trusted plan source.
//
// Layout (one directory, the "authority store"):
//   current-authority.json   CurrentAuthorityState — CURRENT | UNRESOLVABLE
//   grant-hmac.key           base64 32-byte HMAC key (authority-held)
//   helper-pin.json          pinned helper/relay identity + revision
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
 * Privileged-side verifier for `validateGrantPresentation`. Deliberately
 * returns false on ANY substrate failure (missing/corrupt key file): an
 * unverifiable envelope is an unauthentic grant, and the boundary never
 * degrades to "presented, therefore fine".
 */
export function hmacGrantIntegrityVerifier(authorityDir: string) {
  return (grant: AuthorizationGrant, envelope: GrantIntegrity): boolean => {
    if (envelope.scheme !== 'HMAC_SHA256') return false;
    let keyBase64: string;
    try {
      keyBase64 = readFileSync(join(authorityDir, 'grant-hmac.key'), 'utf8').trim();
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
