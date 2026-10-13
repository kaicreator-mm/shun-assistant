// T10/#75: externally issued, short-lived registry/currentness proof.
// The real ControlBackend may VERIFY this proof but must never mint it.
// Issuance keys remain outside the candidate process; an in-process digest
// or writable revision sidecar is NOT proof of a trusted registry source.
import { createPublicKey, verify } from 'node:crypto';
import { resolve } from 'node:path';
import { canonicalJson } from '@shun/contracts';
import { type RegistrySnapshot, snapshotFactsRevision } from '@shun/resolver';

const FIELDS = [
  'currentRevision',
  'expiresAt',
  'issuedAt',
  'schema',
  'signature',
  'snapshot',
  'workspace',
] as const;
export const ISSUANCE_SCHEMA = 'shun.registry-issuance/1';
export const MAX_ISSUANCE_LIFETIME_MS = 2 * 60_000;
const CLOCK_SKEW_MS = 5_000;

export interface RegistryIssuanceBody {
  readonly schema: typeof ISSUANCE_SCHEMA;
  readonly workspace: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly snapshot: RegistrySnapshot;
  readonly currentRevision: string;
}

export interface VerifiedRegistryIssuance {
  readonly snapshot: RegistrySnapshot;
  readonly currentRevision: string;
  readonly expiresAt: string;
}

function reject(reason: string): never {
  throw new Error(`REAL_STORAGE_REGISTRY_ISSUANCE_${reason}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireIso(value: unknown): number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    return reject('INVALID_TIME');
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    return reject('INVALID_TIME');
  }
  return parsed;
}

/**
 * Verify an independent Ed25519 authority's one-piece snapshot + revision.
 *
 * The input MUST come from an operator-issued atomic file with a separately
 * protected private signing key. A candidate-computed digest, even if equal,
 * is insufficient; signature and short source issuance window are mandatory.
 *
 * The calling Windows adapter must also validate source file identity/ACL and
 * compare issued environment facts with fresh host observations, refusing
 * drift rather than rewriting the proof. This function has no write path.
 */
export function verifyRegistryIssuance(
  raw: unknown,
  publicKeyPem: string,
  expectedWorkspace: string,
  nowIso: string,
): VerifiedRegistryIssuance {
  if (!isRecord(raw)) reject('MALFORMED');
  if (
    Object.keys(raw).sort().join('|') !== [...FIELDS].sort().join('|') ||
    raw.schema !== ISSUANCE_SCHEMA
  ) {
    reject('MALFORMED');
  }
  if (
    typeof raw.workspace !== 'string' ||
    !raw.workspace ||
    typeof raw.currentRevision !== 'string' ||
    !raw.currentRevision ||
    typeof raw.signature !== 'string' ||
    !/^[a-zA-Z0-9+/]{86}==$/.test(raw.signature) ||
    !isRecord(raw.snapshot)
  ) {
    reject('MALFORMED');
  }
  if (resolve(raw.workspace).toLowerCase() !== resolve(expectedWorkspace).toLowerCase()) {
    reject('WORKSPACE_MISMATCH');
  }
  const issued = requireIso(raw.issuedAt);
  const expires = requireIso(raw.expiresAt);
  const now = requireIso(nowIso);
  if (expires <= issued || expires - issued > MAX_ISSUANCE_LIFETIME_MS) {
    reject('UNBOUNDED_LIFETIME');
  }
  if (issued > now + CLOCK_SKEW_MS) reject('FUTURE');
  if (now >= expires) reject('EXPIRED');

  const snapshot = raw.snapshot as unknown as RegistrySnapshot;
  // Never treat this digest as attestation by itself: only the independent
  // source signature below can bind it to the current issued fact snapshot.
  if (raw.currentRevision !== snapshotFactsRevision(snapshot)) reject('REVISION_MISMATCH');
  const body: RegistryIssuanceBody = {
    schema: ISSUANCE_SCHEMA,
    workspace: raw.workspace,
    issuedAt: raw.issuedAt as string,
    expiresAt: raw.expiresAt as string,
    snapshot,
    currentRevision: raw.currentRevision,
  };
  let valid = false;
  try {
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== 'ed25519') reject('KEY_NOT_ED25519');
    valid = verify(
      null,
      Buffer.from(canonicalJson(body), 'utf8'),
      key,
      Buffer.from(raw.signature, 'base64'),
    );
  } catch {
    reject('SIGNATURE_INVALID');
  }
  if (!valid) reject('SIGNATURE_INVALID');
  return { snapshot, currentRevision: raw.currentRevision, expiresAt: raw.expiresAt as string };
}
