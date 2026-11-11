/**
 * R02-B G6: trusted provenance authority contract for the durable Guided
 * Host boundary.
 *
 * The G5 schema marker was self-asserted: a public SHA-256 formula over
 * schema_version and initialized_at, stored inside the same SQLite database
 * it vouched for. Any legacy database could mint the same marker and claim
 * G5 provenance. G6 replaces that with an INJECTED authority which lives
 * OUTSIDE the database and keeps its own protected trust record, so:
 *
 *  - a marker or receipt copied into another database (different identity
 *    or path) cannot be verified, because the authority binds every issued
 *    database identifier to exactly one canonical database path;
 *  - a forged receipt without the authority secret cannot produce a valid
 *    receipt digest;
 *  - the trust root is never the marker contents, an environment variable,
 *    or a key stored beside/in the database.
 *
 * Production wiring (apps/control-api main.ts / composition) is owned by
 * R02-E (#269) and is intentionally NOT part of the R02-B write set. The
 * `developmentGuidedProvenanceAuthority` below exists so that test and
 * scratch databases under the operating system's temp directory keep
 * working; it refuses every path outside the temp directory, so a
 * production Guided database without a real injected authority fails
 * closed instead of silently trusting a development key.
 */
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { resolve, sep } from 'node:path';

/** Current Guided durable schema generation bound into every receipt. */
export const GUIDED_SCHEMA_VERSION = 6;

/** Authenticated provenance record for one Guided database. */
export type GuidedDatabaseReceipt = {
  /** Must equal GUIDED_SCHEMA_VERSION. */
  readonly schemaVersion: number;
  /** Canonical digest of the exact expected schema definition. */
  readonly schemaDigest: string;
  /** Authority-issued identifier, unique per canonical database path. */
  readonly databaseId: string;
  readonly issuedAtUnixMs: number;
  /** Authority authentication over all fields above. */
  readonly receiptDigest: string;
};

export type GuidedProvenanceIssueInput = {
  readonly canonicalDatabasePath: string;
  readonly schemaDigest: string;
  readonly issuedAtUnixMs: number;
};

/**
 * Trust anchor contract. `issueFreshReceipt` is called exactly once per
 * canonical database path, before the fresh schema commits; the authority
 * records the binding in a protected store outside the database.
 * `verifyReceipt` re-checks a persisted receipt against that protected
 * record for the canonical path of the database being opened.
 */
export type GuidedProvenanceAuthority = {
  readonly issueFreshReceipt: (input: GuidedProvenanceIssueInput) => GuidedDatabaseReceipt;
  readonly verifyReceipt: (receipt: unknown, canonicalDatabasePath: string) => boolean;
};

export function isGuidedProvenanceAuthority(value: unknown): value is GuidedProvenanceAuthority {
  return typeof value === 'object' && value !== null &&
    typeof (value as { issueFreshReceipt?: unknown }).issueFreshReceipt === 'function' &&
    typeof (value as { verifyReceipt?: unknown }).verifyReceipt === 'function';
}

/**
 * Development-only authority. The secret below is deliberately public and
 * labeled non-production; the trust decision comes from a deterministic
 * binding of every issued databaseId to the canonical lowercase database
 * path (derived from the secret), plus a hard policy that refuses every
 * path outside the OS temp directory. Because the binding is derived, not
 * remembered, verification survives real process restarts; a database file
 * copied to a different path no longer verifies, and a forged receipt
 * cannot produce a valid digest. Production databases fail closed until
 * R02-E (#269) injects a real authority through its own write set.
 */
const DEVELOPMENT_AUTHORITY_SECRET =
  'shun-r02-b-guided-g6-development-authority-not-for-production';

function developmentReceiptDigest(
  receipt: Omit<GuidedDatabaseReceipt, 'receiptDigest'>,
): string {
  return createHash('sha256').update(
    `${DEVELOPMENT_AUTHORITY_SECRET}|${receipt.databaseId}|${receipt.schemaVersion}|` +
    `${receipt.schemaDigest}|${receipt.issuedAtUnixMs}`,
    'utf8',
  ).digest('hex');
}

function developmentDatabaseId(canonicalLowerPath: string): string {
  return `guidedb-${createHash('sha256')
    .update(`${DEVELOPMENT_AUTHORITY_SECRET}|${canonicalLowerPath}`, 'utf8')
    .digest('hex')
    .slice(0, 24)}`;
}

function isScratchPath(canonicalDatabasePath: string): boolean {
  const canonical = resolve(canonicalDatabasePath).toLowerCase();
  const tempRoot = resolve(tmpdir()).toLowerCase();
  return canonical === tempRoot || canonical.startsWith(`${tempRoot}${sep}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export const developmentGuidedProvenanceAuthority: GuidedProvenanceAuthority = {
  issueFreshReceipt({ canonicalDatabasePath, schemaDigest, issuedAtUnixMs }) {
    if (!isScratchPath(canonicalDatabasePath)) {
      throw new Error('GUIDED_PROVENANCE_DEVELOPMENT_PATH_REFUSED');
    }
    const receipt = {
      schemaVersion: GUIDED_SCHEMA_VERSION,
      schemaDigest,
      databaseId: developmentDatabaseId(resolve(canonicalDatabasePath).toLowerCase()),
      issuedAtUnixMs,
    };
    return { ...receipt, receiptDigest: developmentReceiptDigest(receipt) };
  },
  verifyReceipt(receipt: unknown, canonicalDatabasePath: string) {
    if (!isScratchPath(canonicalDatabasePath)) return false;
    if (!isRecord(receipt) ||
        receipt.schemaVersion !== GUIDED_SCHEMA_VERSION ||
        typeof receipt.databaseId !== 'string' ||
        typeof receipt.schemaDigest !== 'string' ||
        typeof receipt.issuedAtUnixMs !== 'number' ||
        typeof receipt.receiptDigest !== 'string') {
      return false;
    }
    if (receipt.databaseId !== developmentDatabaseId(resolve(canonicalDatabasePath).toLowerCase())) {
      return false;
    }
    return developmentReceiptDigest({
      schemaVersion: receipt.schemaVersion,
      schemaDigest: receipt.schemaDigest,
      databaseId: receipt.databaseId,
      issuedAtUnixMs: receipt.issuedAtUnixMs,
    }) === receipt.receiptDigest;
  },
};
