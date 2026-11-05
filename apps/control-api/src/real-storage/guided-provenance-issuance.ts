// R02-E (#348): externally issued, operator-signed Guided database
// provenance receipt. The runtime ControlBackend may VERIFY this receipt but
// must never mint it: this module contains NO signing path and NO private-key
// import, and the returned authority adapter accepts no key material of any
// kind. The Ed25519 private key lives only on the operator issuance side
// (scripts/issue-guided-provenance.ts) under an elevated, operator-only
// Windows identity, outside the repository, SQLite database, database
// directory and every runtime environment.
//
// Trust derives from TWO independent anchors, never from the receipt or
// trust-anchor contents, an environment variable, a DB marker, a
// same-directory sidecar secret or an unpinned public key:
//  1. an operator-pinned SPKI SHA-256 fingerprint (supplied by the #269
//     production composition as an explicit constant), and
//  2. a Windows owner/ACL policy scan requiring Administrators/SYSTEM
//     ownership of the whole trust tree, verified before any receipt is
//     accepted (probe failure fails closed).
import { execFileSync } from 'node:child_process';
import { createHash, createPublicKey, timingSafeEqual, verify } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, isAbsolute, resolve, sep } from 'node:path';
import { canonicalJson } from '@shun/contracts';
import {
  GUIDED_SCHEMA_VERSION,
  type GuidedProvenanceAuthority,
} from '../../../../packages/domain-host/src/guided/guided-provenance-authority.ts';

/** Signed envelope schema bound into every signature. */
export const GUIDED_PROVENANCE_RECEIPT_SCHEMA = 'shun.guided-provenance-receipt/1';
/** Trust anchor file schema. The anchor's own contents establish no trust. */
export const GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA = 'shun.guided-provenance-trust/1';
export const GUIDED_PROVENANCE_TRUST_ANCHOR_FILE = 'trust-anchor.json';
export const GUIDED_PROVENANCE_RECEIPTS_SUBDIR = 'receipts';
export const GUIDED_PROVENANCE_DATABASE_ID_PATTERN = /^guidedb-[0-9a-f]{32}$/;
export const GUIDED_PROVENANCE_SIGNATURE_PATTERN = /^[a-zA-Z0-9+/]{86}==$/;
export const GUIDED_PROVENANCE_DIGEST_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Fixed default runtime trust directory, baked into source like the
 * executor authority store — never argv/env controlled. Production wiring
 * (#269) uses this default; tests inject a temp directory explicitly.
 */
export function defaultGuidedProvenanceTrustDirectory(): string {
  return 'C:\\ProgramData\\Shun\\authority\\guided-provenance';
}

function reject(reason: string): never {
  throw new Error(`GUIDED_PROVENANCE_${reason}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Canonical lowercase absolute form every binding compares against. */
export function canonicalGuidedDatabasePath(databasePath: string): string {
  if (typeof databasePath !== 'string' || !databasePath) reject('DATABASE_PATH_REQUIRED');
  const canonical = resolve(databasePath).toLowerCase();
  if (!isAbsolute(canonical)) reject('DATABASE_PATH_NOT_ABSOLUTE');
  return canonical;
}

/** Receipt file name for one canonical database path (content-addressed). */
export function guidedReceiptFileName(canonicalDatabasePath: string): string {
  return `${createHash('sha256')
    .update(canonicalGuidedDatabasePath(canonicalDatabasePath), 'utf8')
    .digest('hex')}.json`;
}

export interface GuidedReceiptBody {
  readonly schema: typeof GUIDED_PROVENANCE_RECEIPT_SCHEMA;
  readonly schemaVersion: number;
  readonly schemaDigest: string;
  readonly databaseId: string;
  readonly databasePath: string;
  readonly issuedAtUnixMs: number;
}

export interface GuidedReceiptEnvelope extends GuidedReceiptBody {
  readonly signature: string;
}

const ENVELOPE_FIELDS = [
  'databaseId',
  'databasePath',
  'issuedAtUnixMs',
  'schema',
  'schemaDigest',
  'schemaVersion',
  'signature',
] as const;

/**
 * Canonical signing bytes. The schema field inside the body provides domain
 * separation; the exact field set is pinned by ENVELOPE_FIELDS checks.
 */
export function buildGuidedReceiptSigningBytes(body: GuidedReceiptBody): string {
  return canonicalJson(body);
}

/** SPKI SHA-256 of an Ed25519 public key PEM; throws coded key errors. */
export function guidedPublicKeySpkiSha256(publicKeyPem: string): string {
  let key: ReturnType<typeof createPublicKey>;
  try {
    key = createPublicKey(publicKeyPem);
  } catch {
    reject('TRUST_PUBLIC_KEY_INVALID');
  }
  if (key.asymmetricKeyType !== 'ed25519') reject('TRUST_PUBLIC_KEY_NOT_ED25519');
  return createHash('sha256')
    .update(key.export({ type: 'spki', format: 'der' }))
    .digest('hex');
}

/**
 * Strict parse of one signed receipt envelope. Throws a coded
 * GUIDED_PROVENANCE_* error for every malformed/unknown/extra field; returns
 * the parsed envelope only when the shape is exact.
 */
export function parseGuidedReceiptEnvelope(raw: unknown): GuidedReceiptEnvelope {
  if (!isRecord(raw)) reject('RECEIPT_MALFORMED');
  if (Object.keys(raw).sort().join('|') !== [...ENVELOPE_FIELDS].sort().join('|')) {
    reject('RECEIPT_MALFORMED');
  }
  if (
    raw.schema !== GUIDED_PROVENANCE_RECEIPT_SCHEMA ||
    typeof raw.schemaVersion !== 'number' ||
    !Number.isInteger(raw.schemaVersion) ||
    typeof raw.schemaDigest !== 'string' ||
    !GUIDED_PROVENANCE_DIGEST_PATTERN.test(raw.schemaDigest) ||
    typeof raw.databaseId !== 'string' ||
    !GUIDED_PROVENANCE_DATABASE_ID_PATTERN.test(raw.databaseId) ||
    typeof raw.databasePath !== 'string' ||
    !raw.databasePath ||
    typeof raw.issuedAtUnixMs !== 'number' ||
    !Number.isInteger(raw.issuedAtUnixMs) ||
    raw.issuedAtUnixMs < 0 ||
    typeof raw.signature !== 'string' ||
    !GUIDED_PROVENANCE_SIGNATURE_PATTERN.test(raw.signature)
  ) {
    reject('RECEIPT_MALFORMED');
  }
  return raw as unknown as GuidedReceiptEnvelope;
}

export interface GuidedReceiptExpectations {
  readonly canonicalDatabasePath: string;
  readonly schemaVersion: number;
  readonly schemaDigest: string;
}

/**
 * Verify one signed envelope against an Ed25519 public key and every bound
 * expectation (canonical path, schema generation, exact DDL digest). A
 * copied receipt, a moved database, a schema drift or a forged signature all
 * fail closed here.
 */
export function verifyGuidedProvenanceEnvelope(
  raw: unknown,
  publicKeyPem: string,
  expectations: GuidedReceiptExpectations,
): GuidedReceiptEnvelope {
  const envelope = parseGuidedReceiptEnvelope(raw);
  const canonicalPath = canonicalGuidedDatabasePath(envelope.databasePath);
  if (canonicalPath !== canonicalGuidedDatabasePath(expectations.canonicalDatabasePath)) {
    reject('RECEIPT_DATABASE_PATH_MISMATCH');
  }
  if (envelope.schemaVersion !== expectations.schemaVersion) reject('RECEIPT_SCHEMA_MISMATCH');
  if (envelope.schemaDigest !== expectations.schemaDigest) reject('RECEIPT_SCHEMA_MISMATCH');
  let key: ReturnType<typeof createPublicKey>;
  try {
    key = createPublicKey(publicKeyPem);
  } catch {
    reject('TRUST_PUBLIC_KEY_INVALID');
  }
  if (key.asymmetricKeyType !== 'ed25519') reject('TRUST_PUBLIC_KEY_NOT_ED25519');
  let valid = false;
  try {
    const { signature, ...body } = envelope;
    valid = verify(
      null,
      Buffer.from(buildGuidedReceiptSigningBytes(body), 'utf8'),
      key,
      Buffer.from(signature, 'base64'),
    );
  } catch {
    valid = false;
  }
  if (!valid) reject('RECEIPT_SIGNATURE_INVALID');
  return envelope;
}

export interface GuidedTrustAnchor {
  readonly schema: typeof GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA;
  readonly publicKeyPem: string;
  readonly spkiSha256: string;
}

/** Read + strictly parse the trust anchor file (contents establish no trust). */
export function readGuidedTrustAnchor(trustDir: string): GuidedTrustAnchor {
  let rawText: string;
  try {
    rawText = readFileSync(resolve(trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE), 'utf8');
  } catch {
    reject('TRUST_ANCHOR_MISSING');
  }
  let raw: unknown;
  try {
    raw = JSON.parse(rawText);
  } catch {
    reject('TRUST_ANCHOR_MALFORMED');
  }
  if (
    !isRecord(raw) ||
    raw.schema !== GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA ||
    typeof raw.publicKeyPem !== 'string' ||
    !raw.publicKeyPem ||
    typeof raw.spkiSha256 !== 'string' ||
    !GUIDED_PROVENANCE_DIGEST_PATTERN.test(raw.spkiSha256)
  ) {
    reject('TRUST_ANCHOR_MALFORMED');
  }
  const anchor = raw as unknown as GuidedTrustAnchor;
  // Consistency only: trust comes from the pinned fingerprint + ACL, and
  // the anchor must at least describe the key it carries.
  if (guidedPublicKeySpkiSha256(anchor.publicKeyPem) !== anchor.spkiSha256) {
    reject('TRUST_ANCHOR_INCONSISTENT');
  }
  return anchor;
}

/** Complete Windows DACL allow/deny entry, including inherited ACEs. */
export interface GuidedTrustAccessRule {
  readonly identitySid: string | null;
  readonly rightsMask: number;
  readonly accessType: 'Allow' | 'Deny';
  readonly isInherited: boolean;
}
export interface GuidedTrustAclEntry {
  readonly path: string;
  readonly ownerSid: string | null;
  readonly accessRules: readonly GuidedTrustAccessRule[];
}
export type GuidedTrustAclSnapshot = ReadonlyArray<GuidedTrustAclEntry>;
export type GuidedAclInspector = (
  trustDir: string,
  extraPaths: readonly string[],
) => GuidedTrustAclSnapshot | undefined;
const PRIVILEGED_OWNER_SIDS = new Set(['S-1-5-18', 'S-1-5-32-544']);
// Write/create/append/attributes/delete/write-DAC/take-ownership and generic write/all.
const DANGEROUS_WRITE_MASK =
  0x00000002 | 0x00000004 | 0x00000010 | 0x00000040 |
  0x00000100 | 0x00010000 | 0x00040000 | 0x00080000 |
  0x10000000 | 0x40000000;

/** Read-only, terminating whole-tree Get-Acl: no partial scan counts as success. */
export function inspectWindowsGuidedTrustAcl(
  trustDir: string,
  extraPaths: readonly string[] = [],
): GuidedTrustAclSnapshot | undefined {
  if (process.platform !== 'win32') return undefined;
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  const powershell = resolve(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const script = [
    '$ErrorActionPreference = "Stop"',
    '$root = $env:SHUN_GUIDED_ACL_ROOT',
    'if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "TRUST_ROOT_MISSING" }',
    '$paths = New-Object System.Collections.Generic.List[string]',
    '$paths.Add($root)',
    'Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop | ForEach-Object { $paths.Add($_.FullName) }',
    'foreach ($extra in @($env:SHUN_GUIDED_ACL_EXTRA -split ";")) {',
    '  if ($extra -and -not $paths.Contains($extra)) { $paths.Add($extra) }',
    '}',
    '$rows = foreach ($p in $paths) {',
    '  $acl = Get-Acl -LiteralPath $p -ErrorAction Stop',
    '  $owner = New-Object System.Security.Principal.NTAccount($acl.Owner)',
    '  $ownerSid = $owner.Translate([System.Security.Principal.SecurityIdentifier]).Value',
    '  $rules = @($acl.Access | ForEach-Object {',
    '    [pscustomobject]@{',
    '      identitySid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value',
    '      rightsMask = [int64]$_.FileSystemRights',
    '      accessType = $_.AccessControlType.ToString()',
    '      isInherited = [bool]$_.IsInherited',
    '    }',
    '  })',
    '  [pscustomobject]@{ path = $p; ownerSid = $ownerSid; accessRules = $rules }',
    '}',
    '$rows | ConvertTo-Json -Compress -Depth 8',
  ].join('; ');
  const env = { ...process.env };
  env.SHUN_GUIDED_ACL_ROOT = trustDir;
  env.SHUN_GUIDED_ACL_EXTRA = extraPaths.join(';');
  delete env.PSModulePath;
  try {
    const out = execFileSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', script], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 30_000,
      env,
      maxBuffer: 4 * 1024 * 1024,
    }).trim();
    const decoded: unknown = JSON.parse(out);
    const rows = Array.isArray(decoded) ? decoded : [decoded];
    return rows.length > 0 ? (rows as GuidedTrustAclEntry[]) : undefined;
  } catch {
    return undefined;
  }
}

/** Owners AND effective writable DACL entries must meet the pinned policy. */
export function assessGuidedTrustProtection(
  trustDir: string,
  receiptPaths: readonly string[],
  snapshot?: GuidedTrustAclSnapshot,
): string[] {
  const rows = snapshot ?? inspectWindowsGuidedTrustAcl(trustDir, receiptPaths);
  if (!rows) return ['guided trust ACL/DACL probe failed (fail closed)'];
  const reasons: string[] = [];
  const norm = (path: string): string => resolve(path).toLowerCase();
  const required = [
    trustDir,
    resolve(trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE),
    resolve(trustDir, GUIDED_PROVENANCE_RECEIPTS_SUBDIR),
    ...receiptPaths,
  ].filter((path) => existsSync(path));
  const seen = new Set<string>();
  for (const row of rows) {
    if (
      !row ||
      typeof row.path !== 'string' ||
      typeof row.ownerSid !== 'string' ||
      !PRIVILEGED_OWNER_SIDS.has(row.ownerSid) ||
      !Array.isArray(row.accessRules)
    ) {
      reasons.push('guided trust object has invalid owner or incomplete DACL snapshot');
      continue;
    }
    const key = norm(row.path);
    if (seen.has(key)) reasons.push('guided trust ACL scan has duplicate objects');
    seen.add(key);
    try {
      assertGuidedRegularCanonicalPath(row.path, 'TRUST_PATH_UNTRUSTED');
    } catch {
      reasons.push('guided trust ACL scan contains symlink/reparse/alias');
    }
    for (const rule of row.accessRules) {
      if (
        !rule ||
        typeof rule.identitySid !== 'string' ||
        !Number.isSafeInteger(rule.rightsMask) ||
        (rule.accessType !== 'Allow' && rule.accessType !== 'Deny') ||
        typeof rule.isInherited !== 'boolean'
      ) {
        reasons.push('guided trust DACL contains malformed or untranslatable rule');
        continue;
      }
      if (
        rule.accessType === 'Allow' &&
        !PRIVILEGED_OWNER_SIDS.has(rule.identitySid) &&
        ((rule.rightsMask | 0) & DANGEROUS_WRITE_MASK) !== 0
      ) {
        reasons.push('guided trust DACL grants non-privileged write/modify/delete/ACL-control');
      }
    }
  }
  for (const path of required) {
    if (!seen.has(norm(path))) reasons.push('guided trust ACL scan is incomplete: ' + path);
  }
  return reasons;
}

/**
 * Refuse alias/symlink/reparse forms: the path must already be canonical
 * (realpath === resolved path, case-insensitive on Windows) and must not be
 * a symbolic link itself.
 */
export function assertGuidedRegularCanonicalPath(path: string, code: string): string {
  const canonical = resolve(path);
  const info = lstatSync(canonical);
  if (info.isSymbolicLink()) reject(code);
  const real = realpathSync(canonical);
  if (real.toLowerCase() !== canonical.toLowerCase()) reject(`${code}_ALIAS`);
  return canonical;
}

/** Refuse a path that falls inside any protected root. */
export function assertGuidedPathOutside(
  path: string,
  roots: readonly string[],
  code: string,
): void {
  const canonical = resolve(path).toLowerCase();
  for (const root of roots) {
    const base = resolve(root).toLowerCase();
    if (canonical === base || canonical.startsWith(`${base}${sep}`)) reject(code);
  }
}

/** An issuer key must never live in scopes the runtime or repo can reach. */
export function assertGuidedPrivateKeyScope(
  issuerKeyPath: string,
  workspaceRoot: string,
  databasePath?: string,
  trustDir?: string,
  testOnlyAllowTemporaryKey = false,
): void {
  const forbiddenRoots = [
    workspaceRoot,
    defaultGuidedProvenanceTrustDirectory(),
    resolve(homedir(), '.shun'),
    ...(databasePath ? [dirname(resolve(databasePath))] : []),
    ...(trustDir ? [trustDir] : []),
    ...(!testOnlyAllowTemporaryKey ? [tmpdir()] : []),
  ];
  assertGuidedPathOutside(issuerKeyPath, forbiddenRoots, 'ISSUER_KEY_SCOPE_REFUSED');
}

/**
 * Atomically persist one pre-issued receipt envelope. Operator side only.
 * `overwrite: false` (the default) refuses to replace an existing receipt:
 * a schema/path change requires an explicit operator decision, never a
 * silent refresh.
 */
export function writeGuidedReceiptAtomically(
  trustDir: string,
  canonicalDatabasePath: string,
  envelope: GuidedReceiptEnvelope,
  options: { readonly overwrite?: boolean } = {},
): string {
  const receiptsDir = resolve(trustDir, GUIDED_PROVENANCE_RECEIPTS_SUBDIR);
  mkdirSync(receiptsDir, { recursive: true });
  const destination = resolve(receiptsDir, guidedReceiptFileName(canonicalDatabasePath));
  if (options.overwrite !== true && existsSync(destination)) {
    reject('ISSUER_RECEIPT_ALREADY_EXISTS');
  }
  const tmp = `${destination}.issuer-${process.pid}.tmp`;
  let written = false;
  try {
    const fd = openSync(tmp, 'wx', 0o600);
    try {
      writeFileSync(fd, `${JSON.stringify(envelope)}\n`, 'utf8');
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    if (options.overwrite === true) rmSync(destination, { force: true });
    renameSync(tmp, destination);
    written = true;
  } finally {
    if (!written) rmSync(tmp, { force: true });
  }
  return destination;
}

/** List every receipt file currently provisioned under a trust directory. */
export function listGuidedReceiptPaths(trustDir: string): string[] {
  const receiptsDir = resolve(trustDir, GUIDED_PROVENANCE_RECEIPTS_SUBDIR);
  let names: string[];
  try {
    names = readdirSync(receiptsDir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  return names.filter((name) => name.endsWith('.json')).map((name) => resolve(receiptsDir, name));
}

export interface ExternalGuidedAuthorityOptions {
  /**
   * Fixed trust directory. Defaults to the baked-in ProgramData location;
   * only tests pass an override.
   */
  readonly trustDir?: string;
  /**
   * Operator-pinned SPKI SHA-256 fingerprint of the Ed25519 trust anchor.
   * REQUIRED — there is deliberately no default pin, so an unpinned public
   * key can never establish trust. Production composition (#269) supplies
   * the real constant.
   */
  readonly pinnedSpkiSha256: string;
  /** ACL snapshot injector (tests). Production uses the real Windows scan. */
  readonly inspectAcl?: GuidedAclInspector;
}

/**
 * Build the production GuidedProvenanceAuthority: a verify-only runtime
 * adapter. `issueFreshReceipt` retrieves and validates the pre-issued
 * receipt for the exact canonical path + schema digest (it NEVER signs);
 * `verifyReceipt` re-checks a persisted DB receipt row against the external
 * signed envelope and the pinned public key. Missing/malformed/mismatched
 * material fails closed with stable GUIDED_PROVENANCE_* codes — the
 * development authority is never a fallback.
 */
export function createExternalGuidedProvenanceAuthority(
  options: ExternalGuidedAuthorityOptions,
): GuidedProvenanceAuthority {
  const { pinnedSpkiSha256, inspectAcl } = options;
  if (
    typeof pinnedSpkiSha256 !== 'string' ||
    !GUIDED_PROVENANCE_DIGEST_PATTERN.test(pinnedSpkiSha256)
  ) {
    reject('TRUST_PIN_REQUIRED');
  }
  const trustDir = options.trustDir ?? defaultGuidedProvenanceTrustDirectory();

  // Verified lazily once per adapter instance: trust anchor pin + ACL policy.
  let initialized: { publicKeyPem: string } | undefined;
  const init = (): { publicKeyPem: string } => {
    if (initialized) return initialized;
    const anchor = readGuidedTrustAnchor(trustDir);
    const actual = guidedPublicKeySpkiSha256(anchor.publicKeyPem);
    if (!timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(pinnedSpkiSha256, 'hex'))) {
      reject('TRUST_PUBLIC_KEY_PIN_MISMATCH');
    }
    const reasons = assessGuidedTrustProtection(
      trustDir,
      listGuidedReceiptPaths(trustDir),
      inspectAcl ? inspectAcl(trustDir, listGuidedReceiptPaths(trustDir)) : undefined,
    );
    if (reasons.length > 0) reject(`TRUST_ACL_UNPROTECTED:${reasons.join(' | ')}`);
    initialized = { publicKeyPem: anchor.publicKeyPem };
    return initialized;
  };

  const receiptPathFor = (canonicalPath: string): string =>
    resolve(trustDir, GUIDED_PROVENANCE_RECEIPTS_SUBDIR, guidedReceiptFileName(canonicalPath));

  const readEnvelope = (canonicalPath: string): GuidedReceiptEnvelope => {
    let text: string;
    try {
      text = readFileSync(receiptPathFor(canonicalPath), 'utf8');
    } catch {
      reject('AUTHORITY_UNAVAILABLE');
    }
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      reject('RECEIPT_MALFORMED');
    }
    return parseGuidedReceiptEnvelope(raw);
  };

  return {
    issueFreshReceipt({ canonicalDatabasePath, schemaDigest }) {
      const canonicalPath = canonicalGuidedDatabasePath(canonicalDatabasePath);
      const { publicKeyPem } = init();
      if (
        typeof schemaDigest !== 'string' ||
        !GUIDED_PROVENANCE_DIGEST_PATTERN.test(schemaDigest)
      ) {
        reject('RECEIPT_SCHEMA_MISMATCH');
      }
      const envelope = readEnvelope(canonicalPath);
      const body = verifyGuidedProvenanceEnvelope(envelope, publicKeyPem, {
        canonicalDatabasePath: canonicalPath,
        schemaVersion: GUIDED_SCHEMA_VERSION,
        schemaDigest,
      });
      // The G6 receipt row carries the signature as its receiptDigest: the
      // persisted row alone is cryptographically self-verifying later.
      return {
        schemaVersion: body.schemaVersion,
        schemaDigest: body.schemaDigest,
        databaseId: body.databaseId,
        issuedAtUnixMs: body.issuedAtUnixMs,
        receiptDigest: envelope.signature,
      };
    },
    verifyReceipt(receipt: unknown, canonicalDatabasePath: string) {
      try {
        const canonicalPath = canonicalGuidedDatabasePath(canonicalDatabasePath);
        if (!isRecord(receipt)) return false;
        const keys = Object.keys(receipt).sort().join('|');
        if (
          keys !==
          ['databaseId', 'issuedAtUnixMs', 'receiptDigest', 'schemaDigest', 'schemaVersion'].join(
            '|',
          )
        ) {
          return false;
        }
        if (
          typeof receipt.schemaVersion !== 'number' ||
          typeof receipt.schemaDigest !== 'string' ||
          typeof receipt.databaseId !== 'string' ||
          typeof receipt.issuedAtUnixMs !== 'number' ||
          typeof receipt.receiptDigest !== 'string' ||
          !GUIDED_PROVENANCE_SIGNATURE_PATTERN.test(receipt.receiptDigest)
        ) {
          return false;
        }
        const { publicKeyPem } = init();
        const envelope = readEnvelope(canonicalPath);
        // The external envelope must describe exactly the row it vouches
        // for; then the row's own signature is verified independently.
        if (
          envelope.databaseId !== receipt.databaseId ||
          envelope.schemaDigest !== receipt.schemaDigest ||
          envelope.schemaVersion !== receipt.schemaVersion ||
          envelope.issuedAtUnixMs !== receipt.issuedAtUnixMs ||
          envelope.signature !== receipt.receiptDigest
        ) {
          return false;
        }
        verifyGuidedProvenanceEnvelope(envelope, publicKeyPem, {
          canonicalDatabasePath: canonicalPath,
          schemaVersion: GUIDED_SCHEMA_VERSION,
          schemaDigest: receipt.schemaDigest,
        });
        return true;
      } catch {
        return false;
      }
    },
  };
}
