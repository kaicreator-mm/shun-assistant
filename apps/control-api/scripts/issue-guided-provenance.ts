// R02-E (#348): trusted operator-side Guided provenance receipt issuer.
// NEVER imported or invoked by control-api's HTTP/candidate Goal path and
// never by the runtime authority adapter. Requires an already-elevated
// operator token on Windows; this script must NOT initiate UAC itself and
// performs no physical Windows effect beyond writing the trust anchor and
// receipt files it is explicitly asked to create.
//
// The Ed25519 private key is supplied ONLY to this process via
// SHUN_GUIDED_ISSUER_PRIVATE_KEY_FILE, must live outside the repository,
// workspace, database directory, trust directory and OS temp directory, and
// is never copied, logged, uploaded or read by any runtime code. The
// matching public key is published into the protected trust anchor.
import { execFileSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, randomBytes, sign } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { GUIDED_SCHEMA_VERSION } from '../../../packages/domain-host/src/guided/guided-provenance-authority.ts';
import {
  assertGuidedPrivateKeyScope,
  assertGuidedPathOutside,
  assertGuidedRegularCanonicalPath,
  assessGuidedTrustProtection,
  buildGuidedReceiptSigningBytes,
  canonicalGuidedDatabasePath,
  defaultGuidedProvenanceTrustDirectory,
  GUIDED_PROVENANCE_DIGEST_PATTERN,
  GUIDED_PROVENANCE_RECEIPT_SCHEMA,
  GUIDED_PROVENANCE_TRUST_ANCHOR_FILE,
  GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA,
  type GuidedAclInspector,
  type GuidedReceiptBody,
  type GuidedReceiptEnvelope,
  guidedPublicKeySpkiSha256,
  listGuidedReceiptPaths,
  readGuidedTrustAnchor,
  verifyGuidedProvenanceEnvelope,
  writeGuidedReceiptAtomically,
} from '../src/real-storage/guided-provenance-issuance.ts';

/**
 * Fail closed unless the current token is already elevated (High Mandatory
 * Level S-1-16-12288). This only OBSERVES the token; it never triggers a
 * UAC elevation prompt.
 */
export function assertGuidedIssuerElevated(): void {
  if (process.platform !== 'win32') throw new Error('ISSUER_REAL_WINDOWS_ONLY');
  let out: string;
  try {
    out = execFileSync('whoami.exe', ['/groups'], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 15_000,
    });
  } catch {
    throw new Error('ISSUER_ELEVATION_PROBE_FAILED');
  }
  if (!out.includes('S-1-16-12288')) throw new Error('ISSUER_NOT_ELEVATED');
}

/** Load the operator Ed25519 private key and prove it matches the public key. */
export function loadGuidedIssuerPrivateKey(
  privateKeyPath: string,
  expectedPublicKeyPem: string,
): { readonly privateKeyPem: string } {
  let privateKeyPem: string;
  try {
    privateKeyPem = readFileSync(privateKeyPath, 'utf8');
  } catch {
    throw new Error('ISSUER_PRIVATE_KEY_UNREADABLE');
  }
  let privateKey: ReturnType<typeof createPrivateKey>;
  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch {
    throw new Error('ISSUER_PRIVATE_KEY_INVALID');
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('ISSUER_KEY_NOT_ED25519');
  const derived = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const expected = createPublicKey(expectedPublicKeyPem).export({ type: 'spki', format: 'der' });
  if (!Buffer.from(derived).equals(Buffer.from(expected))) {
    throw new Error('ISSUER_OPERATOR_PUBLIC_KEY_MISMATCH');
  }
  // Never retain parsed key objects longer than necessary; callers sign and
  // drop. The PEM itself is never logged or echoed.
  return { privateKeyPem };
}

/** Strict, no-alias validation of the database path being provisioned. */
export function assertGuidedIssuerDatabasePath(
  databasePath: string,
  workspaceRoot: string,
): string {
  if (typeof databasePath !== 'string' || !databasePath) {
    throw new Error('ISSUER_DATABASE_PATH_REQUIRED');
  }
  const canonical = resolve(databasePath);
  if (!existsSync(canonical)) {
    // The DB file may legitimately not exist yet (provisioning precedes
    // first open); its parent must be real, regular and protected-scope.
    assertGuidedRegularCanonicalPath(dirname(canonical), 'ISSUER_DATABASE_PARENT_UNTRUSTED');
  } else {
    assertGuidedRegularCanonicalPath(canonical, 'ISSUER_DATABASE_PATH_UNTRUSTED');
  }
  const lower = canonical.toLowerCase();
  for (const root of [workspaceRoot, defaultGuidedProvenanceTrustDirectory()]) {
    const base = resolve(root).toLowerCase();
    if (lower === base || lower.startsWith(`${base}\\`) || lower.startsWith(`${base}/`)) {
      throw new Error('ISSUER_DATABASE_PATH_INSIDE_FORBIDDEN_SCOPE');
    }
  }
  return canonicalGuidedDatabasePath(canonical);
}

export interface GuidedIssuanceInput {
  readonly databasePath: string;
  readonly schemaDigest: string;
  readonly privateKeyPath: string;
  readonly workspaceRoot: string;
  readonly trustDir?: string;
  readonly issuedAtUnixMs?: number;
  readonly databaseId?: string;
  /** ACL snapshot injector (tests). Production uses the real Windows scan. */
  readonly inspectAcl?: GuidedAclInspector;
  /** Test-only ephemeral key exception: CLI never supplies this flag. */
  readonly testOnlyAllowTemporaryKey?: boolean;
}

export interface GuidedIssuanceResult {
  readonly databaseId: string;
  readonly receiptPath: string;
  readonly trustAnchorPath: string;
  readonly spkiSha256: string;
  readonly envelope: GuidedReceiptEnvelope;
}

/**
 * Provision (or continue) the protected trust anchor and issue one receipt.
 * Refuses reparse/symlink aliases, unprotected or forbidden scopes, schema
 * digest drift, and any overwrite of existing records. Atomic writes only.
 * Throws coded ISSUER_* / GUIDED_PROVENANCE_* errors; never logs key
 * material.
 */
export function issueGuidedProvenanceReceipt(input: GuidedIssuanceInput): GuidedIssuanceResult {
  if (!GUIDED_PROVENANCE_DIGEST_PATTERN.test(input.schemaDigest)) {
    throw new Error('ISSUER_SCHEMA_DIGEST_INVALID');
  }
  const workspaceRoot = resolve(input.workspaceRoot);
  const trustDir =
    input.trustDir === undefined
      ? defaultGuidedProvenanceTrustDirectory()
      : assertGuidedRegularCanonicalPath(input.trustDir, 'ISSUER_TRUST_DIR_UNTRUSTED');
  const canonicalDbPath = assertGuidedIssuerDatabasePath(input.databasePath, workspaceRoot);
  // Disjoint trust and database roots, even for a directly injected test path.
  assertGuidedPathOutside(canonicalDbPath, [trustDir], 'ISSUER_DATABASE_INSIDE_TRUST_DIR');
  assertGuidedPathOutside(trustDir, [dirname(canonicalDbPath)], 'ISSUER_TRUST_INSIDE_DATABASE_DIR');

  const privateKeyPath = assertGuidedRegularCanonicalPath(
    input.privateKeyPath,
    'ISSUER_PRIVATE_KEY_PATH_UNTRUSTED',
  );
  assertGuidedPrivateKeyScope(
    privateKeyPath,
    workspaceRoot,
    canonicalDbPath,
    trustDir,
    input.testOnlyAllowTemporaryKey === true && input.inspectAcl !== undefined,
  );

  // The trust tree itself must be alias-free and outside every forbidden
  // scope before anything is written into it.
  if (existsSync(trustDir)) {
    assertGuidedRegularCanonicalPath(trustDir, 'ISSUER_TRUST_DIR_UNTRUSTED');
  } else {
    mkdirSync(trustDir, { recursive: true });
    const created = realpathSync(trustDir);
    if (created.toLowerCase() !== trustDir.toLowerCase()) {
      rmSync(trustDir, { recursive: true, force: true });
      throw new Error('ISSUER_TRUST_DIR_ALIAS');
    }
  }

  const anchorPath = resolve(trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE);
  let publicKeyPem: string;
  if (existsSync(anchorPath)) {
    const anchor = readGuidedTrustAnchor(trustDir);
    publicKeyPem = anchor.publicKeyPem;
  } else {
    // First provisioning publishes the operator's public key. The private
    // key must be outside every forbidden scope (checked above); its public
    // half is derived here WITHOUT echoing anything secret.
    const probe = readFileSync(privateKeyPath, 'utf8');
    const privateKey = createPrivateKey(probe);
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('ISSUER_KEY_NOT_ED25519');
    publicKeyPem = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
    const anchor = {
      schema: GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA,
      publicKeyPem,
      spkiSha256: guidedPublicKeySpkiSha256(publicKeyPem),
    };
    writeGuidedFileAtomic(anchorPath, `${JSON.stringify(anchor)}\n`);
  }

  const { privateKeyPem } = loadGuidedIssuerPrivateKey(privateKeyPath, publicKeyPem);
  const spkiSha256 = guidedPublicKeySpkiSha256(publicKeyPem);
  const databaseId = input.databaseId ?? `guidedb-${randomBytes(16).toString('hex')}`;
  const issuedAtUnixMs = input.issuedAtUnixMs ?? Date.now();
  const body: GuidedReceiptBody = {
    schema: GUIDED_PROVENANCE_RECEIPT_SCHEMA,
    schemaVersion: GUIDED_SCHEMA_VERSION,
    schemaDigest: input.schemaDigest,
    databaseId,
    databasePath: canonicalDbPath,
    issuedAtUnixMs,
  };
  const signature = sign(
    null,
    Buffer.from(buildGuidedReceiptSigningBytes(body), 'utf8'),
    createPrivateKey(privateKeyPem),
  ).toString('base64');
  const envelope: GuidedReceiptEnvelope = { ...body, signature };
  // Self-check with the exact runtime verifier before anything is written.
  verifyGuidedProvenanceEnvelope(envelope, publicKeyPem, {
    canonicalDatabasePath: canonicalDbPath,
    schemaVersion: GUIDED_SCHEMA_VERSION,
    schemaDigest: input.schemaDigest,
  });
  const receiptPath = writeGuidedReceiptAtomically(trustDir, canonicalDbPath, envelope);

  // The completed trust tree must satisfy the same policy the runtime will
  // enforce; refuse to leave half-protected evidence behind.
  const reasons = assessGuidedTrustProtection(
    trustDir,
    listGuidedReceiptPaths(trustDir),
    input.inspectAcl ? input.inspectAcl(trustDir, listGuidedReceiptPaths(trustDir)) : undefined,
  );
  if (reasons.length > 0) {
    rmSync(receiptPath, { force: true });
    throw new Error(`ISSUER_TRUST_TREE_UNPROTECTED:${reasons.join(' | ')}`);
  }
  return { databaseId, receiptPath, trustAnchorPath: anchorPath, spkiSha256, envelope };
}

function writeGuidedFileAtomic(destination: string, contents: string): void {
  const tmp = `${destination}.issuer-${process.pid}.tmp`;
  let written = false;
  try {
    const fd = openSync(tmp, 'wx', 0o600);
    try {
      writeFileSync(fd, contents, 'utf8');
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, destination);
    written = true;
  } finally {
    if (!written) rmSync(tmp, { force: true });
  }
}

function requiredFrom(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) throw new Error(`ISSUER_MISSING_${name}`);
  return value;
}

export function runGuidedIssuerCli(env: NodeJS.ProcessEnv = process.env): GuidedIssuanceResult {
  if (env.SHUN_GUIDED_TRUST_DIR !== undefined) {
    throw new Error('ISSUER_TRUST_DIR_OVERRIDE_FORBIDDEN');
  }
  assertGuidedIssuerElevated();
  const result = issueGuidedProvenanceReceipt({
    databasePath: requiredFrom(env, 'SHUN_GUIDED_DATABASE_PATH'),
    schemaDigest: requiredFrom(env, 'SHUN_GUIDED_SCHEMA_DIGEST'),
    privateKeyPath: requiredFrom(env, 'SHUN_GUIDED_ISSUER_PRIVATE_KEY_FILE'),
    workspaceRoot: requiredFrom(env, 'SHUN_GUIDED_WORKSPACE_ROOT'),
  });
  // Evidence lines only: identifiers, paths and fingerprints. NEVER key
  // material, key paths' contents, or anything derived from the secret half.
  console.log(`ISSUER_OK databaseId=${result.databaseId}`);
  console.log(`ISSUER_RECEIPT=${result.receiptPath}`);
  console.log(`ISSUER_TRUST_ANCHOR=${result.trustAnchorPath}`);
  console.log(`ISSUER_SPKI_SHA256=${result.spkiSha256}`);
  console.log('ISSUER_REQUIRES_WINDOWS_DACL_AND_PROCESS_IDENTITY_VALIDATION=YES');
  return result;
}

const invokedDirectly =
  typeof process.argv[1] === 'string' && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  try {
    runGuidedIssuerCli();
  } catch (error) {
    console.error(`ISSUER_FAIL ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
