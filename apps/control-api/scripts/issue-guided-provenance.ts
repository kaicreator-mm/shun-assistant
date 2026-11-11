// R02-E (#348): trusted operator-side Guided provenance receipt issuer,
// R04 (#404): adapted to the per-user LocalAppData trust root.
// NEVER imported or invoked by control-api's HTTP/candidate Goal path and
// never by the runtime authority adapter. Per-user bootstrap needs NO
// elevation (the trust tree lives in the operator's own profile): the only
// identity requirement is that an ELEVATED token belongs to the SAME account
// as the interactive console session user — an over-the-shoulder elevation
// must never plant authority in the administrator's profile. This script
// must NOT initiate UAC itself and performs no physical Windows effect
// beyond writing the trust anchor and receipt files it is explicitly asked
// to create.
//
// The Ed25519 private key is supplied ONLY to this process via
// SHUN_GUIDED_ISSUER_PRIVATE_KEY_FILE (the per-user bootstrap keeps it in
// the distinct per-user secret directory), must live outside the repository,
// workspace, database directory, trust directory and OS temp directory, and
// is never copied, logged, uploaded or read by any runtime code. The
// matching public key is published into the protected trust anchor.
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
  assertGuidedBootstrapIdentityContext,
  assertGuidedPathOutside,
  assertGuidedPrivateKeyScope,
  assertGuidedRegularCanonicalPath,
  assessGuidedTrustAncestorProtection,
  assessGuidedTrustProtection,
  buildGuidedReceiptSigningBytes,
  canonicalGuidedDatabasePath,
  GUIDED_PROVENANCE_DIGEST_PATTERN,
  GUIDED_PROVENANCE_RECEIPT_SCHEMA,
  GUIDED_PROVENANCE_TRUST_ANCHOR_FILE,
  GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA,
  type GuidedAclInspector,
  type GuidedIdentityProbeSource,
  type GuidedReceiptBody,
  type GuidedReceiptEnvelope,
  guidedPublicKeySpkiSha256,
  listGuidedReceiptPaths,
  perUserGuidedTrustAncestorChain,
  perUserGuidedTrustDirectory,
  readGuidedTrustAnchor,
  resolveWindowsLocalAppDataBase,
  verifyGuidedProvenanceEnvelope,
  writeGuidedReceiptAtomically,
} from '../src/real-storage/guided-provenance-issuance.ts';

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
  const base = resolve(workspaceRoot).toLowerCase();
  if (lower === base || lower.startsWith(`${base}\\`) || lower.startsWith(`${base}/`)) {
    throw new Error('ISSUER_DATABASE_PATH_INSIDE_FORBIDDEN_SCOPE');
  }
  // Trust-directory overlap gets its own precise codes immediately after.
  return canonicalGuidedDatabasePath(canonical);
}

export interface GuidedIssuanceInput {
  readonly databasePath: string;
  readonly schemaDigest: string;
  readonly privateKeyPath: string;
  readonly workspaceRoot: string;
  /**
   * R04 per-user policy: the interactive user SID that must own the trust
   * tree (per-user owner/DACL policy). REQUIRED — there is no privileged-
   * owner default anymore.
   */
  readonly ownerSid: string;
  /**
   * Ancestor chain of the resolved default per-user trust root, REQUIRED
   * when provisioning the default root (CLI/bootstrap always provide it);
   * injected non-default test trust directories omit it (tree-only).
   */
  readonly ancestorChain?: readonly string[];
  readonly trustDir?: string;
  readonly issuedAtUnixMs?: number;
  readonly databaseId?: string;
  /**
   * Designated per-user secret location (bootstrap passes the resolved
   * `<base>\Shun\secrets\guided-issuer\issuer-private.pem`): the one
   * bounded exception to the issuer-key scope rule (see
   * assertGuidedPrivateKeyScope). The raw issuer CLI does not designate one.
   */
  readonly designatedPerUserKeyPath?: string;
  /** ACL snapshot injector (tests). Production uses the real Windows scan. */
  readonly inspectAcl?: GuidedAclInspector;
  /**
   * Test-only ephemeral key exception: requires an injected ACL snapshot AND
   * a test-runner context (VITEST); the CLI never supplies this flag and it
   * throws outside a test runner even if set.
   */
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
  // The OS-temp key relaxation is test-only: refuse it anywhere outside a
  // test runner, even when paired with an injected ACL snapshot.
  if (input.testOnlyAllowTemporaryKey === true && process.env.VITEST === undefined) {
    throw new Error('ISSUER_TEST_ONLY_KEY_FLAG_OUTSIDE_TEST_CONTEXT');
  }
  if (input.ancestorChain !== undefined && !input.ownerSid) {
    throw new Error('ISSUER_OWNER_SID_REQUIRED_WITH_ANCESTORS');
  }
  const workspaceRoot = resolve(input.workspaceRoot);
  // The trust tree itself must be alias-free and outside every forbidden
  // scope before anything is written into it. First provisioning creates it
  // (atomically verified against aliasing); an existing tree must already be
  // canonical.
  const resolveTrustDir = (): string => {
    const dir = resolve(
      input.trustDir ?? perUserGuidedTrustDirectory(resolveWindowsLocalAppDataBase()),
    );
    if (existsSync(dir)) {
      return assertGuidedRegularCanonicalPath(dir, 'ISSUER_TRUST_DIR_UNTRUSTED');
    }
    mkdirSync(dir, { recursive: true });
    const created = realpathSync(dir);
    if (created.toLowerCase() !== dir.toLowerCase()) {
      rmSync(dir, { recursive: true, force: true });
      throw new Error('ISSUER_TRUST_DIR_ALIAS');
    }
    return dir;
  };
  const trustDir = resolveTrustDir();
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
    input.designatedPerUserKeyPath,
  );

  // The resolved per-user default trust root must sit under a verified
  // ancestor chain (up to the LocalAppData policy boundary) owned by the
  // per-user allowed identities; a foreign-writable ancestor would allow
  // rename/swap of the whole trust root that tree-local DACL cannot
  // prevent. Injected non-default test trust directories are exempt.
  if (input.ancestorChain !== undefined) {
    const ancestors = input.ancestorChain;
    const ancestorReasons = assessGuidedTrustAncestorProtection(
      ancestors,
      input.ownerSid ?? '',
      input.inspectAcl ? input.inspectAcl(ancestors[0] ?? '', ancestors.slice(1)) : undefined,
    );
    if (ancestorReasons.length > 0) {
      throw new Error(`ISSUER_TRUST_ANCESTORS_UNPROTECTED:${ancestorReasons.join(' | ')}`);
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

  // The completed trust tree must satisfy the same per-user policy the
  // runtime will enforce; refuse to leave half-protected evidence behind.
  // (Tree-only here: the ancestor chain was gated before any write.)
  const receiptsAfterWrite = listGuidedReceiptPaths(trustDir);
  const reasons = assessGuidedTrustProtection(
    trustDir,
    receiptsAfterWrite,
    input.ownerSid,
    input.inspectAcl ? input.inspectAcl(trustDir, receiptsAfterWrite) : undefined,
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

export function runGuidedIssuerCli(
  env: NodeJS.ProcessEnv = process.env,
  identityProbes: GuidedIdentityProbeSource = {},
): GuidedIssuanceResult {
  if (env.SHUN_GUIDED_TRUST_DIR !== undefined) {
    throw new Error('ISSUER_TRUST_DIR_OVERRIDE_FORBIDDEN');
  }
  // R04: per-user issuance runs unelevated by default. The only identity
  // requirement is same-account context: an elevated token that belongs to
  // a DIFFERENT account than the interactive console user must not plant
  // trust in the administrator's profile.
  const identity = assertGuidedBootstrapIdentityContext(identityProbes);
  const localAppDataBase = resolveWindowsLocalAppDataBase(env);
  const result = issueGuidedProvenanceReceipt({
    databasePath: requiredFrom(env, 'SHUN_GUIDED_DATABASE_PATH'),
    schemaDigest: requiredFrom(env, 'SHUN_GUIDED_SCHEMA_DIGEST'),
    privateKeyPath: requiredFrom(env, 'SHUN_GUIDED_ISSUER_PRIVATE_KEY_FILE'),
    workspaceRoot: requiredFrom(env, 'SHUN_GUIDED_WORKSPACE_ROOT'),
    ownerSid: identity.processUserSid,
    ancestorChain: perUserGuidedTrustAncestorChain(localAppDataBase),
  });
  // Evidence lines only: identifiers, paths and fingerprints. NEVER key
  // material, key paths' contents, or anything derived from the secret half.
  console.log(`ISSUER_OK databaseId=${result.databaseId}`);
  console.log(`ISSUER_RECEIPT=${result.receiptPath}`);
  console.log(`ISSUER_TRUST_ANCHOR=${result.trustAnchorPath}`);
  console.log(`ISSUER_SPKI_SHA256=${result.spkiSha256}`);
  console.log('ISSUER_PER_USER_LOCALAPPDATA_IDENTITY_VALIDATED=YES');
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
