// R04 (#404): per-user LocalAppData Guided trust bootstrap — the ONE
// consented first-run action a normal Windows user runs. It is a trusted
// local script, deliberately SEPARATE from ordinary runtime: it generates
// the per-user Ed25519 issuer key (the user never manufactures keys, copies
// SPKI pins or calls internal CLIs), stores the private key in the distinct
// user-owned secret directory under the same profile, provisions the trust
// anchor + receipt through the issuer module, and publishes the sibling
// public pin. No HTTP endpoint, browser surface, LLM or DB row can invoke
// any of this.
//
// Safety properties (Owner L2 #404):
//  - explicit consent: without --consent the tool only PRINTS the plan and
//    the current per-user state; nothing is written;
//  - idempotent: a complete, verifying trust setup is a NO-OP — never
//    rotated, never re-signed, never re-keyed (restart-stable);
//  - partial setups are surfaced truthfully: --repair completes ONLY the
//    missing pieces while every present piece still verifies; any
//    present-but-INVALID piece is refused (no overwrite of adversarial
//    bytes, no automatic reset — the operator decides manually);
//  - identity-bound: runs unelevated as the target interactive user; an
//    elevated token belonging to a DIFFERENT account (UAC over-the-
//    shoulder) is refused so authority never lands in the administrator's
//    profile. Daily runtime needs no UAC at all;
//  - no key bytes are ever logged, echoed or derived into output.
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  developmentGuidedProvenanceAuthority,
  GUIDED_SCHEMA_VERSION,
} from '../../../packages/domain-host/src/guided/guided-provenance-authority.ts';
import { HostGuidedService } from '../../../packages/domain-host/src/guided/host-guided-service.ts';
import {
  assertGuidedBootstrapIdentityContext,
  assertGuidedPathOutside,
  canonicalGuidedDatabasePath,
  GUIDED_ISSUER_SECRET_FILE,
  GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
  GUIDED_PROVENANCE_TRUST_ANCHOR_FILE,
  GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA,
  type GuidedAclInspector,
  type GuidedBootstrapIdentityContext,
  type GuidedIdentityProbeSource,
  type GuidedTrustAnchor,
  guidedPublicKeySpkiSha256,
  guidedReceiptFileName,
  perUserGuidedTrustAncestorChain,
  perUserGuidedTrustDirectory,
  perUserIssuerSecretDirectory,
  readGuidedTrustAnchor,
  resolveWindowsLocalAppDataBase,
  verifyGuidedProvenanceEnvelope,
} from '../src/real-storage/guided-provenance-issuance.ts';
import {
  issueGuidedProvenanceReceipt,
  loadGuidedIssuerPrivateKey,
} from './issue-guided-provenance.ts';

/** Sibling public pin schema — identical to the composition's pin reader. */
const TRUST_PIN_SCHEMA = 'shun.guided.provenance-trust-pin.v1';

export interface GuidedBootstrapPaths {
  readonly localAppDataBase: string;
  readonly trustDir: string;
  readonly pinPath: string;
  readonly secretDir: string;
  readonly secretKeyPath: string;
  readonly ancestorChain: readonly string[];
}

/** Resolve every per-user path the bootstrap touches for one session base. */
export function resolveGuidedBootstrapPaths(localAppDataBase: string): GuidedBootstrapPaths {
  const trustDir = perUserGuidedTrustDirectory(localAppDataBase);
  const secretDir = perUserIssuerSecretDirectory(localAppDataBase);
  return {
    localAppDataBase: resolve(localAppDataBase),
    trustDir,
    pinPath: resolve(dirname(trustDir), 'guided-provenance-trust-pin.json'),
    secretDir,
    secretKeyPath: join(secretDir, GUIDED_ISSUER_SECRET_FILE),
    ancestorChain: perUserGuidedTrustAncestorChain(localAppDataBase),
  };
}

/**
 * Exact frozen Guided schema digest, derived from an ephemeral scratch
 * database (development authority, OS temp): the user never pastes internal
 * digests. No production DB, key or receipt is created by this derivation.
 */
export function deriveGuidedSchemaDigest(): string {
  const scratchDir = mkdtempSync(join(tmpdir(), 'shun-guided-bootstrap-'));
  try {
    const scratchDb = join(scratchDir, 'schema.sqlite');
    const scratch = new HostGuidedService(
      scratchDb,
      Date.now,
      developmentGuidedProvenanceAuthority,
    );
    scratch.close();
    const db = new DatabaseSync(scratchDb);
    try {
      const row = db.prepare('SELECT schema_digest FROM guided_schema_receipt').get() as
        | { schema_digest?: string }
        | undefined;
      if (
        !row ||
        typeof row.schema_digest !== 'string' ||
        !/^[0-9a-f]{64}$/.test(row.schema_digest)
      ) {
        throw new Error('GUIDED_BOOTSTRAP_SCHEMA_DIGEST_UNAVAILABLE');
      }
      return row.schema_digest;
    } finally {
      db.close();
    }
  } finally {
    rmSync(scratchDir, { recursive: true, force: true });
  }
}

/** Verification verdict of one trust piece for the planned database. */
export type GuidedBootstrapPieceState = 'ABSENT' | 'PRESENT_VALID' | 'PRESENT_INVALID';

export interface GuidedBootstrapPlan {
  readonly paths: GuidedBootstrapPaths;
  readonly databasePath: string;
  /** COMPLETE: runtime-usable trust (anchor+pin+receipt all verify). */
  readonly status: 'COMPLETE' | 'FRESH' | 'PARTIAL' | 'INVALID';
  readonly anchor: GuidedBootstrapPieceState;
  readonly pin: GuidedBootstrapPieceState;
  readonly receipt: GuidedBootstrapPieceState;
  readonly secret: GuidedBootstrapPieceState;
  /** Present, valid anchor's public key (for repair completion). */
  readonly anchorPublicKeyPem?: string;
  /** Human-readable explanation lines (no secrets, no key bytes). */
  readonly notes: readonly string[];
}

function pinDigestOf(pinPath: string): string | undefined {
  try {
    const raw = JSON.parse(readFileSync(pinPath, 'utf8')) as Record<string, unknown>;
    if (
      Object.keys(raw).sort().join('|') === 'schema|spkiSha256' &&
      raw.schema === TRUST_PIN_SCHEMA &&
      typeof raw.spkiSha256 === 'string' &&
      /^[0-9a-f]{64}$/.test(raw.spkiSha256)
    ) {
      return raw.spkiSha256;
    }
  } catch {
    // fall through: invalid
  }
  return undefined;
}

function secretMatchesAnchor(secretKeyPath: string, anchor: GuidedTrustAnchor): boolean {
  try {
    const { privateKeyPem } = loadGuidedIssuerPrivateKey(secretKeyPath, anchor.publicKeyPem);
    return privateKeyPem.length > 0;
  } catch {
    return false;
  }
}

/**
 * Read-only per-user trust inventory for one canonical database path and
 * schema digest. Nothing is modified; nothing secret is returned.
 */
export function planGuidedLocalAppDataBootstrap(input: {
  readonly databasePath: string;
  readonly schemaDigest: string;
  readonly paths: GuidedBootstrapPaths;
}): GuidedBootstrapPlan {
  const { paths } = input;
  const canonicalPath = canonicalGuidedDatabasePath(input.databasePath);
  const notes: string[] = [];

  let anchor: GuidedTrustAnchor | undefined;
  let anchorState: GuidedBootstrapPieceState = 'ABSENT';
  const anchorPath = join(paths.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE);
  if (existsSync(anchorPath)) {
    try {
      anchor = readGuidedTrustAnchor(paths.trustDir);
      anchorState = 'PRESENT_VALID';
    } catch (error) {
      anchorState = 'PRESENT_INVALID';
      notes.push(`anchor invalid: ${(error as Error).message}`);
    }
  }

  let pinState: GuidedBootstrapPieceState = 'ABSENT';
  let pinDigest: string | undefined;
  if (existsSync(paths.pinPath)) {
    pinDigest = pinDigestOf(paths.pinPath);
    if (pinDigest === undefined) {
      pinState = 'PRESENT_INVALID';
      notes.push('pin invalid: malformed schema/digest');
    } else if (anchor !== undefined && anchorState === 'PRESENT_VALID') {
      pinState = pinDigest === anchor.spkiSha256 ? 'PRESENT_VALID' : 'PRESENT_INVALID';
      if (pinState === 'PRESENT_INVALID') notes.push('pin does not match anchor SPKI');
    } else {
      // Pin present without a valid anchor: cannot verify binding yet.
      pinState = 'PRESENT_VALID';
    }
  }

  let receiptState: GuidedBootstrapPieceState = 'ABSENT';
  const receiptPath = join(
    paths.trustDir,
    GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
    guidedReceiptFileName(canonicalPath),
  );
  if (existsSync(receiptPath)) {
    if (anchor !== undefined && anchorState === 'PRESENT_VALID') {
      try {
        const raw = JSON.parse(readFileSync(receiptPath, 'utf8'));
        verifyGuidedProvenanceEnvelope(raw, anchor.publicKeyPem, {
          canonicalDatabasePath: canonicalPath,
          schemaVersion: GUIDED_SCHEMA_VERSION,
          schemaDigest: input.schemaDigest,
        });
        receiptState = 'PRESENT_VALID';
      } catch (error) {
        receiptState = 'PRESENT_INVALID';
        notes.push(`receipt invalid: ${(error as Error).message}`);
      }
    } else {
      // Cannot verify the receipt without a valid anchor.
      receiptState = 'PRESENT_VALID';
    }
  }

  let secretState: GuidedBootstrapPieceState = 'ABSENT';
  if (existsSync(paths.secretKeyPath)) {
    if (anchor !== undefined && anchorState === 'PRESENT_VALID') {
      secretState = secretMatchesAnchor(paths.secretKeyPath, anchor)
        ? 'PRESENT_VALID'
        : 'PRESENT_INVALID';
      if (secretState === 'PRESENT_INVALID') notes.push('issuer secret does not match anchor');
    } else {
      secretState = 'PRESENT_VALID';
    }
  }

  const anyInvalid =
    anchorState === 'PRESENT_INVALID' ||
    pinState === 'PRESENT_INVALID' ||
    receiptState === 'PRESENT_INVALID' ||
    secretState === 'PRESENT_INVALID';
  const runtimeComplete =
    anchorState === 'PRESENT_VALID' &&
    pinState === 'PRESENT_VALID' &&
    receiptState === 'PRESENT_VALID';
  const nothingPresent =
    anchorState === 'ABSENT' &&
    pinState === 'ABSENT' &&
    receiptState === 'ABSENT' &&
    secretState === 'ABSENT';

  let status: GuidedBootstrapPlan['status'];
  if (anyInvalid) {
    status = 'INVALID';
    notes.push(
      'present-but-invalid material must be resolved by an explicit operator reset decision; the bootstrap never overwrites or re-signs unverified bytes',
    );
  } else if (runtimeComplete) {
    status = 'COMPLETE';
    if (secretState !== 'PRESENT_VALID') {
      notes.push(
        'runtime trust is complete; the issuer secret is absent, so future receipts for OTHER databases cannot be signed by this bootstrap (by design — never re-keyed)',
      );
    }
  } else if (nothingPresent) {
    status = 'FRESH';
  } else {
    status = 'PARTIAL';
    notes.push('incomplete setup: re-run with --repair to complete ONLY the missing pieces');
  }

  return {
    paths,
    databasePath: canonicalPath,
    status,
    anchor: anchorState,
    pin: pinState,
    receipt: receiptState,
    secret: secretState,
    anchorPublicKeyPem: anchorState === 'PRESENT_VALID' ? anchor?.publicKeyPem : undefined,
    notes,
  };
}

function writeGuidedFileAtomic(destination: string, contents: string): void {
  mkdirSync(dirname(destination), { recursive: true });
  const tmp = `${destination}.bootstrap-${process.pid}.tmp`;
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

export interface GuidedBootstrapExecuteInput {
  readonly databasePath: string;
  readonly workspaceRoot: string;
  readonly localAppDataBase: string;
  readonly identity: GuidedBootstrapIdentityContext;
  readonly schemaDigest?: string;
  readonly issuedAtUnixMs?: number;
  readonly databaseId?: string;
  /** ACL snapshot injector (tests). Production uses the real Windows scan. */
  readonly inspectAcl?: GuidedAclInspector;
}

export interface GuidedBootstrapExecuteOptions {
  /** Explicit user consent for writes; without it only plans are produced. */
  readonly consent: boolean;
  /** Allow completing a verifiable PARTIAL setup. */
  readonly repair?: boolean;
}

export interface GuidedBootstrapResult {
  readonly status: 'BOOTSTRAP_CREATED' | 'REPAIR_COMPLETED' | 'ALREADY_COMPLETE';
  readonly plan: GuidedBootstrapPlan;
  readonly receiptPath: string;
  readonly trustAnchorPath: string;
  readonly pinPath: string;
  readonly secretKeyPath?: string;
  readonly spkiSha256?: string;
  readonly databaseId?: string;
}

/**
 * Execute the consented per-user bootstrap. FRESH: generate the issuer key
 * into the per-user secret directory, provision anchor + receipt via the
 * issuer module, publish the sibling pin. PARTIAL (repair): complete ONLY
 * missing pieces while every present piece verifies. COMPLETE: no-op.
 * Throws GUIDED_BOOTSTRAP_* codes otherwise; never logs key bytes.
 */
export function executeGuidedLocalAppDataBootstrap(
  input: GuidedBootstrapExecuteInput,
  options: GuidedBootstrapExecuteOptions,
): GuidedBootstrapResult {
  const schemaDigest = input.schemaDigest ?? deriveGuidedSchemaDigest();
  const paths = resolveGuidedBootstrapPaths(input.localAppDataBase);
  // The database must live outside the workspace, trust tree and secret dir.
  assertGuidedPathOutside(
    input.databasePath,
    [input.workspaceRoot],
    'GUIDED_BOOTSTRAP_DATABASE_SCOPE_REFUSED',
  );
  assertGuidedPathOutside(
    input.databasePath,
    [paths.trustDir],
    'GUIDED_BOOTSTRAP_DATABASE_SCOPE_REFUSED',
  );
  assertGuidedPathOutside(
    input.databasePath,
    [paths.secretDir],
    'GUIDED_BOOTSTRAP_DATABASE_SCOPE_REFUSED',
  );
  assertGuidedPathOutside(
    paths.secretKeyPath,
    [paths.trustDir],
    'GUIDED_BOOTSTRAP_SECRET_SCOPE_REFUSED',
  );

  const plan = planGuidedLocalAppDataBootstrap({
    databasePath: input.databasePath,
    schemaDigest,
    paths,
  });
  const receiptPath = join(
    paths.trustDir,
    GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
    guidedReceiptFileName(plan.databasePath),
  );
  const anchorPath = join(paths.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE);

  if (plan.status === 'COMPLETE') {
    return {
      status: 'ALREADY_COMPLETE',
      plan,
      receiptPath,
      trustAnchorPath: anchorPath,
      pinPath: paths.pinPath,
    };
  }
  if (plan.status === 'INVALID') {
    throw new Error(`GUIDED_BOOTSTRAP_STATE_INVALID:${plan.notes.join(' | ')}`);
  }
  if (!options.consent) {
    throw new Error('GUIDED_BOOTSTRAP_CONSENT_REQUIRED');
  }
  // A structural partial (missing anchor or pin with other pieces present)
  // needs the explicit repair decision. Missing ONLY the receipt for THIS
  // database is ordinary consented provisioning: a second Guided store
  // under the same verified per-user anchor needs no repair semantics.
  const receiptOnlyMissing =
    plan.status === 'PARTIAL' &&
    plan.anchor === 'PRESENT_VALID' &&
    plan.pin === 'PRESENT_VALID' &&
    plan.receipt === 'ABSENT';
  if (plan.status === 'PARTIAL' && options.repair !== true && !receiptOnlyMissing) {
    throw new Error(
      `GUIDED_BOOTSTRAP_PARTIAL: re-run with --repair after reviewing the plan (${plan.notes.join(' | ')})`,
    );
  }

  if (plan.status === 'FRESH') {
    // One consented first-run setup: key -> anchor+receipt -> pin. The
    // issuer receives the EXACT resolved per-user trust directory (tests
    // inject their fixture directory; production passes the resolved
    // per-user root) — it never re-resolves on its own here.
    const keys = generateKeyPairSync('ed25519');
    const privateKeyPem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    writeGuidedFileAtomic(paths.secretKeyPath, privateKeyPem);
    const issued = issueGuidedProvenanceReceipt({
      databasePath: plan.databasePath,
      schemaDigest,
      privateKeyPath: paths.secretKeyPath,
      workspaceRoot: input.workspaceRoot,
      ownerSid: input.identity.processUserSid,
      ancestorChain: paths.ancestorChain,
      trustDir: paths.trustDir,
      issuedAtUnixMs: input.issuedAtUnixMs,
      databaseId: input.databaseId,
      designatedPerUserKeyPath: paths.secretKeyPath,
      inspectAcl: input.inspectAcl,
      testOnlyAllowTemporaryKey: input.inspectAcl !== undefined,
    });
    writeGuidedFileAtomic(
      paths.pinPath,
      `${JSON.stringify({ schema: TRUST_PIN_SCHEMA, spkiSha256: issued.spkiSha256 })}\n`,
    );
    return {
      status: 'BOOTSTRAP_CREATED',
      plan,
      receiptPath: issued.receiptPath,
      trustAnchorPath: issued.trustAnchorPath,
      pinPath: paths.pinPath,
      secretKeyPath: paths.secretKeyPath,
      spkiSha256: issued.spkiSha256,
      databaseId: issued.databaseId,
    };
  }

  // PARTIAL + repair: complete only the missing pieces. Every present piece
  // already verified in the plan; the anchor public key is re-derived from
  // the present secret when the anchor itself is the missing piece.
  const anchorFromSecret = (): { readonly publicKeyPem: string; readonly spkiSha256: string } => {
    if (plan.secret !== 'PRESENT_VALID') {
      throw new Error('GUIDED_BOOTSTRAP_REPAIR_REQUIRES_SECRET_OR_ANCHOR');
    }
    const privateKeyPem = readFileSync(paths.secretKeyPath, 'utf8');
    const publicKeyPem = createPublicKey(createPrivateKey(privateKeyPem))
      .export({ type: 'spki', format: 'pem' })
      .toString();
    return { publicKeyPem, spkiSha256: guidedPublicKeySpkiSha256(publicKeyPem) };
  };

  if (plan.anchor === 'ABSENT') {
    const { publicKeyPem, spkiSha256 } = anchorFromSecret();
    writeGuidedFileAtomic(
      anchorPath,
      `${JSON.stringify({
        schema: GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA,
        publicKeyPem,
        spkiSha256,
      })}\n`,
    );
  }
  let databaseId: string | undefined;
  let spkiSha256: string | undefined;
  if (plan.receipt === 'ABSENT') {
    const issued = issueGuidedProvenanceReceipt({
      databasePath: plan.databasePath,
      schemaDigest,
      privateKeyPath: paths.secretKeyPath,
      workspaceRoot: input.workspaceRoot,
      ownerSid: input.identity.processUserSid,
      ancestorChain: paths.ancestorChain,
      trustDir: paths.trustDir,
      issuedAtUnixMs: input.issuedAtUnixMs,
      databaseId: input.databaseId,
      designatedPerUserKeyPath: paths.secretKeyPath,
      inspectAcl: input.inspectAcl,
      testOnlyAllowTemporaryKey: input.inspectAcl !== undefined,
    });
    databaseId = issued.databaseId;
    spkiSha256 = issued.spkiSha256;
  }
  if (plan.pin === 'ABSENT') {
    const anchor = readGuidedTrustAnchor(paths.trustDir);
    writeGuidedFileAtomic(
      paths.pinPath,
      `${JSON.stringify({ schema: TRUST_PIN_SCHEMA, spkiSha256: anchor.spkiSha256 })}\n`,
    );
    spkiSha256 ??= anchor.spkiSha256;
  }
  return {
    // Receipt-only completion is ordinary provisioning (a second Guided
    // store under the same anchor); structural completion is a repair.
    status: receiptOnlyMissing ? 'BOOTSTRAP_CREATED' : 'REPAIR_COMPLETED',
    plan,
    receiptPath,
    trustAnchorPath: anchorPath,
    pinPath: paths.pinPath,
    secretKeyPath: existsSync(paths.secretKeyPath) ? paths.secretKeyPath : undefined,
    spkiSha256,
    databaseId,
  };
}

/** CLI: node scripts/bootstrap-guided-localappdata.ts --database <path> [--consent] [--repair] */
export function runGuidedBootstrapCli(
  argv: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
  identityProbes: GuidedIdentityProbeSource = {},
): number {
  const args = [...argv];
  const databasePath = takeValue(args, '--database');
  const consent = args.includes('--consent');
  const repair = args.includes('--repair');
  if (!databasePath) {
    console.error(
      'usage: bootstrap-guided-localappdata.ts --database <guided.sqlite> [--consent] [--repair]',
    );
    return 1;
  }
  const identity = assertGuidedBootstrapIdentityContext(identityProbes);
  const localAppDataBase = resolveWindowsLocalAppDataBase(env);
  const paths = resolveGuidedBootstrapPaths(localAppDataBase);
  const here = dirname(fileURLToPath(import.meta.url));
  const workspaceRoot = resolve(here, '../../..');
  const schemaDigest = deriveGuidedSchemaDigest();
  const plan = planGuidedLocalAppDataBootstrap({ databasePath, schemaDigest, paths });
  // Plan output first: identity context, per-user paths, current state.
  console.log(`BOOTSTRAP_USER_SID=${identity.processUserSid}`);
  console.log(`BOOTSTRAP_ELEVATED=${identity.elevated ? 'YES' : 'NO'}`);
  console.log(`BOOTSTRAP_TRUST_DIR=${paths.trustDir}`);
  console.log(`BOOTSTRAP_PIN=${paths.pinPath}`);
  console.log(`BOOTSTRAP_SECRET_DIR=${paths.secretDir}`);
  console.log(`BOOTSTRAP_STATUS=${plan.status}`);
  for (const note of plan.notes) console.log(`BOOTSTRAP_NOTE=${note}`);
  if (!consent) {
    console.log(
      'BOOTSTRAP_PLAN_ONLY: re-run with --consent to execute this plan' +
        (plan.status === 'PARTIAL' ? ' (and --repair to complete a partial setup)' : ''),
    );
    return plan.status === 'COMPLETE' ? 0 : 3;
  }
  const result = executeGuidedLocalAppDataBootstrap(
    {
      databasePath,
      workspaceRoot,
      localAppDataBase,
      identity,
      schemaDigest,
    },
    { consent: true, repair },
  );
  console.log(`BOOTSTRAP_RESULT=${result.status}`);
  console.log(`BOOTSTRAP_RECEIPT=${result.receiptPath}`);
  console.log(`BOOTSTRAP_TRUST_ANCHOR=${result.trustAnchorPath}`);
  if (result.spkiSha256) console.log(`BOOTSTRAP_SPKI_SHA256=${result.spkiSha256}`);
  if (result.databaseId) console.log(`BOOTSTRAP_DATABASE_ID=${result.databaseId}`);
  // Never any key material: only identifiers, paths and fingerprints.
  return 0;
}

function takeValue(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  if (index === -1) return undefined;
  const value = args[index + 1];
  args.splice(index, 2);
  return value && !value.startsWith('--') ? value : undefined;
}

const invokedDirectly =
  typeof process.argv[1] === 'string' && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  try {
    process.exitCode = runGuidedBootstrapCli(process.argv.slice(2));
  } catch (error) {
    console.error(`BOOTSTRAP_FAIL ${(error as Error).message}`);
    process.exitCode = 1;
  }
}
