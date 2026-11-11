// R02-E (#348) / R04 (#404): deterministic test-key coverage for the
// externally signed Guided provenance receipt under the PER-USER
// LocalAppData trust model. All Ed25519 keys here are ephemeral and
// test-only, generated per run and never persisted anywhere outside the OS
// temp directory. No production key, credential or signed production
// receipt exists in this repository.
import { generateKeyPairSync, sign } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { GUIDED_SCHEMA_VERSION } from '../../../packages/domain-host/src/guided/guided-provenance-authority.ts';
import {
  assertGuidedIssuerDatabasePath,
  issueGuidedProvenanceReceipt,
  loadGuidedIssuerPrivateKey,
  runGuidedIssuerCli,
} from '../scripts/issue-guided-provenance.ts';
import {
  assertGuidedBootstrapIdentityContext,
  assertGuidedPrivateKeyScope,
  assertGuidedRegularCanonicalPath,
  assessGuidedBootstrapIdentity,
  assessGuidedTrustAncestorProtection,
  assessGuidedTrustProtection,
  buildGuidedReceiptSigningBytes,
  canonicalGuidedDatabasePath,
  createExternalGuidedProvenanceAuthority,
  type ExternalGuidedAuthorityOptions,
  GUIDED_PROVENANCE_RECEIPT_SCHEMA,
  GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
  GUIDED_PROVENANCE_TRUST_ANCHOR_FILE,
  GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA,
  type GuidedReceiptBody,
  type GuidedReceiptEnvelope,
  type GuidedTrustAccessRule,
  type GuidedTrustAclSnapshot,
  guidedPublicKeySpkiSha256,
  inspectWindowsGuidedTrustAcl,
  perUserGuidedTrustAncestorChain,
  perUserGuidedTrustDirectory,
  perUserIssuerSecretDirectory,
  queryWindowsProcessUserSid,
  resolveWindowsLocalAppDataBase,
  writeGuidedReceiptAtomically,
} from '../src/real-storage/guided-provenance-issuance.ts';

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const ISSUED_AT = 1_761_000_000_000;
/** Fixture interactive-user SID for the per-user owner/DACL policy. */
const TEST_USER_SID = 'S-1-5-21-11888-22222-33333-1001';
const OTHER_USER_SID = 'S-1-5-21-11888-22222-33333-1002';

interface Fixture {
  root: string;
  workspaceRoot: string;
  keyDir: string;
  dbDir: string;
  trustDir: string;
  dbPath: string;
  keys: ReturnType<typeof generateKeyPairSync>;
  publicKeyPem: string;
  pinnedSha256: string;
}

function makeFixture(): Fixture {
  const root = mkdtempSync(join(tmpdir(), 'guided-provenance-'));
  const workspaceRoot = join(root, 'workspace');
  const keyDir = join(root, 'operator-key');
  const dbDir = join(root, 'db');
  const trustDir = join(root, 'trust');
  for (const dir of [workspaceRoot, keyDir, dbDir, trustDir, join(trustDir, 'receipts')]) {
    mkdirSync(dir, { recursive: true });
  }
  const keys = generateKeyPairSync('ed25519');
  const publicKeyPem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  writeFileSync(
    join(trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE),
    `${JSON.stringify({
      schema: GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA,
      publicKeyPem,
      spkiSha256: guidedPublicKeySpkiSha256(publicKeyPem),
    })}\n`,
    'utf8',
  );
  return {
    root,
    workspaceRoot,
    keyDir,
    dbDir,
    trustDir,
    dbPath: join(dbDir, 'guided.db'),
    keys,
    publicKeyPem,
    pinnedSha256: guidedPublicKeySpkiSha256(publicKeyPem),
  };
}

function protectedAcl(trustDir: string, extraPaths: readonly string[]): GuidedTrustAclSnapshot {
  const paths = [
    trustDir,
    join(trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE),
    join(trustDir, GUIDED_PROVENANCE_RECEIPTS_SUBDIR),
    ...extraPaths,
  ];
  return [...new Set(paths.filter(existsSync))].map((path) => ({
    path,
    ownerSid: TEST_USER_SID,
    accessRules: [
      // Per-user profile shape: the interactive user reads/executes (and
      // would own writes), SYSTEM/Administrators keep full control.
      {
        identitySid: TEST_USER_SID,
        rightsMask: 0x001200a9,
        accessType: 'Allow',
        isInherited: true,
      },
      { identitySid: 'S-1-5-18', rightsMask: 0x001f01ff, accessType: 'Allow', isInherited: true },
      {
        identitySid: 'S-1-5-32-544',
        rightsMask: 0x001f01ff,
        accessType: 'Allow',
        isInherited: true,
      },
    ] as GuidedTrustAccessRule[],
  }));
}

const protectedInspector = (trustDir: string, extraPaths: readonly string[]) =>
  protectedAcl(trustDir, extraPaths);

/** One healthy per-user ancestor row (user-owned, user-readable). */
const protectedAncestorRow = (path: string) => ({
  path,
  ownerSid: TEST_USER_SID,
  accessRules: [
    {
      identitySid: TEST_USER_SID,
      rightsMask: 0x001f01ff,
      accessType: 'Allow',
      isInherited: true,
    },
    {
      identitySid: 'S-1-5-18',
      rightsMask: 0x001f01ff,
      accessType: 'Allow',
      isInherited: true,
    },
  ] as GuidedTrustAccessRule[],
});

function envelopeBody(
  fixture: Fixture,
  overrides: Partial<GuidedReceiptBody> = {},
): GuidedReceiptBody {
  return {
    schema: GUIDED_PROVENANCE_RECEIPT_SCHEMA,
    schemaVersion: GUIDED_SCHEMA_VERSION,
    schemaDigest: DIGEST_A,
    databaseId: 'guidedb-0123456789abcdef0123456789abcdef',
    databasePath: canonicalGuidedDatabasePath(fixture.dbPath),
    issuedAtUnixMs: ISSUED_AT,
    ...overrides,
  };
}

function signedEnvelope(
  fixture: Fixture,
  overrides: Partial<GuidedReceiptBody> = {},
  signer: ReturnType<typeof generateKeyPairSync> = fixture.keys,
): GuidedReceiptEnvelope {
  const body = envelopeBody(fixture, overrides);
  return {
    ...body,
    signature: sign(
      null,
      Buffer.from(buildGuidedReceiptSigningBytes(body), 'utf8'),
      signer.privateKey,
    ).toString('base64'),
  };
}

function provisionReceipt(fixture: Fixture, envelope: GuidedReceiptEnvelope): string {
  return writeGuidedReceiptAtomically(
    fixture.trustDir,
    canonicalGuidedDatabasePath(fixture.dbPath),
    envelope,
  );
}

function replaceReceipt(fixture: Fixture, envelope: GuidedReceiptEnvelope): void {
  writeGuidedReceiptAtomically(
    fixture.trustDir,
    canonicalGuidedDatabasePath(fixture.dbPath),
    envelope,
    { overwrite: true },
  );
}

function authorityFor(fixture: Fixture, overrides: Partial<ExternalGuidedAuthorityOptions> = {}) {
  return createExternalGuidedProvenanceAuthority({
    trustDir: fixture.trustDir,
    pinnedSpkiSha256: fixture.pinnedSha256,
    ownerSid: TEST_USER_SID,
    inspectAcl: protectedInspector,
    ...overrides,
  });
}

describe('external Guided provenance receipt issuance + verify-only runtime adapter', () => {
  it('accepts a valid operator-issued receipt and returns the bound G6 receipt row', () => {
    const fixture = makeFixture();
    try {
      const envelope = signedEnvelope(fixture);
      provisionReceipt(fixture, envelope);
      const authority = authorityFor(fixture);
      const receipt = authority.issueFreshReceipt({
        canonicalDatabasePath: fixture.dbPath,
        schemaDigest: DIGEST_A,
        issuedAtUnixMs: ISSUED_AT,
      });
      expect(receipt).toEqual({
        schemaVersion: GUIDED_SCHEMA_VERSION,
        schemaDigest: DIGEST_A,
        databaseId: envelope.databaseId,
        issuedAtUnixMs: ISSUED_AT,
        receiptDigest: envelope.signature,
      });
      expect(authority.verifyReceipt(receipt, fixture.dbPath)).toBe(true);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('end-to-end: operator issuer output verifies with the runtime adapter (ephemeral keys)', () => {
    const fixture = makeFixture();
    try {
      const privateKeyPath = join(fixture.keyDir, 'issuer.pem');
      writeFileSync(
        privateKeyPath,
        fixture.keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        'utf8',
      );
      const issued = issueGuidedProvenanceReceipt({
        databasePath: fixture.dbPath,
        schemaDigest: DIGEST_A,
        privateKeyPath,
        workspaceRoot: fixture.workspaceRoot,
        ownerSid: TEST_USER_SID,
        trustDir: fixture.trustDir,
        inspectAcl: protectedInspector,
        testOnlyAllowTemporaryKey: true,
      });
      expect(issued.databaseId).toMatch(/^guidedb-[0-9a-f]{32}$/);
      const authority = authorityFor(fixture);
      const receipt = authority.issueFreshReceipt({
        canonicalDatabasePath: fixture.dbPath,
        schemaDigest: DIGEST_A,
        issuedAtUnixMs: issued.envelope.issuedAtUnixMs,
      });
      expect(receipt.databaseId).toBe(issued.databaseId);
      expect(authority.verifyReceipt(receipt, fixture.dbPath)).toBe(true);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses a tampered signature and a tampered receipt body', () => {
    const fixture = makeFixture();
    try {
      const envelope = signedEnvelope(fixture);
      const flipped = envelope.signature.startsWith('A')
        ? `B${envelope.signature.slice(1)}`
        : `A${envelope.signature.slice(1)}`;
      provisionReceipt(fixture, { ...envelope, signature: flipped });
      const authority = authorityFor(fixture);
      expect(() =>
        authority.issueFreshReceipt({
          canonicalDatabasePath: fixture.dbPath,
          schemaDigest: DIGEST_A,
          issuedAtUnixMs: ISSUED_AT,
        }),
      ).toThrow('GUIDED_PROVENANCE_RECEIPT_SIGNATURE_INVALID');
      expect(
        authority.verifyReceipt(
          {
            schemaVersion: GUIDED_SCHEMA_VERSION,
            schemaDigest: DIGEST_A,
            databaseId: envelope.databaseId,
            issuedAtUnixMs: ISSUED_AT,
            receiptDigest: flipped,
          },
          fixture.dbPath,
        ),
      ).toBe(false);

      // Body edit without re-signing: same valid signature, new databaseId.
      const resigned = signedEnvelope(fixture, {
        databaseId: 'guidedb-ffffffffffffffffffffffffffffffff',
      });
      replaceReceipt(fixture, { ...resigned, signature: envelope.signature });
      expect(() =>
        authority.issueFreshReceipt({
          canonicalDatabasePath: fixture.dbPath,
          schemaDigest: DIGEST_A,
          issuedAtUnixMs: ISSUED_AT,
        }),
      ).toThrow('GUIDED_PROVENANCE_RECEIPT_SIGNATURE_INVALID');
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses a receipt copied to a different database path and a moved database', () => {
    const fixture = makeFixture();
    try {
      const envelope = signedEnvelope(fixture);
      provisionReceipt(fixture, envelope);
      const authority = authorityFor(fixture);
      // The DB file moved to a new canonical path: no receipt is bound there.
      expect(() =>
        authority.issueFreshReceipt({
          canonicalDatabasePath: join(fixture.dbDir, 'moved.db'),
          schemaDigest: DIGEST_A,
          issuedAtUnixMs: ISSUED_AT,
        }),
      ).toThrow('GUIDED_PROVENANCE_AUTHORITY_UNAVAILABLE');
      expect(
        authority.verifyReceipt(
          {
            schemaVersion: GUIDED_SCHEMA_VERSION,
            schemaDigest: DIGEST_A,
            databaseId: envelope.databaseId,
            issuedAtUnixMs: ISSUED_AT,
            receiptDigest: envelope.signature,
          },
          join(fixture.dbDir, 'moved.db'),
        ),
      ).toBe(false);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses a receipt issued for the wrong schema generation or DDL digest', () => {
    const fixture = makeFixture();
    try {
      provisionReceipt(fixture, signedEnvelope(fixture, { schemaVersion: 5 }));
      const authority = authorityFor(fixture);
      expect(() =>
        authority.issueFreshReceipt({
          canonicalDatabasePath: fixture.dbPath,
          schemaDigest: DIGEST_A,
          issuedAtUnixMs: ISSUED_AT,
        }),
      ).toThrow('GUIDED_PROVENANCE_RECEIPT_SCHEMA_MISMATCH');
      expect(
        authority.verifyReceipt(
          {
            schemaVersion: 5,
            schemaDigest: DIGEST_A,
            databaseId: 'guidedb-0123456789abcdef0123456789abcdef',
            issuedAtUnixMs: ISSUED_AT,
            receiptDigest: signedEnvelope(fixture, { schemaVersion: 5 }).signature,
          },
          fixture.dbPath,
        ),
      ).toBe(false);

      const fixture2 = makeFixture();
      try {
        provisionReceipt(fixture2, signedEnvelope(fixture2));
        const authority2 = authorityFor(fixture2);
        // DDL drifted: the bound digest no longer matches the caller's digest.
        expect(() =>
          authority2.issueFreshReceipt({
            canonicalDatabasePath: fixture2.dbPath,
            schemaDigest: DIGEST_B,
            issuedAtUnixMs: ISSUED_AT,
          }),
        ).toThrow('GUIDED_PROVENANCE_RECEIPT_SCHEMA_MISMATCH');
        expect(
          authority2.verifyReceipt(
            {
              schemaVersion: GUIDED_SCHEMA_VERSION,
              schemaDigest: DIGEST_B,
              databaseId: 'guidedb-0123456789abcdef0123456789abcdef',
              issuedAtUnixMs: ISSUED_AT,
              receiptDigest: signedEnvelope(fixture2).signature,
            },
            fixture2.dbPath,
          ),
        ).toBe(false);
      } finally {
        rmSync(fixture2.root, { recursive: true, force: true });
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses envelopes with unknown, extra, missing or mistyped fields', () => {
    const fixture = makeFixture();
    try {
      const envelope = signedEnvelope(fixture);
      const cases: unknown[] = [
        null,
        { ...envelope, attested: true },
        { ...envelope, schema: 'untrusted/self-attestation' },
        { ...envelope, signature: '' },
        { ...envelope, databaseId: 'self-asserted-id' },
        { ...envelope, issuedAtUnixMs: '1761000000000' },
        { ...envelope, schemaDigest: 'not-hex' },
        { schema: envelope.schema, schemaVersion: envelope.schemaVersion },
      ];
      for (const candidate of cases) {
        replaceReceipt(fixture, candidate as GuidedReceiptEnvelope);
        const authority = authorityFor(fixture);
        expect(() =>
          authority.issueFreshReceipt({
            canonicalDatabasePath: fixture.dbPath,
            schemaDigest: DIGEST_A,
            issuedAtUnixMs: ISSUED_AT,
          }),
        ).toThrow(/GUIDED_PROVENANCE_RECEIPT_MALFORMED/);
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('fails closed with a stable code when the trust anchor or receipt is missing', () => {
    const fixture = makeFixture();
    try {
      // Receipt not provisioned yet.
      const authority = authorityFor(fixture);
      expect(() =>
        authority.issueFreshReceipt({
          canonicalDatabasePath: fixture.dbPath,
          schemaDigest: DIGEST_A,
          issuedAtUnixMs: ISSUED_AT,
        }),
      ).toThrow('GUIDED_PROVENANCE_AUTHORITY_UNAVAILABLE');
      expect(
        authority.verifyReceipt(
          {
            schemaVersion: GUIDED_SCHEMA_VERSION,
            schemaDigest: DIGEST_A,
            databaseId: 'guidedb-0123456789abcdef0123456789abcdef',
            issuedAtUnixMs: ISSUED_AT,
            receiptDigest: signedEnvelope(fixture).signature,
          },
          fixture.dbPath,
        ),
      ).toBe(false);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }

    // Trust anchor missing entirely.
    const fixture2 = makeFixture();
    try {
      rmSync(join(fixture2.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE));
      const authority2 = authorityFor(fixture2);
      expect(() =>
        authority2.issueFreshReceipt({
          canonicalDatabasePath: fixture2.dbPath,
          schemaDigest: DIGEST_A,
          issuedAtUnixMs: ISSUED_AT,
        }),
      ).toThrow('GUIDED_PROVENANCE_TRUST_ANCHOR_MISSING');
    } finally {
      rmSync(fixture2.root, { recursive: true, force: true });
    }
  });

  it('refuses a public key that does not match the operator-pinned fingerprint', () => {
    const fixture = makeFixture();
    try {
      provisionReceipt(fixture, signedEnvelope(fixture));
      const outsider = generateKeyPairSync('ed25519');
      const outsiderPem = outsider.publicKey.export({ type: 'spki', format: 'pem' }).toString();
      const authority = authorityFor(fixture, {
        pinnedSpkiSha256: guidedPublicKeySpkiSha256(outsiderPem),
      });
      expect(() =>
        authority.issueFreshReceipt({
          canonicalDatabasePath: fixture.dbPath,
          schemaDigest: DIGEST_A,
          issuedAtUnixMs: ISSUED_AT,
        }),
      ).toThrow('GUIDED_PROVENANCE_TRUST_PUBLIC_KEY_PIN_MISMATCH');
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses to construct an authority without a well-formed operator pin or owner SID', () => {
    for (const pinnedSpkiSha256 of ['', 'not-hex', 'A'.repeat(63)]) {
      expect(() =>
        createExternalGuidedProvenanceAuthority({
          trustDir: join(tmpdir(), 'unused'),
          ownerSid: TEST_USER_SID,
          pinnedSpkiSha256: pinnedSpkiSha256 as string,
          inspectAcl: protectedInspector,
        }),
      ).toThrow('GUIDED_PROVENANCE_TRUST_PIN_REQUIRED');
    }
    expect(() =>
      createExternalGuidedProvenanceAuthority({
        trustDir: join(tmpdir(), 'unused'),
        pinnedSpkiSha256: DIGEST_A,
        ownerSid: '',
        inspectAcl: protectedInspector,
      }),
    ).toThrow('GUIDED_PROVENANCE_TRUST_OWNER_SID_REQUIRED');
  });

  it('refuses receipt rows whose shape is not exactly the G6 contract', () => {
    const fixture = makeFixture();
    try {
      const envelope = signedEnvelope(fixture);
      provisionReceipt(fixture, envelope);
      const authority = authorityFor(fixture);
      const valid = {
        schemaVersion: GUIDED_SCHEMA_VERSION,
        schemaDigest: DIGEST_A,
        databaseId: envelope.databaseId,
        issuedAtUnixMs: ISSUED_AT,
        receiptDigest: envelope.signature,
      };
      expect(authority.verifyReceipt(valid, fixture.dbPath)).toBe(true);
      for (const candidate of [
        null,
        { ...valid, extra: 1 },
        { ...valid, receiptDigest: valid.receiptDigest.slice(0, 40) },
        { ...valid, issuedAtUnixMs: ISSUED_AT + 1 },
        { ...valid, databaseId: 'guidedb-ffffffffffffffffffffffffffffffff' },
        { schemaVersion: valid.schemaVersion, schemaDigest: valid.schemaDigest },
      ]) {
        expect(authority.verifyReceipt(candidate, fixture.dbPath)).toBe(false);
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });
});

describe('per-user trust-tree ACL/owner policy (fail closed)', () => {
  it('reports the real owner snapshot: the per-user identities own the tree', () => {
    const fixture = makeFixture();
    try {
      // Real probe (no injection). R04: per-user ownership means the process
      // user SID (an admin-profile tree may record Administrators) or the
      // machine authority identities — never a foreign user. The shared OS
      // temp directory on some dev machines carries foreign inherited write
      // ACEs (correctly refused by policy); ownership is the deterministic
      // machine-independent fact asserted here.
      if (process.platform === 'win32') {
        const snapshot = inspectWindowsGuidedTrustAcl(fixture.trustDir, []);
        expect(snapshot).toBeDefined();
        const rows = snapshot ?? [];
        expect(rows.length).toBeGreaterThan(0);
        const processUserSid = queryWindowsProcessUserSid();
        expect(processUserSid).toBeDefined();
        for (const row of rows) {
          expect([processUserSid, 'S-1-5-18', 'S-1-5-32-544']).toContain(row.ownerSid);
        }
      } else {
        expect(inspectWindowsGuidedTrustAcl(fixture.trustDir, [])).toBeUndefined();
        const authority = createExternalGuidedProvenanceAuthority({
          trustDir: fixture.trustDir,
          pinnedSpkiSha256: fixture.pinnedSha256,
          ownerSid: TEST_USER_SID,
        });
        expect(() =>
          authority.issueFreshReceipt({
            canonicalDatabasePath: fixture.dbPath,
            schemaDigest: DIGEST_A,
            issuedAtUnixMs: ISSUED_AT,
          }),
        ).toThrow(/GUIDED_PROVENANCE_TRUST_ACL_UNPROTECTED/);
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses injected ACL snapshots with foreign owners or probe failure', () => {
    const fixture = makeFixture();
    try {
      provisionReceipt(fixture, signedEnvelope(fixture));
      // Another local user's SID owning the tree: never a per-user trust owner.
      const unprotected = (trustDir: string, extraPaths: readonly string[]) => [
        {
          path: trustDir,
          ownerSid: OTHER_USER_SID,
          accessRules: [],
        },
        ...extraPaths.map((path) => ({
          path,
          ownerSid: OTHER_USER_SID,
          accessRules: [],
        })),
      ];
      const authority = authorityFor(fixture, { inspectAcl: unprotected });
      expect(() =>
        authority.issueFreshReceipt({
          canonicalDatabasePath: fixture.dbPath,
          schemaDigest: DIGEST_A,
          issuedAtUnixMs: ISSUED_AT,
        }),
      ).toThrow(/GUIDED_PROVENANCE_TRUST_ACL_UNPROTECTED/);

      const probeFailed = authorityFor(fixture, { inspectAcl: () => undefined });
      expect(() =>
        probeFailed.issueFreshReceipt({
          canonicalDatabasePath: fixture.dbPath,
          schemaDigest: DIGEST_A,
          issuedAtUnixMs: ISSUED_AT,
        }),
      ).toThrow(/GUIDED_PROVENANCE_TRUST_ACL_UNPROTECTED/);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });
});

describe('R04 per-user LocalAppData trust-root resolution (fail closed)', () => {
  /** One disposable profile fixture: root = USERPROFILE, base = AppData/Local. */
  function makeProfileFixture(): { root: string; base: string; env: NodeJS.ProcessEnv } {
    const root = mkdtempSync(join(tmpdir(), 'shun-r04-profile-'));
    const base = join(root, 'AppData', 'Local');
    mkdirSync(base, { recursive: true });
    return { root, base, env: { LOCALAPPDATA: base, USERPROFILE: root } };
  }

  it('accepts the documented USERPROFILE\\AppData\\Local relationship and returns it canonically', () => {
    const fixture = makeProfileFixture();
    try {
      expect(resolveWindowsLocalAppDataBase(fixture.env)).toBe(resolve(fixture.base));
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses absent, relative, root-aliased or missing-directory values', () => {
    const fixture = makeProfileFixture();
    try {
      expect(() => resolveWindowsLocalAppDataBase({ ...fixture.env, LOCALAPPDATA: '' })).toThrow(
        'GUIDED_PROVENANCE_LOCALAPPDATA_UNRESOLVED',
      );
      expect(() =>
        resolveWindowsLocalAppDataBase({ ...fixture.env, LOCALAPPDATA: 'relative/dir' }),
      ).toThrow('GUIDED_PROVENANCE_LOCALAPPDATA_UNRESOLVED');
      expect(() =>
        resolveWindowsLocalAppDataBase({
          ...fixture.env,
          LOCALAPPDATA: parse(fixture.root).root,
        }),
      ).toThrow('GUIDED_PROVENANCE_LOCALAPPDATA_ROOT_ALIAS');
      expect(() =>
        resolveWindowsLocalAppDataBase({
          ...fixture.env,
          LOCALAPPDATA: join(fixture.root, 'AppData', 'NotThere'),
        }),
      ).toThrow(/GUIDED_PROVENANCE_LOCALAPPDATA_(MISSING|PROFILE_MISMATCH)/);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses a LocalAppData value that breaks the documented profile relationship', () => {
    const fixture = makeProfileFixture();
    try {
      const otherRoot = mkdtempSync(join(tmpdir(), 'shun-r04-otherprofile-'));
      try {
        mkdirSync(join(otherRoot, 'AppData', 'Local'), { recursive: true });
        // A different profile's LocalAppData: mismatch with THIS session's
        // USERPROFILE — must never silently issue trust for the wrong user.
        expect(() =>
          resolveWindowsLocalAppDataBase({
            ...fixture.env,
            LOCALAPPDATA: join(otherRoot, 'AppData', 'Local'),
          }),
        ).toThrow('GUIDED_PROVENANCE_LOCALAPPDATA_PROFILE_MISMATCH');
      } finally {
        rmSync(otherRoot, { recursive: true, force: true });
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses an aliased (symlinked) LocalAppData base', () => {
    if (process.platform === 'win32') return; // directory symlink needs elevation here
    const fixture = makeProfileFixture();
    try {
      // The alias sits at the DOCUMENTED profile location of another profile
      // root, so the profile-relationship check passes and the failure is
      // isolated to the reparse/alias refusal itself.
      const aliasedParent = mkdtempSync(join(tmpdir(), 'shun-r04-aliasparent-'));
      const aliasBase = join(aliasedParent, 'AppData', 'Local');
      mkdirSync(join(aliasedParent, 'AppData'), { recursive: true });
      symlinkSync(fixture.base, aliasBase, 'dir');
      try {
        expect(() =>
          resolveWindowsLocalAppDataBase({
            LOCALAPPDATA: aliasBase,
            USERPROFILE: aliasedParent,
          }),
        ).toThrow(/GUIDED_PROVENANCE_LOCALAPPDATA_UNTRUSTED/);
      } finally {
        rmSync(aliasedParent, { recursive: true, force: true });
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses machine-scope Windows locations as LocalAppData', () => {
    if (process.platform !== 'win32') return; // the scope roots are Windows literals
    const fixture = makeProfileFixture();
    try {
      const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
      expect(() =>
        resolveWindowsLocalAppDataBase({ ...fixture.env, LOCALAPPDATA: systemRoot }),
      ).toThrow('GUIDED_PROVENANCE_LOCALAPPDATA_UNEXPECTED_SCOPE');
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('derives the per-user trust tree, secret dir and ancestor chain from the resolved base', () => {
    const fixture = makeProfileFixture();
    try {
      const base = resolve(fixture.base);
      expect(perUserGuidedTrustDirectory(fixture.base)).toBe(
        join(base, 'Shun', 'authority', 'guided-provenance'),
      );
      expect(perUserIssuerSecretDirectory(fixture.base)).toBe(
        join(base, 'Shun', 'secrets', 'guided-issuer'),
      );
      // The ancestor chain terminates exactly at the LocalAppData policy
      // boundary: authority -> Shun -> base, nothing above it.
      expect(perUserGuidedTrustAncestorChain(fixture.base)).toEqual([
        join(base, 'Shun', 'authority'),
        join(base, 'Shun'),
        base,
      ]);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });
});

describe('R04 bootstrap identity guard (read-only, fail closed)', () => {
  it('accepts an unelevated same-user run and a same-account elevation', () => {
    expect(
      assessGuidedBootstrapIdentity({
        processUserSid: () => TEST_USER_SID,
        elevated: () => false,
      }),
    ).toEqual({ processUserSid: TEST_USER_SID, elevated: false });
    expect(
      assessGuidedBootstrapIdentity({
        processUserSid: () => TEST_USER_SID,
        elevated: () => true,
        consoleUserSid: () => TEST_USER_SID,
      }),
    ).toEqual({ processUserSid: TEST_USER_SID, elevated: true });
    // Unelevated runs never probe the console session: the normal per-user
    // path (including a remote RDP target user) needs no elevation at all.
    expect(
      assessGuidedBootstrapIdentity({
        processUserSid: () => TEST_USER_SID,
        elevated: () => false,
        consoleUserSid: () => null,
      }),
    ).toEqual({ processUserSid: TEST_USER_SID, elevated: false });
  });

  it('refuses an over-the-shoulder elevation that belongs to a different account', () => {
    // Elevated as the ADMIN while the console session user is the TARGET
    // user: planting trust now would write the admin's profile, not the
    // target interactive user's.
    expect(() =>
      assessGuidedBootstrapIdentity({
        processUserSid: () => 'S-1-5-21-9-9-9-500',
        elevated: () => true,
        consoleUserSid: () => TEST_USER_SID,
      }),
    ).toThrow(/GUIDED_BOOTSTRAP_WRONG_ACCOUNT_ELEVATION/);
  });

  it('refuses an elevation whose console target cannot be resolved (unverifiable is not same-account)', () => {
    // Whole-version RQ repair of review #5830194105 P2-IDENTITY-UNKNOWN:
    // with NO resolvable interactive console session, an elevated token
    // cannot be proven to belong to the target interactive user, so the
    // privileged path fails closed — run unelevated as the target user.
    expect(() =>
      assessGuidedBootstrapIdentity({
        processUserSid: () => TEST_USER_SID,
        elevated: () => true,
        consoleUserSid: () => null,
      }),
    ).toThrow('GUIDED_BOOTSTRAP_ELEVATED_TARGET_UNVERIFIABLE');
  });

  it('fails closed when any identity probe fails', () => {
    expect(() =>
      assessGuidedBootstrapIdentity({
        processUserSid: () => undefined,
        elevated: () => false,
      }),
    ).toThrow('GUIDED_BOOTSTRAP_IDENTITY_PROBE_FAILED');
    expect(() =>
      assessGuidedBootstrapIdentity({
        processUserSid: () => TEST_USER_SID,
        elevated: () => undefined,
      }),
    ).toThrow('GUIDED_BOOTSTRAP_IDENTITY_PROBE_FAILED');
    expect(() =>
      assessGuidedBootstrapIdentity({
        processUserSid: () => TEST_USER_SID,
        elevated: () => true,
        consoleUserSid: () => undefined,
      }),
    ).toThrow('GUIDED_BOOTSTRAP_IDENTITY_PROBE_FAILED');
  });

  it('the production wrapper requires real Windows', () => {
    if (process.platform === 'win32') return;
    expect(() => assertGuidedBootstrapIdentityContext()).toThrow(
      'GUIDED_BOOTSTRAP_REAL_WINDOWS_ONLY',
    );
  });
});

describe('operator issuer guards (no elevation required for these checks)', () => {
  it('refuses a private key that does not match the pinned public key', () => {
    const fixture = makeFixture();
    try {
      const outsider = generateKeyPairSync('ed25519');
      expect(() =>
        loadGuidedIssuerPrivateKey(
          // Write the outsider private key to a temp file the helper reads.
          (() => {
            const path = join(fixture.keyDir, 'outsider.pem');
            writeFileSync(
              path,
              outsider.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
              'utf8',
            );
            return path;
          })(),
          fixture.publicKeyPem,
        ),
      ).toThrow('ISSUER_OPERATOR_PUBLIC_KEY_MISMATCH');
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses database paths inside the workspace scope', () => {
    const fixture = makeFixture();
    try {
      expect(() =>
        assertGuidedIssuerDatabasePath(
          join(fixture.workspaceRoot, 'guided.db'),
          fixture.workspaceRoot,
        ),
      ).toThrow('ISSUER_DATABASE_PATH_INSIDE_FORBIDDEN_SCOPE');
      // Trust-directory overlap is refused with its own precise codes at the
      // issuer level (covered by the overlapping-directories test below).
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses reparse point / symlink aliases for trust paths', () => {
    const fixture = makeFixture();
    try {
      const junction = join(fixture.root, 'trust-junction');
      symlinkSync(fixture.trustDir, junction, process.platform === 'win32' ? 'junction' : 'dir');
      expect(() =>
        assertGuidedRegularCanonicalPath(junction, 'ISSUER_TRUST_DIR_UNTRUSTED'),
      ).toThrow('GUIDED_PROVENANCE_ISSUER_TRUST_DIR_UNTRUSTED');
      // File symlinks need an elevated token on Windows; a second junction
      // exercises the identical lstat guard for the issuer key path code.
      const keyDirJunction = join(fixture.root, 'key-junction');
      symlinkSync(
        fixture.keyDir,
        keyDirJunction,
        process.platform === 'win32' ? 'junction' : 'dir',
      );
      expect(() =>
        assertGuidedRegularCanonicalPath(keyDirJunction, 'ISSUER_PRIVATE_KEY_PATH_UNTRUSTED'),
      ).toThrow('GUIDED_PROVENANCE_ISSUER_PRIVATE_KEY_PATH_UNTRUSTED');
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses to overwrite an existing receipt; a schema/path change needs explicit operator action', () => {
    const fixture = makeFixture();
    try {
      const envelope = signedEnvelope(fixture);
      provisionReceipt(fixture, envelope);
      expect(() => provisionReceipt(fixture, envelope)).toThrow(
        'GUIDED_PROVENANCE_ISSUER_RECEIPT_ALREADY_EXISTS',
      );

      const privateKeyPath = join(fixture.keyDir, 'issuer.pem');
      writeFileSync(
        privateKeyPath,
        fixture.keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        'utf8',
      );
      expect(() =>
        issueGuidedProvenanceReceipt({
          databasePath: fixture.dbPath,
          schemaDigest: DIGEST_A,
          privateKeyPath,
          workspaceRoot: fixture.workspaceRoot,
          ownerSid: TEST_USER_SID,
          trustDir: fixture.trustDir,
          inspectAcl: protectedInspector,
          testOnlyAllowTemporaryKey: true,
        }),
      ).toThrow('GUIDED_PROVENANCE_ISSUER_RECEIPT_ALREADY_EXISTS');
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses issuance when the completed trust tree fails the same ACL policy the runtime enforces', () => {
    const fixture = makeFixture();
    try {
      rmSync(join(fixture.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE));
      const privateKeyPath = join(fixture.keyDir, 'issuer.pem');
      writeFileSync(
        privateKeyPath,
        fixture.keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        'utf8',
      );
      expect(() =>
        issueGuidedProvenanceReceipt({
          databasePath: fixture.dbPath,
          schemaDigest: DIGEST_A,
          privateKeyPath,
          workspaceRoot: fixture.workspaceRoot,
          ownerSid: TEST_USER_SID,
          trustDir: fixture.trustDir,
          inspectAcl: () => undefined, // probe failure ⇒ refuse
          testOnlyAllowTemporaryKey: true,
        }),
      ).toThrow(/ISSUER_TRUST_TREE_UNPROTECTED/);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });
});

describe('runtime adapter is verify-only (no signing reachability)', () => {
  it('contains no private-key import or signing API', () => {
    const modulePath = fileURLToPath(
      new URL('../src/real-storage/guided-provenance-issuance.ts', import.meta.url),
    );
    const source = readFileSync(modulePath, 'utf8');
    expect(source).not.toMatch(/createPrivateKey/);
    expect(source).not.toMatch(/generateKeyPair/);
    expect(source).not.toMatch(/\bsign\s*\(/);
    expect(source).not.toMatch(/privateKey/);
    // Trust never comes from caller-controlled environment: the only env
    // touches are the outward SystemRoot lookup (ACL/PowerShell probes) and
    // the STRICTLY VALIDATED OS session LocalAppData/USERPROFILE values that
    // must satisfy the documented profile relationship — never a raw
    // caller-picked trust directory.
    expect(source).not.toMatch(/pinnedSpkiSha256\s*=\s*process\.env/);
    expect(source).not.toMatch(/trustDir\s*=\s*process\.env/);
    expect(source).not.toMatch(/process\.env\.ProgramData/);
  });

  it('verifies receipts with only the public trust anchor present — no secret anywhere in the trust tree', () => {
    const fixture = makeFixture();
    try {
      const envelope = signedEnvelope(fixture);
      provisionReceipt(fixture, envelope);
      // No private key file exists anywhere under the trust directory.
      const trustTreeHasSecret = existsSync(join(fixture.trustDir, 'guided-issuer.key'));
      expect(trustTreeHasSecret).toBe(false);
      const authority = authorityFor(fixture);
      const receipt = authority.issueFreshReceipt({
        canonicalDatabasePath: fixture.dbPath,
        schemaDigest: DIGEST_A,
        issuedAtUnixMs: ISSUED_AT,
      });
      expect(authority.verifyReceipt(receipt, fixture.dbPath)).toBe(true);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });
});

describe('G2 DACL and issuer-key custody repairs (per-user policy)', () => {
  it('rejects foreign-identity DACL write/DELETE/WRITE_DAC/WRITE_OWNER rights', () => {
    const fixture = makeFixture();
    try {
      for (const mask of [2, 0x10000, 0x40000, 0x80000, 0x001f01ff]) {
        const rows = protectedAcl(fixture.trustDir, []).map((row) => ({
          ...row,
          accessRules: [
            ...row.accessRules,
            {
              identitySid: 'S-1-5-11',
              rightsMask: mask,
              accessType: 'Allow' as const,
              isInherited: true,
            },
          ],
        }));
        expect(assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, rows)).toEqual(
          expect.arrayContaining([expect.stringContaining('non-owner write')]),
        );
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('allows the interactive user full control, SYSTEM/Administrators full control and read-only foreign ACEs', () => {
    const fixture = makeFixture();
    try {
      // The default per-user profile ACL shape: user + SYSTEM +
      // Administrators full control, plus a foreign read-only ACE, plus an
      // inherited deny ACE for an unrelated SID — all legitimate.
      const rows = protectedAcl(fixture.trustDir, []).map((row) => ({
        ...row,
        accessRules: [
          ...row.accessRules,
          {
            identitySid: TEST_USER_SID,
            rightsMask: 0x001f01ff,
            accessType: 'Allow' as const,
            isInherited: true,
          },
          {
            identitySid: 'S-1-5-99',
            rightsMask: 0x000200a9,
            accessType: 'Allow' as const,
            isInherited: true,
          },
          {
            identitySid: 'S-1-5-99',
            rightsMask: 0x001f01ff,
            accessType: 'Deny' as const,
            isInherited: true,
          },
        ],
      }));
      expect(assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, rows)).toEqual([]);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('fails closed when neither the owner nor any runtime group can read the trust tree', () => {
    const fixture = makeFixture();
    try {
      const noRead = protectedAcl(fixture.trustDir, []).map((row) => ({
        ...row,
        accessRules: [],
      }));
      expect(assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, noRead)).toEqual(
        expect.arrayContaining([expect.stringContaining('runtime read/execute')]),
      );

      const deniedRead = protectedAcl(fixture.trustDir, []).map((row) => ({
        ...row,
        accessRules: [
          ...row.accessRules,
          {
            identitySid: 'S-1-1-0',
            rightsMask: 0x00000001,
            accessType: 'Deny' as const,
            isInherited: true,
          },
        ],
      }));
      expect(assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, deniedRead)).toEqual(
        expect.arrayContaining([expect.stringContaining('runtime read/execute')]),
      );
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('fails closed when ACL scan is incomplete or a rule SID cannot translate', () => {
    const fixture = makeFixture();
    try {
      const rows = protectedAcl(fixture.trustDir, []);
      expect(
        assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, rows.slice(0, 1)),
      ).not.toEqual([]);
      const [firstRow, ...restRows] = rows;
      if (!firstRow) throw new Error('fixture produced no ACL rows');
      expect(
        assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, [
          {
            ...firstRow,
            accessRules: [
              { identitySid: null, rightsMask: 2, accessType: 'Allow', isInherited: true },
            ],
          },
          ...restRows,
        ]),
      ).not.toEqual([]);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('rejects OS temp, database, trust, and workspace private-key paths', () => {
    const fixture = makeFixture();
    try {
      for (const path of [
        join(fixture.keyDir, 'key.pem'),
        join(fixture.dbDir, 'key.pem'),
        join(fixture.trustDir, 'key.pem'),
        join(fixture.workspaceRoot, 'key.pem'),
      ]) {
        expect(() =>
          assertGuidedPrivateKeyScope(
            path,
            fixture.workspaceRoot,
            fixture.dbPath,
            fixture.trustDir,
          ),
        ).toThrow('GUIDED_PROVENANCE_ISSUER_KEY_SCOPE_REFUSED');
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('rejects overlapping database and trust directories in either direction', () => {
    const fixture = makeFixture();
    try {
      const keyFile = join(fixture.keyDir, 'issuer.pem');
      writeFileSync(
        keyFile,
        fixture.keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      );
      const args = {
        schemaDigest: DIGEST_A,
        privateKeyPath: keyFile,
        workspaceRoot: fixture.workspaceRoot,
        ownerSid: TEST_USER_SID,
        inspectAcl: protectedInspector,
        testOnlyAllowTemporaryKey: true,
      };
      expect(() =>
        issueGuidedProvenanceReceipt({
          ...args,
          databasePath: join(fixture.trustDir, 'inside.db'),
          trustDir: fixture.trustDir,
        }),
      ).toThrow('GUIDED_PROVENANCE_ISSUER_DATABASE_INSIDE_TRUST_DIR');
      const nestedTrust = join(fixture.dbDir, 'nested-trust');
      mkdirSync(nestedTrust);
      expect(() =>
        issueGuidedProvenanceReceipt({
          ...args,
          databasePath: fixture.dbPath,
          trustDir: nestedTrust,
        }),
      ).toThrow('GUIDED_PROVENANCE_ISSUER_TRUST_INSIDE_DATABASE_DIR');
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('rejects production CLI trust-directory overrides before identity checks', () => {
    expect(() =>
      runGuidedIssuerCli({
        SHUN_GUIDED_TRUST_DIR: 'C:\\wrong\\user-writable',
      }),
    ).toThrow('ISSUER_TRUST_DIR_OVERRIDE_FORBIDDEN');
  });

  it('refuses deny read ACEs for interactive-logon SIDs the runtime token always holds', () => {
    const fixture = makeFixture();
    try {
      for (const sid of ['S-1-5-4', 'S-1-2-0', 'S-1-2-1']) {
        const rows = protectedAcl(fixture.trustDir, []).map((row) => ({
          ...row,
          accessRules: [
            ...row.accessRules,
            {
              identitySid: sid,
              rightsMask: 0x00000001,
              accessType: 'Deny' as const,
              isInherited: true,
            },
          ],
        }));
        expect(assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, rows)).toEqual(
          expect.arrayContaining([expect.stringContaining('runtime read/execute')]),
        );
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('exempts CREATOR OWNER/CREATOR GROUP placeholder ACEs from the write check', () => {
    const fixture = makeFixture();
    try {
      for (const sid of ['S-1-3-0', 'S-1-3-1']) {
        const rows = protectedAcl(fixture.trustDir, []).map((row) => ({
          ...row,
          accessRules: [
            ...row.accessRules,
            {
              identitySid: sid,
              rightsMask: 0x001f01ff,
              accessType: 'Allow' as const,
              isInherited: true,
            },
          ],
        }));
        expect(assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, rows)).toEqual([]);
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('assesses the per-user ancestor chain and refuses foreign write on it', () => {
    const base = resolve(join(mkdtempSync(join(tmpdir(), 'shun-r04-chain-')), 'AppData', 'Local'));
    const chain = perUserGuidedTrustAncestorChain(base);
    expect(chain.map((path) => path.toLowerCase())).toEqual([
      join(base, 'Shun', 'authority').toLowerCase(),
      join(base, 'Shun').toLowerCase(),
      base.toLowerCase(),
    ]);
    const ancestorRow = (path: string) => ({
      path,
      ownerSid: TEST_USER_SID,
      accessRules: [
        {
          identitySid: TEST_USER_SID,
          rightsMask: 0x001f01ff,
          accessType: 'Allow',
          isInherited: true,
        },
      ] as GuidedTrustAccessRule[],
    });
    const healthy = chain.map(ancestorRow);
    expect(assessGuidedTrustAncestorProtection(chain, TEST_USER_SID, healthy)).toEqual([]);
    // The user's own FULL CONTROL on the profile ancestors is legitimate
    // per-user profile semantics (unlike the retired privileged-only rule).
    const userWritable = chain.map((path, index) =>
      index === 2
        ? {
            ...ancestorRow(path),
            accessRules: [
              ...ancestorRow(path).accessRules,
              {
                identitySid: TEST_USER_SID,
                rightsMask: 0x001f01ff,
                accessType: 'Allow' as const,
                isInherited: true,
              },
            ],
          }
        : ancestorRow(path),
    );
    expect(assessGuidedTrustAncestorProtection(chain, TEST_USER_SID, userWritable)).toEqual([]);
    const foreignDeletable = chain.map((path, index) =>
      index === 1
        ? {
            ...ancestorRow(path),
            accessRules: [
              ...ancestorRow(path).accessRules,
              {
                identitySid: 'S-1-5-11',
                rightsMask: 0x00010000,
                accessType: 'Allow' as const,
                isInherited: true,
              },
            ],
          }
        : ancestorRow(path),
    );
    expect(assessGuidedTrustAncestorProtection(chain, TEST_USER_SID, foreignDeletable)).toEqual(
      expect.arrayContaining([expect.stringContaining('non-owner write')]),
    );
    expect(
      assessGuidedTrustAncestorProtection(chain, TEST_USER_SID, healthy.slice(0, 2)),
    ).not.toEqual([]);
    const deniedTraverse = chain.map((path, index) =>
      index === 0
        ? {
            ...ancestorRow(path),
            accessRules: [
              ...ancestorRow(path).accessRules,
              {
                identitySid: 'S-1-5-4',
                rightsMask: 0x00000020,
                accessType: 'Deny' as const,
                isInherited: true,
              },
            ],
          }
        : ancestorRow(path),
    );
    expect(assessGuidedTrustAncestorProtection(chain, TEST_USER_SID, deniedTraverse)).toEqual(
      expect.arrayContaining([expect.stringContaining('runtime read/execute')]),
    );
  });

  it('refuses the test-only temporary-key flag outside a test-runner context', () => {
    const fixture = makeFixture();
    const originalVitest = process.env.VITEST;
    delete process.env.VITEST;
    try {
      const keyFile = join(fixture.keyDir, 'issuer.pem');
      writeFileSync(
        keyFile,
        fixture.keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      );
      expect(() =>
        issueGuidedProvenanceReceipt({
          schemaDigest: DIGEST_A,
          databasePath: fixture.dbPath,
          privateKeyPath: keyFile,
          workspaceRoot: fixture.workspaceRoot,
          ownerSid: TEST_USER_SID,
          trustDir: fixture.trustDir,
          inspectAcl: protectedInspector,
          testOnlyAllowTemporaryKey: true,
        }),
      ).toThrow('ISSUER_TEST_ONLY_KEY_FLAG_OUTSIDE_TEST_CONTEXT');
    } finally {
      if (originalVitest !== undefined) process.env.VITEST = originalVitest;
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });
});

describe('R04 combined per-user default-trust policy', () => {
  /**
   * Real per-user layout under a disposable profile fixture: the trust tree
   * exists on disk exactly where the resolver would put it, so the combined
   * assessment exercises the same paths production would.
   */
  function makePerUserFixture(): {
    root: string;
    base: string;
    trustDir: string;
    cleanup: () => void;
  } {
    const root = mkdtempSync(join(tmpdir(), 'shun-r04-default-'));
    const base = join(root, 'AppData', 'Local');
    const trustDir = perUserGuidedTrustDirectory(base);
    mkdirSync(join(trustDir, GUIDED_PROVENANCE_RECEIPTS_SUBDIR), { recursive: true });
    writeFileSync(
      join(trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE),
      `${JSON.stringify({
        schema: GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA,
        publicKeyPem: 'placeholder-not-loaded-here',
        spkiSha256: '0'.repeat(64),
      })}\n`,
      'utf8',
    );
    return { root, base, trustDir, cleanup: () => rmSync(root, { recursive: true, force: true }) };
  }

  /** Explicit three-row trust snapshot, existsSync-free (see G4 heritage). */
  const treeRows = (trustDir: string): GuidedTrustAclSnapshot =>
    [
      trustDir,
      join(trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE),
      join(trustDir, GUIDED_PROVENANCE_RECEIPTS_SUBDIR),
    ].map((path) => ({
      path,
      ownerSid: TEST_USER_SID,
      accessRules: [
        {
          identitySid: TEST_USER_SID,
          rightsMask: 0x001200a9,
          accessType: 'Allow',
          isInherited: true,
        },
      ] as GuidedTrustAccessRule[],
    }));

  it('combined policy accepts the healthy per-user profile shape and the user-owned ancestor chain', () => {
    const fixture = makePerUserFixture();
    try {
      const chain = perUserGuidedTrustAncestorChain(fixture.base);
      const tree = treeRows(fixture.trustDir);
      expect(tree).toHaveLength(3);
      const healthy = chain.map((path) => protectedAncestorRow(path));
      expect(
        assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, tree, healthy, chain),
      ).toEqual([]);
    } finally {
      fixture.cleanup();
    }
  });

  it('combined policy rejects foreign-writable, incomplete, read-denied or unprobed ancestors', () => {
    const fixture = makePerUserFixture();
    try {
      const chain = perUserGuidedTrustAncestorChain(fixture.base);
      const tree = treeRows(fixture.trustDir);
      expect(tree).toHaveLength(3);
      const healthy = chain.map((path) => protectedAncestorRow(path));

      // Ancestor writable by a foreign identity (DELETE on one entry).
      const writable = chain.map((path, index) =>
        index === 1
          ? {
              ...protectedAncestorRow(path),
              accessRules: [
                ...protectedAncestorRow(path).accessRules,
                {
                  identitySid: 'S-1-5-11',
                  rightsMask: 0x00010000,
                  accessType: 'Allow' as const,
                  isInherited: true,
                },
              ],
            }
          : protectedAncestorRow(path),
      );
      expect(
        assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, tree, writable, chain),
      ).toEqual(expect.arrayContaining([expect.stringContaining('non-owner write')]));

      // Incomplete ancestor snapshot: one enumerated directory missing.
      expect(
        assessGuidedTrustProtection(
          fixture.trustDir,
          [],
          TEST_USER_SID,
          tree,
          healthy.slice(0, 2),
          chain,
        ),
      ).toEqual(expect.arrayContaining([expect.stringContaining('incomplete')]));

      // Runtime read denied on the closest ancestor.
      const readDenied = chain.map((path, index) =>
        index === 0
          ? {
              ...protectedAncestorRow(path),
              accessRules: [
                ...protectedAncestorRow(path).accessRules,
                {
                  identitySid: 'S-1-5-4',
                  rightsMask: 0x00000020,
                  accessType: 'Deny' as const,
                  isInherited: true,
                },
              ],
            }
          : protectedAncestorRow(path),
      );
      expect(
        assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, tree, readDenied, chain),
      ).toEqual(expect.arrayContaining([expect.stringContaining('runtime read/execute')]));

      // Malformed ancestor row (owner not resolvable to a SID string).
      const malformed = [
        { path: chain[0] ?? '', ownerSid: null, accessRules: [] },
        ...healthy.slice(1),
      ];
      expect(
        assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, tree, malformed, chain),
      ).toEqual(expect.arrayContaining([expect.stringContaining('invalid owner or incomplete')]));

      // No injected ancestor snapshot: production defaults to the real
      // non-recursive probe, which cannot prove a protected chain in test
      // environments — fail closed rather than skip the ancestor policy.
      expect(
        assessGuidedTrustProtection(fixture.trustDir, [], TEST_USER_SID, tree, undefined, chain),
      ).not.toEqual([]);
    } finally {
      fixture.cleanup();
    }
  });

  it('exempts injected non-default test trust directories from the ancestor policy', () => {
    const fixture = makeFixture();
    try {
      // Tree-only injected snapshot on a non-default trust dir: no ancestor
      // rows may be required and the real ancestor probe must not run.
      expect(
        assessGuidedTrustProtection(
          fixture.trustDir,
          [],
          TEST_USER_SID,
          protectedAcl(fixture.trustDir, []),
        ),
      ).toEqual([]);
      provisionReceipt(fixture, signedEnvelope(fixture));
      const authority = authorityFor(fixture);
      const receipt = authority.issueFreshReceipt({
        canonicalDatabasePath: fixture.dbPath,
        schemaDigest: DIGEST_A,
        issuedAtUnixMs: ISSUED_AT,
      });
      expect(authority.verifyReceipt(receipt, fixture.dbPath)).toBe(true);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('runtime init wiring passes ownerSid and the resolved ancestor chain into the combined policy', () => {
    // Deterministic source-wiring assertion over the actual `const init =`
    // body (comments stripped): the per-user combined policy must receive
    // the owner SID and the resolved ancestor chain.
    const modulePath = fileURLToPath(
      new URL('../src/real-storage/guided-provenance-issuance.ts', import.meta.url),
    );
    const code = readFileSync(modulePath, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/[^\n]*/g, '');
    const initStart = code.indexOf('const init =');
    expect(initStart).toBeGreaterThan(-1);
    const initEnd = code.indexOf('const receiptPathFor =', initStart);
    expect(initEnd).toBeGreaterThan(initStart);
    const initBody = code.slice(initStart, initEnd);
    expect(initBody).toContain('assessGuidedTrustProtection(');

    const callStart = initBody.indexOf('assessGuidedTrustProtection');
    const openParen = initBody.indexOf('(', callStart);
    expect(openParen).toBeGreaterThan(callStart);
    let depth = 0;
    let closeParen = -1;
    for (let index = openParen; index < initBody.length; index += 1) {
      const ch = initBody[index];
      if (ch === '(') depth += 1;
      else if (ch === ')') {
        depth -= 1;
        if (depth === 0) {
          closeParen = index;
          break;
        }
      }
    }
    expect(closeParen).toBeGreaterThan(openParen);

    // Split the argument list on top-level commas only (nested calls keep
    // their commas), and require the per-user policy arguments in place.
    const argText = initBody.slice(openParen + 1, closeParen);
    const args: string[] = [];
    let current = '';
    depth = 0;
    for (const ch of argText) {
      if (ch === '(') depth += 1;
      else if (ch === ')') depth -= 1;
      if (ch === ',' && depth === 0) {
        args.push(current.trim());
        current = '';
      } else {
        current += ch;
      }
    }
    args.push(current.trim());
    const filled = args.filter((arg) => arg.length > 0);
    expect(filled).toHaveLength(6);
    expect(filled[2]).toBe('ownerSid');
    expect(filled[5]).toBe('ancestorChain');
  });
});
