// R02-E (#348): deterministic test-key coverage for the externally signed
// Guided provenance receipt. All Ed25519 keys here are ephemeral and
// test-only, generated per run and never persisted to any location outside
// the OS temp directory. No production key, credential or signed production
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
import { join } from 'node:path';
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
  assertGuidedPrivateKeyScope,
  assertGuidedRegularCanonicalPath,
  assessGuidedTrustAncestorProtection,
  assessGuidedTrustProtection,
  buildGuidedReceiptSigningBytes,
  canonicalGuidedDatabasePath,
  createExternalGuidedProvenanceAuthority,
  defaultGuidedProvenanceTrustDirectory,
  defaultGuidedTrustAncestorChain,
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
  writeGuidedReceiptAtomically,
} from '../src/real-storage/guided-provenance-issuance.ts';

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const ISSUED_AT = 1_761_000_000_000;

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
    ownerSid: 'S-1-5-32-544',
    accessRules: [
      { identitySid: 'S-1-5-32-545', rightsMask: 0x200a9, accessType: 'Allow', isInherited: true },
    ] as GuidedTrustAccessRule[],
  }));
}

const protectedInspector = (trustDir: string, extraPaths: readonly string[]) =>
  protectedAcl(trustDir, extraPaths);

/** One healthy admin-owned ancestor row ( Administrators/SYSTEM-owned). */
const protectedAncestorRow = (path: string) => ({
  path,
  ownerSid: 'S-1-5-18',
  accessRules: [
    {
      identitySid: 'S-1-5-32-545',
      rightsMask: 0x001200a9,
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

  it('refuses to construct an authority without a well-formed operator pin', () => {
    for (const pinnedSpkiSha256 of ['', 'not-hex', 'A'.repeat(63)]) {
      expect(() =>
        createExternalGuidedProvenanceAuthority({
          trustDir: join(tmpdir(), 'unused'),
          pinnedSpkiSha256: pinnedSpkiSha256 as string,
          inspectAcl: protectedInspector,
        }),
      ).toThrow('GUIDED_PROVENANCE_TRUST_PIN_REQUIRED');
    }
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

describe('Windows trust-tree ACL/owner policy (fail closed)', () => {
  it('reports the real owner snapshot and refuses a trust tree the runtime cannot prove protected', () => {
    const fixture = makeFixture();
    try {
      // Real probe (no injection): a temp-dir trust tree is user-owned, so
      // the adapter must refuse it — on Windows by policy, elsewhere because
      // the probe cannot run. Both are fail-closed.
      if (process.platform === 'win32') {
        const snapshot = inspectWindowsGuidedTrustAcl(fixture.trustDir, []);
        expect(snapshot).toBeDefined();
        const rows = snapshot ?? [];
        expect(rows.length).toBeGreaterThan(0);
        for (const row of rows) {
          expect(['S-1-5-18', 'S-1-5-32-544']).not.toContain(row.ownerSid);
        }
      } else {
        expect(inspectWindowsGuidedTrustAcl(fixture.trustDir, [])).toBeUndefined();
      }
      const authority = createExternalGuidedProvenanceAuthority({
        trustDir: fixture.trustDir,
        pinnedSpkiSha256: fixture.pinnedSha256,
      });
      expect(() =>
        authority.issueFreshReceipt({
          canonicalDatabasePath: fixture.dbPath,
          schemaDigest: DIGEST_A,
          issuedAtUnixMs: ISSUED_AT,
        }),
      ).toThrow(/GUIDED_PROVENANCE_TRUST_ACL_UNPROTECTED/);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('refuses injected ACL snapshots with non-privileged owners or probe failure', () => {
    const fixture = makeFixture();
    try {
      provisionReceipt(fixture, signedEnvelope(fixture));
      const unprotected = (trustDir: string, extraPaths: readonly string[]) => [
        {
          path: trustDir,
          ownerSid: 'S-1-5-32-545',
          accessRules: [],
        }, // Users — never a trust owner.
        ...extraPaths.map((path) => ({
          path,
          ownerSid: 'S-1-5-32-545' as const,
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
    // Trust never comes from the environment: the only env touch is the
    // outward SystemRoot lookup that locates the system PowerShell binary
    // for the read-only ACL probe (mirrors executor anchor-protection).
    expect(source).not.toMatch(/pinnedSpkiSha256\s*=\s*process\.env/);
    expect(source).not.toMatch(/trustDir\s*=\s*process\.env/);
    // G4: the trust-root ancestor boundary is source-pinned; a caller
    // exported ProgramData must never shorten or redirect the chain.
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

describe('G2 DACL and issuer-key custody repairs', () => {
  it('rejects inherited nonprivileged DACL write/DELETE/WRITE_DAC/WRITE_OWNER rights', () => {
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
        expect(assessGuidedTrustProtection(fixture.trustDir, [], rows)).toEqual(
          expect.arrayContaining([expect.stringContaining('non-privileged write')]),
        );
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('allows read-only Users ACE and inherited deny ACE', () => {
    const fixture = makeFixture();
    try {
      const rows = protectedAcl(fixture.trustDir, []).map((row) => ({
        ...row,
        accessRules: [
          ...row.accessRules,
          {
            identitySid: 'S-1-5-99',
            rightsMask: 0x001f01ff,
            accessType: 'Deny' as const,
            isInherited: true,
          },
        ],
      }));
      expect(assessGuidedTrustProtection(fixture.trustDir, [], rows)).toEqual([]);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('fails closed when Users/Authenticated Users cannot read or traverse the trust tree', () => {
    const fixture = makeFixture();
    try {
      const noRead = protectedAcl(fixture.trustDir, []).map((row) => ({
        ...row,
        accessRules: [],
      }));
      expect(assessGuidedTrustProtection(fixture.trustDir, [], noRead)).toEqual(
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
      expect(assessGuidedTrustProtection(fixture.trustDir, [], deniedRead)).toEqual(
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
      expect(assessGuidedTrustProtection(fixture.trustDir, [], rows.slice(0, 1))).not.toEqual([]);
      const [firstRow, ...restRows] = rows;
      if (!firstRow) throw new Error('fixture produced no ACL rows');
      expect(
        assessGuidedTrustProtection(
          fixture.trustDir,
          [],
          [
            {
              ...firstRow,
              accessRules: [
                { identitySid: null, rightsMask: 2, accessType: 'Allow', isInherited: true },
              ],
            },
            ...restRows,
          ],
        ),
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

  it('rejects production CLI trust-directory overrides before elevation check', () => {
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
        expect(assessGuidedTrustProtection(fixture.trustDir, [], rows)).toEqual(
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
        expect(assessGuidedTrustProtection(fixture.trustDir, [], rows)).toEqual([]);
      }
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('assesses the default-trust ancestor chain and refuses non-privileged write on it', () => {
    const chain = defaultGuidedTrustAncestorChain();
    expect(chain.map((path) => path.toLowerCase())).toEqual([
      'c:\\programdata\\shun\\authority',
      'c:\\programdata\\shun',
      'c:\\programdata',
    ]);
    const ancestorRow = (path: string) => ({
      path,
      ownerSid: 'S-1-5-18',
      accessRules: [
        {
          identitySid: 'S-1-5-32-545',
          rightsMask: 0x001200a9,
          accessType: 'Allow',
          isInherited: true,
        },
      ] as GuidedTrustAccessRule[],
    });
    const healthy = chain.map(ancestorRow);
    expect(assessGuidedTrustAncestorProtection(chain, healthy)).toEqual([]);
    // OS-default ProgramData shape: Users "create children" (0x116) on the
    // folder itself cannot rename/delete/re-ACL an existing admin-owned entry.
    const defaultCreate = chain.map((path, index) =>
      index === 2
        ? {
            ...ancestorRow(path),
            accessRules: [
              ...ancestorRow(path).accessRules,
              {
                identitySid: 'S-1-5-32-545',
                rightsMask: 0x00000116,
                accessType: 'Allow' as const,
                isInherited: true,
              },
            ],
          }
        : ancestorRow(path),
    );
    expect(assessGuidedTrustAncestorProtection(chain, defaultCreate)).toEqual([]);
    const deletable = chain.map((path, index) =>
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
    expect(assessGuidedTrustAncestorProtection(chain, deletable)).toEqual(
      expect.arrayContaining([expect.stringContaining('non-privileged write')]),
    );
    expect(assessGuidedTrustAncestorProtection(chain, healthy.slice(0, 2))).not.toEqual([]);
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
    expect(assessGuidedTrustAncestorProtection(chain, deniedTraverse)).toEqual(
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

describe('G4 repairs: pinned ancestor boundary and combined default-trust policy', () => {
  it('pins the ancestor chain to source C:\\ProgramData even when process.env.ProgramData points inside the trust root', () => {
    const original = process.env.ProgramData;
    process.env.ProgramData = 'C:\\ProgramData\\Shun\\authority';
    try {
      expect(defaultGuidedTrustAncestorChain()).toEqual([
        'C:\\ProgramData\\Shun\\authority',
        'C:\\ProgramData\\Shun',
        'C:\\ProgramData',
      ]);
    } finally {
      if (original === undefined) delete process.env.ProgramData;
      else process.env.ProgramData = original;
    }
  });

  it('combined default-trust policy accepts healthy ancestors and the real ProgramData ACL shape', () => {
    const trustDir = defaultGuidedProvenanceTrustDirectory();
    const chain = defaultGuidedTrustAncestorChain();
    const healthy = chain.map((path) => protectedAncestorRow(path));
    expect(assessGuidedTrustProtection(trustDir, [], protectedAcl(trustDir, []), healthy)).toEqual(
      [],
    );
    // The real OS-default ProgramData shape grants Users "create children"
    // (0x116) on the folder itself; that cannot rename/delete/re-ACL an
    // existing admin-owned entry and must stay accepted.
    const realProgramDataShape = chain.map((path, index) =>
      index === 2
        ? {
            ...protectedAncestorRow(path),
            accessRules: [
              ...protectedAncestorRow(path).accessRules,
              {
                identitySid: 'S-1-5-32-545',
                rightsMask: 0x00000116,
                accessType: 'Allow' as const,
                isInherited: true,
              },
            ],
          }
        : protectedAncestorRow(path),
    );
    expect(
      assessGuidedTrustProtection(trustDir, [], protectedAcl(trustDir, []), realProgramDataShape),
    ).toEqual([]);
  });

  it('combined default-trust policy rejects writable, incomplete, read-denied or unprobed ancestors', () => {
    const trustDir = defaultGuidedProvenanceTrustDirectory();
    const chain = defaultGuidedTrustAncestorChain();
    const tree = protectedAcl(trustDir, []);
    const healthy = chain.map((path) => protectedAncestorRow(path));

    // Ancestor writable by a non-privileged identity (DELETE on one entry).
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
    expect(assessGuidedTrustProtection(trustDir, [], tree, writable)).toEqual(
      expect.arrayContaining([expect.stringContaining('non-privileged write')]),
    );

    // Incomplete ancestor snapshot: one enumerated directory missing.
    expect(assessGuidedTrustProtection(trustDir, [], tree, healthy.slice(0, 2))).toEqual(
      expect.arrayContaining([expect.stringContaining('incomplete')]),
    );

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
    expect(assessGuidedTrustProtection(trustDir, [], tree, readDenied)).toEqual(
      expect.arrayContaining([expect.stringContaining('runtime read/execute')]),
    );

    // Malformed ancestor row (owner not resolvable to a SID string).
    const malformed = [
      { path: chain[0] ?? '', ownerSid: null, accessRules: [] },
      ...healthy.slice(1),
    ];
    expect(assessGuidedTrustProtection(trustDir, [], tree, malformed)).toEqual(
      expect.arrayContaining([expect.stringContaining('invalid owner or incomplete')]),
    );

    // No injected ancestor snapshot: production defaults to the real
    // non-recursive probe, which cannot prove a protected chain in test
    // environments — fail closed rather than skip the ancestor policy.
    expect(assessGuidedTrustProtection(trustDir, [], tree)).not.toEqual([]);
  });

  it('exempts injected non-default test trust directories from the ancestor policy', () => {
    const fixture = makeFixture();
    try {
      // Tree-only injected snapshot on a non-default trust dir: no ancestor
      // rows may be required and the real ancestor probe must not run.
      expect(
        assessGuidedTrustProtection(fixture.trustDir, [], protectedAcl(fixture.trustDir, [])),
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

  it('runtime init never accepts the default trust root without the combined policy', () => {
    const authority = createExternalGuidedProvenanceAuthority({
      trustDir: defaultGuidedProvenanceTrustDirectory(),
      pinnedSpkiSha256: 'a'.repeat(64),
      inspectAcl: protectedInspector,
      inspectAclAncestors: () => [],
    });
    expect(() =>
      authority.issueFreshReceipt({
        canonicalDatabasePath: join(tmpdir(), 'guided-default-root.db'),
        schemaDigest: DIGEST_A,
        issuedAtUnixMs: ISSUED_AT,
      }),
    ).toThrow(
      /GUIDED_PROVENANCE_(TRUST_ANCHOR_MISSING|TRUST_PUBLIC_KEY_PIN_MISMATCH|TRUST_ACL_UNPROTECTED)/,
    );
  });
});
