import { generateKeyPairSync } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it } from 'vitest';
import {
  HostGuidedService,
} from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import {
  developmentGuidedProvenanceAuthority,
} from '../../../../packages/domain-host/src/guided/guided-provenance-authority.ts';
import {
  GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
  GUIDED_PROVENANCE_TRUST_ANCHOR_FILE,
  type GuidedAclAncestorInspector,
  type GuidedAclInspector,
  type GuidedTrustAclSnapshot,
} from '../../../../apps/control-api/src/real-storage/guided-provenance-issuance.ts';
import { issueGuidedProvenanceReceipt } from '../../../../apps/control-api/scripts/issue-guided-provenance.ts';
import {
  createProductionGuidedService,
  type GuidedServiceTestOverrides,
} from '../../../../apps/control-api/src/v03/composition-guided-provenance.ts';

const TRUST_PIN_SCHEMA = 'shun.guided.provenance-trust-pin.v1';
const ISSUED_AT = Date.now();
const roots: string[] = [];
/** Fixture interactive-user SID for the R04 per-user owner/DACL policy. */
const TEST_USER_SID = 'S-1-5-21-11888-22222-33333-1003';

function safeAcl(trustDir: string, extraPaths: readonly string[]): GuidedTrustAclSnapshot {
  const paths = [
    trustDir,
    resolve(trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE),
    resolve(trustDir, GUIDED_PROVENANCE_RECEIPTS_SUBDIR),
    ...extraPaths,
  ];
  return [...new Set(paths.filter(existsSync).map((path) => resolve(path)))].map((path) => ({
    path,
    ownerSid: TEST_USER_SID,
    accessRules: [
      {
        identitySid: TEST_USER_SID,
        rightsMask: 0x001200a9,
        accessType: 'Allow' as const,
        isInherited: true,
      },
      {
        identitySid: 'S-1-5-18',
        rightsMask: 0x001f01ff,
        accessType: 'Allow' as const,
        isInherited: true,
      },
    ],
  }));
}

const safeAncestorAcl: GuidedAclAncestorInspector = (paths) =>
  paths.map((path) => ({
    path,
    ownerSid: TEST_USER_SID,
    accessRules: [
      {
        identitySid: 'S-1-5-32-545',
        rightsMask: 0x001200a9,
        accessType: 'Allow' as const,
        isInherited: true,
      },
    ],
  }));

interface Fixture {
  readonly root: string;
  readonly workspaceRoot: string;
  readonly trustDir: string;
  readonly pinPath: string;
  readonly databasePath: string;
  readonly receiptPath: string;
}

function makeFixture(): Fixture {
  const root = mkdtempSync(join(tmpdir(), 'shun-guided-production-'));
  roots.push(root);
  const workspaceRoot = join(root, 'workspace');
  const trustDir = join(root, 'authority', 'guided-provenance');
  const pinPath = join(dirname(trustDir), 'guided-provenance-trust-pin.json');
  // The issuer refuses a Guided database inside the registry workspace root
  // (ISSUER_DATABASE_PATH_INSIDE_FORBIDDEN_SCOPE): the durable store lives in
  // its own directory, disjoint from the workspace and the trust tree.
  const databasePath = join(root, 'guided-store', 'guided.sqlite');
  const scratchDatabasePath = join(root, 'scratch', 'schema.sqlite');
  const privateKeyPath = join(root, 'operator-key', 'issuer-private.pem');
  mkdirSync(workspaceRoot, { recursive: true });
  mkdirSync(trustDir, { recursive: true });
  mkdirSync(dirname(databasePath), { recursive: true });
  mkdirSync(dirname(scratchDatabasePath), { recursive: true });
  mkdirSync(dirname(privateKeyPath), { recursive: true });

  // Obtain the exact frozen Host schema digest from an ephemeral scratch DB;
  // no production DB, key or receipt is created by this fixture.
  const scratch = new HostGuidedService(
    scratchDatabasePath,
    () => ISSUED_AT,
    developmentGuidedProvenanceAuthority,
  );
  scratch.close();
  const scratchDb = new DatabaseSync(scratchDatabasePath);
  const schemaRow = scratchDb
    .prepare('SELECT schema_digest FROM guided_schema_receipt')
    .get() as { schema_digest: string } | undefined;
  scratchDb.close();
  if (!schemaRow || !/^[0-9a-f]{64}$/.test(schemaRow.schema_digest)) {
    throw new Error('TEST_GUIDED_SCHEMA_DIGEST_UNAVAILABLE');
  }

  const keys = generateKeyPairSync('ed25519');
  writeFileSync(
    privateKeyPath,
    keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    { encoding: 'utf8', mode: 0o600 },
  );
  const issued = issueGuidedProvenanceReceipt({
    databasePath,
    schemaDigest: schemaRow.schema_digest,
    privateKeyPath,
    workspaceRoot,
    ownerSid: TEST_USER_SID,
    trustDir,
    issuedAtUnixMs: ISSUED_AT,
    inspectAcl: safeAcl,
    testOnlyAllowTemporaryKey: true,
  });
  writeFileSync(
    pinPath,
    `${JSON.stringify({ schema: TRUST_PIN_SCHEMA, spkiSha256: issued.spkiSha256 })}\n`,
    { encoding: 'utf8', mode: 0o600 },
  );
  return { root, workspaceRoot, trustDir, pinPath, databasePath, receiptPath: issued.receiptPath };
}

function testOverrides(
  fixture: Fixture,
  inspectAcl: GuidedAclInspector = safeAcl,
): GuidedServiceTestOverrides {
  return {
    trustDir: fixture.trustDir,
    pinPath: fixture.pinPath,
    ownerSid: TEST_USER_SID,
    inspectAcl,
    inspectAclAncestors: safeAncestorAcl,
  };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('R02-E production Guided composition', () => {
  it('accepts only an externally signed receipt and a protected fixed-sibling public pin', () => {
    const fixture = makeFixture();
    const service = createProductionGuidedService(
      fixture.databasePath,
      testOverrides(fixture),
    );
    try {
      expect(service.decide(null)).toEqual({
        status: 'REFUSED',
        code: 'RELAY_SCHEMA_REFUSED',
      });
    } finally {
      service.close();
    }
  });

  it('refuses a never-provisioned pin with SETUP_REQUIRED before opening the Guided database', () => {
    const fixture = makeFixture();
    rmSync(fixture.pinPath);
    // R04: first-run detection — a pin that was never provisioned for this
    // Windows user is a truthful SETUP_REQUIRED refusal with the one-time
    // bootstrap path in the operator record, while startup stays fail-closed
    // (never a DEMO fallback, never misreading corruption as absence).
    const errors: string[] = [];
    const originalError = console.error;
    console.error = (...args: unknown[]) => {
      errors.push(args.join(' '));
    };
    try {
      expect(() =>
        createProductionGuidedService(fixture.databasePath, testOverrides(fixture)),
      ).toThrow('GUIDED_TRUST_SETUP_REQUIRED');
    } finally {
      console.error = originalError;
    }
    expect(errors.some((line) => line.startsWith('KEY_NOT_PROVISIONED'))).toBe(true);
    expect(
      errors.some((line) => line.startsWith('GUIDED_TRUST_SETUP_REQUIRED')),
    ).toBe(true);
    expect(existsSync(fixture.databasePath)).toBe(false);
  });

  it('refuses malformed, aliased-key or extra-key pin JSON', () => {
    const fixture = makeFixture();
    writeFileSync(
      fixture.pinPath,
      JSON.stringify({
        schema: TRUST_PIN_SCHEMA,
        spkiSha256: 'a'.repeat(64),
        fallback: true,
      }),
    );
    expect(() =>
      createProductionGuidedService(fixture.databasePath, testOverrides(fixture)),
    ).toThrow('GUIDED_TRUST_PIN_MALFORMED');
    expect(existsSync(fixture.databasePath)).toBe(false);

    // Not JSON at all.
    writeFileSync(fixture.pinPath, 'not json at all');
    expect(() =>
      createProductionGuidedService(fixture.databasePath, testOverrides(fixture)),
    ).toThrow('GUIDED_TRUST_PIN_MALFORMED');

    // Wrong schema constant.
    writeFileSync(
      fixture.pinPath,
      JSON.stringify({ schema: 'shun.guided.provenance-trust-pin.v2', spkiSha256: 'a'.repeat(64) }),
    );
    expect(() =>
      createProductionGuidedService(fixture.databasePath, testOverrides(fixture)),
    ).toThrow('GUIDED_TRUST_PIN_MALFORMED');

    // Digest must be lowercase 64-hex (an aliased uppercase encoding is refused).
    writeFileSync(
      fixture.pinPath,
      JSON.stringify({ schema: TRUST_PIN_SCHEMA, spkiSha256: 'A'.repeat(64) }),
    );
    expect(() =>
      createProductionGuidedService(fixture.databasePath, testOverrides(fixture)),
    ).toThrow('GUIDED_TRUST_PIN_MALFORMED');
    expect(existsSync(fixture.databasePath)).toBe(false);
  });

  it('refuses a symlink pin file', () => {
    if (process.platform === 'win32') return;
    const fixture = makeFixture();
    const realPin = join(fixture.root, 'real-pin.json');
    writeFileSync(realPin, readFileSync(fixture.pinPath));
    rmSync(fixture.pinPath);
    symlinkSync(realPin, fixture.pinPath, 'file');
    expect(() =>
      createProductionGuidedService(fixture.databasePath, testOverrides(fixture)),
    ).toThrow('GUIDED_TRUST_PIN_UNTRUSTED');
    expect(existsSync(fixture.databasePath)).toBe(false);
  });

  it('refuses a non-regular pin path', () => {
    const fixture = makeFixture();
    rmSync(fixture.pinPath);
    mkdirSync(fixture.pinPath);
    expect(() =>
      createProductionGuidedService(fixture.databasePath, testOverrides(fixture)),
    ).toThrow('GUIDED_TRUST_PIN_UNTRUSTED');
    expect(existsSync(fixture.databasePath)).toBe(false);
  });

  it('refuses a missing trust anchor or exact database receipt before service construction', () => {
    const anchorFixture = makeFixture();
    rmSync(resolve(anchorFixture.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE));
    expect(() =>
      createProductionGuidedService(anchorFixture.databasePath, testOverrides(anchorFixture)),
    ).toThrow('GUIDED_TRUST_ANCHOR_UNTRUSTED');
    expect(existsSync(anchorFixture.databasePath)).toBe(false);

    const receiptFixture = makeFixture();
    rmSync(receiptFixture.receiptPath);
    expect(() =>
      createProductionGuidedService(receiptFixture.databasePath, testOverrides(receiptFixture)),
    ).toThrow('GUIDED_PROVENANCE_RECEIPT_MISSING_OR_UNTRUSTED');
    expect(existsSync(receiptFixture.databasePath)).toBe(false);
  });

  it('requires the pin ACL row and rejects unsafe write ACEs', () => {
    const fixture = makeFixture();
    const unsafeAcl: GuidedAclInspector = (trustDir, extraPaths) =>
      safeAcl(trustDir, extraPaths).map((entry) =>
        resolve(entry.path).toLowerCase() === resolve(fixture.pinPath).toLowerCase()
          ? {
              ...entry,
              accessRules: [
                ...entry.accessRules,
                {
                  identitySid: 'S-1-5-32-545',
                  rightsMask: 0x00000002,
                  accessType: 'Allow' as const,
                  isInherited: false,
                },
              ],
            }
          : entry,
      );
    expect(() =>
      createProductionGuidedService(fixture.databasePath, testOverrides(fixture, unsafeAcl)),
    ).toThrow(/GUIDED_TRUST_ACL_UNPROTECTED/);
    expect(existsSync(fixture.databasePath)).toBe(false);

    const missingPinRow: GuidedAclInspector = (trustDir, extraPaths) =>
      safeAcl(
        trustDir,
        extraPaths.filter((path) => resolve(path).toLowerCase() !== resolve(fixture.pinPath).toLowerCase()),
      );
    expect(() =>
      createProductionGuidedService(fixture.databasePath, testOverrides(fixture, missingPinRow)),
    ).toThrow('GUIDED_TRUST_ACL_PIN_ROW_MISSING');
    expect(existsSync(fixture.databasePath)).toBe(false);
  });

  it('fails closed when the runtime ACL probe is unavailable instead of falling back without the pin', () => {
    const fixture = makeFixture();
    let calls = 0;
    const interruptedProbe: GuidedAclInspector = (trustDir, extraPaths) => {
      calls += 1;
      return calls === 1 ? safeAcl(trustDir, extraPaths) : undefined;
    };
    expect(() =>
      createProductionGuidedService(
        fixture.databasePath,
        testOverrides(fixture, interruptedProbe),
      ),
    ).toThrow(/V03_GUIDED_PROVENANCE_UNAVAILABLE/);
    expect(calls).toBeGreaterThanOrEqual(2);
  });

  it('keeps the exact operator entrypoint Node 24/26 transform-aware and uses external composition', () => {
    const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
    const apiPackage = JSON.parse(
      readFileSync(resolve(repoRoot, 'apps/control-api/package.json'), 'utf8'),
    ) as { scripts?: { dev?: string }; devDependencies?: Record<string, string | undefined> };
    const main = readFileSync(resolve(repoRoot, 'apps/control-api/src/main.ts'), 'utf8');
    const composition = readFileSync(
      resolve(repoRoot, 'apps/control-api/src/v03/composition-guided-provenance.ts'),
      'utf8',
    );
    // G11 (Issue #371, pack PR #373): Node 26 removed
    // `--experimental-transform-types`; the exact operator entrypoint stays
    // transform-aware on Node 24 AND 26 through the exact pinned
    // TypeScript-aware runner declared in package.json (reproducible
    // lockfile, frozen install). No floating range, no direct-node fallback.
    expect(apiPackage.scripts?.dev).toBe('tsx src/main.ts');
    expect(apiPackage.devDependencies?.tsx).toBe('4.23.15');
    expect(main).toContain('createProductionGuidedService(resolve(guidedDb))');
    expect(main).not.toContain('new HostGuidedService');
    expect(composition).not.toContain('SHUN_GUIDED_PROVENANCE_TRUST_PIN');
  });
});
