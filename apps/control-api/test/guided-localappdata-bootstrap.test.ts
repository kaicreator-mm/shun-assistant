// R04 (#404): per-user LocalAppData Guided trust bootstrap coverage. All
// keys are ephemeral and test-only; every fixture lives under the OS temp
// directory as a disposable isolated profile (LocalAppData base + trust tree
// + distinct secret directory). Nothing here touches a real Windows profile,
// ProgramData, or any production trust material.
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  deriveGuidedSchemaDigest,
  executeGuidedLocalAppDataBootstrap,
  planGuidedLocalAppDataBootstrap,
  resolveGuidedBootstrapPaths,
  runGuidedBootstrapCli,
} from '../scripts/bootstrap-guided-localappdata.ts';
import {
  canonicalGuidedDatabasePath,
  GUIDED_ISSUER_SECRET_FILE,
  GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
  GUIDED_PROVENANCE_TRUST_ANCHOR_FILE,
  type GuidedAclAncestorInspector,
  type GuidedAclInspector,
  type GuidedTrustAclSnapshot,
  guidedReceiptFileName,
  queryWindowsProcessUserSid,
} from '../src/real-storage/guided-provenance-issuance.ts';
import { createProductionGuidedService } from '../src/v03/composition-guided-provenance.ts';

const TEST_USER_SID = 'S-1-5-21-11888-22222-33333-1002';
const IDENTITY = { processUserSid: TEST_USER_SID, elevated: false as const };

/**
 * Windows only: reset a fixture root to the REAL per-user profile ACL shape
 * (explicit user/SYSTEM/Administrators full control, inheritance removed).
 * The OS temp directory on shared dev machines can carry foreign inherited
 * write ACEs; the actual `%LOCALAPPDATA%` profile tree does not, and the
 * real-probe paths here must model the profile, not the shared temp ACL.
 */
function hardenFixtureAcl(dir: string): void {
  if (process.platform !== 'win32') return;
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  const icacls = resolve(systemRoot, 'System32', 'icacls.exe');
  const processSid = queryWindowsProcessUserSid();
  const grants = [
    '*S-1-5-18:(OI)(CI)F',
    '*S-1-5-32-544:(OI)(CI)F',
    ...(processSid ? [`*${processSid}:(OI)(CI)F`] : []),
  ];
  execFileSync(icacls, [dir, '/grant', ...grants], {
    windowsHide: true,
    timeout: 30_000,
  });
  execFileSync(icacls, [dir, '/inheritance:r'], { windowsHide: true, timeout: 30_000 });
}

/** One disposable isolated profile: base = USERPROFILE-style AppData/Local. */
interface BootstrapFixture {
  root: string;
  base: string;
  workspaceRoot: string;
  dbDir: string;
  dbPath: string;
  otherDbPath: string;
  paths: ReturnType<typeof resolveGuidedBootstrapPaths>;
}

const roots: string[] = [];

function makeBootstrapFixture(): BootstrapFixture {
  const root = mkdtempSync(join(tmpdir(), 'shun-r04-bootstrap-'));
  roots.push(root);
  const base = join(root, 'AppData', 'Local');
  const workspaceRoot = join(root, 'workspace');
  const dbDir = join(root, 'guided-store');
  mkdirSync(base, { recursive: true });
  mkdirSync(workspaceRoot, { recursive: true });
  mkdirSync(dbDir, { recursive: true });
  // Model the real profile ACL before any trust material is created under
  // it, so the REAL probe paths see the per-user profile shape.
  hardenFixtureAcl(root);
  return {
    root,
    base,
    workspaceRoot,
    dbDir,
    dbPath: join(dbDir, 'guided.sqlite'),
    otherDbPath: join(dbDir, 'other-guided.sqlite'),
    paths: resolveGuidedBootstrapPaths(base),
  };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

/** Per-user profile ACL shape for every path the policy may probe. */
const fixtureAcl: GuidedAclInspector = (root, extraPaths) => {
  const candidates = [
    root,
    ...extraPaths,
    join(root, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE),
    join(root, GUIDED_PROVENANCE_RECEIPTS_SUBDIR),
  ];
  return [...new Set(candidates.filter(existsSync).map((path) => resolve(path)))].map((path) => ({
    path,
    ownerSid: TEST_USER_SID,
    accessRules: [
      {
        identitySid: TEST_USER_SID,
        rightsMask: 0x001f01ff,
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
};

const fixtureAncestorAcl: GuidedAclAncestorInspector = (paths) =>
  paths.map((path) => ({
    path: resolve(path),
    ownerSid: TEST_USER_SID,
    accessRules: [
      {
        identitySid: TEST_USER_SID,
        rightsMask: 0x001f01ff,
        accessType: 'Allow' as const,
        isInherited: true,
      },
    ],
  }));

function executeInput(fixture: BootstrapFixture) {
  return {
    databasePath: fixture.dbPath,
    workspaceRoot: fixture.workspaceRoot,
    localAppDataBase: fixture.base,
    identity: IDENTITY,
    schemaDigest: deriveGuidedSchemaDigest(),
    inspectAcl: fixtureAcl,
  };
}

function compositionOverrides(fixture: BootstrapFixture) {
  return {
    trustDir: fixture.paths.trustDir,
    pinPath: fixture.paths.pinPath,
    ownerSid: TEST_USER_SID,
    inspectAcl: fixtureAcl,
    inspectAclAncestors: fixtureAncestorAcl,
  };
}

describe('R04 per-user bootstrap: paths and frozen schema derivation', () => {
  it('resolves the per-user trust tree, sibling pin and distinct secret directory', () => {
    const fixture = makeBootstrapFixture();
    const base = resolve(fixture.base);
    expect(fixture.paths.trustDir).toBe(join(base, 'Shun', 'authority', 'guided-provenance'));
    expect(fixture.paths.pinPath).toBe(
      join(base, 'Shun', 'authority', 'guided-provenance-trust-pin.json'),
    );
    expect(fixture.paths.secretKeyPath).toBe(
      join(base, 'Shun', 'secrets', 'guided-issuer', GUIDED_ISSUER_SECRET_FILE),
    );
    // Secret directory is OUTSIDE the trust tree it signs for.
    expect(fixture.paths.secretDir.startsWith(fixture.paths.trustDir)).toBe(false);
  });

  it('derives the frozen Guided schema digest deterministically (user never pastes digests)', () => {
    const digest = deriveGuidedSchemaDigest();
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(deriveGuidedSchemaDigest()).toBe(digest);
  });
});

describe('R04 per-user bootstrap: consented first-run setup and idempotence', () => {
  it('FRESH plan reports every piece absent; execution without consent refuses', () => {
    const fixture = makeBootstrapFixture();
    const plan = planGuidedLocalAppDataBootstrap({
      databasePath: fixture.dbPath,
      schemaDigest: deriveGuidedSchemaDigest(),
      paths: fixture.paths,
    });
    expect(plan.status).toBe('FRESH');
    expect(plan.anchor).toBe('ABSENT');
    expect(plan.pin).toBe('ABSENT');
    expect(plan.receipt).toBe('ABSENT');
    expect(plan.secret).toBe('ABSENT');
    expect(() =>
      executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: false }),
    ).toThrow('GUIDED_BOOTSTRAP_CONSENT_REQUIRED');
    // Nothing was written by the refused attempt.
    expect(existsSync(fixture.paths.trustDir)).toBe(false);
    expect(existsSync(fixture.paths.secretKeyPath)).toBe(false);
  });

  it('one consented run provisions secret+anchor+receipt+pin and boots the production service', () => {
    const fixture = makeBootstrapFixture();
    const result = executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true });
    expect(result.status).toBe('BOOTSTRAP_CREATED');
    expect(result.spkiSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(existsSync(fixture.paths.secretKeyPath)).toBe(true);
    expect(existsSync(join(fixture.paths.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE))).toBe(
      true,
    );
    expect(
      existsSync(
        join(
          fixture.paths.trustDir,
          GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
          guidedReceiptFileName(canonicalGuidedDatabasePath(fixture.dbPath)),
        ),
      ),
    ).toBe(true);
    expect(existsSync(fixture.paths.pinPath)).toBe(true);

    // The exact production composition accepts the bootstrapped trust.
    const service = createProductionGuidedService(fixture.dbPath, compositionOverrides(fixture));
    try {
      expect(service.decide(null)).toEqual({ status: 'REFUSED', code: 'RELAY_SCHEMA_REFUSED' });
    } finally {
      service.close();
    }
  });

  it('a complete setup is a stable NO-OP: never rotated, never re-signed', () => {
    const fixture = makeBootstrapFixture();
    executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true });
    const before = [
      readFileSync(fixture.paths.secretKeyPath, 'utf8'),
      readFileSync(join(fixture.paths.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE), 'utf8'),
      readFileSync(fixture.paths.pinPath, 'utf8'),
      readFileSync(resultReceiptPath(fixture), 'utf8'),
    ];
    const again = executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true });
    expect(again.status).toBe('ALREADY_COMPLETE');
    const after = [
      readFileSync(fixture.paths.secretKeyPath, 'utf8'),
      readFileSync(join(fixture.paths.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE), 'utf8'),
      readFileSync(fixture.paths.pinPath, 'utf8'),
      readFileSync(resultReceiptPath(fixture), 'utf8'),
    ];
    expect(after).toEqual(before);
    const plan = planGuidedLocalAppDataBootstrap({
      databasePath: fixture.dbPath,
      schemaDigest: deriveGuidedSchemaDigest(),
      paths: fixture.paths,
    });
    expect(plan.status).toBe('COMPLETE');
  });

  it('a second database under the SAME per-user anchor needs no key rotation', () => {
    const fixture = makeBootstrapFixture();
    executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true });
    const anchorBefore = readFileSync(
      join(fixture.paths.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE),
      'utf8',
    );
    const second = executeGuidedLocalAppDataBootstrap(
      { ...executeInput(fixture), databasePath: fixture.otherDbPath },
      { consent: true },
    );
    expect(second.status).toBe('BOOTSTRAP_CREATED');
    expect(
      readFileSync(join(fixture.paths.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE), 'utf8'),
    ).toBe(anchorBefore);
    const otherService = createProductionGuidedService(
      fixture.otherDbPath,
      compositionOverrides(fixture),
    );
    try {
      expect(otherService.decide(null)).toEqual({
        status: 'REFUSED',
        code: 'RELAY_SCHEMA_REFUSED',
      });
    } finally {
      otherService.close();
    }
  });
});

describe('R04 per-user bootstrap: partial setups, repair and refusal', () => {
  it('a missing pin is surfaced as PARTIAL and only --repair completes it', () => {
    const fixture = makeBootstrapFixture();
    executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true });
    const pinBefore = readFileSync(fixture.paths.pinPath, 'utf8');
    rmSync(fixture.paths.pinPath);
    const plan = planGuidedLocalAppDataBootstrap({
      databasePath: fixture.dbPath,
      schemaDigest: deriveGuidedSchemaDigest(),
      paths: fixture.paths,
    });
    expect(plan.status).toBe('PARTIAL');
    expect(() =>
      executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true }),
    ).toThrow(/GUIDED_BOOTSTRAP_PARTIAL/);
    const repaired = executeGuidedLocalAppDataBootstrap(executeInput(fixture), {
      consent: true,
      repair: true,
    });
    expect(repaired.status).toBe('REPAIR_COMPLETED');
    expect(readFileSync(fixture.paths.pinPath, 'utf8')).toBe(pinBefore);
  });

  it('a missing receipt is re-issued under the unchanged anchor; a missing anchor is restored from the secret', () => {
    const fixture = makeBootstrapFixture();
    executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true });
    // Missing receipt only: ordinary consented provisioning under the same
    // verified anchor — completes without repair semantics.
    rmSync(resultReceiptPath(fixture));
    const receiptRepaired = executeGuidedLocalAppDataBootstrap(executeInput(fixture), {
      consent: true,
    });
    expect(receiptRepaired.status).toBe('BOOTSTRAP_CREATED');
    const anchorBefore = readFileSync(
      join(fixture.paths.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE),
      'utf8',
    );
    // Missing anchor only: restored from the per-user secret, byte-identical.
    rmSync(join(fixture.paths.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE));
    const anchorRepaired = executeGuidedLocalAppDataBootstrap(executeInput(fixture), {
      consent: true,
      repair: true,
    });
    expect(anchorRepaired.status).toBe('REPAIR_COMPLETED');
    expect(
      readFileSync(join(fixture.paths.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE), 'utf8'),
    ).toBe(anchorBefore);
    const service = createProductionGuidedService(fixture.dbPath, compositionOverrides(fixture));
    try {
      expect(service.decide(null)).toEqual({ status: 'REFUSED', code: 'RELAY_SCHEMA_REFUSED' });
    } finally {
      service.close();
    }
  });

  it('an absent secret with complete runtime trust stays COMPLETE (never re-keyed)', () => {
    const fixture = makeBootstrapFixture();
    executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true });
    rmSync(fixture.paths.secretKeyPath);
    const plan = planGuidedLocalAppDataBootstrap({
      databasePath: fixture.dbPath,
      schemaDigest: deriveGuidedSchemaDigest(),
      paths: fixture.paths,
    });
    expect(plan.status).toBe('COMPLETE');
    expect(plan.notes.some((note) => note.includes('issuer secret is absent'))).toBe(true);
    // Still a no-op: runtime trust is complete and must not be touched.
    const again = executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true });
    expect(again.status).toBe('ALREADY_COMPLETE');
  });

  it('present-but-invalid material is refused, never overwritten or re-signed', () => {
    const fixture = makeBootstrapFixture();
    executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true });
    const anchorPath = join(fixture.paths.trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE);
    const tamperedAnchor = readFileSync(anchorPath, 'utf8').replace(
      /"spkiSha256":"[0-9a-f]+"/,
      '"spkiSha256":"' + '0'.repeat(64) + '"',
    );
    writeFileSync(anchorPath, tamperedAnchor, 'utf8');
    const plan = planGuidedLocalAppDataBootstrap({
      databasePath: fixture.dbPath,
      schemaDigest: deriveGuidedSchemaDigest(),
      paths: fixture.paths,
    });
    expect(plan.status).toBe('INVALID');
    expect(() =>
      executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true, repair: true }),
    ).toThrow(/GUIDED_BOOTSTRAP_STATE_INVALID/);
    // Refusal left the (tampered) bytes untouched — the operator decides.
    expect(readFileSync(anchorPath, 'utf8')).toBe(tamperedAnchor);

    // A pin that pins a DIFFERENT key than the anchor is equally invalid.
    const clean = makeBootstrapFixture();
    executeGuidedLocalAppDataBootstrap(executeInput(clean), { consent: true });
    const outsider = generateKeyPairSync('ed25519');
    const pinPath = clean.paths.pinPath;
    writeFileSync(
      pinPath,
      `${JSON.stringify({
        schema: 'shun.guided.provenance-trust-pin.v1',
        // Wrong key pinned: verifier would refuse anyway; bootstrap refuses
        // to "repair" it silently into validity.
        spkiSha256: 'f'.repeat(64),
      })}\n`,
      'utf8',
    );
    const mismatchPlan = planGuidedLocalAppDataBootstrap({
      databasePath: clean.dbPath,
      schemaDigest: deriveGuidedSchemaDigest(),
      paths: clean.paths,
    });
    expect(mismatchPlan.status).toBe('INVALID');
    expect(() =>
      executeGuidedLocalAppDataBootstrap(executeInput(clean), { consent: true, repair: true }),
    ).toThrow(/GUIDED_BOOTSTRAP_STATE_INVALID/);
  });

  it('a secret that does not match the anchor is invalid, not silently replaced', () => {
    const fixture = makeBootstrapFixture();
    executeGuidedLocalAppDataBootstrap(executeInput(fixture), { consent: true });
    const outsider = generateKeyPairSync('ed25519');
    writeFileSync(
      fixture.paths.secretKeyPath,
      outsider.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      'utf8',
    );
    const plan = planGuidedLocalAppDataBootstrap({
      databasePath: fixture.dbPath,
      schemaDigest: deriveGuidedSchemaDigest(),
      paths: fixture.paths,
    });
    expect(plan.status).toBe('INVALID');
    expect(plan.secret).toBe('PRESENT_INVALID');
  });

  it('refuses databases inside the workspace, trust tree or secret directory', () => {
    const fixture = makeBootstrapFixture();
    for (const bad of [
      join(fixture.workspaceRoot, 'guided.sqlite'),
      join(fixture.paths.trustDir, 'guided.sqlite'),
      join(fixture.paths.secretDir, 'guided.sqlite'),
    ]) {
      expect(() =>
        executeGuidedLocalAppDataBootstrap(
          { ...executeInput(fixture), databasePath: bad },
          { consent: true },
        ),
      ).toThrow(/GUIDED_BOOTSTRAP_DATABASE_SCOPE_REFUSED/);
    }
  });
});

describe('R04 per-user bootstrap CLI (real Windows session only)', () => {
  it.skipIf(process.platform !== 'win32')(
    'plan-only without --consent prints the plan, exits 3, writes nothing; --consent provisions',
    () => {
      const fixture = makeBootstrapFixture();
      const lines: string[] = [];
      const originalLog = console.log;
      console.log = (...args: unknown[]) => {
        lines.push(args.join(' '));
      };
      try {
        const code = runGuidedBootstrapCli(['--database', fixture.dbPath], {
          LOCALAPPDATA: fixture.base,
          USERPROFILE: fixture.root,
        });
        expect(code).toBe(3);
        expect(lines.some((line) => line.startsWith('BOOTSTRAP_PLAN_ONLY'))).toBe(true);
        expect(lines.some((line) => line.startsWith('BOOTSTRAP_STATUS=FRESH'))).toBe(true);
        // No key material in the output — identifiers and paths only.
        const allOutput = lines.join('\n');
        expect(allOutput).not.toContain('PRIVATE KEY');
        expect(existsSync(fixture.paths.secretKeyPath)).toBe(false);

        lines.length = 0;
        const created = runGuidedBootstrapCli(['--database', fixture.dbPath, '--consent'], {
          LOCALAPPDATA: fixture.base,
          USERPROFILE: fixture.root,
        });
        expect(created).toBe(0);
        expect(lines.some((line) => line.startsWith('BOOTSTRAP_RESULT=BOOTSTRAP_CREATED'))).toBe(
          true,
        );
        expect(lines.some((line) => line.startsWith('BOOTSTRAP_SPKI_SHA256='))).toBe(true);
        expect(lines.join('\n')).not.toContain('PRIVATE KEY');
        const service = createProductionGuidedService(
          fixture.dbPath,
          compositionOverrides(fixture),
        );
        try {
          expect(service.decide(null)).toEqual({ status: 'REFUSED', code: 'RELAY_SCHEMA_REFUSED' });
        } finally {
          service.close();
        }
      } finally {
        console.log = originalLog;
      }
    },
    120_000,
  );
});

function resultReceiptPath(fixture: BootstrapFixture): string {
  return join(
    fixture.paths.trustDir,
    GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
    guidedReceiptFileName(canonicalGuidedDatabasePath(fixture.dbPath)),
  );
}
