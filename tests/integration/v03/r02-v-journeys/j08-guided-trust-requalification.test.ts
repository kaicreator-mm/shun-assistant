/**
 * R02-V generation-2 (post-R02-E integration) targeted J08 requalification.
 *
 * The nine-path R02-E integration (#375, WIP 47ecf345) introduced the
 * external Guided trust authority into the production composition: the
 * runtime accepts only an operator-pinned SPKI digest (fixed sibling pin
 * file), a signed trust anchor, an exact per-database provenance receipt and
 * a protected Windows ACL policy — never environment, database or caller
 * input. J08 is therefore requalified through that EXACT production trust
 * composition (`createProductionGuidedService`) and the real HTTP decision
 * seam on this native Windows host.
 *
 * TRUST PROVENANCE — TEST_FIXTURE, NOT real operator provisioning: every
 * positive case here uses an ephemeral test-only Ed25519 issuer under
 * isolated temp paths via the VITEST-gated overrides (the issuer refuses
 * this mode outside a test runner). The genuine positive production trust
 * path (the fixed ProgramData authority directory) cannot be established
 * without an already-elevated operator token and persistent OS mutation,
 * both out of scope for this zero-paid/zero-physical suite; positive
 * PRODUCTION-path J08 is recorded UNKNOWN in the qualification matrix, and
 * this suite claims nothing for it.
 *
 * Proven here over real SQLite + real loopback HTTP:
 *   - trusted Host-staged Case surfaces through /api/v03/guided/state;
 *   - HTTP relays can never mint authority (schema/hostile tuples 422);
 *   - navigation (BACK) records without consuming, granting or effecting;
 *   - terminal REFUSE consumes exactly once: 200 RECORDED, 409 replay,
 *     humanGrantIssued=false, effectSent=false;
 *   - consumption, history and trust verification survive a full service
 *     restart over the same database and trust tree; a stale Host
 *     observation cannot restage, a genuinely new observation may;
 *   - a swapped/untrusted trust anchor under the same pin refuses boot
 *     without creating any database (fail closed);
 *   - a receipt bound to one database path never authorizes another.
 */
import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { issueGuidedProvenanceReceipt } from '../../../../apps/control-api/scripts/issue-guided-provenance.ts';
import { DemoShunBackend } from '../../../../apps/control-api/src/demo/backend.ts';
import {
  GUIDED_PROVENANCE_RECEIPTS_SUBDIR,
  GUIDED_PROVENANCE_TRUST_ANCHOR_FILE,
  GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA,
  type GuidedAclAncestorInspector,
  type GuidedTrustAclSnapshot,
} from '../../../../apps/control-api/src/real-storage/guided-provenance-issuance.ts';
import { createControlServer } from '../../../../apps/control-api/src/server.ts';
import { provisionGuidedCaseFromHostFile } from '../../../../apps/control-api/src/v03/composition-guided.ts';
import {
  createProductionGuidedService,
  type GuidedServiceTestOverrides,
} from '../../../../apps/control-api/src/v03/composition-guided-provenance.ts';
import { developmentGuidedProvenanceAuthority } from '../../../../packages/domain-host/src/guided/guided-provenance-authority.ts';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');

const TRUST_PIN_SCHEMA = 'shun.guided.provenance-trust-pin.v1';
const ISSUED_AT = Date.now();

const sha256Hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

interface Fixture {
  readonly root: string;
  readonly workspaceRoot: string;
  readonly trustDir: string;
  readonly pinPath: string;
  readonly databasePath: string;
  readonly receiptPath: string;
  readonly anchorPath: string;
}

function safeAcl(trustDir: string, extraPaths: readonly string[]): GuidedTrustAclSnapshot {
  const paths = [
    trustDir,
    resolve(trustDir, GUIDED_PROVENANCE_TRUST_ANCHOR_FILE),
    resolve(trustDir, GUIDED_PROVENANCE_RECEIPTS_SUBDIR),
    ...extraPaths,
  ];
  return [...new Set(paths.filter(existsSync).map((path) => resolve(path)))].map((path) => ({
    path,
    ownerSid: 'S-1-5-32-544',
    accessRules: [
      {
        identitySid: 'S-1-5-32-545',
        rightsMask: 0x000200a9,
        accessType: 'Allow' as const,
        isInherited: true,
      },
    ],
  }));
}

const safeAncestorAcl: GuidedAclAncestorInspector = (paths) =>
  paths.map((path) => ({
    path,
    ownerSid: 'S-1-5-18',
    accessRules: [
      {
        identitySid: 'S-1-5-32-545',
        rightsMask: 0x001200a9,
        accessType: 'Allow' as const,
        isInherited: true,
      },
    ],
  }));

/**
 * TEST_FIXTURE trust material: an ephemeral Ed25519 issuer (temp-scoped key,
 * VITEST-gated `testOnlyAllowTemporaryKey`) provisions anchor + exact-DB
 * receipt inside an isolated temp trust tree, and the fixed-sibling pin file
 * binds its SPKI digest. Mirrors the operator issuance semantics without
 * touching the real ProgramData authority directory.
 */
function makeFixture(label: string): Fixture {
  const root = mkdtempSync(join(tmpdir(), `shun-r02v-g2-j08-${label}-`));
  const workspaceRoot = join(root, 'workspace');
  const trustDir = join(root, 'authority', 'guided-provenance');
  const pinPath = join(dirname(trustDir), 'guided-provenance-trust-pin.json');
  const databasePath = join(root, 'guided-store', 'guided.sqlite');
  const scratchDatabasePath = join(root, 'scratch', 'schema.sqlite');
  const privateKeyPath = join(root, 'operator-key', 'issuer-private.pem');
  mkdirSync(workspaceRoot, { recursive: true });
  mkdirSync(trustDir, { recursive: true });
  mkdirSync(dirname(databasePath), { recursive: true });
  mkdirSync(dirname(scratchDatabasePath), { recursive: true });
  mkdirSync(dirname(privateKeyPath), { recursive: true });

  // Exact frozen Host schema digest from an ephemeral scratch DB (no
  // production database, key or receipt is created by this fixture).
  const scratch = new HostGuidedService(
    scratchDatabasePath,
    () => ISSUED_AT,
    developmentGuidedProvenanceAuthority,
  );
  scratch.close();
  const scratchDb = new DatabaseSync(scratchDatabasePath);
  const schemaRow = scratchDb.prepare('SELECT schema_digest FROM guided_schema_receipt').get() as
    | { schema_digest: string }
    | undefined;
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
  return {
    root,
    workspaceRoot,
    trustDir,
    pinPath,
    databasePath,
    receiptPath: issued.receiptPath,
    anchorPath: issued.trustAnchorPath,
  };
}

function testOverrides(fixture: Fixture): GuidedServiceTestOverrides {
  return {
    trustDir: fixture.trustDir,
    pinPath: fixture.pinPath,
    inspectAcl: safeAcl,
    inspectAclAncestors: safeAncestorAcl,
  };
}

const roots: string[] = [];
const track = (fixture: Fixture): Fixture => {
  roots.push(fixture.root);
  return fixture;
};
function cleanupRoot(root: string): void {
  // Windows may keep the SQLite WAL handle alive briefly after close(); retry
  // per entry so cleanup never masks a real assertion failure as an EPERM.
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      rmSync(root, { recursive: true, force: true });
      return;
    } catch {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
    }
  }
}
// Negative fixtures are per-test and cleaned immediately; the journey fixture
// MUST survive every afterEach (the restart journey reopens it) and is
// cleaned only in the journey describe's afterAll.
afterEach(() => {
  for (const root of roots.splice(0)) cleanupRoot(root);
});

interface StepLike {
  readonly stepId: string;
  readonly journeyId: string;
  readonly taskId: string;
  readonly templateRef: { readonly digest: string };
  readonly caseRef: unknown;
}

function stageInput(taskId: string, revision: string, at: number) {
  return {
    observation: {
      schema: 'shun.guided.host-observation.v1',
      taskId,
      journeyId: 'journey-r02v-g2-j08',
      sourceRef: 'host:obs:r02v-g2-j08',
      revision,
      caseRef: { snapshotId: 'snap-r02v-g2', digest: 'c'.repeat(64) },
      observedAtUnixMs: at - 1_000,
      validUntilUnixMs: at + 3_600_000,
      evidenceRefs: ['host:scope:r02v-g2'],
    },
    semanticSelection: {
      status: 'SELECTED',
      semantic: {
        schema: 'shun.goal-semantic.v1',
        taskId,
        goalContract: { taskId, objective: 'summarize selected folder' },
        capabilityId: 'system.storage.diagnose_bounded_action',
        capabilityRevision: 'r1',
        provenance: { resolverRevision: 'resolver-v03' },
      },
    },
    scope: { status: 'KNOWN', selectedRootRef: undefined },
  };
}

function outcomeFor(step: StepLike, sourceRef: string, overrides: Record<string, unknown> = {}) {
  return {
    schema: 'shun.guided.step-outcome.v1',
    journeyId: step.journeyId,
    taskId: step.taskId,
    stepId: step.stepId,
    caseRef: step.caseRef,
    event: 'USER_SUBMIT',
    source: 'USER',
    sourceRef,
    answers: [] as unknown[],
    evidenceRefs: [] as unknown[],
    occurredAtUnixMs: Date.now(),
    ...overrides,
  };
}

function relayFor(step: StepLike, decision: 'ANSWER' | 'APPROVE' | 'REFUSE', outcome: unknown) {
  return {
    kind: 'USER_DECISION_RELAY',
    humanApproval: decision !== 'ANSWER',
    authorityClaimed: false,
    decision,
    relayedVia: '/api',
    stepId: step.stepId,
    stepDigest: step.templateRef.digest,
    caseRef: step.caseRef,
    outcome,
  };
}

async function json(
  port: number,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: unknown }> {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text === '' ? undefined : JSON.parse(text) };
}

describe('R02-V G2 J08: production Guided trust composition over real HTTP (TEST_FIXTURE trust)', () => {
  let fixture: Fixture;
  let service: ReturnType<typeof createProductionGuidedService>;
  let server: ReturnType<typeof createControlServer> | undefined;
  let port: number;
  let caseId: string;
  let consumedRelay: unknown;

  beforeAll(async () => {
    fixture = makeFixture('journey');
    service = createProductionGuidedService(fixture.databasePath, testOverrides(fixture));
    caseId = 'task-r02v-g2-j08';
    const caseJson = JSON.stringify(stageInput(caseId, 'r02v-g2-r1', Date.now()));
    const caseFile = join(fixture.root, 'guided-case.json');
    writeFileSync(caseFile, caseJson);
    const provisioned = provisionGuidedCaseFromHostFile({
      service,
      file: caseFile,
      sha256: sha256Hex(caseJson),
    });
    expect(provisioned.status).toBe('CURRENT');
    server = createControlServer({
      backend: new DemoShunBackend(),
      uiDir: resolve(repoRoot, 'apps/control-ui/public'),
      port: 0,
      v03Guided: service,
    });
    port = await server.start();
    console.log(
      '[J08-G2] host record:',
      JSON.stringify({
        platform: process.platform,
        node: process.version,
        trustMode: 'TEST_FIXTURE_EPHEMERAL_ISSUER',
        productionTrustPathPositive: 'UNKNOWN',
      }),
    );
  });

  afterAll(async () => {
    await server?.close();
    try {
      service?.close();
    } catch {
      /* closed by the restart journey */
    }
    cleanupRoot(fixture.root);
  });

  it('trusted operator Case surfaces through the real HTTP state seam', async () => {
    const state = await json(port, 'GET', '/api/v03/guided/state');
    expect(state.status).toBe(200);
    const body = state.body as { currentStep?: StepLike; journey: { paused: boolean } };
    expect(body.currentStep?.taskId).toBe(caseId);
    expect(body.journey.paused).toBe(false);
  });

  it('HTTP relays can never mint authority: hostile tuples are refused 422 pre-consume', async () => {
    const state = (await json(port, 'GET', '/api/v03/guided/state')).body as {
      currentStep?: StepLike;
    };
    const step = state.currentStep;
    expect(step).toBeTruthy();
    if (!step) return;
    const authority = {
      ...relayFor(step, 'REFUSE', outcomeFor(step, 'ui:r02v-g2-auth')),
      authorityClaimed: true,
    };
    const hostile = await json(port, 'POST', '/api/v03/guided/decision', authority);
    expect(hostile.status).toBe(422);
    expect(hostile.body).toMatchObject({ status: 'REFUSED', code: 'RELAY_SCHEMA_REFUSED' });

    const approvingAnswer = {
      ...relayFor(step, 'ANSWER', outcomeFor(step, 'ui:r02v-g2-answer-grant')),
      humanApproval: true,
    };
    const grantish = await json(port, 'POST', '/api/v03/guided/decision', approvingAnswer);
    expect(grantish.status).toBe(422);
    expect(grantish.body).toMatchObject({ status: 'REFUSED', code: 'RELAY_SCHEMA_REFUSED' });
  });

  it('navigation records without consuming, granting or effecting', async () => {
    const state = (await json(port, 'GET', '/api/v03/guided/state')).body as {
      currentStep?: StepLike;
    };
    const step = state.currentStep;
    expect(step).toBeTruthy();
    if (!step) return;
    const back = await json(
      port,
      'POST',
      '/api/v03/guided/decision',
      relayFor(step, 'ANSWER', { ...outcomeFor(step, 'ui:r02v-g2-back'), event: 'BACK' }),
    );
    expect(back.status).toBe(200);
    expect(back.body).toMatchObject({
      status: 'RECORDED',
      humanGrantIssued: false,
      effectSent: false,
    });
    const after = (await json(port, 'GET', '/api/v03/guided/state')).body as {
      currentStep?: StepLike;
    };
    expect(after.currentStep?.stepId).toBe(step.stepId);
  });

  it('terminal REFUSE consumes exactly once: 200 RECORDED then 409 replay, never a grant or effect', async () => {
    const state = (await json(port, 'GET', '/api/v03/guided/state')).body as {
      currentStep?: StepLike;
    };
    const step = state.currentStep;
    expect(step).toBeTruthy();
    if (!step) return;
    consumedRelay = relayFor(
      step,
      'REFUSE',
      outcomeFor(step, 'ui:r02v-g2-refuse', {
        answers: [{ fieldId: 'selectedRoot', value: 'C:Work' }],
      }),
    );
    const first = await json(port, 'POST', '/api/v03/guided/decision', consumedRelay);
    expect(first.status).toBe(200);
    expect(first.body).toMatchObject({
      status: 'RECORDED',
      humanGrantIssued: false,
      effectSent: false,
    });
    const replay = await json(port, 'POST', '/api/v03/guided/decision', consumedRelay);
    expect(replay.status).toBe(409);
    expect(replay.body).toMatchObject({ status: 'STALE' });
    const replayAgain = await json(port, 'POST', '/api/v03/guided/decision', consumedRelay);
    expect(replayAgain.status).toBe(409);
  });

  it('restart durability: consumption and trust verification survive reopen; stale restage refused, fresh observation may restage', async () => {
    await server?.close();
    server = undefined;
    service.close();

    // Full production trust re-verification over the SAME database and trust
    // tree: pin, anchor, exact-database receipt and ACL policy re-evaluate.
    // The side-effect-free invalid relay probe must distinguish a healthy
    // service (REFUSED/RELAY_SCHEMA_REFUSED) from an unavailable ledger.
    const reopened = createProductionGuidedService(fixture.databasePath, testOverrides(fixture));
    try {
      expect(reopened.decide({})).toMatchObject({
        status: 'REFUSED',
        code: 'RELAY_SCHEMA_REFUSED',
      });

      const state = reopened.state();
      expect(state.currentStep).toBeUndefined();
      expect(state.history.some((entry) => entry.status === 'REFUSED')).toBe(true);

      // The consumed step stays consumed through the exact replay relay.
      const replay = reopened.decide(consumedRelay);
      expect(replay).toMatchObject({ status: 'STALE', code: 'GUIDED_STEP_NOT_CURRENT' });

      // A stale Host observation (same revision replayed) cannot restage the
      // Case; the integrated truthfully reports the seed replay, not a fresh
      // staging.
      const stale = reopened.stageTrustedSelection(stageInput(caseId, 'r02v-g2-r1', Date.now()));
      expect(stale).toMatchObject({ status: 'REFUSED', code: 'GUIDED_SEED_REPLAY' });

      // A genuinely NEW Host observation may stage the next step.
      const fresh = reopened.stageTrustedSelection(stageInput(caseId, 'r02v-g2-r2', Date.now()));
      expect(fresh.status).toBe('CURRENT');
    } finally {
      reopened.close();
    }
  }, 60_000);
});

describe('R02-V G2 J08 fail-closed trust negatives (fresh TEST_FIXTURE fixtures)', () => {
  it('a swapped/untrusted trust anchor under the same pin refuses boot and creates no database', () => {
    const fixture = track(makeFixture('anchor-swap'));
    const forged = generateKeyPairSync('ed25519');
    const forgedPem = forged.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const forgedSpki = createHash('sha256')
      .update(forged.publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex');
    // Simulated untrusted anchor swap: the pin still names the original key.
    writeFileSync(
      fixture.anchorPath,
      `${JSON.stringify({
        schema: GUIDED_PROVENANCE_TRUST_ANCHOR_SCHEMA,
        publicKeyPem: forgedPem,
        spkiSha256: forgedSpki,
      })}\n`,
    );
    expect(() =>
      createProductionGuidedService(fixture.databasePath, testOverrides(fixture)),
    ).toThrow('GUIDED_TRUST_PUBLIC_KEY_PIN_MISMATCH');
    expect(existsSync(fixture.databasePath)).toBe(false);
  });

  it('a receipt bound to one database path never authorizes a different database', () => {
    const fixture = track(makeFixture('db-binding'));
    const otherDatabase = join(fixture.root, 'guided-store', 'other.sqlite');
    expect(() => createProductionGuidedService(otherDatabase, testOverrides(fixture))).toThrow(
      'GUIDED_PROVENANCE_RECEIPT_MISSING_OR_UNTRUSTED',
    );
    expect(existsSync(otherDatabase)).toBe(false);
    expect(existsSync(fixture.databasePath)).toBe(false);
  });
});
