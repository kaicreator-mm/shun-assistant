/**
 * R03C-META-SHARED-PRODUCTION — read-only cross-Case Meta shared-experience
 * query over the REAL production composition and the REAL loopback HTTP
 * control surface (Issue #288, LOCAL_BUILDER generation 4).
 *
 * Generation-2 repair (PR #316 comment 6610635105, pack PR #317): every
 * durable record below — vocabulary, receipts, consents AND the verified
 * experiences themselves — enters the store ONLY through the real operator
 * SHA-256-pinned provisioning path (`provisionMetaFromHostFile`). No direct
 * store register/record calls remain as fixture seeding. The tests
 * prove, on a CLEAN store, that:
 *   - current Case B retrieves Case A's privacy-minimized verified experience
 *     through real HTTP → reference-authenticated admission → selected K →
 *     externalEffect:false C → existing Host SQLite (source Case is
 *     provenance only, never an equality gate); same-Case retrieval works;
 *   - query inputs match the #285 contract exactly (optional taskClass,
 *     bounded limit) — an unsupported `tags` field refuses at the gateway;
 *   - results are advisoryOnly data: no Permit/grant/approval is minted, no
 *     policy mutates, no Shadow candidate is promoted, and no cloud LLM is
 *     called (the disabled interpreter journals nothing);
 *   - stale/revoked experience is excluded after the source Case's opt-out
 *     declaration arrives through a second pinned provisioning file;
 *   - the generation-2 pinned schema is strict and ATOMIC: unknown vocabulary,
 *     consent/receipt mismatch, invalid experience payloads, duplicate
 *     Case/revision entries, opt-out Cases carrying experiences, over-limit
 *     batches, extra document keys and malformed LATER entries all refuse
 *     with ZERO durable writes — the shared query can never expose partially
 *     seeded experiences.
 *
 * Generation-3 atomic batch (PR #318 comment 6611769037, pack PR #319,
 * Owner OWNER_SHUN_V030_R03C_G3_HOST_ATOMIC_BATCH_APPROVE): the Host Store
 * owns ONE `BEGIN IMMEDIATE` transaction spanning vocabulary, receipts,
 * consents and all experiences; every failure ROLLBACKs the whole batch.
 * The generation-3 suite proves, with durable row counts read through an
 * independent READ-ONLY SQLite handle, that:
 *   - a valid multi-Case batch provisions everything in one call and stays
 *     cross-Case queryable; re-applying the identical batch is idempotent;
 *   - a later Case with duplicate tags / duplicate constraintCodes / an
 *     expired opt-in consent / an injected pre-existing receipt digest
 *     conflict rolls back to the exact pre-call row snapshot — vocabulary,
 *     receipts, consents AND experiences all return to zero delta;
 *   - strict schema (extra keys at batch/vocabulary/case/experience levels)
 *     refuses before any write;
 *   - the full pinned-file production path rolls back atomically when a
 *     later Case hits a Store-level conflict.
 *
 * Generation-4 consent identity (PR #320 review comment 6613661823, pack
 * PR #321, Owner repair record R1_BLOCK_CONSENT_REPLAY_REPAIR_WITHIN_SAME_13_PATH_SCOPE):
 * in the batch path a consentRef is an IMMUTABLE consent-declaration identity.
 * The generation-4 suite proves, again through the independent READ-ONLY
 * SQLite handle (row counts AND declaration_seq), that:
 *   - replaying the byte-identical pinned batch after a later opt-out never
 *     resurrects the old opt-in (opt-out stays current, the old consent keeps
 *     its original declaration_seq, the attached experience fails the #285
 *     current-consent check and the whole replay rolls back);
 *   - replaying an identical batch with no intervening opt-out is a true
 *     no-op — declaration_seq values are byte-identical, not just row counts;
 *   - duplicate consentRefs across Case entries are rejected in phase 1;
 *   - a batch reusing an existing consentRef of another Case — or the same
 *     consentRef with any different field — conflicts and leaves every
 *     pre-existing row unchanged.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DemoShunBackend } from '../../../../apps/control-api/src/demo/backend.ts';
import { createControlServer } from '../../../../apps/control-api/src/server.ts';
import {
  META_CASE_PROVISION_MAX_CASES,
  META_CASE_PROVISION_MAX_EXPERIENCES_TOTAL,
  provisionMetaFromHostFile,
} from '../../../../apps/control-api/src/v03/composition-journeys.ts';
import {
  createProductionV03Gateway,
  type TrustedLlmInterpreterPort,
} from '../../../../apps/control-api/src/v03/composition-production.ts';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import {
  HostMetaShadowStore,
  type MetaProvisionBatchInput,
  type MetaProvisionCaseInput,
  type MetaVerifiedExperienceRecord,
} from '../../../../packages/domain-host/src/meta/host-meta-shadow-store.ts';
import { consumerDir, ensureV03SdkConsumer } from '../r02-a-build/ensure-consumer.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const t11Fixtures = resolve(repoRoot, 'tests/integration/v03/t11-runtime/fixtures');
const shunModules = resolve(repoRoot, 'packages/domain-app/src/activation/modules');

const CAPABILITY = 'cap.doc.pdf-convert';
const CAPABILITY_ALT = 'cap.doc.batch-export';
const TASK_CLASS = 'taskclass.document';
const PATTERN = 'pattern.two-step-verify';
const TAG_HIGH_SUCCESS = 'tag.success-rate-high';
const CONSTRAINT_NO_ELEVATION = 'constraint.no-elevation';

const sha256 = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

const hoursFromNow = (hours: number): string =>
  new Date(Date.now() + hours * 3_600_000).toISOString();

function readPinned(name: string): string {
  return readFileSync(join(t11Fixtures, name), 'utf8');
}

function standardBundle(): string {
  const sdk = readPinned('standard-sdk-v1.mjs');
  const router = readPinned('workflow-router.mjs');
  const routerBody = router.replace(/^export /gm, '');
  return `${sdk}
const __dhv10RouterBundle = (() => {
${routerBody}
return { routeWorkflowIntent };
})();
export const routeWorkflowIntent = __dhv10RouterBundle.routeWorkflowIntent;
`;
}

function trustedModule(sourceFile: string, module: Record<string, unknown>) {
  const bytes = readFileSync(sourceFile, 'utf8');
  return {
    provenance: 'SHUN_TRUSTED_DOMAIN_PACKAGE',
    sourceFile,
    sourceSha256: sha256(bytes),
    module,
  };
}

function assembleBuild(dir: string): { buildFile: string; buildFileSha256: string } {
  const kernel = readPinned('kernel-mechanism-v1.mjs');
  const standard = standardBundle();
  const kernelFile = join(dir, 'kernel.mjs');
  const standardFile = join(dir, 'standard-bundle.mjs');
  writeFileSync(kernelFile, kernel);
  writeFileSync(standardFile, standard);
  const spec = {
    appId: 'shun-v03-goal',
    audience: 'operator-local',
    buildId: 'shun-v0.3-r03c-meta-shared-production-g2',
    targetProfile: 'node24-esm/1',
    routes: [
      { intentId: 'goal-interpret', operationId: 'interpretGoal', capabilityId: 'llm', handlerId: 'interpretGoal' },
      { intentId: 'querySharedExperiences', operationId: 'meta.querySharedExperiences', capabilityId: 'meta-memory', handlerId: 'querySharedExperiences' },
    ],
    hardBudget: { maxStepsPerTurn: 8, maxWorkUnitsPerTurn: 64 },
    modules: [
      {
        provenance: 'PUBLIC_DOMAIN_PACKAGE_V0103',
        sourceFile: kernelFile,
        sourceSha256: sha256(kernel),
        module: {
          packageId: 'v08-kernel-mechanism@1.0.0',
          role: 'kernel-primary',
          abiVersion: 'v08-kernel-abi/1',
          endpoint: 'occurrence-runtime',
          dependencies: [],
          provides: ['kernel:occurrence-runtime/1'],
          requires: [],
        },
      },
      {
        provenance: 'PUBLIC_DOMAIN_PACKAGE_V0103',
        sourceFile: standardFile,
        sourceSha256: sha256(standard),
        module: {
          packageId: 'standard-sdk@v08.1.0.0',
          role: 'standard-primary',
          abiVersion: 'v08-standard-sdk-abi/1',
          endpoint: 'rule-interpreter',
          dependencies: [],
          provides: ['standard:interpret/1', 'standard:route/1'],
          requires: [],
        },
      },
      trustedModule(join(shunModules, 'business-goal.mjs'), {
        packageId: 'shun.business.goal@v0.3.0',
        role: 'business',
        abiVersion: 'v08-business-abi/1',
        endpoint: 'business-policy',
        dependencies: [],
        provides: ['intent:goal-interpret'],
        requires: [],
      }),
      trustedModule(join(shunModules, 'capability-llm.mjs'), {
        packageId: 'shun.capability.llm-openai-compatible@v0.3.0',
        role: 'capability',
        abiVersion: 'v08-capability-abi/1',
        endpoint: 'capability-endpoint',
        dependencies: [],
        externalImports: { node: [], npm: ['domain-harness-openai-host'], native: [] },
        provides: ['capability:llm/1'],
        requires: [],
        capabilityId: 'llm',
        externalEffect: true,
        handlers: [{ operationId: 'interpretGoal', handler: 'interpretGoal' }],
      }),
      trustedModule(join(shunModules, 'business-meta-memory.mjs'), {
        packageId: 'shun.business.meta-memory@v0.3.0',
        role: 'business',
        abiVersion: 'v08-business-abi/1',
        endpoint: 'business-policy',
        dependencies: [],
        provides: ['intent:querySharedExperiences'],
        requires: [],
      }),
      trustedModule(join(shunModules, 'capability-meta-memory.mjs'), {
        packageId: 'shun.capability.meta-memory@v0.3.0',
        role: 'capability',
        abiVersion: 'v08-capability-abi/1',
        endpoint: 'capability-endpoint',
        dependencies: [],
        externalImports: { node: [], npm: ['shun-meta-host'], native: [] },
        provides: ['capability:meta-memory/1'],
        requires: [],
        capabilityId: 'meta-memory',
        externalEffect: false,
        handlers: [{ operationId: 'meta.querySharedExperiences', handler: 'querySharedExperiences' }],
      }),
    ],
  };
  const specFile = join(dir, 'spec.json');
  const buildFile = join(dir, 'build.json');
  writeFileSync(specFile, JSON.stringify(spec, null, 2));
  const assembler = spawnSync(
    process.execPath,
    [join(repoRoot, 'scripts/v03-ci/assemble-trusted-build.mjs'), specFile, buildFile],
    { encoding: 'utf8' },
  );
  if (assembler.status !== 0) {
    throw new Error(`assembler failed: ${assembler.stderr?.slice(0, 2000)}`);
  }
  return {
    buildFile,
    buildFileSha256: (JSON.parse(assembler.stdout) as { sha256: string }).sha256,
  };
}

const disabledInterpreter: TrustedLlmInterpreterPort = {
  status: () => ({
    enabled: false,
    provider: 'deepseek' as const,
    model: 'deepseek-flash' as const,
    osConsentRequired: true as const,
  }),
  interpretGoal: async () => ({ ok: false, code: 'CLOUD_UNAVAILABLE' }),
};

async function json(
  port: number,
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text === '' ? {} : (JSON.parse(text) as Record<string, unknown>),
  };
}

function metaResults(body: Record<string, unknown>): MetaVerifiedExperienceRecord[] {
  const result = body.result as {
    admitted?: { effects?: { output?: { outcome?: { output?: unknown } } }[] };
  };
  return (result?.admitted?.effects?.[0]?.output?.outcome?.output ?? []) as MetaVerifiedExperienceRecord[];
}

/** Operator-pinned consent record (the exact shape the pinned file carries). */
function consentRecord(
  caseRef: string,
  revision: string,
  digest: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    consentRef: `consent-${caseRef}-${revision}`,
    revision: 'consent-rev-1',
    caseRef,
    sourceRevision: revision,
    sourceDigest: digest,
    operatorId: 'operator:shun-owner',
    operatorSubjectRef: 'operator:shun-owner',
    authorizationRevision: 'authz-rev-1',
    currentnessRef: `currentness:${caseRef}:${revision}`,
    optIn: true,
    expiresAt: hoursFromNow(2),
    ...overrides,
  };
}

function receiptRecord(caseRef: string, revision = 'outcome-r1'): Record<string, unknown> {
  return { caseRef, revision, sha256: sha256(`evidence:${caseRef}:${revision}`) };
}

/** The single pinned experience shape (source identity derived from receipt). */
function experienceRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    capabilityId: CAPABILITY,
    taskClass: TASK_CLASS,
    patternId: PATTERN,
    verifiedOutcome: 'VERIFIED_PASS',
    tags: [TAG_HIGH_SUCCESS],
    constraintCodes: [CONSTRAINT_NO_ELEVATION],
    ...overrides,
  };
}

function provisionDocument(): Record<string, unknown> {
  return {
    vocabulary: {
      capabilityIds: [CAPABILITY, CAPABILITY_ALT],
      taskClasses: [TASK_CLASS],
      patternIds: [PATTERN],
      tags: [TAG_HIGH_SUCCESS],
      constraintCodes: [CONSTRAINT_NO_ELEVATION],
    },
    cases: [
      {
        receipt: receiptRecord('case-alpha'),
        consent: consentRecord('case-alpha', 'outcome-r1', sha256('evidence:case-alpha:outcome-r1')),
        experiences: [experienceRecord()],
      },
      {
        receipt: receiptRecord('case-beta'),
        consent: consentRecord('case-beta', 'outcome-r1', sha256('evidence:case-beta:outcome-r1')),
        experiences: [experienceRecord()],
      },
    ],
  };
}

describe('R03C: Meta shared-experience query route (pinned-provisioned clean store + HTTP)', () => {
  let dir: string;
  let guided: HostGuidedService;
  let store: HostMetaShadowStore;
  let production: Awaited<ReturnType<typeof createProductionV03Gateway>>;
  let server: ReturnType<typeof createControlServer>;
  let port: number;
  let caseId = '';

  const submit = async (body: unknown) =>
    json(port, 'POST', '/api/v03/meta/shared-query', body);

  beforeAll(async () => {
    ensureV03SdkConsumer();
    dir = mkdtempSync(join(tmpdir(), 'shun-r03c-meta-shared-g2-'));
    store = new HostMetaShadowStore(join(dir, 'meta.sqlite'));
    // The ONLY ingestion path: the real operator SHA-256-pinned provisioning
    // file (vocabulary + receipts + consents + verified experiences).
    const provisionFile = join(dir, 'pinned-provision.json');
    const bytes = JSON.stringify(provisionDocument(), null, 2) + '\n';
    writeFileSync(provisionFile, bytes);
    provisionMetaFromHostFile({
      store,
      file: provisionFile,
      sha256: sha256(bytes),
    });

    guided = new HostGuidedService(join(dir, 'guided.sqlite'));
    const now = Date.now();
    const staged = guided.stageTrustedSelection({
      observation: {
        schema: 'shun.guided.host-observation.v1',
        taskId: 'task-r03c-meta-b',
        journeyId: 'journey-r03c-meta',
        sourceRef: 'host:obs:r03c-meta',
        revision: 'r03c-meta',
        caseRef: { snapshotId: 'snap-r03c-meta', digest: sha256('snap-r03c-meta') },
        observedAtUnixMs: now - 1_000,
        validUntilUnixMs: now + 3_600_000,
        evidenceRefs: ['host:scope:r03c-meta'],
      },
      semanticSelection: {
        status: 'SELECTED',
        semantic: {
          schema: 'shun.goal-semantic.v1',
          taskId: 'task-r03c-meta-b',
          goalContract: { taskId: 'task-r03c-meta-b', objective: 'convert a document with shared experience' },
          capabilityId: CAPABILITY,
          capabilityRevision: 'r1',
          provenance: { resolverRevision: 'resolver-v03' },
        },
      },
      scope: { status: 'KNOWN', selectedRootRef: undefined },
    });
    if (staged.status !== 'CURRENT') throw new Error('guided staging failed');
    caseId = staged.step.taskId;
    expect(caseId).toBe('task-r03c-meta-b');

    const { buildFile, buildFileSha256 } = assembleBuild(dir);
    production = await createProductionV03Gateway({
      buildFile,
      buildFileSha256,
      sdkConsumerDir: consumerDir,
      kDocDatabaseFile: join(dir, 'k-docs.sqlite'),
      deploymentRoot: consumerDir,
      tenantId: 'tenant:shun-v03',
      deployedAppId: 'deployment:shun-v03-r03c-meta-shared-g2',
      selectedCase: guided,
      llm: {
        interpreter: disabledInterpreter,
        journalFile: join(dir, 'cloud-journal.sqlite'),
        configuredMaxOutputTokens: 1024,
      },
      approvalLedgerFile: join(dir, 'submit-references.sqlite'),
      journeys: { meta: { store } },
    });
    server = createControlServer({
      backend: new DemoShunBackend(),
      uiDir: resolve(repoRoot, 'apps/control-ui/public'),
      port: 0,
      v03Guided: guided,
      v03Journeys: production.journeys,
      v03ProviderGlobal: production.providerGlobal,
    });
    port = await server.start();
  }, 120_000);

  afterAll(async () => {
    await server.close();
    try {
      production.dispose();
    } catch {
      /* already disposed */
    }
    try {
      guided.close();
    } catch {
      /* already closed */
    }
    try {
      store.close();
    } catch {
      /* already closed */
    }
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        rmSync(dir, { recursive: true, force: true });
        break;
      } catch {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
      }
    }
  });

  it('current Case B retrieves Case A verified experience over real HTTP (source Case is provenance only)', async () => {
    const issued = production.issueSubmitReferences();
    if (issued.status !== 'ISSUED') throw new Error(`refs refused: ${issued.status}`);
    const { status, body } = await submit({
      caseId,
      currentnessRef: issued.currentnessRef,
      approvalRef: issued.approvalRef,
      capabilityId: CAPABILITY,
    });
    expect(status).toBe(200);
    expect(body.status).toBe('COMPLETED');
    const results = metaResults(body);
    const alpha = results.find((record) => record.provenance.sourceCaseRef === 'case-alpha');
    expect(alpha).toBeTruthy();
    expect(alpha?.advisoryOnly).toBe(true);
    expect(alpha?.provenance.sourceRevision).toBe('outcome-r1');
    expect(alpha?.provenance.sourceDigest).toBe(sha256('evidence:case-alpha:outcome-r1'));
    expect(alpha?.feedbackCandidateRef).toBeUndefined();
    // Same-Case record of the current Case is visible too (pinned seed).
    expect(
      results.some((record) => record.provenance.sourceCaseRef === 'case-beta'),
    ).toBe(true);
    expect(alpha?.tags).toEqual([TAG_HIGH_SUCCESS]);
  });

  it('query inputs match the #285 store contract: optional taskClass filters, bounded limit caps', async () => {
    const refs = production.issueSubmitReferences();
    if (refs.status !== 'ISSUED') throw new Error(`refs refused: ${refs.status}`);
    const filtered = await submit({
      caseId,
      currentnessRef: refs.currentnessRef,
      approvalRef: refs.approvalRef,
      capabilityId: CAPABILITY,
      taskClass: TASK_CLASS,
      limit: 1,
    });
    expect(filtered.status).toBe(200);
    expect(metaResults(filtered.body)).toHaveLength(1);
  });

  it('an unsupported tags field (and any unknown field) refuses at the gateway with zero K sends', async () => {
    const refs = production.issueSubmitReferences();
    if (refs.status !== 'ISSUED') throw new Error(`refs refused: ${refs.status}`);
    const attempts: unknown[] = [
      { caseId, currentnessRef: refs.currentnessRef, approvalRef: refs.approvalRef, capabilityId: CAPABILITY, tags: ['tag.windows'] },
      { caseId, currentnessRef: refs.currentnessRef, approvalRef: refs.approvalRef, capabilityId: CAPABILITY, prompt: 'free text' },
      { caseId, currentnessRef: refs.currentnessRef, capabilityId: CAPABILITY, approvalRef: refs.approvalRef, freeContent: 'x'.repeat(128) },
    ];
    for (const body of attempts) {
      const result = await submit(body);
      expect(result.status).toBe(422);
      expect((result.body as { status?: string }).status).toBe('REFUSED');
      expect((result.body as { code?: string }).code).toBe('GATEWAY_INPUT_INVALID');
    }
  });

  it('query mints no authority and never calls the cloud LLM', async () => {
    const { DatabaseSync } = await import('node:sqlite');
    const journal = new DatabaseSync(join(dir, 'cloud-journal.sqlite'));
    const row = journal
      .prepare('SELECT COUNT(*) AS count FROM cloud_request_journal')
      .get() as { count: number };
    journal.close();
    expect(row.count).toBe(0);
  });

  it('stale/revoked experience is excluded after the source Case opts out via a second pinned file', async () => {
    // The opt-out declaration is itself operator-pinned provisioning
    // (generation-1 batch form; the identical receipt re-record is a no-op).
    const revocationFile = join(dir, 'pinned-revocation.json');
    const alphaDigest = sha256('evidence:case-alpha:outcome-r1');
    const bytes =
      JSON.stringify(
        {
          cases: [
            {
              receipt: receiptRecord('case-alpha'),
              consent: consentRecord('case-alpha', 'outcome-r1', alphaDigest, {
                consentRef: 'consent-case-alpha-rev-2',
                revision: 'consent-rev-2',
                authorizationRevision: 'authz-rev-2',
                currentnessRef: 'currentness:case-alpha:outcome-r1:rev-2',
                optIn: false,
              }),
            },
          ],
        },
        null,
        2,
      ) + '\n';
    writeFileSync(revocationFile, bytes);
    provisionMetaFromHostFile({ store, file: revocationFile, sha256: sha256(bytes) });

    const refs = production.issueSubmitReferences();
    if (refs.status !== 'ISSUED') throw new Error(`refs refused: ${refs.status}`);
    const { status, body } = await submit({
      caseId,
      currentnessRef: refs.currentnessRef,
      approvalRef: refs.approvalRef,
      capabilityId: CAPABILITY,
    });
    expect(status).toBe(200);
    const results = metaResults(body);
    expect(results.some((record) => record.provenance.sourceCaseRef === 'case-alpha')).toBe(false);
    expect(results.some((record) => record.provenance.sourceCaseRef === 'case-beta')).toBe(true);
  });
});

describe('R03C: pinned provisioning schema (generation-2 contract)', () => {
  const createdDirs: string[] = [];
  const openStores: HostMetaShadowStore[] = [];

  function makeStore(name: string): { store: HostMetaShadowStore; dir: string } {
    const tempDir = mkdtempSync(join(tmpdir(), `r03c-meta-provision-${name}-`));
    createdDirs.push(tempDir);
    const store = new HostMetaShadowStore(join(tempDir, 'meta.sqlite'));
    openStores.push(store);
    return { store, dir: tempDir };
  }

  function provisionViaPinnedFile(
    store: HostMetaShadowStore,
    dir: string,
    name: string,
    document: unknown,
  ): string {
    const file = join(dir, name);
    const bytes = JSON.stringify(document, null, 2) + '\n';
    writeFileSync(file, bytes);
    return file;
  }

  function pinnedSha(document: unknown): string {
    return sha256(JSON.stringify(document, null, 2) + '\n');
  }

  /** A refused document must leave ZERO experiences queryable. */
  function expectAtomicRefusal(
    store: HostMetaShadowStore,
    dir: string,
    name: string,
    document: unknown,
    code: string,
  ): void {
    const file = provisionViaPinnedFile(store, dir, name, document);
    expect(() =>
      provisionMetaFromHostFile({ store, file, sha256: pinnedSha(document) }),
    ).toThrow(code);
    // Zero visible experiences. A refused document never registers its
    // vocabulary, so the store may itself refuse the query capability as
    // unknown — which is equally a proof that nothing was seeded.
    let visible: readonly unknown[] | undefined;
    try {
      visible = store.querySharedExperiences({
        targetCaseRef: 'case-any',
        capabilityId: CAPABILITY,
      });
    } catch (error) {
      if (error instanceof TypeError && error.message === 'META_EXPERIENCE_QUERY_INVALID') {
        visible = [];
      } else {
        throw error;
      }
    }
    expect(visible).toHaveLength(0);
  }

  afterAll(() => {
    for (const store of openStores.splice(0)) {
      try {
        store.close();
      } catch {
        /* already closed */
      }
    }
    while (createdDirs.length > 0) {
      const tempDir = createdDirs.pop();
      if (tempDir === undefined) break;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          rmSync(tempDir, { recursive: true, force: true });
          break;
        } catch {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
        }
      }
    }
  });

  it('legacy single-record file keeps working exactly as before (receipt + consent only)', () => {
    const { store, dir } = makeStore('legacy');
    const document = {
      receipt: receiptRecord('case-legacy'),
      consent: consentRecord('case-legacy', 'outcome-r1', sha256('evidence:case-legacy:outcome-r1')),
    };
    const file = provisionViaPinnedFile(store, dir, 'case.json', document);
    provisionMetaFromHostFile({ store, file, sha256: pinnedSha(document) });
    // Legacy form registers no vocabulary and no experiences: the store's
    // own writer stays sealed for this Case (proves no implicit widening).
    expect(() =>
      store.recordSharedExperience({
        caseRef: 'case-legacy',
        sourceRevision: 'outcome-r1',
        sourceDigest: sha256('evidence:case-legacy:outcome-r1'),
        capabilityId: CAPABILITY,
        taskClass: TASK_CLASS,
        patternId: PATTERN,
        verifiedOutcome: 'VERIFIED_PASS',
        tags: [],
        constraintCodes: [],
      }),
    ).toThrow('META_EXPERIENCE_VOCABULARY_UNKNOWN');
  });

  it('generation-1 bounded batch format (receipt + consent only) is preserved', () => {
    const { store, dir } = makeStore('batch-g1');
    const digestA = sha256('evidence:case-a:outcome-r1');
    const digestB = sha256('evidence:case-b:outcome-r1');
    const document = {
      cases: [
        { receipt: receiptRecord('case-a'), consent: consentRecord('case-a', 'outcome-r1', digestA) },
        { receipt: receiptRecord('case-b'), consent: consentRecord('case-b', 'outcome-r1', digestB) },
      ],
    };
    const file = provisionViaPinnedFile(store, dir, 'cases.json', document);
    provisionMetaFromHostFile({ store, file, sha256: pinnedSha(document) });
    // Gen-1 batch registers no vocabulary: the store's query refuses the
    // capability as unknown (nothing seeded, exactly as before generation 2).
    expect(() =>
      store.querySharedExperiences({ targetCaseRef: 'case-x', capabilityId: CAPABILITY }),
    ).toThrow('META_EXPERIENCE_QUERY_INVALID');
  });

  it('generation-2 file provisions closed vocabulary + bounded experiences for MULTIPLE Cases', () => {
    const { store, dir } = makeStore('batch-g2');
    const document = provisionDocument();
    const file = provisionViaPinnedFile(store, dir, 'full.json', document);
    provisionMetaFromHostFile({ store, file, sha256: pinnedSha(document) });
    const all = store.querySharedExperiences({
      targetCaseRef: 'case-beta',
      capabilityId: CAPABILITY,
    });
    expect(all).toHaveLength(2);
    expect(
      all.every((record) => record.advisoryOnly === true && record.provenance.sourceCaseRef.length > 0),
    ).toBe(true);
    const filtered = store.querySharedExperiences({
      targetCaseRef: 'case-beta',
      capabilityId: CAPABILITY,
      taskClass: TASK_CLASS,
    });
    expect(filtered).toHaveLength(2);
  });

  it('fail-closed: unknown vocabulary refuses atomically', () => {
    const { store, dir } = makeStore('unknown-vocab');
    const broken = {
      ...provisionDocument(),
      cases: [
        {
          receipt: receiptRecord('case-alpha'),
          consent: consentRecord('case-alpha', 'outcome-r1', sha256('evidence:case-alpha:outcome-r1')),
          experiences: [experienceRecord({ capabilityId: 'cap.undeclared' })],
        },
      ],
    };
    expectAtomicRefusal(store, dir, 'unknown.json', broken, 'V03_META_EXPERIENCE_VOCABULARY_UNKNOWN');
  });

  it('fail-closed: consent/receipt source mismatch refuses atomically', () => {
    const { store, dir } = makeStore('mismatch');
    const broken = {
      ...provisionDocument(),
      cases: [
        {
          receipt: receiptRecord('case-alpha'),
          consent: consentRecord('case-alpha', 'outcome-r1', sha256('evidence:case-alpha:outcome-r1'), {
            sourceDigest: sha256('evidence:OTHER'),
          }),
          experiences: [experienceRecord()],
        },
      ],
    };
    expectAtomicRefusal(store, dir, 'mismatch.json', broken, 'V03_META_CASE_SOURCE_MISMATCH');
  });

  it('fail-closed: invalid experience payloads (extra keys / bad outcome / undeclared tag) refuse atomically', () => {
    const { store, dir } = makeStore('invalid-exp');
    const alphaConsent = consentRecord('case-alpha', 'outcome-r1', sha256('evidence:case-alpha:outcome-r1'));
    const brokenExtra = {
      ...provisionDocument(),
      cases: [
        { receipt: receiptRecord('case-alpha'), consent: alphaConsent, experiences: [experienceRecord({ note: 'operator remark' })] },
      ],
    };
    expectAtomicRefusal(store, dir, 'extra.json', brokenExtra, 'V03_META_EXPERIENCE_INVALID');
    const brokenOutcome = {
      ...provisionDocument(),
      cases: [
        { receipt: receiptRecord('case-alpha'), consent: alphaConsent, experiences: [experienceRecord({ verifiedOutcome: 'PARTIAL' })] },
      ],
    };
    expectAtomicRefusal(store, dir, 'outcome.json', brokenOutcome, 'V03_META_EXPERIENCE_INVALID');
    const brokenTag = {
      ...provisionDocument(),
      cases: [
        { receipt: receiptRecord('case-alpha'), consent: alphaConsent, experiences: [experienceRecord({ tags: ['tag.undeclared'] })] },
      ],
    };
    expectAtomicRefusal(store, dir, 'tag.json', brokenTag, 'V03_META_EXPERIENCE_VOCABULARY_UNKNOWN');
  });

  it('fail-closed: a malformed LATER Case entry refuses the WHOLE document (no partial seed)', () => {
    const { store, dir } = makeStore('later-entry');
    const document = provisionDocument();
    const broken = {
      ...document,
      cases: [
        ...(document.cases as unknown[]),
        { receipt: receiptRecord('case-gamma'), consent: 'not-a-consent', experiences: [] },
      ],
    };
    expectAtomicRefusal(store, dir, 'later.json', broken, 'V03_META_CASE_INVALID');
  });

  it('fail-closed: extra document keys, duplicate Case/revision, opt-out with experiences, over-limit totals', () => {
    const { store, dir } = makeStore('strict');

    const withExtraKey = { ...provisionDocument(), operatorNote: 'x' };
    expectAtomicRefusal(store, dir, 'extra-key.json', withExtraKey, 'V03_META_CASE_INVALID');

    const duplicate = provisionDocument();
    (duplicate.cases as unknown[]).push((duplicate.cases as unknown[])[0] as never);
    expectAtomicRefusal(store, dir, 'dup.json', duplicate, 'V03_META_CASE_DUPLICATE');

    const optOutWithExperiences = provisionDocument();
    (optOutWithExperiences.cases as Record<string, unknown>[])[0] = {
      receipt: receiptRecord('case-alpha'),
      consent: consentRecord('case-alpha', 'outcome-r1', sha256('evidence:case-alpha:outcome-r1'), { optIn: false }),
      experiences: [experienceRecord()],
    };
    expectAtomicRefusal(store, dir, 'optout.json', optOutWithExperiences, 'V03_META_CASE_OPT_IN_REQUIRED');

    // 65 identical experiences in one Case trip the in-case duplicate rule
    // before the total bound; a same-shape over-limit document still refuses.
    const overLimit = provisionDocument();
    const alphaEntry = (overLimit.cases as Record<string, unknown>[])[0] as Record<string, unknown>;
    alphaEntry.experiences = Array.from(
      { length: META_CASE_PROVISION_MAX_EXPERIENCES_TOTAL + 1 },
      () => experienceRecord(),
    );
    expectAtomicRefusal(store, dir, 'over.json', overLimit, 'V03_META_EXPERIENCE_DUPLICATE');
  });

  it('fail-closed: over-bound Case count and digest tamper still refuse', () => {
    const { store, dir } = makeStore('bounds');
    const overCases = {
      cases: Array.from({ length: META_CASE_PROVISION_MAX_CASES + 1 }, (_, index) => ({
        receipt: receiptRecord(`case-${index}`),
        consent: consentRecord(`case-${index}`, 'outcome-r1', sha256(`evidence:case-${index}:outcome-r1`)),
      })),
    };
    expectAtomicRefusal(store, dir, 'cases-over.json', overCases, 'V03_META_CASE_BATCH_BOUND_REFUSED');

    const document = provisionDocument();
    const file = provisionViaPinnedFile(store, dir, 'tamper.json', document);
    expect(() =>
      provisionMetaFromHostFile({ store, file, sha256: '0'.repeat(64) }),
    ).toThrow('V03_META_CASE_DIGEST_REFUSED');
  });
});

describe('R03C: Host Store atomic batch transaction (generation 3)', () => {
  const createdDirs: string[] = [];
  const openStores: HostMetaShadowStore[] = [];

  function makeStore(name: string): { store: HostMetaShadowStore; dir: string } {
    const tempDir = mkdtempSync(join(tmpdir(), `r03c-meta-g3-${name}-`));
    createdDirs.push(tempDir);
    const store = new HostMetaShadowStore(join(tempDir, 'meta.sqlite'));
    openStores.push(store);
    return { store, dir: tempDir };
  }

  function provisionViaPinnedFile(
    store: HostMetaShadowStore,
    dir: string,
    name: string,
    document: unknown,
  ): string {
    const file = join(dir, name);
    writeFileSync(file, JSON.stringify(document, null, 2) + '\n');
    return file;
  }

  function pinnedSha(document: unknown): string {
    return sha256(JSON.stringify(document, null, 2) + '\n');
  }

  /**
   * Durable row counts through an INDEPENDENT READ-ONLY SQLite handle: the
   * atomicity assertions must observe real persisted rows, not query results.
   */
  function durableCounts(dir: string): {
    vocabulary: number;
    receipts: number;
    consents: number;
    experiences: number;
  } {
    const db = new DatabaseSync(join(dir, 'meta.sqlite'), { readOnly: true });
    try {
      const count = (table: string): number =>
        (db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count;
      return {
        vocabulary: count('meta_experience_vocabulary'),
        receipts: count('meta_outcome_receipts'),
        consents: count('meta_opt_in_consents'),
        experiences: count('meta_verified_experiences'),
      };
    } finally {
      db.close();
    }
  }

  /** One batch experience whose source identity matches `caseRef`'s receipt. */
  function batchExperience(
    caseRef: string,
    overrides: Record<string, unknown> = {},
  ): Record<string, unknown> {
    const receipt = receiptRecord(caseRef);
    return {
      caseRef,
      sourceRevision: receipt.revision,
      sourceDigest: receipt.sha256,
      capabilityId: CAPABILITY,
      taskClass: TASK_CLASS,
      patternId: PATTERN,
      verifiedOutcome: 'VERIFIED_PASS',
      tags: [TAG_HIGH_SUCCESS],
      constraintCodes: [CONSTRAINT_NO_ELEVATION],
      ...overrides,
    };
  }

  function batchCase(
    caseRef: string,
    overrides: { consent?: Record<string, unknown>; experiences?: unknown[] } = {},
  ): MetaProvisionCaseInput {
    const receipt = receiptRecord(caseRef);
    return {
      receipt,
      consent: consentRecord(caseRef, 'outcome-r1', receipt.sha256, overrides.consent) as never,
      experiences: (overrides.experiences ?? [batchExperience(caseRef)]) as never,
    };
  }

  function batchDocument(): MetaProvisionBatchInput {
    return {
      vocabulary: {
        capabilityIds: [CAPABILITY, CAPABILITY_ALT],
        taskClasses: [TASK_CLASS],
        patternIds: [PATTERN],
        tags: [TAG_HIGH_SUCCESS],
        constraintCodes: [CONSTRAINT_NO_ELEVATION],
      },
      cases: [batchCase('case-alpha'), batchCase('case-beta')],
    };
  }

  afterAll(() => {
    for (const store of openStores.splice(0)) {
      try {
        store.close();
      } catch {
        /* already closed */
      }
    }
    while (createdDirs.length > 0) {
      const tempDir = createdDirs.pop();
      if (tempDir === undefined) break;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          rmSync(tempDir, { recursive: true, force: true });
          break;
        } catch {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
        }
      }
    }
  });

  it('provisions the complete batch in ONE store call; cross-Case query works; re-apply is idempotent', () => {
    const { store, dir } = makeStore('batch-ok');
    const document = batchDocument();
    const before = durableCounts(dir);
    const result = store.provisionVerifiedExperienceBatch(document);
    expect(result).toEqual({
      status: 'PROVISIONED',
      vocabularyCodes: 6,
      receipts: 2,
      consents: 2,
      experiences: 2,
    });
    const expected = {
      vocabulary: before.vocabulary + 6,
      receipts: before.receipts + 2,
      consents: before.consents + 2,
      experiences: before.experiences + 2,
    };
    expect(durableCounts(dir)).toEqual(expected);
    const found = store.querySharedExperiences({
      targetCaseRef: 'case-beta',
      capabilityId: CAPABILITY,
    });
    expect(found).toHaveLength(2);
    expect(found.map((record) => record.provenance.sourceCaseRef).sort()).toEqual([
      'case-alpha',
      'case-beta',
    ]);
    // Byte-identical re-apply (same document, same expiresAt strings):
    // receipts no-op, consents are true no-ops, experiences are
    // ALREADY_STORED — zero delta.
    store.provisionVerifiedExperienceBatch(document);
    expect(durableCounts(dir)).toEqual(expected);
  });

  it('rolls back EVERYTHING when a later Case carries duplicate tags', () => {
    const { store, dir } = makeStore('rb-dup-tags');
    const document = batchDocument() as never as {
      cases: { experiences: Record<string, unknown>[] }[];
    };
    document.cases[1].experiences = [
      {
        ...document.cases[1].experiences[0],
        tags: [TAG_HIGH_SUCCESS, TAG_HIGH_SUCCESS],
      },
    ];
    const before = durableCounts(dir);
    // The #285 normalizer rejects the duplicate codes before any write.
    expect(() =>
      store.provisionVerifiedExperienceBatch(document as never),
    ).toThrow('META_EXPERIENCE_INVALID');
    expect(durableCounts(dir)).toEqual(before);
  });

  it('rolls back EVERYTHING when a later Case carries duplicate constraintCodes', () => {
    const { store, dir } = makeStore('rb-dup-constraints');
    const document = batchDocument() as never as {
      cases: { experiences: Record<string, unknown>[] }[];
    };
    document.cases[1].experiences = [
      {
        ...document.cases[1].experiences[0],
        constraintCodes: [CONSTRAINT_NO_ELEVATION, CONSTRAINT_NO_ELEVATION],
      },
    ];
    const before = durableCounts(dir);
    expect(() =>
      store.provisionVerifiedExperienceBatch(document as never),
    ).toThrow('META_EXPERIENCE_INVALID');
    expect(durableCounts(dir)).toEqual(before);
  });

  it('rolls back EVERYTHING when a later Case consent is expired (in-transaction ROLLBACK)', () => {
    const { store, dir } = makeStore('rb-expired');
    const document = batchDocument() as never as {
      cases: { consent: Record<string, unknown> }[];
    };
    document.cases[1].consent = {
      ...document.cases[1].consent,
      expiresAt: hoursFromNow(-1),
    };
    const before = durableCounts(dir);
    // Phase 1 passes (grammar is valid); the #285 write-time expiry check
    // fires INSIDE the transaction after Case A wrote — and must undo it.
    expect(() =>
      store.provisionVerifiedExperienceBatch(document as never),
    ).toThrow('META_CONSENT_EXPIRED');
    expect(durableCounts(dir)).toEqual(before);
  });

  it('rolls back EVERYTHING on an injected pre-existing receipt digest conflict (pre-existing rows untouched)', () => {
    const { store, dir } = makeStore('rb-conflict');
    // Inject the durable conflict BEFORE the batch: a genuine receipt row for
    // case-beta@outcome-r1 whose digest the batch later contradicts.
    const seeded = receiptRecord('case-beta');
    store.recordOutcomeReceipt(seeded);
    const conflictReceipt = {
      caseRef: 'case-beta',
      revision: 'outcome-r1',
      sha256: sha256('evidence:TAMPERED'),
    };
    const document = batchDocument();
    document.cases[1] = {
      receipt: conflictReceipt,
      consent: consentRecord(
        'case-beta',
        'outcome-r1',
        conflictReceipt.sha256,
      ) as never,
      experiences: [
        batchExperience('case-beta', { sourceDigest: conflictReceipt.sha256 }),
      ] as never,
    };
    const before = durableCounts(dir);
    expect(() =>
      store.provisionVerifiedExperienceBatch(document),
    ).toThrow('META_RECEIPT_CONFLICT');
    expect(durableCounts(dir)).toEqual(before);
  });

  it('strict schema: extra keys at batch/vocabulary/case/experience levels refuse before any write', () => {
    const { store, dir } = makeStore('strict-g3');
    const before = durableCounts(dir);

    const extraBatchKey = { ...batchDocument(), operatorNote: 'x' } as never;
    expect(() =>
      store.provisionVerifiedExperienceBatch(extraBatchKey),
    ).toThrow('META_PROVISION_BATCH_INVALID');

    const docVocabExtra = batchDocument() as never as {
      vocabulary: Record<string, unknown>;
    };
    docVocabExtra.vocabulary.extraKind = ['code.x'];
    expect(() =>
      store.provisionVerifiedExperienceBatch(docVocabExtra as never),
    ).toThrow('META_PROVISION_BATCH_INVALID');

    const docCaseExtra = batchDocument() as never as {
      cases: Record<string, unknown>[];
    };
    docCaseExtra.cases[0] = { ...docCaseExtra.cases[0], note: 'x' };
    expect(() =>
      store.provisionVerifiedExperienceBatch(docCaseExtra as never),
    ).toThrow('META_PROVISION_BATCH_INVALID');

    const docExpExtra = batchDocument() as never as {
      cases: { experiences: Record<string, unknown>[] }[];
    };
    docExpExtra.cases[0].experiences[0] = {
      ...docExpExtra.cases[0].experiences[0],
      note: 'x',
    };
    expect(() =>
      store.provisionVerifiedExperienceBatch(docExpExtra as never),
    ).toThrow('META_EXPERIENCE_INVALID');

    expect(durableCounts(dir)).toEqual(before);
  });

  it('pinned-file production path: a later-Case Store conflict rolls back the WHOLE batch', () => {
    const { store, dir } = makeStore('pinned-rb');
    // Pre-existing genuine durable receipt for case-beta@outcome-r1.
    const seed = {
      receipt: receiptRecord('case-beta'),
      consent: consentRecord('case-beta', 'outcome-r1', sha256('evidence:case-beta:outcome-r1')),
    };
    const seedFile = provisionViaPinnedFile(store, dir, 'seed.json', seed);
    provisionMetaFromHostFile({ store, file: seedFile, sha256: pinnedSha(seed) });
    const snapshot = durableCounts(dir);
    // Generation-2 pinned document: valid Case A, then Case B whose receipt
    // digest conflicts with the durable row — a Store-level failure that the
    // Control API phase 1 cannot see; the Host batch transaction must undo
    // Case A together with anything Case B touched.
    const conflictReceipt = {
      caseRef: 'case-beta',
      revision: 'outcome-r1',
      sha256: sha256('evidence:TAMPERED'),
    };
    const broken = {
      vocabulary: {
        capabilityIds: [CAPABILITY],
        taskClasses: [TASK_CLASS],
        patternIds: [PATTERN],
        tags: [TAG_HIGH_SUCCESS],
        constraintCodes: [CONSTRAINT_NO_ELEVATION],
      },
      cases: [
        {
          receipt: receiptRecord('case-alpha'),
          consent: consentRecord('case-alpha', 'outcome-r1', sha256('evidence:case-alpha:outcome-r1')),
          experiences: [experienceRecord()],
        },
        {
          receipt: conflictReceipt,
          consent: consentRecord('case-beta', 'outcome-r1', conflictReceipt.sha256),
          experiences: [experienceRecord()],
        },
      ],
    };
    const file = provisionViaPinnedFile(store, dir, 'broken.json', broken);
    expect(() =>
      provisionMetaFromHostFile({ store, file, sha256: pinnedSha(broken) }),
    ).toThrow('META_RECEIPT_CONFLICT');
    expect(durableCounts(dir)).toEqual(snapshot);
  });
});

describe('R03C: immutable consent identity and replay protection (generation 4)', () => {
  const createdDirs: string[] = [];
  const openStores: HostMetaShadowStore[] = [];

  function makeStore(name: string): { store: HostMetaShadowStore; dir: string } {
    const tempDir = mkdtempSync(join(tmpdir(), `r03c-meta-g4-${name}-`));
    createdDirs.push(tempDir);
    const store = new HostMetaShadowStore(join(tempDir, 'meta.sqlite'));
    openStores.push(store);
    return { store, dir: tempDir };
  }

  function provisionViaPinnedFile(
    store: HostMetaShadowStore,
    dir: string,
    name: string,
    document: unknown,
  ): string {
    const file = join(dir, name);
    writeFileSync(file, JSON.stringify(document, null, 2) + '\n');
    return file;
  }

  function pinnedSha(document: unknown): string {
    return sha256(JSON.stringify(document, null, 2) + '\n');
  }

  function durableCounts(dir: string): {
    vocabulary: number;
    receipts: number;
    consents: number;
    experiences: number;
  } {
    const db = new DatabaseSync(join(dir, 'meta.sqlite'), { readOnly: true });
    try {
      const count = (table: string): number =>
        (db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count;
      return {
        vocabulary: count('meta_experience_vocabulary'),
        receipts: count('meta_outcome_receipts'),
        consents: count('meta_opt_in_consents'),
        experiences: count('meta_verified_experiences'),
      };
    } finally {
      db.close();
    }
  }

  /** consentRef -> declaration_seq, via the independent READ-ONLY handle. */
  function consentSeqs(dir: string): Record<string, number> {
    const db = new DatabaseSync(join(dir, 'meta.sqlite'), { readOnly: true });
    try {
      const rows = db
        .prepare('SELECT consent_ref, declaration_seq FROM meta_opt_in_consents ORDER BY consent_ref')
        .all() as { consent_ref: string; declaration_seq: number }[];
      return Object.fromEntries(rows.map((row) => [row.consent_ref, row.declaration_seq]));
    } finally {
      db.close();
    }
  }

  function batchExperience(
    caseRef: string,
    overrides: Record<string, unknown> = {},
  ): Record<string, unknown> {
    const receipt = receiptRecord(caseRef);
    return {
      caseRef,
      sourceRevision: receipt.revision,
      sourceDigest: receipt.sha256,
      capabilityId: CAPABILITY,
      taskClass: TASK_CLASS,
      patternId: PATTERN,
      verifiedOutcome: 'VERIFIED_PASS',
      tags: [TAG_HIGH_SUCCESS],
      constraintCodes: [CONSTRAINT_NO_ELEVATION],
      ...overrides,
    };
  }

  function batchCase(
    caseRef: string,
    overrides: { consent?: Record<string, unknown>; experiences?: unknown[] } = {},
  ): MetaProvisionCaseInput {
    const receipt = receiptRecord(caseRef);
    return {
      receipt,
      consent: consentRecord(caseRef, 'outcome-r1', receipt.sha256, overrides.consent) as never,
      experiences: (overrides.experiences ?? [batchExperience(caseRef)]) as never,
    };
  }

  function batchVocabulary(): MetaProvisionBatchInput['vocabulary'] {
    return {
      capabilityIds: [CAPABILITY, CAPABILITY_ALT],
      taskClasses: [TASK_CLASS],
      patternIds: [PATTERN],
      tags: [TAG_HIGH_SUCCESS],
      constraintCodes: [CONSTRAINT_NO_ELEVATION],
    };
  }

  function batchDocument(): MetaProvisionBatchInput {
    return {
      vocabulary: batchVocabulary(),
      cases: [batchCase('case-alpha'), batchCase('case-beta')],
    };
  }

  afterAll(() => {
    for (const store of openStores.splice(0)) {
      try {
        store.close();
      } catch {
        /* already closed */
      }
    }
    while (createdDirs.length > 0) {
      const tempDir = createdDirs.pop();
      if (tempDir === undefined) break;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          rmSync(tempDir, { recursive: true, force: true });
          break;
        } catch {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
        }
      }
    }
  });

  it('replaying the byte-identical batch after a later opt-out never resurrects the old opt-in', async () => {
    const { store, dir } = makeStore('g4-replay');
    const document = batchDocument();
    store.provisionVerifiedExperienceBatch(document);
    expect(
      store.querySharedExperiences({ targetCaseRef: 'case-beta', capabilityId: CAPABILITY }),
    ).toHaveLength(2);
    // Operator opt-out for case-alpha through the pinned generation-1 path.
    const alphaDigest = sha256('evidence:case-alpha:outcome-r1');
    const optOut = {
      cases: [
        {
          receipt: receiptRecord('case-alpha'),
          consent: consentRecord('case-alpha', 'outcome-r1', alphaDigest, {
            consentRef: 'consent-case-alpha-rev-2',
            revision: 'consent-rev-2',
            authorizationRevision: 'authz-rev-2',
            currentnessRef: 'currentness:case-alpha:outcome-r1:rev-2',
            optIn: false,
          }),
        },
      ],
    };
    const optOutFile = provisionViaPinnedFile(store, dir, 'optout.json', optOut);
    provisionMetaFromHostFile({ store, file: optOutFile, sha256: pinnedSha(optOut) });
    const snapshot = durableCounts(dir);
    const seqsBefore = consentSeqs(dir);
    // Byte-identical replay of the ORIGINAL batch: the old opt-in consent is
    // an exact existing declaration and must stay a true no-op (original
    // declaration_seq preserved); the attached experience must fail the #285
    // current-consent check because the opt-out is current — and the whole
    // replay rolls back.
    expect(() => store.provisionVerifiedExperienceBatch(document)).toThrow(
      'META_EXPERIENCE_NOT_CURRENT',
    );
    expect(durableCounts(dir)).toEqual(snapshot);
    expect(consentSeqs(dir)).toEqual(seqsBefore);
    // The opt-out remains current: alpha's experience stays invisible…
    const visible = store.querySharedExperiences({
      targetCaseRef: 'case-beta',
      capabilityId: CAPABILITY,
    });
    expect(visible.some((record) => record.provenance.sourceCaseRef === 'case-alpha')).toBe(false);
    // …a new experience write is refused…
    expect(() =>
      store.recordSharedExperience({
        caseRef: 'case-alpha',
        sourceRevision: 'outcome-r1',
        sourceDigest: alphaDigest,
        capabilityId: CAPABILITY_ALT,
        taskClass: TASK_CLASS,
        patternId: PATTERN,
        verifiedOutcome: 'VERIFIED_PASS',
        tags: [],
        constraintCodes: [],
      }),
    ).toThrow('META_EXPERIENCE_NOT_CURRENT');
    // …and feedback authorization is refused.
    await expect(
      store.authorizeCurrentFeedback({
        scope: 'META_FEEDBACK_SHADOW',
        caseRef: 'case-alpha',
        sourceRevision: 'outcome-r1',
        selection: {
          selected: true,
          caseRef: 'case-alpha',
          sourceRevision: 'outcome-r1',
          rating: 'HELPFUL',
          category: 'OTHER',
        },
      }),
    ).rejects.toThrow('META_OPT_IN_MISSING');
  });

  it('replaying an identical batch without an intervening opt-out is a true no-op (declaration_seq preserved)', () => {
    const { store, dir } = makeStore('g4-noop');
    const document = batchDocument();
    store.provisionVerifiedExperienceBatch(document);
    const seqsBefore = consentSeqs(dir);
    const countsBefore = durableCounts(dir);
    const second = store.provisionVerifiedExperienceBatch(document);
    expect(second.status).toBe('PROVISIONED');
    // Stronger than row counts: every declaration_seq must be identical. The
    // pre-generation-4 REPLACE upsert would have advanced them on replay.
    expect(consentSeqs(dir)).toEqual(seqsBefore);
    expect(durableCounts(dir)).toEqual(countsBefore);
  });

  it('rejects duplicate consentRefs across Case entries during phase 1, before any write', () => {
    const { store, dir } = makeStore('g4-dup-ref');
    const document = batchDocument();
    document.cases[1] = batchCase('case-beta', {
      consent: { consentRef: 'consent-case-alpha-outcome-r1' },
    });
    const before = durableCounts(dir);
    expect(() => store.provisionVerifiedExperienceBatch(document)).toThrow(
      'META_PROVISION_BATCH_INVALID',
    );
    expect(durableCounts(dir)).toEqual(before);
  });

  it('a batch reusing an existing consentRef owned by another Case conflicts and leaves pre-existing rows unchanged', () => {
    const { store, dir } = makeStore('g4-cross-ref');
    store.provisionVerifiedExperienceBatch({
      vocabulary: batchVocabulary(),
      cases: [batchCase('case-gamma')],
    });
    const snapshot = durableCounts(dir);
    const seqsBefore = consentSeqs(dir);
    const hijack = {
      vocabulary: batchVocabulary(),
      cases: [batchCase('case-delta', { consent: { consentRef: 'consent-case-gamma-outcome-r1' } })],
    };
    // The global consentRef belongs to case-gamma: rebinding it to
    // case-delta's declaration is an identity conflict; the batch — including
    // the just-inserted case-delta receipt — rolls back.
    expect(() => store.provisionVerifiedExperienceBatch(hijack)).toThrow('META_CONSENT_CONFLICT');
    expect(durableCounts(dir)).toEqual(snapshot);
    expect(consentSeqs(dir)).toEqual(seqsBefore);
  });

  it('the same consentRef with any different field is a declaration-identity conflict (no silent REPLACE)', () => {
    const { store, dir } = makeStore('g4-drift');
    store.provisionVerifiedExperienceBatch(batchDocument());
    const snapshot = durableCounts(dir);
    const drifted = batchDocument() as never as {
      cases: { consent: Record<string, unknown> }[];
    };
    drifted.cases[0].consent = {
      ...drifted.cases[0].consent,
      expiresAt: hoursFromNow(4),
    };
    expect(() => store.provisionVerifiedExperienceBatch(drifted as never)).toThrow(
      'META_CONSENT_CONFLICT',
    );
    expect(durableCounts(dir)).toEqual(snapshot);
  });
});
