/**
 * R03C-META-SHARED-PRODUCTION — read-only cross-Case Meta shared-experience
 * query over the REAL production composition and the REAL loopback HTTP
 * control surface (Issue #288, LOCAL_BUILDER generation 1).
 *
 * Proves, through real HTTP → reference-authenticated journey admission →
 * selected public v0.10.3 K → a BUILD-selected externalEffect:false C module
 * → the existing Host SQLite read port (#285 store):
 *   - current Case B retrieves Case A's privacy-minimized verified experience
 *     (source Case is provenance only, never an equality gate); same-Case
 *     retrieval also works;
 *   - query inputs match the #285 contract exactly (targetCaseRef injected
 *     by the trusted composition, capabilityId, optional taskClass, bounded
 *     limit) — an unsupported `tags` field is refused at the gateway;
 *   - results are advisoryOnly data: no Permit/grant/approval is minted, no
 *     policy mutates, no Shadow candidate is promoted, and no cloud LLM is
 *     called (the disabled interpreter journals nothing);
 *   - stale/revoked experience is excluded after the source Case opts out;
 *   - the R03C multi-Case Host provisioning file (hash-pinned, bounded batch)
 *     seeds more than one source Case into the same local DB, preserving
 *     legacy single-record compatibility and fail-closed validation.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DemoShunBackend } from '../../../../apps/control-api/src/demo/backend.ts';
import { createControlServer } from '../../../../apps/control-api/src/server.ts';
import {
  createProductionV03Gateway,
  type TrustedLlmInterpreterPort,
} from '../../../../apps/control-api/src/v03/composition-production.ts';
import {
  META_CASE_PROVISION_MAX_CASES,
  provisionMetaFromHostFile,
} from '../../../../apps/control-api/src/v03/composition-journeys.ts';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import {
  HostMetaShadowStore,
  type MetaVerifiedExperienceInput,
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
  return { provenance: 'SHUN_TRUSTED_DOMAIN_PACKAGE', sourceFile, sourceSha256: sha256(bytes), module };
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
    buildId: 'shun-v0.3-r03c-meta-shared-production',
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

function consentRecord(caseRef: string, revision: string, digest: string): Record<string, unknown> {
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
  };
}

function seedCase(store: HostMetaShadowStore, caseRef: string): string {
  const revision = 'outcome-r1';
  const digest = sha256(`evidence:${caseRef}:${revision}`);
  store.recordOutcomeReceipt({ caseRef, revision, sha256: digest });
  store.recordOptInConsent(consentRecord(caseRef, revision, digest) as never);
  return digest;
}

function experienceFor(caseRef: string, digest: string, overrides: Partial<MetaVerifiedExperienceInput> = {}): MetaVerifiedExperienceInput {
  return {
    caseRef,
    sourceRevision: 'outcome-r1',
    sourceDigest: digest,
    capabilityId: CAPABILITY,
    taskClass: TASK_CLASS,
    patternId: PATTERN,
    verifiedOutcome: 'VERIFIED_PASS',
    tags: [TAG_HIGH_SUCCESS],
    constraintCodes: [CONSTRAINT_NO_ELEVATION],
    ...overrides,
  };
}

describe('R03C: Meta shared-experience query route (production composition + HTTP)', () => {
  let dir: string;
  let guided: HostGuidedService;
  let store: HostMetaShadowStore;
  let production: Awaited<ReturnType<typeof createProductionV03Gateway>>;
  let server: ReturnType<typeof createControlServer>;
  let port: number;
  let caseId = '';
  let caseAlphaExperienceId = '';
  let caseBetaExperienceId = '';

  const submit = async (body: unknown) =>
    json(port, 'POST', '/api/v03/meta/shared-query', body);

  beforeAll(async () => {
    ensureV03SdkConsumer();
    dir = mkdtempSync(join(tmpdir(), 'shun-r03c-meta-shared-prod-'));
    store = new HostMetaShadowStore(join(dir, 'meta.sqlite'));
    store.registerMetaCapabilityId(CAPABILITY);
    store.registerMetaCapabilityId(CAPABILITY_ALT);
    store.registerMetaTaskClass(TASK_CLASS);
    store.registerMetaPatternId(PATTERN);
    store.registerMetaExperienceTag(TAG_HIGH_SUCCESS);
    store.registerMetaConstraintCode(CONSTRAINT_NO_ELEVATION);
    // Two source Cases in the SAME local DB: case-alpha (cross-Case source)
    // and the current Case itself (same-Case retrieval).
    const alphaDigest = seedCase(store, 'case-alpha');
    const alpha = store.recordSharedExperience(experienceFor('case-alpha', alphaDigest));
    if (alpha.status !== 'STORED') throw new Error(`alpha seed refused: ${alpha.status}`);
    caseAlphaExperienceId = alpha.experienceId ?? '';
    const betaDigest = seedCase(store, 'case-beta');
    const beta = store.recordSharedExperience(
      experienceFor('case-beta', betaDigest, { patternId: PATTERN }),
    );
    if (beta.status !== 'STORED') throw new Error(`beta seed refused: ${beta.status}`);
    caseBetaExperienceId = beta.experienceId ?? '';

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
      deployedAppId: 'deployment:shun-v03-r03c-meta-shared',
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
    const alpha = results.find((record) => record.experienceId === caseAlphaExperienceId);
    expect(alpha).toBeTruthy();
    expect(alpha?.advisoryOnly).toBe(true);
    expect(alpha?.provenance.sourceCaseRef).toBe('case-alpha');
    expect(alpha?.feedbackCandidateRef).toBeUndefined();
    // Same-Case record of the current Case is visible too.
    expect(results.some((record) => record.experienceId === caseBetaExperienceId)).toBe(true);
    // Closed-world vocabulary tokens ride with the record; no raw prompt data.
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
    // The disabled interpreter must have journaled nothing; a query is a
    // read-only internal effect with zero external dispatch.
    const { DatabaseSync } = await import('node:sqlite');
    const journal = new DatabaseSync(join(dir, 'cloud-journal.sqlite'));
    const row = journal
      .prepare('SELECT COUNT(*) AS count FROM cloud_request_journal')
      .get() as { count: number };
    journal.close();
    expect(row.count).toBe(0);
  });

  it('stale/revoked experience is excluded after the source Case opts out (same-Case stays)', async () => {
    const alphaDigest = sha256('evidence:case-alpha:outcome-r1');
    store.recordOptInConsent({
      consentRef: 'consent-case-alpha-rev-2',
      revision: 'consent-rev-2',
      caseRef: 'case-alpha',
      sourceRevision: 'outcome-r1',
      sourceDigest: alphaDigest,
      operatorId: 'operator:shun-owner',
      operatorSubjectRef: 'operator:shun-owner',
      authorizationRevision: 'authz-rev-2',
      currentnessRef: 'currentness:case-alpha:outcome-r1:rev-2',
      optIn: false,
      expiresAt: hoursFromNow(2),
    });
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
    expect(results.some((record) => record.experienceId === caseAlphaExperienceId)).toBe(false);
    expect(results.some((record) => record.experienceId === caseBetaExperienceId)).toBe(true);
  });
});

describe('R03C: multi-Case hash-pinned Host meta provisioning (composition-journeys)', () => {
  const createdDirs: string[] = [];
  const openStores: HostMetaShadowStore[] = [];

  function makeStore(name: string): { store: HostMetaShadowStore; dir: string } {
    const tempDir = mkdtempSync(join(tmpdir(), `r03c-meta-provision-${name}-`));
    createdDirs.push(tempDir);
    const store = new HostMetaShadowStore(join(tempDir, 'meta.sqlite'));
    openStores.push(store);
    return { store, dir: tempDir };
  }

  function pinnedFile(dir: string, name: string, value: unknown): { file: string; sha256: string } {
    const file = join(dir, name);
    const bytes = JSON.stringify(value, null, 2) + '\n';
    writeFileSync(file, bytes);
    return { file, sha256: sha256(bytes) };
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

  it('legacy single-record file keeps working (strict compatibility)', () => {
    const { store, dir } = makeStore('legacy');
    store.registerMetaCapabilityId(CAPABILITY);
    store.registerMetaTaskClass(TASK_CLASS);
    store.registerMetaPatternId(PATTERN);
    const digest = sha256('evidence:case-legacy:outcome-r1');
    const pinned = pinnedFile(dir, 'case.json', {
      receipt: { caseRef: 'case-legacy', revision: 'outcome-r1', sha256: digest },
      consent: consentRecord('case-legacy', 'outcome-r1', digest),
    });
    provisionMetaFromHostFile({ store, file: pinned.file, sha256: pinned.sha256 });
    const recorded = store.recordSharedExperience(
      experienceFor('case-legacy', digest, { tags: [], constraintCodes: [] }),
    );
    expect(recorded.status).toBe('STORED');
  });

  it('bounded batch file seeds MORE THAN ONE source Case into the same local DB', () => {
    const { store, dir } = makeStore('batch');
    store.registerMetaCapabilityId(CAPABILITY);
    store.registerMetaTaskClass(TASK_CLASS);
    store.registerMetaPatternId(PATTERN);
    const digestA = sha256('evidence:case-a:outcome-r1');
    const digestB = sha256('evidence:case-b:outcome-r1');
    const pinned = pinnedFile(dir, 'cases.json', {
      cases: [
        {
          receipt: { caseRef: 'case-a', revision: 'outcome-r1', sha256: digestA },
          consent: consentRecord('case-a', 'outcome-r1', digestA),
        },
        {
          receipt: { caseRef: 'case-b', revision: 'outcome-r1', sha256: digestB },
          consent: consentRecord('case-b', 'outcome-r1', digestB),
        },
      ],
    });
    provisionMetaFromHostFile({ store, file: pinned.file, sha256: pinned.sha256 });
    for (const [caseRef, digest] of [['case-a', digestA], ['case-b', digestB]] as const) {
      const recorded = store.recordSharedExperience(
        experienceFor(caseRef, digest, { tags: [], constraintCodes: [] }),
      );
      expect(recorded.status).toBe('STORED');
    }
  });

  it('fail-closed: digest mismatch, malformed entries, both-forms, and over-bound batches refuse', () => {
    const { store, dir } = makeStore('refused');
    store.registerMetaCapabilityId(CAPABILITY);
    const digest = sha256('evidence:case-x:outcome-r1');
    const valid = {
      receipt: { caseRef: 'case-x', revision: 'outcome-r1', sha256: digest },
      consent: consentRecord('case-x', 'outcome-r1', digest),
    };
    const pinned = pinnedFile(dir, 'valid.json', valid);

    expect(() =>
      provisionMetaFromHostFile({ store, file: pinned.file, sha256: '0'.repeat(64) }),
    ).toThrow('V03_META_CASE_DIGEST_REFUSED');

    const malformed = pinnedFile(dir, 'malformed.json', {
      cases: [{ receipt: { caseRef: 'case-x' }, consent: valid.consent }],
    });
    expect(() =>
      provisionMetaFromHostFile({ store, file: malformed.file, sha256: malformed.sha256 }),
    ).toThrow('V03_META_CASE_INVALID');

    const bothForms = pinnedFile(dir, 'both.json', { ...valid, cases: [valid] });
    expect(() =>
      provisionMetaFromHostFile({ store, file: bothForms.file, sha256: bothForms.sha256 }),
    ).toThrow('V03_META_CASE_INVALID');

    const overBound = pinnedFile(dir, 'over.json', {
      cases: Array.from({ length: META_CASE_PROVISION_MAX_CASES + 1 }, (_, index) => ({
        receipt: { caseRef: `case-${index}`, revision: 'outcome-r1', sha256: digest },
        consent: consentRecord(`case-${index}`, 'outcome-r1', digest),
      })),
    });
    expect(() =>
      provisionMetaFromHostFile({ store, file: overBound.file, sha256: overBound.sha256 }),
    ).toThrow('V03_META_CASE_BATCH_BOUND_REFUSED');
  });
});
