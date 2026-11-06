/**
 * R02-E production shipping composition journey — the REAL production entry
 * (`createProductionV03Gateway`) over the installed public v0.10.3 SDK
 * consumer, the real operator manifest, the durable Guided Case, the SQLite
 * K doc store, the durable cloud request journal and the durable
 * Host-issued submit-reference ledger.
 *
 * Zero paid calls / zero physical effects: the trusted T04 binding is
 * installed with a controlled interpreter double whose status/interpretGoal
 * follow the real frozen port; the single-sender/replay/no-retry invariants
 * are asserted against the REAL Kernel gate.
 *
 * Reference-binding negatives (preflight repair): valid-shaped FORGED,
 * EXPIRED and CROSS-CASE reference submissions must be refused BEFORE the
 * Kernel facade is entered — zero K doc writes, zero cloud-journal writes
 * and zero T04 interpreter calls for every unauthenticated submission.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { DatabaseSync } from 'node:sqlite';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createProductionV03Gateway } from '../../../../apps/control-api/src/v03/composition-production.ts';
import { HostGuidedService } from '../../../../packages/domain-host/src/guided/host-guided-service.ts';
import { consumerDir } from '../r02-a-build/ensure-consumer.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../../..');
const t11Fixtures = resolve(repoRoot, 'tests/integration/v03/t11-runtime/fixtures');
const shunModules = resolve(repoRoot, 'packages/domain-app/src/activation/modules');

const sha256Hex = (value: string): string =>
  createHash('sha256').update(value, 'utf8').digest('hex');

function readPinned(name: string): string {
  const source = readFileSync(join(t11Fixtures, name), 'utf8');
  const receipts = new Map<string, string>();
  for (const line of readFileSync(join(t11Fixtures, 'SHA256SUMS.txt'), 'utf8').split(/\r?\n/)) {
    const match = line.match(/^([0-9a-f]{64})\s+\*?(.+)$/);
    const [, digest, fileName] = match ?? [];
    if (typeof digest === 'string' && typeof fileName === 'string') {
      receipts.set(fileName.trim(), digest);
    }
  }
  const expected = receipts.get(name);
  if (expected !== undefined) expect(sha256Hex(source)).toBe(expected);
  return source;
}

function standardBundle(): string {
  const sdk = readPinned('standard-sdk-v1.mjs');
  const router = readPinned('workflow-router.mjs');
  const routerBody = router.replace(/^export /gm, '');
  return `${sdk}
// R02-E BUILD-style vendored bundle: the pure Standard WorkflowRouter.
const __dhv10RouterBundle = (() => {
${routerBody}
return { routeWorkflowIntent };
})();
export const routeWorkflowIntent = __dhv10RouterBundle.routeWorkflowIntent;
`;
}

/** Assemble the SHUN_V03_BUILD_FILE through the REAL operator script. */
function assembleBuild(dir: string): { buildFile: string; buildFileSha256: string } {
  const kernel = readPinned('kernel-mechanism-v1.mjs');
  const standard = standardBundle();
  const business = readFileSync(join(shunModules, 'business-goal.mjs'), 'utf8');
  const capability = readFileSync(join(shunModules, 'capability-llm.mjs'), 'utf8');
  const kernelFile = join(dir, 'kernel.mjs');
  const standardFile = join(dir, 'standard-bundle.mjs');
  writeFileSync(kernelFile, kernel);
  writeFileSync(standardFile, standard);
  const spec = {
    appId: 'shun-v03-goal',
    audience: 'operator-local',
    buildId: 'shun-v0.3-r02e-production',
    targetProfile: 'node24-esm/1',
    routes: [
      {
        intentId: 'goal-interpret',
        operationId: 'interpretGoal',
        capabilityId: 'llm',
        handlerId: 'interpretGoal',
      },
    ],
    hardBudget: { maxStepsPerTurn: 8, maxWorkUnitsPerTurn: 64 },
    modules: [
      {
        provenance: 'PUBLIC_DOMAIN_PACKAGE_V0103',
        sourceFile: kernelFile,
        sourceSha256: sha256Hex(kernel),
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
        sourceSha256: sha256Hex(standard),
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
      {
        provenance: 'SHUN_TRUSTED_DOMAIN_PACKAGE',
        sourceFile: join(shunModules, 'business-goal.mjs'),
        sourceSha256: sha256Hex(business),
        module: {
          packageId: 'shun.business.goal@v0.3.0',
          role: 'business',
          abiVersion: 'v08-business-abi/1',
          endpoint: 'business-policy',
          dependencies: [],
          provides: ['intent:goal-interpret'],
          requires: [],
        },
      },
      {
        provenance: 'SHUN_TRUSTED_DOMAIN_PACKAGE',
        sourceFile: join(shunModules, 'capability-llm.mjs'),
        sourceSha256: sha256Hex(capability),
        module: {
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
        },
      },
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
  expect(assembler.status, `assembler failed: ${assembler.stderr?.slice(0, 2000)}`).toBe(0);
  return {
    buildFile,
    buildFileSha256: (JSON.parse(assembler.stdout) as { sha256: string }).sha256,
  };
}

interface InterpreterState {
  calls: { goalText: string; deadlineUnixMs: number }[];
  nextResult: 'proposal' | 'consent-declined';
}

/** Durable-effect evidence counters (K doc store / cloud request journal). */
function sqliteRowCount(file: string, table: string): number {
  const db = new DatabaseSync(file);
  try {
    const row = db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as
      | { count: number }
      | undefined;
    return row?.count ?? -1;
  } finally {
    db.close();
  }
}

describe('R02-E shipping production gateway over the real SDK consumer', () => {
  let dir: string;
  let guided: HostGuidedService;
  let interpreter: InterpreterState;
  let gateway: Awaited<ReturnType<typeof createProductionV03Gateway>>;
  let caseId: string;
  let issuedRefs: { currentnessRef: string; approvalRef: string };
  let kDocsFile: string;
  let cloudJournalFile: string;
  /** Real advancing clock plus a controllable offset (reference-expiry test). */
  let clockOffsetMs = 0;
  let issuedAtRealMs = 0;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'shun-r02e-'));
    const now = Date.now();
    // The trusted Host stages a CURRENT Guided Case; the production gateway
    // binds every submit to exactly this live step identity.
    guided = new HostGuidedService(join(dir, 'guided.sqlite'));
    const staged = guided.stageTrustedSelection({
      observation: {
        schema: 'shun.guided.host-observation.v1',
        taskId: 'task-r02e-goal',
        journeyId: 'journey-r02e',
        sourceRef: 'host:obs:r02e',
        revision: 'r02e',
        caseRef: { snapshotId: 'snap-r02e', digest: 'b'.repeat(64) },
        observedAtUnixMs: now - 1_000,
        validUntilUnixMs: now + 3_600_000,
        evidenceRefs: ['host:scope:r02e'],
        selectedRootRef: 'host:root:r02e',
      },
      semanticSelection: {
        status: 'SELECTED',
        semantic: {
          schema: 'shun.goal-semantic.v1',
          taskId: 'task-r02e-goal',
          goalContract: { taskId: 'task-r02e-goal', objective: 'summarize selected folder' },
          capabilityId: 'system.storage.diagnose_bounded_action',
          capabilityRevision: 'r1',
          provenance: { resolverRevision: 'resolver-v03' },
        },
      },
      scope: { status: 'KNOWN', selectedRootRef: 'host:root:r02e' },
    });
    expect(staged.status).toBe('CURRENT');
    if (staged.status !== 'CURRENT') throw new Error('staging failed');
    caseId = staged.step.taskId;

    interpreter = { calls: [], nextResult: 'proposal' };
    const { buildFile, buildFileSha256 } = assembleBuild(dir);
    kDocsFile = join(dir, 'k-docs.sqlite');
    cloudJournalFile = join(dir, 'cloud-journal.sqlite');
    gateway = await createProductionV03Gateway({
      buildFile,
      buildFileSha256,
      sdkConsumerDir: consumerDir,
      kDocDatabaseFile: kDocsFile,
      deploymentRoot: consumerDir,
      tenantId: 'tenant:shun-v03',
      deployedAppId: 'deployment:shun-v03-r02e',
      selectedCase: guided,
      llm: {
        interpreter: {
          status: () => ({
            enabled: true,
            provider: 'deepseek' as const,
            model: 'deepseek-flash' as const,
            osConsentRequired: true as const,
          }),
          interpretGoal: async (input: { goalText: string; deadlineUnixMs: number }) => {
            interpreter.calls.push({
              goalText: input.goalText,
              deadlineUnixMs: input.deadlineUnixMs,
            });
            if (interpreter.nextResult === 'consent-declined') {
              return { ok: false, code: 'CONSENT_DECLINED' };
            }
            return {
              ok: true,
              taskId: 'cloud-task-r02e',
              status: 'UNTRUSTED_REMOTE_PROPOSAL',
              proposalText: '{"proposalId":"r02e-proposal"}',
              model: 'deepseek-flash',
              costState: 'UNKNOWN_COST',
              executed: false,
            };
          },
        },
        journalFile: cloudJournalFile,
        configuredMaxOutputTokens: 256,
      },
      approvalLedgerFile: join(dir, 'submit-references.sqlite'),
      now: () => Date.now() + clockOffsetMs,
    });
    // Trusted process-side issuance: the ONLY way submit references exist.
    const issued = gateway.issueSubmitReferences();
    expect(issued.status).toBe('ISSUED');
    if (issued.status !== 'ISSUED') throw new Error('reference issuance failed');
    expect(issued.caseId).toBe(caseId);
    issuedRefs = { currentnessRef: issued.currentnessRef, approvalRef: issued.approvalRef };
    issuedAtRealMs = Date.now();
  });

  afterAll(() => {
    try {
      gateway?.dispose();
    } catch {
      /* already disposed */
    }
    guided?.close();
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        rmSync(dir, { recursive: true, force: true });
        break;
      } catch {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
      }
    }
  });

  function submission(
    submitCaseId: string,
    goal: string,
    refs: { currentnessRef: string; approvalRef: string } = issuedRefs,
  ): Record<string, unknown> {
    return {
      caseId: submitCaseId,
      request: {
        taskId: submitCaseId,
        goal,
        objects: [],
        constraints: {},
        policyContext: {
          privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
          environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
        },
      },
      currentnessRef: refs.currentnessRef,
      approvalRef: refs.approvalRef,
    };
  }

  it('boots the production composition with the real SDK closure', () => {
    expect(gateway.subjectDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it('positive: live Case submit with Host-issued references reaches COMPLETED', async () => {
    const kDocsBefore = sqliteRowCount(kDocsFile, 'k_v10_docs');
    const receipt = await gateway.gateway.submit(
      submission(caseId, 'Summarize the selected folder.'),
    );
    expect(receipt.status).toBe('COMPLETED');
    if (receipt.status !== 'COMPLETED') return;
    const effect = (receipt.result as { admitted: { effects: Array<Record<string, unknown>> } })
      .admitted.effects[0];
    const llm = (effect?.output as { outcome: { output: { status: string; text: string } } })
      .outcome.output;
    expect(llm.status).toBe('completed');
    expect(llm.text).toBe('{"proposalId":"r02e-proposal"}');
    expect(interpreter.calls).toHaveLength(1);
    // The exact Host-minted disclosure reached the only sender entry.
    expect(interpreter.calls[0]?.goalText).toBe('Summarize the selected folder.');
    // A real K send leaves durable K doc writes — the counter the negatives
    // below rely on to prove ZERO Kernel sends.
    expect(sqliteRowCount(kDocsFile, 'k_v10_docs')).toBeGreaterThan(kDocsBefore);
  });

  it('re-submitting identical content is refused by the K non-idempotency fence, never re-sent', async () => {
    const receipt = await gateway.gateway.submit(
      submission(caseId, 'Summarize the selected folder.'),
    );
    // The real Kernel refuses re-entry of the same content-derived effect
    // idempotency key; the journaled result is never re-sent or re-minted.
    expect(receipt.status).toBe('KERNEL_REFUSED');
    expect(interpreter.calls).toHaveLength(1);
  });

  it('a submit for a foreign/stale Case is refused before any K send', async () => {
    const receipt = await gateway.gateway.submit(
      submission('case-not-staged', 'Read something else.'),
    );
    expect(receipt).toMatchObject({ status: 'KERNEL_REFUSED', sendCalls: 1 });
    expect(interpreter.calls).toHaveLength(1);
  });

  it('consent decline surfaces as a truthful non-success receipt, no retry', async () => {
    interpreter.nextResult = 'consent-declined';
    // A DIFFERENT goal mints a fresh requestId so the journal reserves anew.
    const receipt = await gateway.gateway.submit(
      submission(caseId, 'Summarize again with decline.'),
    );
    expect(receipt.status).toBe('KERNEL_REFUSED');
    expect(interpreter.calls).toHaveLength(2);
    expect(interpreter.calls[1]?.goalText).toBe('Summarize again with decline.');
  });

  it('hostile submission shape is refused pre-send with zero journal risk', async () => {
    const receipt = await gateway.gateway.submit({ ...submission(caseId, 'x'), extra: true });
    expect(receipt).toMatchObject({ status: 'REFUSED', sendCalls: 0, journalEntries: 0 });
    expect(interpreter.calls).toHaveLength(2);
  });

  it('FORGED valid-shaped references are refused pre-Kernel: zero sends, zero journals, zero T04', async () => {
    const kDocs = sqliteRowCount(kDocsFile, 'k_v10_docs');
    const journal = sqliteRowCount(cloudJournalFile, 'cloud_request_journal');
    const t04 = interpreter.calls.length;
    const receipt = await gateway.gateway.submit(
      submission(caseId, 'Summarize with forged references.', {
        currentnessRef: `shun.currentness.v1/${'a'.repeat(48)}`,
        approvalRef: `shun.approval.v1/${'b'.repeat(48)}`,
      }),
    );
    // Grammar-valid but never issued by the trusted Host: the composition
    // refuses before the Kernel facade — no K doc write, no cloud-journal
    // reservation, no interpreter call, no egress.
    expect(receipt).toMatchObject({ status: 'KERNEL_REFUSED', sendCalls: 1 });
    expect(interpreter.calls).toHaveLength(t04);
    expect(sqliteRowCount(kDocsFile, 'k_v10_docs')).toBe(kDocs);
    expect(sqliteRowCount(cloudJournalFile, 'cloud_request_journal')).toBe(journal);
  });

  it('EXPIRED Host-issued references are refused pre-Kernel while the Case step is still live', async () => {
    const kDocs = sqliteRowCount(kDocsFile, 'k_v10_docs');
    const journal = sqliteRowCount(cloudJournalFile, 'cloud_request_journal');
    const t04 = interpreter.calls.length;
    // References live strictly inside the Guided step window (composition
    // caps the TTL at 270s while the step lives 300s): advance the trusted
    // clock to exactly past the reference validity but NOT past the step
    // validity (the offset is anchored at the real issuance instant, so real
    // test elapsed time cannot break either bound).
    try {
      clockOffsetMs += issuedAtRealMs + 270_001 - Date.now();
      const receipt = await gateway.gateway.submit(
        submission(caseId, 'Summarize with expired references.'),
      );
      expect(receipt).toMatchObject({ status: 'KERNEL_REFUSED', sendCalls: 1 });
      expect(interpreter.calls).toHaveLength(t04);
      expect(sqliteRowCount(kDocsFile, 'k_v10_docs')).toBe(kDocs);
      expect(sqliteRowCount(cloudJournalFile, 'cloud_request_journal')).toBe(journal);
    } finally {
      clockOffsetMs = 0;
    }
  });

  it('CROSS-CASE references (issued for another Case) are refused pre-Kernel', async () => {
    const kDocs = sqliteRowCount(kDocsFile, 'k_v10_docs');
    const journal = sqliteRowCount(cloudJournalFile, 'cloud_request_journal');
    const t04 = interpreter.calls.length;
    // The control positive at the end must reach the trusted proposal path.
    interpreter.nextResult = 'proposal';
    // Consume the live step (trusted Host observation receipt, REFUSE), then
    // stage a genuinely NEW Case B — the attacker presents Case A's still
    // CURRENT issued references under Case B's live submit.
    const step = guided.state().currentStep;
    expect(step).toBeTruthy();
    if (!step) return;
    const consumed = guided.decide({
      kind: 'USER_DECISION_RELAY',
      humanApproval: true,
      authorityClaimed: false,
      decision: 'REFUSE',
      relayedVia: '/api',
      stepId: step.stepId,
      stepDigest: step.templateRef.digest,
      caseRef: step.caseRef,
      outcome: {
        schema: 'shun.guided.step-outcome.v1',
        journeyId: step.journeyId,
        taskId: step.taskId,
        stepId: step.stepId,
        caseRef: step.caseRef,
        event: 'OBSERVATION_RECEIPT',
        source: 'HOST',
        sourceRef: 'host:obs:r02e',
        answers: [],
        evidenceRefs: ['host:scope:r02e'],
        occurredAtUnixMs: Date.now(),
      },
    });
    expect(consumed.status).toBe('RECORDED');
    const stagedB = guided.stageTrustedSelection({
      observation: {
        schema: 'shun.guided.host-observation.v1',
        taskId: 'task-r02e-goal-b',
        journeyId: 'journey-r02e',
        sourceRef: 'host:obs:r02e-b',
        revision: 'r02e-b',
        caseRef: { snapshotId: 'snap-r02e-b', digest: 'd'.repeat(64) },
        observedAtUnixMs: Date.now() - 1_000,
        validUntilUnixMs: Date.now() + 3_600_000,
        evidenceRefs: ['host:scope:r02e-b'],
        selectedRootRef: 'host:root:r02e-b',
      },
      semanticSelection: {
        status: 'SELECTED',
        semantic: {
          schema: 'shun.goal-semantic.v1',
          taskId: 'task-r02e-goal-b',
          goalContract: { taskId: 'task-r02e-goal-b', objective: 'summarize second folder' },
          capabilityId: 'system.storage.diagnose_bounded_action',
          capabilityRevision: 'r1',
          provenance: { resolverRevision: 'resolver-v03' },
        },
      },
      scope: { status: 'KNOWN', selectedRootRef: 'host:root:r02e-b' },
    });
    expect(stagedB.status).toBe('CURRENT');
    if (stagedB.status !== 'CURRENT') return;
    const crossCase = await gateway.gateway.submit(
      submission('task-r02e-goal-b', 'Summarize the second folder.', issuedRefs),
    );
    expect(crossCase).toMatchObject({ status: 'KERNEL_REFUSED', sendCalls: 1 });
    expect(interpreter.calls).toHaveLength(t04);
    expect(sqliteRowCount(kDocsFile, 'k_v10_docs')).toBe(kDocs);
    expect(sqliteRowCount(cloudJournalFile, 'cloud_request_journal')).toBe(journal);
    // Control: Case B's OWN freshly issued references complete normally —
    // the refusal above was reference authentication, not a broken seam.
    const refsB = gateway.issueSubmitReferences();
    expect(refsB.status).toBe('ISSUED');
    if (refsB.status !== 'ISSUED') return;
    expect(refsB.caseId).toBe('task-r02e-goal-b');
    const genuineB = await gateway.gateway.submit(
      submission(
        'task-r02e-goal-b',
        'Summarize the second folder.',
        { currentnessRef: refsB.currentnessRef, approvalRef: refsB.approvalRef },
      ),
    );
    expect(genuineB.status).toBe('COMPLETED');
    expect(interpreter.calls).toHaveLength(t04 + 1);
  });
});
