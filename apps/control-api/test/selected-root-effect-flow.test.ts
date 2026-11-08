// U05-B2 — the composed selected-root effect vertical slice.
//
// REAL here: the durable HostGuidedService journey (select-root → INSPECT →
// read-only preview → REVIEW_EFFECT human APPROVE), the FolderSelectionHost
// with its private native identity ledger, the REAL ActionController R2 route
// over the REAL ShunStore AuthorizationAuthority (HMAC-signed grant, current
// policy), the real Guided approval adapter, the real executor authority
// store writers (FilePlanSource/FileGrantSource/FileCurrentnessSource shapes)
// and the real K-journey result classification.
//
// INJECTED (zero real effects, zero paid calls): the Windows folder picker
// native port (fake identity), the storage metadata walker and the selected-K
// facade — the facade replays the exact K journey contract (admitted
// envelopes) without minting a permit. The real selected-K Permit chain is
// proven separately by the t11 real-kernel-permit suite, and the real
// effect-time Host recheck chain by the domain-host selected-root binding
// suite. No real filesystem write happens anywhere in this file.

import { randomUUID } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync as writeFileRaw,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, win32 } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { ActionController, AuthorizationAuthority } from '@shun/authorization';
import {
  ActionPlanSchema,
  type CurrentAuthorityState,
  computePlanHash,
  validateGrantPresentation,
} from '@shun/contracts';
import { ShunStore, ShunStoreAuthorizationAdapter } from '@shun/store';
import { afterEach, describe, expect, it } from 'vitest';
import { HostGuidedService } from '../../../packages/domain-host/src/guided/host-guided-service.ts';
import { createWindowsEffectHost } from '../../../packages/domain-host/src/windows/effect-host.ts';
import { createWindowsOsAuthorityPort } from '../../../packages/domain-host/src/windows/effect-host-binding.ts';
import {
  FileCurrentnessSource,
  FileGrantSource,
  FilePlanSource,
  hmacGrantIntegrityVerifier,
  resolveGrantHmacKeyFile,
  verifyGrantWithHmac,
  writeCurrentAuthority,
  writeGrantHmacKey,
  writeGrantRecord,
  writePlanRecord,
} from '../../../packages/executor-windows/src/trusted-store.ts';
import { SqliteHostSubmitReferenceLedger } from '../src/v03/composition-approval.ts';
import { classifyJourneyKernelResult } from '../src/v03/composition-journeys.ts';
import {
  createProductionFolderSelectionHost,
  FolderSelectionHost,
} from '../src/v03/folder-selection-host.ts';
import {
  createGuidedReviewApprovalPort,
  createSelectedRootEffectSubmit,
  deriveSelectedRootEffect,
  SELECTED_ROOT_JOURNAL_FILENAME,
  type SelectedRootEffectAuthority,
  type SelectedRootEffectSubmitReceipt,
} from '../src/v03/selected-root-effect-flow.ts';

const NOW = 1_900_000_000_000;
const identity = { volumeSerial: '1a2b3c4d', fileId: '0123456789abcdef' };
const POLICY = 'shun.selected-root-effect.policy-v1';
const TASK = 'task-b2-effect';
const JOURNEY = 'journey-b2-effect';
const ISSUANCE_SECRET = 'issuance-secret-b2';
const INTEGRITY_SECRET = 'integrity-secret-b2';

function evidence(root: string, now: number) {
  return {
    observedAt: new Date(now).toISOString(),
    roots: [root],
    directories: [
      {
        path: join(root, 'Documents'),
        bytes: 10,
        files: 1,
        lastModifiedMs: 1_700_000_000_000,
        inaccessibleEntries: [],
      },
    ],
    rootFiles: [{ path: join(root, 'root.txt'), bytes: 5 }],
    totalBytes: 15,
  };
}

interface Fixture {
  readonly directory: string;
  readonly root: string;
  readonly guided: HostGuidedService;
  readonly host: FolderSelectionHost;
  readonly references: SqliteHostSubmitReferenceLedger;
  readonly authorityDir: string;
  readonly submit: (raw: unknown) => Promise<SelectedRootEffectSubmitReceipt>;
  readonly facade: {
    sends: unknown[];
    respond: (sendCount: number) => unknown;
  };
  readonly hasPlanRecord: (planHash: string) => boolean;
  readonly reviewStepId: () => string;
  readonly setRootDrift: (enabled: boolean) => void;
  readonly advanceClock: (deltaMs: number) => void;
  readonly now: () => number;
  readonly cleanup: () => void;
}

/**
 * Drives the REAL guided journey to the durable human APPROVE terminal and
 * wires the REAL R2 authority stack + flow. `approved: false` stops right
 * before the human decision (approval-required negatives).
 */
async function createFixture(
  options: { approved?: boolean; respond?: (sendCount: number) => unknown } = {},
): Promise<Fixture> {
  const directory = mkdtempSync(join(tmpdir(), 'shun-b2-effect-'));
  const root = join(directory, 'selected-root');
  mkdirSync(root);
  mkdirSync(join(root, 'Documents'));
  writeFileSync(join(root, 'root.txt'), 'x');
  let now = NOW;
  const clock = (): number => now;
  const guided = new HostGuidedService(join(directory, 'guided.sqlite'), clock);
  let rootDrift = false;
  const host = new FolderSelectionHost({
    guided,
    databaseFile: join(directory, 'folder-selection.sqlite'),
    clock,
    native: {
      pickFolder: async () => ({
        status: 'SELECTED' as const,
        path: root,
        displayName: 'Documents',
        identity,
      }),
      inspectFolder: () => ({
        ...(rootDrift ? { ...identity, fileId: 'ffffffffffffffff' } : identity),
        isDirectory: true,
        isReparsePoint: false,
        isNetworkPath: false,
        isVolumeRoot: false,
      }),
      acquireDirectoryLease: () => ({
        leaseId: 'a'.repeat(32),
        directory: {
          ...identity,
          isDirectory: true,
          isReparsePoint: false,
          isNetworkPath: false,
          isVolumeRoot: false,
        },
      }),
      verifyDirectoryLease: () => ({
        ...identity,
        isDirectory: true,
        isReparsePoint: false,
        isNetworkPath: false,
        isVolumeRoot: false,
      }),
      releaseDirectoryLease: () => {},
      directoryLeasePath: () => root,
    },
    storage: {
      resolveScope: async (_volume, declared) => ({ roots: [...declared.roots] }),
      observeStorage: async (scope) => evidence(scope.roots[0] as string, clock()),
    },
  });
  // The REAL guided journey: select-root ASK → INSPECT → preview → REVIEW_EFFECT.
  const staged = guided.stageTrustedSelection({
    observation: {
      schema: 'shun.guided.host-observation.v1',
      taskId: TASK,
      journeyId: JOURNEY,
      sourceRef: 'host:obs:b2-effect',
      revision: 'b2-effect-r1',
      caseRef: { snapshotId: 'snap-b2-effect', digest: 'c'.repeat(64) },
      observedAtUnixMs: clock() - 1_000,
      validUntilUnixMs: clock() + 3_600_000,
      evidenceRefs: ['host:scope:b2-effect'],
    },
    semanticSelection: {
      status: 'SELECTED',
      semantic: {
        schema: 'shun.goal-semantic.v1',
        taskId: TASK,
        goalContract: { taskId: TASK, objective: 'journal the selected folder metadata' },
        capabilityId: 'system.storage.diagnose_bounded_action',
        capabilityRevision: 'r1',
        provenance: { resolverRevision: 'resolver-v03' },
      },
    },
    scope: { status: 'KNOWN' },
  });
  if (staged.status !== 'CURRENT') throw new Error(`fixture staging failed: ${staged.code}`);
  now += 1_000;
  const selected = await host.selectRoot();
  if (selected.status !== 'SELECTED')
    throw new Error(`fixture selection failed: ${JSON.stringify(selected)}`);
  now += 1_000;
  const selectStep = guided.state().currentStep;
  if (!selectStep) throw new Error('fixture select step missing');
  const outcome = {
    schema: 'shun.guided.step-outcome.v1',
    journeyId: selectStep.journeyId,
    taskId: selectStep.taskId,
    stepId: selectStep.stepId,
    caseRef: selectStep.caseRef,
    event: 'USER_SUBMIT',
    source: 'USER',
    sourceRef: 'ui:b2-session',
    answers: [{ fieldId: 'selectedRoot', value: selected.selectionRef }],
    evidenceRefs: [],
    occurredAtUnixMs: clock(),
  };
  const relay = {
    kind: 'USER_DECISION_RELAY',
    authorityClaimed: false,
    relayedVia: '/api',
    decision: 'ANSWER',
    humanApproval: false,
    stepId: selectStep.stepId,
    stepDigest: selectStep.templateRef.digest,
    caseRef: selectStep.caseRef,
    outcome,
  };
  if (host.validateSelectionAnswer(relay, selectStep) !== null) {
    throw new Error('fixture selection answer refused');
  }
  const recorded = guided.decide(relay);
  if (recorded.status !== 'RECORDED') throw new Error(`fixture answer refused: ${recorded.code}`);
  const after = host.afterSelectionRecorded(relay, selectStep, recorded);
  if (after.status !== 'RECORDED') throw new Error(`fixture post-answer refused: ${after.code}`);
  now += 1_000;
  const observed = await host.observeCurrentSelectedFolder();
  if (!observed.ok) throw new Error(`fixture observation failed: ${observed.code}`);
  now += 1_000;
  const previewStaged = host.stageReadOnlyPlanPreview();
  if (previewStaged.status !== 'STAGED') {
    throw new Error(`fixture preview staging failed: ${previewStaged.code}`);
  }
  now += 1_000;
  const reviewStepId = previewStaged.stepId;
  if (options.approved !== false) {
    const reviewStep = guided.state().currentStep;
    if (!reviewStep) throw new Error('fixture review step missing');
    const approveOutcome = {
      schema: 'shun.guided.step-outcome.v1',
      journeyId: reviewStep.journeyId,
      taskId: reviewStep.taskId,
      stepId: reviewStep.stepId,
      caseRef: reviewStep.caseRef,
      event: 'USER_SUBMIT',
      source: 'USER',
      sourceRef: 'ui:b2-session',
      answers: [{ fieldId: 'continue', value: 'continue-to-independent-approval' }],
      evidenceRefs: [],
      occurredAtUnixMs: clock(),
    };
    const approveRelay = {
      kind: 'USER_DECISION_RELAY',
      authorityClaimed: false,
      relayedVia: '/api',
      decision: 'APPROVE',
      humanApproval: true,
      stepId: reviewStep.stepId,
      stepDigest: reviewStep.templateRef.digest,
      caseRef: reviewStep.caseRef,
      outcome: approveOutcome,
    };
    const approved = guided.decide(approveRelay);
    if (approved.status !== 'RECORDED')
      throw new Error(`fixture approval refused: ${approved.code}`);
  }
  // The REAL R2 authority stack (same assembly as the production composition).
  const authorityDir = join(directory, 'authority');
  const policyStore = new ShunStore({ file: join(directory, 'policy.sqlite') });
  const adapter = new ShunStoreAuthorizationAdapter(policyStore);
  const clockIso = (): string => new Date(clock()).toISOString();
  const authority = new AuthorizationAuthority({
    state: adapter,
    grants: adapter,
    integritySecret: INTEGRITY_SECRET,
    issuanceSecret: ISSUANCE_SECRET,
    clock: clockIso,
    // Same frozen K→C grammar coherence as the production composition.
    newGrantId: () => `grant-${randomUUID()}`,
  });
  await adapter.compareAndSaveAuthorityRecord(
    {
      authorityId: 'shun.local.selected-root-effect',
      authorityRevision: 'r1',
      updatedAt: clockIso(),
      policyInitialized: true,
      priorAuthorityRevisions: [],
    },
    null,
  );
  await adapter.compareAndSavePolicySnapshot(
    {
      policySnapshotRevision: POLICY,
      status: 'ACTIVE',
      authorityId: 'shun.local.selected-root-effect',
      authorityRevision: 'r1',
      revokedGrantIds: [],
      priorRevisions: [],
      rules: [],
      riskGuards: [],
      updatedAt: clockIso(),
    },
    null,
  );
  writeGrantHmacKey(authorityDir, Buffer.from(INTEGRITY_SECRET, 'utf8').toString('base64'));
  const references = new SqliteHostSubmitReferenceLedger(
    join(directory, 'submit-references.sqlite'),
    clock,
  );
  const issued = references.issue({
    caseId: TASK,
    stepId: reviewStepId,
    validUntilUnixMs: clock() + 270_000,
  });
  if (issued.status !== 'ISSUED') throw new Error(`fixture references refused: ${issued.code}`);
  const plansDir = join(authorityDir, 'plans');
  const grantsDir = join(authorityDir, 'grants');
  let sendCount = 0;
  const sends: unknown[] = [];
  const facade = {
    sends,
    respond:
      options.respond ??
      ((count: number) => ({
        status: 'admitted',
        admitted: {
          effects: [
            {
              effectId: `turn:${TASK}:instance-1/effect/${count}`,
              disposition: 'executed',
              output: {
                phase: 'terminal',
                externalRef: `effect-${count}`,
                outcome: {
                  ok: true,
                  output: {
                    actionId: 'windows-fs-write-selected-root-journal',
                    terminal: 'SUCCEEDED',
                    recoveryClassification: 'COMPLETED_VERIFIED',
                    postStateVerified: true,
                  },
                },
              },
            },
          ],
        },
      })),
  };
  const effectAuthority: SelectedRootEffectAuthority = {
    async authorizePlan({ plan, expect }) {
      const controller = new ActionController({
        authority,
        policyState: adapter,
        approvals: createGuidedReviewApprovalPort({ guided, expect }),
        issuanceSecret: ISSUANCE_SECRET,
        clock: clockIso,
      });
      const authorized = await controller.authorizePlan({ plan });
      if (!authorized.ok) return authorized;
      return {
        ok: true,
        plan: authorized.authorization.plan,
        grants: authorized.authorization.grants,
      };
    },
    async readCurrentAuthority() {
      const state = await authority.currentAuthority();
      if (state.kind !== 'CURRENT') throw new Error('authority unresolved');
      return state;
    },
    policySnapshotRevision: () => POLICY,
    writePlanRecord: (plan) => writePlanRecord(plansDir, plan),
    writeGrantRecord: (grant) => writeGrantRecord(grantsDir, grant),
    writeCurrentAuthority: (state: CurrentAuthorityState) =>
      writeCurrentAuthority(authorityDir, state),
    hasPlanRecord: (planHash) => existsSync(join(plansDir, `${planHash}.json`)),
    hmacKeyCoherent: () => {
      try {
        return (
          readFileSync(resolveGrantHmacKeyFile(authorityDir), 'utf8').trim() ===
          Buffer.from(INTEGRITY_SECRET, 'utf8').toString('base64')
        );
      } catch {
        return false;
      }
    },
  };
  const submit = createSelectedRootEffectSubmit({
    host,
    references,
    facade: {
      send: async (payload: unknown) => {
        sendCount += 1;
        sends.push(payload);
        return facade.respond(sendCount);
      },
    },
    classifyJourneyKernelResult,
    now: clock,
    authority: effectAuthority,
  });
  return {
    directory,
    root,
    guided,
    host,
    references,
    authorityDir,
    submit,
    facade,
    hasPlanRecord: (planHash) => existsSync(join(plansDir, `${planHash}.json`)),
    reviewStepId: () => reviewStepId,
    setRootDrift: (enabled: boolean) => {
      rootDrift = enabled;
    },
    advanceClock: (deltaMs: number) => {
      now += deltaMs;
    },
    now: clock,
    cleanup: () => {
      host.close();
      references.close();
      policyStore.close();
      guided.close();
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

function issuedRefs(fixture: Fixture): {
  caseId: string;
  currentnessRef: string;
  approvalRef: string;
} {
  // Re-read the durable pair for the approved step from the ledger.
  const db = new DatabaseSync(join(fixture.directory, 'submit-references.sqlite'), {
    readOnly: true,
  });
  try {
    const row = db
      .prepare(
        "SELECT case_id, currentness_ref, approval_ref FROM host_submit_references WHERE case_id=? AND state='CURRENT'",
      )
      .get(TASK) as { case_id: string; currentness_ref: string; approval_ref: string };
    return {
      caseId: row.case_id,
      currentnessRef: row.currentness_ref,
      approvalRef: row.approval_ref,
    };
  } finally {
    db.close();
  }
}

describe('U05-B2 selected-root effect vertical slice', () => {
  const cleanups: Array<() => void> = [];
  afterEach(() => {
    for (const cleanup of cleanups.splice(0)) cleanup();
  });

  it('completes the approved plan through the real R2 stack with a truthful COMPLETED projection', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const refs = issuedRefs(fixture);
    const receipt = await fixture.submit(refs);
    expect(receipt.status).toBe('COMPLETED');
    expect(receipt.sendCalls).toBe(1);
    expect(receipt.effect).toMatchObject({
      actionRef: 'windows-fs-write-selected-root-journal',
      relativeTarget: SELECTED_ROOT_JOURNAL_FILENAME,
      operation: 'windows.fs.write',
      terminal: 'SUCCEEDED',
      recoveryClassification: 'COMPLETED_VERIFIED',
      postStateVerified: true,
    });
    // The K send is the frozen journey intent with references only.
    expect(fixture.facade.sends[0]).toMatchObject({
      intentType: 'submitWindowsAction',
      instanceKey: TASK,
      input: {
        actionRef: 'windows-fs-write-selected-root-journal',
        taskId: TASK,
      },
    });
    const payload = fixture.facade.sends[0] as { input: { planRef: string; grantRef: string } };
    // The admitted plan record exists at its canonical hash identity and
    // re-derives the same hash byte-for-byte.
    const planFile = join(fixture.authorityDir, 'plans', `${payload.input.planRef}.json`);
    expect(existsSync(planFile)).toBe(true);
    const plan = ActionPlanSchema.parse(JSON.parse(readFileSync(planFile, 'utf8')));
    expect(plan.planHash).toBe(payload.input.planRef);
    expect(computePlanHash(plan)).toBe(plan.planHash);
    // The grant is HMAC-authentic under the executor store's key.
    const grantFile = join(fixture.authorityDir, 'grants', `${payload.input.grantRef}.json`);
    expect(existsSync(grantFile)).toBe(true);
    const grant = JSON.parse(readFileSync(grantFile, 'utf8')) as Parameters<
      typeof verifyGrantWithHmac
    >[1];
    expect(
      verifyGrantWithHmac(
        readFileSync(resolveGrantHmacKeyFile(fixture.authorityDir), 'utf8').trim(),
        grant,
      ),
    ).toBe(true);
    // The current-authority record the effect binding will recheck.
    const current = JSON.parse(
      readFileSync(join(fixture.authorityDir, 'current-authority.json'), 'utf8'),
    ) as CurrentAuthorityState;
    expect(current).toMatchObject({ kind: 'CURRENT', policyStatus: 'ACTIVE' });
    // The durable Host admission binds the plan to the private root identity.
    const targetPath = win32.join(fixture.root, SELECTED_ROOT_JOURNAL_FILENAME);
    expect(
      fixture.host.verifyEffectTimeRootIdentity({
        taskId: TASK,
        planHash: plan.planHash,
        path: targetPath,
      }),
    ).toEqual({ ok: true });
    // No private OS path and no grant material may ever cross the projection.
    const projected = JSON.stringify(receipt);
    expect(projected).not.toContain(fixture.root);
    expect(projected).not.toContain(INTEGRITY_SECRET);
    expect(projected).not.toContain(grant.grantId);
  });

  it('keeps the plan metadata-only: the journal content carries no private path', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const facts = await fixture.host.prepareSelectedRootEffect();
    expect(facts.ok).toBe(true);
    if (!facts.ok) return;
    const derived = deriveSelectedRootEffect({
      facts: facts.facts,
      policySnapshotRevision: POLICY,
    });
    expect(derived.ok).toBe(true);
    if (!derived.ok) return;
    const action = derived.plan.actions[0];
    expect(action?.op).toBe('windows.fs.write');
    const parameters = (action !== undefined ? action.parameters : {}) as { content?: string };
    const content = parameters.content ?? '';
    expect(content).not.toContain(fixture.root);
    expect(derived.descriptor.executionAuthorized).toBe(false);
    expect(derived.descriptor.relativeTarget).toBe(SELECTED_ROOT_JOURNAL_FILENAME);
    // Deterministic identity: the same approved step always re-derives the
    // exact same canonical plan.
    const again = deriveSelectedRootEffect({ facts: facts.facts, policySnapshotRevision: POLICY });
    expect(again.ok && again.plan.planHash === derived.plan.planHash).toBe(true);
  });

  it('P1-03: the proposal descriptor is create-only with an honest undo qualification', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const facts = await fixture.host.prepareSelectedRootEffect();
    expect(facts.ok).toBe(true);
    if (!facts.ok) return;
    const derived = deriveSelectedRootEffect({
      facts: facts.facts,
      policySnapshotRevision: POLICY,
    });
    expect(derived.ok).toBe(true);
    if (!derived.ok) return;
    const { expectedChange, undo } = derived.descriptor;
    // Never "create or update": an existing file is refused, not replaced.
    expect(expectedChange).toContain('create one new');
    expect(expectedChange).not.toContain('create or update');
    expect(expectedChange).toContain('create-only');
    expect(expectedChange).toContain('never created, overwritten or modified');
    // Undo is scoped to what the effect itself created; it never claims to
    // restore content that was never touched.
    expect(undo).toContain('only if this effect executes');
    expect(undo).toContain('no pre-existing content is ever touched');
  });

  it('refuses before any K send when the durable human approval is missing', async () => {
    const fixture = await createFixture({ approved: false });
    cleanups.push(fixture.cleanup);
    const refs = issuedRefs(fixture);
    const receipt = await fixture.submit(refs);
    expect(receipt).toMatchObject({
      status: 'REFUSED',
      code: 'SELECTED_ROOT_EFFECT_APPROVAL_REQUIRED',
      sendCalls: 0,
    });
  });

  it('rejects every malformed or unauthenticated submission with zero sends', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const refs = issuedRefs(fixture);
    for (const body of [
      { ...refs, extra: 1 },
      { caseId: refs.caseId, currentnessRef: refs.currentnessRef },
      { ...refs, currentnessRef: 'shun.currentness.v1/forged' },
      { ...refs, caseId: 'task-other-case' },
      { ...refs, approvalRef: refs.currentnessRef },
      'not-an-object',
      { ...refs, path: 'C:\\evil\\path.txt' },
    ]) {
      const receipt = await fixture.submit(body);
      expect(receipt.status).toBe('REFUSED');
      expect(receipt.sendCalls).toBe(0);
    }
    expect(fixture.facade.sends).toHaveLength(0);
  });

  it('refuses admission when the selected root identity drifted before preparation', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const refs = issuedRefs(fixture);
    // The native identity now reports a different file ID for the same path:
    // the root the human approved is not the root still on disk.
    fixture.setRootDrift(true);
    const receipt = await fixture.submit(refs);
    expect(receipt).toMatchObject({
      status: 'REFUSED',
      code: 'SELECTED_ROOT_EFFECT_ROOT_IDENTITY_STALE',
      sendCalls: 0,
    });
    expect(fixture.facade.sends).toHaveLength(0);
  });

  it('maps an uncertain K outcome to UNKNOWN and never retries it', async () => {
    const fixture = await createFixture({
      respond: () => ({
        status: 'admitted',
        admitted: {
          effects: [
            {
              effectId: 'turn:task/effect/1',
              disposition: 'executed',
              output: { phase: 'running', externalRef: 'effect-1' },
            },
          ],
        },
      }),
    });
    cleanups.push(fixture.cleanup);
    const refs = issuedRefs(fixture);
    const receipt = await fixture.submit(refs);
    expect(receipt).toMatchObject({
      status: 'UNKNOWN',
      code: 'EFFECT_RESULT_UNKNOWN',
      sendCalls: 1,
    });
    const replay = await fixture.submit(refs);
    expect(replay).toMatchObject({
      status: 'REFUSED',
      code: 'SELECTED_ROOT_EFFECT_REPLAY_REFUSED',
      sendCalls: 0,
    });
    expect(fixture.facade.sends).toHaveLength(1);
  });

  it('maps a K refusal and an effect refusal to REFUSED without retry', async () => {
    const refusedFixture = await createFixture({ respond: () => ({ status: 'refused' }) });
    cleanups.push(refusedFixture.cleanup);
    expect(await refusedFixture.submit(issuedRefs(refusedFixture))).toMatchObject({
      status: 'REFUSED',
      code: 'KERNEL_REFUSED',
      sendCalls: 1,
    });
    const effectRefused = await createFixture({
      respond: () => ({
        status: 'admitted',
        admitted: {
          effects: [
            {
              effectId: 'turn:task/effect/1',
              disposition: 'executed',
              output: {
                phase: 'terminal',
                externalRef: 'effect-1',
                outcome: { ok: false, error: { code: 'OS_AUTHORITY_REFUSED', message: 'refused' } },
              },
            },
          ],
        },
      }),
    });
    cleanups.push(effectRefused.cleanup);
    expect(await effectRefused.submit(issuedRefs(effectRefused))).toMatchObject({
      status: 'REFUSED',
      code: 'KERNEL_REFUSED',
      sendCalls: 1,
    });
  });

  it('admits honestly when the K accepted the submission without a terminal effect', async () => {
    const fixture = await createFixture({
      respond: () => ({ status: 'admitted', admitted: { effects: [] } }),
    });
    cleanups.push(fixture.cleanup);
    expect(await fixture.submit(issuedRefs(fixture))).toMatchObject({
      status: 'ADMITTED',
      sendCalls: 1,
    });
  });

  it('fails closed when the executor HMAC key is not the authority secret', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    // The coherence check reads the executor store key file exactly like the
    // production composition: a foreign/rewritten key refuses BEFORE any R2
    // admission or K send.
    writeFileSync(resolveGrantHmacKeyFile(fixture.authorityDir), 'wrong-key', 'utf8');
    const refs = issuedRefs(fixture);
    const receipt = await fixture.submit(refs);
    expect(receipt).toMatchObject({
      status: 'REFUSED',
      code: 'SELECTED_ROOT_EFFECT_AUTHORITY_UNAVAILABLE',
      sendCalls: 0,
    });
    expect(fixture.facade.sends).toHaveLength(0);
  });

  it('expires evidence: a preview past its validity refuses admission', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    fixture.advanceClock(120_000);
    const refs = issuedRefs(fixture);
    const receipt = await fixture.submit(refs);
    expect(receipt.status).toBe('REFUSED');
    expect(receipt.sendCalls).toBe(0);
    expect(fixture.facade.sends).toHaveLength(0);
  });

  it('replays are refused by the durable plan-identity fence after success', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const refs = issuedRefs(fixture);
    expect((await fixture.submit(refs)).status).toBe('COMPLETED');
    expect(await fixture.submit(refs)).toMatchObject({
      status: 'REFUSED',
      code: 'SELECTED_ROOT_EFFECT_REPLAY_REFUSED',
      sendCalls: 0,
    });
    expect(fixture.facade.sends).toHaveLength(1);
  });

  it('keeps production folder selection boot semantics intact (Windows-gated factory)', () => {
    expect(typeof createProductionFolderSelectionHost).toBe('function');
    if (process.platform !== 'win32') {
      // The production factory refuses non-Windows hosts before any I/O.
      expect(() => createProductionFolderSelectionHost(undefined as never)).toThrowError();
    }
  });

  it('refuses a controller rejection mapping through the flow untouched', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const refs = issuedRefs(fixture);
    // Swap the authority for one whose real-controller route refuses.
    const refusing: SelectedRootEffectAuthority = {
      authorizePlan: async () => ({ ok: false, code: 'POLICY_BLOCKED', detail: 'stale policy' }),
      readCurrentAuthority: async () => ({
        kind: 'CURRENT',
        authorityId: 'a',
        authorityRevision: 'r1',
        policySnapshotRevision: POLICY,
        policyStatus: 'ACTIVE',
        revokedGrantIds: [],
      }),
      policySnapshotRevision: () => POLICY,
      writePlanRecord: () => {},
      writeGrantRecord: () => {},
      writeCurrentAuthority: () => {},
      hasPlanRecord: () => false,
      hmacKeyCoherent: () => true,
    };
    const submit = createSelectedRootEffectSubmit({
      host: fixture.host,
      references: fixture.references,
      facade: { send: async () => ({ status: 'admitted', admitted: { effects: [] } }) },
      classifyJourneyKernelResult,
      now: fixture.now,
      authority: refusing,
    });
    expect(await submit(refs)).toMatchObject({
      status: 'REFUSED',
      code: 'POLICY_BLOCKED',
      sendCalls: 0,
    });
  });

  it('binds the guided approval adapter to the exact step identity', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const port = createGuidedReviewApprovalPort({
      guided: fixture.guided,
      expect: {
        taskId: TASK,
        originStepId: fixture.reviewStepId(),
        caseRefJson: JSON.stringify({ snapshotId: 'snap-b2-effect', digest: 'c'.repeat(64) }),
        actionPreviewRef: 'host:preview:unknown',
      },
    });
    const denied = await port.requestApproval({
      taskId: TASK,
      planHash: 'a'.repeat(64),
      summary: 's',
      evidenceRefs: [],
    });
    expect(denied.approved).toBe(false);
  });
});

/**
 * U05-B2 — the REAL Windows Host effect chain composed over the SAME
 * admitted authority records the flow produced: the real
 * `createWindowsEffectHost` adapter, the real extended
 * `createWindowsOsAuthorityPort` (durable currentness + the private
 * selected-root recheck over the REAL FolderSelectionHost), the real
 * FilePlanSource/FileGrantSource/FileCurrentnessSource executor store and
 * the real HMAC grant-presentation validation. Only the physical executor
 * is a recording fake — zero real filesystem effects. The kernel-minted
 * Permit itself is proven by the t11 real-kernel-permit suite; here the
 * adapter-level structural permit grammar stands in for it.
 */
describe('U05-B2 Windows Host effect-time selected-root recheck (real adapter chain)', () => {
  const cleanups: Array<() => void> = [];
  afterEach(() => {
    for (const cleanup of cleanups.splice(0)) cleanup();
  });

  function resolveAuthorization(
    planSource: FilePlanSource,
    grantSource: FileGrantSource,
  ): (input: {
    effectId: string;
    actionRef: string;
    planRef: string;
    grantRef: string;
  }) => unknown {
    return (input) => {
      const plan = planSource.byPlanHash(input.planRef);
      const grant = grantSource.byGrantId(input.grantRef);
      const action = plan?.actions.find((entry) => entry.actionId === input.actionRef);
      if (!plan || !grant || !action) return null;
      return {
        effectId: input.effectId,
        plan,
        grant,
        action: {
          taskId: plan.taskId,
          actionId: action.actionId,
          planHash: plan.planHash,
          policySnapshotRevision: plan.policySnapshotRevision,
          authorizationKind: 'DURABLE_POLICY' as const,
          authorizationRef: grant.grantId,
          expiresAt: grant.expiresAt,
          action,
        },
      };
    };
  }

  function authorizeEffectWith(
    currentness: FileCurrentnessSource,
    verifyIntegrity: ReturnType<typeof hmacGrantIntegrityVerifier>,
    now: () => number,
  ): (input: { plan: unknown; action: unknown; grant: unknown }) => unknown {
    return (input) =>
      validateGrantPresentation({
        grant: input.grant,
        plan: input.plan,
        action: input.action,
        currentAuthority: currentness.read(),
        now: new Date(now()).toISOString(),
        verifyIntegrity,
      });
  }

  function kernelContext(): unknown {
    return {
      capabilityId: 'windows',
      operationId: 'windows.execute',
      effectPermit: {
        effectId: `turn:${TASK}:instance-1/effect/1`,
        durableControlTurnId: `turn:${TASK}:instance-1`,
        attempt: 1,
      },
    };
  }

  async function admittedPayload(
    fixture: Fixture,
  ): Promise<{ actionRef: string; planRef: string; grantRef: string }> {
    const issued = issuedRefs(fixture);
    const receipt = await fixture.submit(issued);
    expect(receipt.status).toBe('COMPLETED');
    const send = fixture.facade.sends[0] as {
      input: { actionRef: string; planRef: string; grantRef: string; taskId: string };
    };
    // The K→C capability payload grammar is EXACTLY {actionRef, planRef,
    // grantRef} (t11 kernel semantics) — the extra journey taskId never
    // crosses the effect boundary.
    return {
      actionRef: send.input.actionRef,
      planRef: send.input.planRef,
      grantRef: send.input.grantRef,
    };
  }

  it('drives the full adapter chain over the admitted plan to a terminal verified receipt', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const payload = await admittedPayload(fixture);
    const currentness = new FileCurrentnessSource(
      join(fixture.authorityDir, 'current-authority.json'),
    );
    const verifyIntegrity = hmacGrantIntegrityVerifier(
      resolveGrantHmacKeyFile(fixture.authorityDir),
    );
    const executions: { effectId: string; actionId: string }[] = [];
    const host = createWindowsEffectHost({
      binding: { capabilityId: 'windows', operationId: 'windows.execute' },
      authorization: {
        resolve: async (input) =>
          resolveAuthorization(
            new FilePlanSource(join(fixture.authorityDir, 'plans')),
            new FileGrantSource(join(fixture.authorityDir, 'grants')),
          )(input),
      },
      actionController: {
        authorizeEffect: async (input) =>
          authorizeEffectWith(currentness, verifyIntegrity, fixture.now)(input),
      },
      osAuthority: createWindowsOsAuthorityPort({
        currentness,
        selectedRoot: {
          recheck: async (input: { effectId: string; action: unknown }) => {
            const action = input.action as {
              taskId: string;
              planHash: string;
              action: { parameters: { path: string } };
            };
            return fixture.host.verifyEffectTimeRootIdentity({
              taskId: action.taskId,
              planHash: action.planHash,
              path: action.action.parameters.path,
            });
          },
        },
      }),
      windows: {
        execute: async (input: { effectId: string; action: { actionId: string } }) => {
          executions.push({ effectId: input.effectId, actionId: input.action.actionId });
          return {
            actionId: input.action.actionId,
            terminal: 'SUCCEEDED',
            sideEffectEvidence: {
              recoveryClassification: 'COMPLETED_VERIFIED',
              postStateVerified: true,
            },
          };
        },
      },
    });
    const envelope = (await host.dispatch(payload, kernelContext())) as {
      phase: string;
      outcome: { ok: boolean; output?: { terminal?: string; postStateVerified?: boolean } };
    };
    expect(envelope.phase).toBe('terminal');
    expect(envelope.outcome.ok).toBe(true);
    expect(envelope.outcome.output).toMatchObject({
      terminal: 'SUCCEEDED',
      postStateVerified: true,
    });
    expect(executions).toHaveLength(1);
    expect(executions[0]).toMatchObject({ actionId: payload.actionRef });
  });

  it('refuses at the OS authority when the root drifted after admission (zero effects)', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const payload = await admittedPayload(fixture);
    fixture.setRootDrift(true);
    const currentness = new FileCurrentnessSource(
      join(fixture.authorityDir, 'current-authority.json'),
    );
    const verifyIntegrity = hmacGrantIntegrityVerifier(
      resolveGrantHmacKeyFile(fixture.authorityDir),
    );
    const executions: { effectId: string; actionId: string }[] = [];
    const host = createWindowsEffectHost({
      binding: { capabilityId: 'windows', operationId: 'windows.execute' },
      authorization: {
        resolve: async (input) =>
          resolveAuthorization(
            new FilePlanSource(join(fixture.authorityDir, 'plans')),
            new FileGrantSource(join(fixture.authorityDir, 'grants')),
          )(input),
      },
      actionController: {
        authorizeEffect: async (input) =>
          authorizeEffectWith(currentness, verifyIntegrity, fixture.now)(input),
      },
      osAuthority: createWindowsOsAuthorityPort({
        currentness,
        selectedRoot: {
          recheck: async (input: { effectId: string; action: unknown }) => {
            const action = input.action as {
              taskId: string;
              planHash: string;
              action: { parameters: { path: string } };
            };
            return fixture.host.verifyEffectTimeRootIdentity({
              taskId: action.taskId,
              planHash: action.planHash,
              path: action.action.parameters.path,
            });
          },
        },
      }),
      windows: {
        execute: async (input: { effectId: string; action: { actionId: string } }) => {
          executions.push({ effectId: input.effectId, actionId: input.action.actionId });
          return {
            actionId: input.action.actionId,
            terminal: 'SUCCEEDED',
            sideEffectEvidence: {
              recoveryClassification: 'COMPLETED_VERIFIED',
              postStateVerified: true,
            },
          };
        },
      },
    });
    const envelope = (await host.dispatch(payload, kernelContext())) as {
      phase: string;
      outcome: { ok: boolean; error?: { code: string } };
    };
    expect(envelope.phase).toBe('terminal');
    expect(envelope.outcome.ok).toBe(false);
    expect(envelope.outcome.error?.code).toBe('OS_AUTHORITY_REFUSED');
    expect(executions).toHaveLength(0);
  });

  it('refuses at the OS authority when the durable currentness moved (zero effects)', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const payload = await admittedPayload(fixture);
    const revoked: CurrentAuthorityState = {
      kind: 'CURRENT',
      authorityId: 'shun.local.selected-root-effect',
      authorityRevision: 'r1',
      policySnapshotRevision: POLICY,
      policyStatus: 'REVOKED',
      revokedGrantIds: [],
    };
    writeCurrentAuthority(fixture.authorityDir, revoked);
    const currentness = new FileCurrentnessSource(
      join(fixture.authorityDir, 'current-authority.json'),
    );
    const verifyIntegrity = hmacGrantIntegrityVerifier(
      resolveGrantHmacKeyFile(fixture.authorityDir),
    );
    const host = createWindowsEffectHost({
      binding: { capabilityId: 'windows', operationId: 'windows.execute' },
      authorization: {
        resolve: async (input) =>
          resolveAuthorization(
            new FilePlanSource(join(fixture.authorityDir, 'plans')),
            new FileGrantSource(join(fixture.authorityDir, 'grants')),
          )(input),
      },
      actionController: {
        authorizeEffect: async (input) =>
          authorizeEffectWith(currentness, verifyIntegrity, fixture.now)(input),
      },
      osAuthority: createWindowsOsAuthorityPort({ currentness }),
      windows: {
        execute: async () => ({ terminal: 'SUCCEEDED', sideEffectEvidence: {} }),
      },
    });
    const envelope = (await host.dispatch(payload, kernelContext())) as {
      phase: string;
      outcome: { ok: boolean; error?: { code: string } };
    };
    expect(envelope.outcome.ok).toBe(false);
    expect(envelope.outcome.error?.code).toBe('OS_AUTHORITY_REFUSED');
  });

  it('refuses a forged grant integrity envelope at the Shun boundary (zero effects)', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const payload = await admittedPayload(fixture);
    const grantFile = join(fixture.authorityDir, 'grants', `${payload.grantRef}.json`);
    const grant = JSON.parse(readFileSync(grantFile, 'utf8')) as {
      integrity: { scheme?: string; value: string };
    };
    grant.integrity = { scheme: 'HMAC_SHA256', value: 'Zm9yZ2Vk' };
    writeFileRaw(grantFile, JSON.stringify(grant, null, 2), 'utf8');
    const currentness = new FileCurrentnessSource(
      join(fixture.authorityDir, 'current-authority.json'),
    );
    const verifyIntegrity = hmacGrantIntegrityVerifier(
      resolveGrantHmacKeyFile(fixture.authorityDir),
    );
    const host = createWindowsEffectHost({
      binding: { capabilityId: 'windows', operationId: 'windows.execute' },
      authorization: {
        resolve: async (input) =>
          resolveAuthorization(
            new FilePlanSource(join(fixture.authorityDir, 'plans')),
            new FileGrantSource(join(fixture.authorityDir, 'grants')),
          )(input),
      },
      actionController: {
        authorizeEffect: async (input) =>
          authorizeEffectWith(currentness, verifyIntegrity, fixture.now)(input),
      },
      osAuthority: createWindowsOsAuthorityPort({ currentness }),
      windows: {
        execute: async () => ({ terminal: 'SUCCEEDED', sideEffectEvidence: {} }),
      },
    });
    const envelope = (await host.dispatch(payload, kernelContext())) as {
      phase: string;
      outcome: { ok: boolean; error?: { code: string } };
    };
    expect(envelope.outcome.ok).toBe(false);
    expect(envelope.outcome.error?.code).toBe('SHUN_AUTHORIZATION_REFUSED');
  });

  it('keeps an executor-side failure non-terminal (UNKNOWN owned by the K journal)', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const payload = await admittedPayload(fixture);
    const currentness = new FileCurrentnessSource(
      join(fixture.authorityDir, 'current-authority.json'),
    );
    const verifyIntegrity = hmacGrantIntegrityVerifier(
      resolveGrantHmacKeyFile(fixture.authorityDir),
    );
    const host = createWindowsEffectHost({
      binding: { capabilityId: 'windows', operationId: 'windows.execute' },
      authorization: {
        resolve: async (input) =>
          resolveAuthorization(
            new FilePlanSource(join(fixture.authorityDir, 'plans')),
            new FileGrantSource(join(fixture.authorityDir, 'grants')),
          )(input),
      },
      actionController: {
        authorizeEffect: async (input) =>
          authorizeEffectWith(currentness, verifyIntegrity, fixture.now)(input),
      },
      osAuthority: createWindowsOsAuthorityPort({ currentness }),
      windows: {
        execute: async () => {
          throw new Error('executor died after crossing the boundary');
        },
      },
    });
    const envelope = (await host.dispatch(payload, kernelContext())) as { phase: string };
    expect(envelope.phase).toBe('running');
  });

  it('binds the effect-time recheck to the exact admitted target (wrong path/task refuses)', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    await admittedPayload(fixture);
    const planHash = (fixture.facade.sends[0] as { input: { planRef: string } }).input.planRef;
    expect(
      fixture.host.verifyEffectTimeRootIdentity({
        taskId: TASK,
        planHash,
        path: win32.join(fixture.root, 'other-target.txt'),
      }),
    ).toMatchObject({ ok: false });
    expect(
      fixture.host.verifyEffectTimeRootIdentity({
        taskId: 'task-other',
        planHash,
        path: win32.join(fixture.root, SELECTED_ROOT_JOURNAL_FILENAME),
      }),
    ).toMatchObject({ ok: false });
  });

  it('P1-03: refuses the effect when the journal target already exists (create-only, zero effects, pre-existing content untouched)', async () => {
    const fixture = await createFixture();
    cleanups.push(fixture.cleanup);
    const payload = await admittedPayload(fixture);
    const planHash = (fixture.facade.sends[0] as { input: { planRef: string } }).input.planRef;
    // A pre-existing user file at the EXACT admitted target, using the plan's
    // own canonical win32 spelling: the admitted plan (and therefore the
    // rechecked path) is win32.join(root, journal) on every platform, so the
    // collision file must exist at exactly that string for the stat to see it.
    const target = win32.join(fixture.root, SELECTED_ROOT_JOURNAL_FILENAME);
    writeFileSync(target, 'pre-existing user content', 'utf8');
    expect(
      fixture.host.verifyEffectTimeRootIdentity({ taskId: TASK, planHash, path: target }),
    ).toEqual({ ok: false, code: 'SELECTED_ROOT_TARGET_COLLISION_REFUSED' });
    // The full real adapter chain refuses at the OS authority: zero executor
    // calls and the pre-existing file is byte-for-byte untouched.
    const currentness = new FileCurrentnessSource(
      join(fixture.authorityDir, 'current-authority.json'),
    );
    const verifyIntegrity = hmacGrantIntegrityVerifier(
      resolveGrantHmacKeyFile(fixture.authorityDir),
    );
    const executions: { effectId: string; actionId: string }[] = [];
    const host = createWindowsEffectHost({
      binding: { capabilityId: 'windows', operationId: 'windows.execute' },
      authorization: {
        resolve: async (input) =>
          resolveAuthorization(
            new FilePlanSource(join(fixture.authorityDir, 'plans')),
            new FileGrantSource(join(fixture.authorityDir, 'grants')),
          )(input),
      },
      actionController: {
        authorizeEffect: async (input) =>
          authorizeEffectWith(currentness, verifyIntegrity, fixture.now)(input),
      },
      osAuthority: createWindowsOsAuthorityPort({
        currentness,
        selectedRoot: {
          recheck: async (input: { effectId: string; action: unknown }) => {
            const action = input.action as {
              taskId: string;
              planHash: string;
              action: { parameters: { path: string } };
            };
            return fixture.host.verifyEffectTimeRootIdentity({
              taskId: action.taskId,
              planHash: action.planHash,
              path: action.action.parameters.path,
            });
          },
        },
      }),
      windows: {
        execute: async (input: { effectId: string; action: { actionId: string } }) => {
          executions.push({ effectId: input.effectId, actionId: input.action.actionId });
          return {
            actionId: input.action.actionId,
            terminal: 'SUCCEEDED',
            sideEffectEvidence: {
              recoveryClassification: 'COMPLETED_VERIFIED',
              postStateVerified: true,
            },
          };
        },
      },
    });
    const envelope = (await host.dispatch(payload, kernelContext())) as {
      phase: string;
      outcome: { ok: boolean; error?: { code: string } };
    };
    expect(envelope.phase).toBe('terminal');
    expect(envelope.outcome.ok).toBe(false);
    expect(envelope.outcome.error?.code).toBe('OS_AUTHORITY_REFUSED');
    expect(executions).toHaveLength(0);
    expect(readFileSync(target, 'utf8')).toBe('pre-existing user content');
  });

  // Windows libuv collapses a file-as-parent-component stat to ENOENT, so the
  // non-ENOENT fail-closed branch below is only reachable deterministically
  // on POSIX (where the authoritative CI runs). In production a replaced root
  // is refused even earlier by the real native identity check; this fixture's
  // mocked native port intentionally isolates the stat path alone.
  it.skipIf(process.platform === 'win32')(
    'P1-03: fails closed when the target stat cannot prove absence',
    async () => {
      const fixture = await createFixture();
      cleanups.push(fixture.cleanup);
      await admittedPayload(fixture);
      const planHash = (fixture.facade.sends[0] as { input: { planRef: string } }).input.planRef;
      // Replace the selected root directory with a regular file: the admitted
      // target now stats as ENOTDIR — an outcome that neither proves absence
      // nor a safe collision, so the recheck fails closed instead of proceeding.
      rmSync(fixture.root, { recursive: true, force: true });
      writeFileSync(fixture.root, 'no-longer-a-directory', 'utf8');
      expect(
        fixture.host.verifyEffectTimeRootIdentity({
          taskId: TASK,
          planHash,
          path: join(fixture.root, SELECTED_ROOT_JOURNAL_FILENAME),
        }),
      ).toEqual({ ok: false, code: 'SELECTED_ROOT_TARGET_STAT_UNKNOWN' });
    },
  );
});
