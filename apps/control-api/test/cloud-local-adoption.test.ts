import type { GoalProposal, GoalRequest } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import { CloudLocalC003Adoption } from '../src/cloud-local-adoption.ts';
import type { CloudTypedProposalAdmission } from '../src/cloud-proposal-admission.ts';

const ROOT = 'C:\\safe-c003-workspace';
const CHOICE = 'C003_BOUNDED_LOCAL_STORAGE';
const NOW = Date.parse('2026-10-29T00:00:00.000Z');

function humanRequest(): GoalRequest {
  return {
    taskId: 'remote-human-01',
    goal: 'system.storage.diagnose_bounded_action: inspect selected workspace storage',
    objects: [{ kind: 'DIRECTORY', ref: ROOT }],
    constraints: {},
    policyContext: {
      privacyPolicy: { localOnly: false, externalDisclosure: 'ALLOWED' },
      environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
    },
  };
}

function admitted(request: GoalRequest): CloudTypedProposalAdmission {
  const proposal: GoalProposal = {
    proposalId: 'only-admitted-by-trusted-host',
    plannerEvidence: {
      operationId: 'actual-cloud-attempt',
      modelEvidence: 'requested=deepseek-flash;immutable_model_revision=UNATTESTED',
    },
    goalContract: {
      taskId: request.taskId,
      objective: request.goal,
      objects: request.objects.map((object) => ({ ...object })),
      constraints: { ...request.constraints },
      privacyPolicy: { ...request.policyContext.privacyPolicy },
      environmentPolicy: { ...request.policyContext.environmentPolicy },
      ambiguityDisposition: 'READY',
    },
  };
  return {
    status: 'TYPED_PROPOSAL_ONLY',
    proposal,
    normalization: { status: 'READY' },
    effectExecuted: false,
    authorizationGranted: false,
  };
}

function host(options: { simulated?: boolean; fails?: boolean } = {}) {
  const submitted: GoalRequest[] = [];
  const backend = {
    meta: () => ({
      policy: { kind: 'ACTIVE' as const, revision: 'trusted-policy-1' },
      localOnly: true as const,
      simulated: options.simulated ?? false,
    }),
    submitGoal: async (goal: GoalRequest) => {
      submitted.push(goal);
      if (options.fails) throw new Error('private-key-or-path-diagnostic');
      return { taskId: goal.taskId };
    },
  };
  const clock = { ms: NOW };
  const adoption = new CloudLocalC003Adoption({
    backend,
    trustedWorkspace: ROOT,
    now: () => clock.ms,
  });
  return { adoption, submitted, clock };
}

describe('#212 host-only cloud suggestion to bounded local C003 selection', () => {
  it('offers a candidate only; a separate explicit choice submits a fixed LOCAL_ONLY task', async () => {
    const h = host();
    const request = humanRequest();
    const offer = h.adoption.offer({
      originalHumanRequest: request,
      admission: admitted(request),
    });
    expect(offer.ok).toBe(true);
    expect(h.submitted).toEqual([]);
    if (!offer.ok) return;
    expect(offer.userChoice).toBe(CHOICE);
    const selected = await h.adoption.select({
      candidateId: offer.candidateId,
      userChoice: CHOICE,
    });
    expect(selected).toMatchObject({
      ok: true,
      nextStep: 'EXISTING_PLAN_PREVIEW_AND_ACTION_CONTROLLER',
    });
    expect(h.submitted).toHaveLength(1);
    expect(h.submitted[0]).toMatchObject({
      goal: 'storage bounded cleanup',
      objects: [{ kind: 'DIRECTORY', ref: ROOT }],
      constraints: {},
      policyContext: {
        privacyPolicy: { localOnly: true, externalDisclosure: 'FORBIDDEN' },
        environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
      },
    });
    expect(h.submitted[0]?.taskId).not.toBe(request.taskId);
    expect(h.submitted[0]?.goal).not.toContain('inspect selected workspace');
    expect(
      await h.adoption.select({
        candidateId: offer.candidateId,
        userChoice: CHOICE,
      }),
    ).toEqual({ ok: false, code: 'SELECTION_REFUSED' });
    expect(h.submitted).toHaveLength(1);
  });

  it('refuses an incorrect local choice and consumes the opaque candidate', async () => {
    const h = host();
    const original = humanRequest();
    const offered = h.adoption.offer({
      originalHumanRequest: original,
      admission: admitted(original),
    });
    if (!offered.ok) throw new Error('TEST_EXPECTED_OFFER');
    expect(
      await h.adoption.select({
        candidateId: offered.candidateId,
        userChoice: 'MODEL_SHELL_ACTION',
      }),
    ).toEqual({ ok: false, code: 'SELECTION_REFUSED' });
    expect(
      await h.adoption.select({
        candidateId: offered.candidateId,
        userChoice: CHOICE,
      }),
    ).toEqual({ ok: false, code: 'SELECTION_REFUSED' });
    expect(h.submitted).toEqual([]);
  });

  it('refuses an expired candidate and any replay without starting a task', async () => {
    const h = host();
    const original = humanRequest();
    const offer = h.adoption.offer({
      originalHumanRequest: original,
      admission: admitted(original),
    });
    if (!offer.ok) throw new Error('TEST_EXPECTED_OFFER');
    h.clock.ms += 61_000;
    expect(
      await h.adoption.select({
        candidateId: offer.candidateId,
        userChoice: CHOICE,
      }),
    ).toEqual({ ok: false, code: 'SELECTION_REFUSED' });
    expect(h.submitted).toEqual([]);
  });

  it('refuses any host/model proposal that alters the original user goal or storage capability', () => {
    const h = host();
    const original = humanRequest();
    const malicious = admitted(original);
    if (malicious.status !== 'TYPED_PROPOSAL_ONLY') throw new Error('TEST_EXPECTED_TYPED_PROPOSAL');
    malicious.proposal.goalContract.objective =
      'system.storage.diagnose_bounded_action: delete all original files';
    expect(
      h.adoption.offer({
        originalHumanRequest: original,
        admission: malicious,
      }),
    ).toEqual({ ok: false, code: 'CANDIDATE_REFUSED' });

    const alternate = humanRequest();
    alternate.goal = 'image.batch_process: overwrite originals';
    expect(
      h.adoption.offer({
        originalHumanRequest: alternate,
        admission: admitted(alternate),
      }),
    ).toEqual({ ok: false, code: 'CANDIDATE_REFUSED' });
    expect(h.submitted).toEqual([]);
  });

  it('refuses absent, added, or different model target objects before creating candidate', () => {
    const h = host();
    const original = humanRequest();
    for (const objects of [
      [],
      [{ kind: 'DIRECTORY' as const, ref: 'D:\\other' }],
      [
        { kind: 'DIRECTORY' as const, ref: ROOT },
        { kind: 'DIRECTORY' as const, ref: ROOT },
      ],
    ]) {
      const model = admitted(original);
      if (model.status !== 'TYPED_PROPOSAL_ONLY') throw new Error('TEST_FIXTURE');
      model.proposal.goalContract.objects = objects;
      expect(
        h.adoption.offer({
          originalHumanRequest: original,
          admission: model,
        }),
      ).toEqual({ ok: false, code: 'CANDIDATE_REFUSED' });
    }
    expect(h.submitted).toEqual([]);
  });

  it('refuses simulated Host, forbidden disclosure and unreviewed proposal', () => {
    const original = humanRequest();
    const demo = host({ simulated: true });
    expect(
      demo.adoption.offer({
        originalHumanRequest: original,
        admission: admitted(original),
      }),
    ).toEqual({ ok: false, code: 'LOCAL_HOST_UNAVAILABLE' });

    const real = host();
    const forbidden = humanRequest();
    forbidden.policyContext.privacyPolicy = {
      localOnly: true,
      externalDisclosure: 'FORBIDDEN',
    };
    expect(
      real.adoption.offer({
        originalHumanRequest: forbidden,
        admission: admitted(forbidden),
      }),
    ).toEqual({ ok: false, code: 'CANDIDATE_REFUSED' });
    expect(
      real.adoption.offer({
        originalHumanRequest: original,
        admission: {
          status: 'PROPOSAL_NOT_READY',
          code: 'INTENT_RECONFIRM_REQUIRED',
          effectExecuted: false,
          authorizationGranted: false,
        },
      }),
    ).toEqual({ ok: false, code: 'CANDIDATE_REFUSED' });
    expect(real.submitted).toEqual([]);
  });

  it('consumes candidate even when existing backend submission fails; no silent retry', async () => {
    const h = host({ fails: true });
    const request = humanRequest();
    const candidate = h.adoption.offer({
      originalHumanRequest: request,
      admission: admitted(request),
    });
    if (!candidate.ok) throw new Error('TEST_EXPECTED_OFFER');
    expect(
      await h.adoption.select({
        candidateId: candidate.candidateId,
        userChoice: CHOICE,
      }),
    ).toEqual({ ok: false, code: 'LOCAL_HOST_UNAVAILABLE' });
    expect(
      await h.adoption.select({
        candidateId: candidate.candidateId,
        userChoice: CHOICE,
      }),
    ).toEqual({ ok: false, code: 'SELECTION_REFUSED' });
    expect(h.submitted).toHaveLength(1);
  });

  it('rejects an untrusted workspace alias or non-Windows absolute root on construction', () => {
    const original = host();
    expect(original.submitted).toHaveLength(0);
    for (const root of ['relative', '/tmp/unsafe', 'C:\\safe-c003-workspace\\.']) {
      expect(
        () =>
          new CloudLocalC003Adoption({
            backend: {
              meta: () => ({
                policy: { kind: 'ACTIVE', revision: 'r1' },
                localOnly: true,
                simulated: false,
              }),
              submitGoal: async () => ({ taskId: 'none' }),
            },
            trustedWorkspace: root,
          }),
      ).toThrow('C003_TRUSTED_WORKSPACE_REQUIRED');
    }
  });
});
