import type { CloudConsentApproval, GoalProposal, GoalRequest } from '@shun/contracts';
import { describe, expect, it } from 'vitest';
import type { DeepSeekGoalInput, DeepSeekTransportResult } from '../src/deepseek-transport.ts';
import { DeepSeekFlashPlannerPort } from '../src/planner-port.ts';

const SHA = 'a'.repeat(64);
const request: GoalRequest = {
  taskId: 'task-1',
  goal: '请分析所选磁盘空间',
  objects: [],
  constraints: {},
  policyContext: {
    privacyPolicy: { localOnly: false, externalDisclosure: 'ALLOWED' },
    environmentPolicy: { allowedBackendKinds: ['LOCAL_WINDOWS'], allowElevation: false },
  },
};

function approved(): CloudConsentApproval {
  return {
    consentId: 'c-1',
    confirmationNonce: 'nonce-1',
    displayedProjectionSha256: SHA,
    displayedDisclosureCategories: ['GOAL_TEXT'],
    issuer: {
      brokerId: 'trusted-private-issuer',
      brokerRevision: 'rev1',
      assertionId: 'a-1',
      channel: 'AUTHENTICATED_PRIVATE_IPC',
      proof: 'test-only-no-real-broker',
    },
    scope: {
      taskId: request.taskId,
      principalId: 'p-1',
      sessionId: 's-1',
      providerId: 'deepseek',
      modelId: 'deepseek-flash',
      destination: 'https://api.deepseek.com/chat/completions',
      approvedProjectionSha256: SHA,
      scopeRevision: 'scope-1',
      disclosureCategories: ['GOAL_TEXT'],
      registryRevision: 'registry-1',
      policyRevision: 'policy-1',
      pricingRevision: 'pricing-1',
      revocationEpoch: 1,
      maxCalls: 1,
      maxInputTokens: 2048,
      maxOutputTokens: 128,
      maxCostMicros: 50000,
      issuedAt: '2026-10-15T00:00:00.000Z',
      expiresAt: '2026-10-16T00:00:00.000Z',
    },
  };
}
function proposed(goal: GoalRequest = request): GoalProposal {
  return {
    proposalId: 'proposal-1',
    goalContract: {
      taskId: goal.taskId,
      objective: 'scan.bounded.disk',
      objects: goal.objects,
      constraints: goal.constraints,
      privacyPolicy: goal.policyContext.privacyPolicy,
      environmentPolicy: goal.policyContext.environmentPolicy,
      ambiguityDisposition: 'READY',
    },
  };
}

function harness(
  output: unknown = proposed(),
  authorize: ((goal: GoalRequest) => Promise<DeepSeekGoalInput | null>) | undefined = undefined,
) {
  let authCalls = 0;
  const outgoing: DeepSeekGoalInput[] = [];
  const planner = new DeepSeekFlashPlannerPort({
    prepareApprovedGoal: async (goal) => {
      authCalls += 1;
      if (authorize) return authorize(goal);
      return {
        approval: approved(),
        attemptId: 'attempt_1',
        goalText: goal.goal,
        maxOutputTokens: 100,
      };
    },
    transport: {
      invoke: async (input): Promise<DeepSeekTransportResult> => {
        outgoing.push(input);
        return {
          ok: true,
          attemptId: input.attemptId,
          costState: 'UNKNOWN_COST',
          proposalText: JSON.stringify(output),
        };
      },
    },
  });
  return { planner, outgoing, authCalls: () => authCalls };
}

describe('T01 typed DeepSeek PlannerPort composition (no real broker or HTTP)', () => {
  it('produces strict typed proposal and overrides model-authored evidence', async () => {
    const fake = proposed();
    fake.plannerEvidence = { operationId: 'forge', modelEvidence: 'I am trusted' };
    const h = harness(fake);
    const result = await h.planner.interpretGoal(request);
    expect(h.outgoing).toHaveLength(1);
    expect(h.outgoing[0]?.goalText).toBe(request.goal);
    expect(result.plannerEvidence).toEqual({
      operationId: 'attempt_1',
      modelEvidence: 'requested=deepseek-flash;immutable_model_revision=UNATTESTED',
    });
    expect(result.goalContract.taskId).toBe(request.taskId);
  });

  it('never contacts authorization or model under offline, forbidden or LOCAL_ONLY', async () => {
    for (const policy of [
      {
        ...request,
        policyContext: {
          ...request.policyContext,
          privacyPolicy: { localOnly: true, externalDisclosure: 'ALLOWED' as const },
        },
      },
      {
        ...request,
        policyContext: {
          ...request.policyContext,
          privacyPolicy: { localOnly: false, externalDisclosure: 'FORBIDDEN' as const },
        },
      },
      { ...request, constraints: { other: { offline: true } } },
    ]) {
      const h = harness();
      await expect(h.planner.interpretGoal(policy)).rejects.toThrow('REMOTE_PLANNER_REFUSED');
      expect(h.authCalls()).toBe(0);
      expect(h.outgoing).toHaveLength(0);
    }
  });

  it('rejects forged task approval and changed approved goal before HTTP', async () => {
    const p = approved();
    p.scope.taskId = 'different-task';
    const h = harness(proposed(), async (goal) => ({
      approval: p,
      goalText: goal.goal,
      attemptId: 'attempt_2',
      maxOutputTokens: 100,
    }));
    await expect(h.planner.interpretGoal(request)).rejects.toThrow('REMOTE_PLANNER_REFUSED');
    expect(h.outgoing).toHaveLength(0);
    const h2 = harness(proposed(), async () => ({
      approval: approved(),
      goalText: 'C:/private/secret.txt',
      attemptId: 'attempt_3',
      maxOutputTokens: 100,
    }));
    await expect(h2.planner.interpretGoal(request)).rejects.toThrow('REMOTE_PLANNER_REFUSED');
    expect(h2.outgoing).toHaveLength(0);
  });

  it('rejects forged object scope or changed constraints/policies after model response', async () => {
    const wrong: GoalProposal = proposed();
    wrong.goalContract.objects = [{ kind: 'FILE', ref: 'C:/private/secret' }];
    const h = harness(wrong);
    await expect(h.planner.interpretGoal(request)).rejects.toThrow('REMOTE_PLANNER_REFUSED');
    const policies: GoalProposal = proposed();
    policies.goalContract.privacyPolicy.localOnly = true;
    const h2 = harness(policies);
    await expect(h2.planner.interpretGoal(request)).rejects.toThrow('REMOTE_PLANNER_REFUSED');
  });

  it('rejects invalid JSON, unregistered proposal shapes, and thrown secrets', async () => {
    const h = harness({ proposalId: 'okay', shell: 'Remove-Item C:/Users/secret' });
    await expect(h.planner.interpretGoal(request)).rejects.toThrow('REMOTE_PLANNER_REFUSED');
    const failing = new DeepSeekFlashPlannerPort({
      prepareApprovedGoal: async () => {
        throw new Error('Bearer private-token');
      },
      transport: {
        invoke: async () => {
          throw new Error('never called');
        },
      },
    });
    await expect(failing.interpretGoal(request)).rejects.toThrow('REMOTE_PLANNER_REFUSED');
  });

  it('redacts nested approval getter/Proxy errors before transport invocation', async () => {
    const proof = approved();
    proof.scope = new Proxy(proof.scope, {
      get(target, property, receiver) {
        if (property === 'taskId') throw new Error('Bearer private-token');
        return Reflect.get(target, property, receiver);
      },
    });
    const h = harness(proposed(), async (goal) => ({
      approval: proof,
      goalText: goal.goal,
      attemptId: 'attempt_nested',
      maxOutputTokens: 100,
    }));
    await expect(h.planner.interpretGoal(request)).rejects.toThrow(/^REMOTE_PLANNER_REFUSED$/);
    expect(h.outgoing).toHaveLength(0);
  });

  it('redacts null, throwing discriminant and throwing proposal getters from transport', async () => {
    const corrupted: unknown[] = [
      null,
      { get ok() { throw new Error('Bearer secret-value'); } },
      {
        ok: true,
        attemptId: 'attempt_1',
        costState: 'UNKNOWN_COST',
        get proposalText() { throw new Error('C:/private/credentials'); },
      },
    ];
    for (const raw of corrupted) {
      const port = new DeepSeekFlashPlannerPort({
        prepareApprovedGoal: async (goal) => ({
          approval: approved(),
          goalText: goal.goal,
          attemptId: 'attempt_1',
          maxOutputTokens: 100,
        }),
        transport: {
          invoke: async (): Promise<DeepSeekTransportResult> =>
            raw as DeepSeekTransportResult,
        },
      });
      await expect(port.interpretGoal(request)).rejects.toThrow(/^REMOTE_PLANNER_REFUSED$/);
    }
  });

  it('rejects a transport with a swapped attempt even when it reports success', async () => {
    const port = new DeepSeekFlashPlannerPort({
      prepareApprovedGoal: async (goal) => ({
        approval: approved(),
        goalText: goal.goal,
        attemptId: 'attempt_1',
        maxOutputTokens: 100,
      }),
      transport: {
        invoke: async () => ({
          ok: true as const,
          attemptId: 'swapped',
          proposalText: JSON.stringify(proposed()),
          costState: 'UNKNOWN_COST' as const,
        }),
      },
    });
    await expect(port.interpretGoal(request)).rejects.toThrow('REMOTE_PLANNER_REFUSED');
  });
});
