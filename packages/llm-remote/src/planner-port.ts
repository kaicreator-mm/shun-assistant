// T01 final source handoff: bounded remote PlannerPort, NOT consent issuance.
// Only trusted Shun backend composition may inject these ports. T08 owns the
// real private authenticated user gesture/issuer; model output is proposal only.
import {
  CloudConsentApprovalSchema,
  canonicalJson,
  type GoalProposal,
  GoalProposalSchema,
  type GoalRequest,
  GoalRequestSchema,
  type PlannerPort,
} from '@shun/contracts';
import type {
  DeepSeekGoalInput,
  DeepSeekTransportResult,
  TrustedDeepSeekTransport,
} from './deepseek-transport.ts';

type TransportPort = Pick<TrustedDeepSeekTransport, 'invoke'>;

/** The host-owned approval is NEVER obtained from a browser/Recipe request. */
export type TrustedPlannerComposition = Readonly<{
  transport: TransportPort;
  prepareApprovedGoal: (goal: GoalRequest) => Promise<DeepSeekGoalInput | null>;
}>;

/** Fixed errors only; rejected model text and credential data are never reflected. */
function refused(): never {
  throw new Error('REMOTE_PLANNER_REFUSED');
}

function exactEqual(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

function normalizedProposal(modelText: string, task: GoalRequest, attemptId: string): GoalProposal {
  let response: unknown;
  try {
    response = JSON.parse(modelText) as unknown;
  } catch {
    return refused();
  }
  const parsed = GoalProposalSchema.safeParse(response);
  if (!parsed.success || !/^[A-Za-z0-9_-]{1,128}$/.test(attemptId)) {
    return refused();
  }
  const proposal = parsed.data;
  const contract = proposal.goalContract;
  if (
    contract.taskId !== task.taskId ||
    !exactEqual(contract.privacyPolicy, task.policyContext.privacyPolicy) ||
    !exactEqual(contract.environmentPolicy, task.policyContext.environmentPolicy) ||
    !exactEqual(contract.constraints, task.constraints) ||
    !exactEqual(contract.verificationIntent ?? null, task.verificationIntent ?? null) ||
    contract.lifecyclePolicy !== undefined
  ) {
    return refused();
  }
  const allowed = new Set(task.objects.map((object) => `${object.kind}:${object.ref}`));
  if (contract.objects.some((object) => !allowed.has(`${object.kind}:${object.ref}`))) {
    return refused();
  }
  // Ignore any model-authored "plannerEvidence": it cannot attest its own
  // issuer or weight revision. The controlled attempt ID is a request receipt,
  // not a claimed immutable model SHA.
  return {
    proposalId: proposal.proposalId,
    goalContract: contract,
    plannerEvidence: {
      operationId: attemptId,
      modelEvidence: 'requested=deepseek-flash;immutable_model_revision=UNATTESTED',
    },
  };
}

export class DeepSeekFlashPlannerPort implements PlannerPort {
  private readonly host: TrustedPlannerComposition;

  constructor(host: TrustedPlannerComposition) {
    if (
      !host?.transport ||
      typeof host.transport.invoke !== 'function' ||
      typeof host.prepareApprovedGoal !== 'function'
    ) {
      throw new Error('REMOTE_PLANNER_CONFIGURATION_REFUSED');
    }
    this.host = host;
  }

  async interpretGoal(input: GoalRequest): Promise<GoalProposal> {
    let goal: GoalRequest;
    try {
      const parsed = GoalRequestSchema.safeParse(input);
      if (!parsed.success) return refused();
      goal = parsed.data;
    } catch {
      return refused();
    }
    // Hard policy gate BEFORE asking the host issuer, key or model for anything.
    if (
      goal.policyContext.privacyPolicy.localOnly ||
      goal.policyContext.privacyPolicy.externalDisclosure === 'FORBIDDEN' ||
      goal.constraints.other?.offline === true
    ) {
      return refused();
    }

    let prepared: DeepSeekGoalInput | null;
    try {
      prepared = await this.host.prepareApprovedGoal(goal);
    } catch {
      return refused();
    }
    if (!prepared) return refused();

    // Snapshot untrusted getter-bearing values once, then consume only parsed
    // broker proof and the exact sanitized GoalRequest projection.
    let approvalInput: unknown;
    let attemptId: string;
    let approvedGoal: string;
    let ceiling: number;
    try {
      approvalInput = prepared.approval;
      attemptId = prepared.attemptId;
      approvedGoal = prepared.goalText;
      ceiling = prepared.maxOutputTokens;
    } catch {
      return refused();
    }
    // Nested broker approval values may be getters/Proxies even after the
    // top-level fields were captured. Zod may invoke them and throw; no
    // private error is permitted to cross the PlannerPort boundary.
    let broker: ReturnType<typeof CloudConsentApprovalSchema.safeParse>;
    try {
      broker = CloudConsentApprovalSchema.safeParse(approvalInput);
    } catch {
      return refused();
    }
    if (
      !broker.success ||
      broker.data.scope.taskId !== goal.taskId ||
      approvedGoal !== goal.goal ||
      !Number.isSafeInteger(ceiling) ||
      ceiling < 1 ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(attemptId)
    ) {
      return refused();
    }
    // The transport/ledger validates the issuer cryptographically via its
    // trusted private verifier, quota/nonce/currentness and outbound digest.
    // Keep transport result getters, malformed results and normalization in
    // the same redacting boundary as invoke(), not only the awaited call.
    try {
      const remote: DeepSeekTransportResult = await this.host.transport.invoke({
        goalText: goal.goal,
        attemptId,
        approval: broker.data,
        maxOutputTokens: ceiling,
      });
      if (
        !remote ||
        typeof remote !== 'object' ||
        remote.ok !== true ||
        remote.attemptId !== attemptId ||
        typeof remote.proposalText !== 'string' ||
        remote.costState !== 'UNKNOWN_COST'
      ) {
        return refused();
      }
      return normalizedProposal(remote.proposalText, goal, attemptId);
    } catch {
      return refused();
    }
  }
}
