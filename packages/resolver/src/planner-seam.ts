// PlannerPort seam — proposal-only goal interpretation (L2 §6.1–§6.3).
//
// Planner output is always untrusted proposal data. It never invokes
// providers, never creates authorization, and never becomes the authoritative
// GoalContract until it re-enters Shun's deterministic normalization and
// validation. A remote planner is an external-model disclosure: under a
// local-only policy it is ineligible, and the outcome is a typed
// PLANNER_UNAVAILABLE — the policy is never silently relaxed.
import {
  type GoalProposal,
  GoalProposalSchema,
  type GoalRequest,
  type PlannerPort,
} from '@shun/contracts';
import { type GoalNormalization, normalizeGoal } from './normalize.ts';
import type { ShunRegistry } from './registry.ts';

export type PlannerTransport = 'LOCAL' | 'REMOTE';

/** Planning layer used for the resolution record (L2 §6.4 progressive determinization). */
export const PLANNER_PROPOSAL_PLAN_CLASS = 'PLANNER_INTERPRETED' as const;

export type PlannerInterpretation =
  | {
      status: 'PROPOSAL_ACCEPTED';
      proposal: GoalProposal;
      /** Deterministic re-resolution of the proposal; may still be NOT_READY — acceptance is not authority. */
      normalization: GoalNormalization;
      planClass: typeof PLANNER_PROPOSAL_PLAN_CLASS;
    }
  | { status: 'PROPOSAL_REJECTED'; reason: string }
  | { status: 'PLANNER_UNAVAILABLE'; reason: string };

function structuralEquals(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export async function interpretGoalViaPlanner(input: {
  request: GoalRequest;
  registry: ShunRegistry;
  planner?: PlannerPort;
  transport?: PlannerTransport;
  objectExists?: (ref: string) => boolean;
}): Promise<PlannerInterpretation> {
  const { request, registry, planner, transport = 'LOCAL', objectExists } = input;

  const localOnly =
    request.policyContext.privacyPolicy.localOnly ||
    request.policyContext.privacyPolicy.externalDisclosure === 'FORBIDDEN';
  if (transport === 'REMOTE' && localOnly) {
    return {
      status: 'PLANNER_UNAVAILABLE',
      reason:
        'local-only / no-disclosure policy makes a remote AI Runtime ineligible (external-model disclosure forbidden, L2 §6.3); deterministic and structured paths remain usable',
    };
  }
  if (!planner) {
    return {
      status: 'PLANNER_UNAVAILABLE',
      reason: 'no PlannerPort configured; deterministic and structured paths remain usable',
    };
  }

  let raw: GoalProposal;
  try {
    raw = await planner.interpretGoal(request);
  } catch (error) {
    return {
      status: 'PROPOSAL_REJECTED',
      reason: `planner raised ${error instanceof Error ? error.name : 'unknown error'}: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  const parsed = GoalProposalSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      status: 'PROPOSAL_REJECTED',
      reason: 'planner proposal violates the frozen GoalProposal contract schema',
    };
  }
  const proposal = parsed.data;

  if (proposal.goalContract.taskId !== request.taskId) {
    return {
      status: 'PROPOSAL_REJECTED',
      reason: `proposal taskId ${proposal.goalContract.taskId} does not match request ${request.taskId}`,
    };
  }

  // The planner may not invent objects beyond the request's referenced set.
  const requestedObjects = new Set(request.objects.map((object) => `${object.kind}:${object.ref}`));
  for (const object of proposal.goalContract.objects) {
    if (!requestedObjects.has(`${object.kind}:${object.ref}`)) {
      return {
        status: 'PROPOSAL_REJECTED',
        reason: `planner proposed object outside the request scope: ${object.kind} ${object.ref}`,
      };
    }
  }

  // Policy comes from the request authority; a proposal may not broaden it.
  if (
    !structuralEquals(proposal.goalContract.privacyPolicy, request.policyContext.privacyPolicy) ||
    !structuralEquals(
      proposal.goalContract.environmentPolicy,
      request.policyContext.environmentPolicy,
    )
  ) {
    return {
      status: 'PROPOSAL_REJECTED',
      reason:
        'planner proposed altered privacy/environment policy — policy is request authority, not planner authority',
    };
  }

  // A remote proposal is an external-model disclosure and must carry its evidence.
  if (transport === 'REMOTE' && proposal.plannerEvidence === undefined) {
    return {
      status: 'PROPOSAL_REJECTED',
      reason:
        'remote planner proposal missing plannerEvidence (external-model disclosure, L2 §6.3)',
    };
  }

  // Shun re-validates: the proposed objective must still resolve
  // deterministically against the frozen capability registry.
  const normalization = normalizeGoal({
    request: { ...request, goal: proposal.goalContract.objective },
    registry,
    objectExists,
  });

  return {
    status: 'PROPOSAL_ACCEPTED',
    proposal,
    normalization,
    planClass: PLANNER_PROPOSAL_PLAN_CLASS,
  };
}
