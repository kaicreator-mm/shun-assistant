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

/**
 * Module-private brand minted ONLY by localPlannerAdapter/remotePlannerAdapter
 * (P2, R1): the seam accepts an adapter's transport provenance solely when it
 * carries this brand, so a caller-forged `{ planner, transport }` object can
 * never masquerade as a factory-issued binding.
 */
const TRUSTED_PLANNER_ADAPTER_BRAND = Symbol('shun.trusted-planner-adapter');

/**
 * A PlannerPort bound to its transport provenance by the trusted adapter
 * factory (P2, R1). The transport value is pinned at minting (frozen): the
 * policy seam reads it from the adapter instead of accepting a parallel
 * caller assertion. Constructing this shape outside the factory requires the
 * module-private brand symbol and therefore fails the seam's provenance check.
 */
export interface TrustedPlannerAdapter {
  readonly planner: PlannerPort;
  readonly transport: PlannerTransport;
  readonly [TRUSTED_PLANNER_ADAPTER_BRAND]: true;
}

/** Bind a PlannerPort to LOCAL transport provenance at the trust boundary. */
export function localPlannerAdapter(planner: PlannerPort): TrustedPlannerAdapter {
  return Object.freeze({
    planner,
    transport: 'LOCAL',
    [TRUSTED_PLANNER_ADAPTER_BRAND]: true,
  } satisfies TrustedPlannerAdapter);
}

/** Bind a PlannerPort to REMOTE transport provenance at the trust boundary. */
export function remotePlannerAdapter(planner: PlannerPort): TrustedPlannerAdapter {
  return Object.freeze({
    planner,
    transport: 'REMOTE',
    [TRUSTED_PLANNER_ADAPTER_BRAND]: true,
  } satisfies TrustedPlannerAdapter);
}

/**
 * Input of the planner seam. Transport provenance is a required trusted fact
 * (P1-01): a configured PlannerPort MUST be declared LOCAL or REMOTE by the
 * caller. Since R1 (P2) the provenance is pinned by the trusted adapter
 * factory — pass `adapter` minted via localPlannerAdapter/remotePlannerAdapter
 * so the transport value cannot be asserted independently of the planner
 * instance. The explicit `{ planner, transport }` pair form remains for the
 * P1-01 fail-closed path: an adapter that omits its transport declaration has
 * unknown provenance — it is never silently treated as LOCAL, because a
 * remote-backed adapter without the flag would otherwise bypass local-only /
 * no-disclosure policy. The discriminated union makes the type system reject
 * a planner without transport; the seam additionally fails closed at runtime
 * for untyped callers and for forged adapters.
 */
export type InterpretGoalViaPlannerInput =
  | {
      request: GoalRequest;
      registry: ShunRegistry;
      /** Planner + transport bound together by the trusted adapter factory (preferred form). */
      adapter: TrustedPlannerAdapter;
      objectExists?: (ref: string) => boolean;
    }
  | {
      request: GoalRequest;
      registry: ShunRegistry;
      planner: PlannerPort;
      transport: PlannerTransport;
      objectExists?: (ref: string) => boolean;
    }
  | {
      request: GoalRequest;
      registry: ShunRegistry;
      planner?: undefined;
      transport?: PlannerTransport;
      objectExists?: (ref: string) => boolean;
    };

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

export async function interpretGoalViaPlanner(
  input: InterpretGoalViaPlannerInput,
): Promise<PlannerInterpretation> {
  const { request, registry, objectExists } = input;

  // Resolve the planner + transport provenance (P2, R1): the adapter form is
  // the trusted path — only adapters minted by the module-private factory
  // brand reach the PlannerPort, so the transport value is pinned to the
  // verified source rather than asserted next to it. The explicit pair form
  // keeps the P1-01 fail-closed semantics.
  let planner: PlannerPort | undefined;
  let transport: PlannerTransport | undefined;
  if ('adapter' in input) {
    if (input.adapter[TRUSTED_PLANNER_ADAPTER_BRAND] !== true) {
      return {
        status: 'PLANNER_UNAVAILABLE',
        reason:
          'planner adapter transport provenance is not minted by the trusted adapter factory (localPlannerAdapter / remotePlannerAdapter) — a forged adapter is never invoked',
      };
    }
    planner = input.adapter.planner;
    transport = input.adapter.transport;
  } else {
    planner = input.planner;
    transport = input.transport;
  }

  // P1-01 fail-closed provenance check, ahead of any policy evaluation or
  // adapter invocation: a configured planner without an explicit LOCAL/REMOTE
  // transport declaration has unknown provenance and is never invoked.
  if (planner !== undefined && transport !== 'LOCAL' && transport !== 'REMOTE') {
    return {
      status: 'PLANNER_UNAVAILABLE',
      reason:
        'planner transport provenance is required: a configured PlannerPort must declare LOCAL or REMOTE explicitly; a missing or unknown transport fails closed instead of defaulting to LOCAL',
    };
  }

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
  // Offline constraint (P1 supplemental, R1): a required offline execution is
  // independent of the disclosure posture — an allowed external disclosure
  // never authorizes network traffic against an offline goal. A remote planner
  // is a network round trip, so it is unavailable with zero invocations.
  if (transport === 'REMOTE' && request.constraints.other?.offline === true) {
    return {
      status: 'PLANNER_UNAVAILABLE',
      reason:
        'offline execution constraint makes a remote AI Runtime ineligible (a remote interpretation is network traffic regardless of the disclosure posture); deterministic and structured paths remain usable',
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
