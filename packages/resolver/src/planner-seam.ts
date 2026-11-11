// PlannerPort seam — proposal-only goal interpretation (L2 §6.1–§6.3).
//
// Planner output is always untrusted proposal data. It never invokes
// providers, never creates authorization, and never becomes the authoritative
// GoalContract until it re-enters Shun's deterministic normalization and
// validation. A remote planner is an external-model disclosure: under a
// local-only policy it is ineligible, and the outcome is a typed
// PLANNER_UNAVAILABLE — the policy is never silently relaxed.
//
// R3 security correction: a public declareLocalPlanner issuer cannot prove
// local transport (it can brand arbitrary remote-backed implementations).
// LOCAL PlannerPort invocation therefore fails closed at the seam until a
// trusted host can enforce no-network execution. REMOTE remains eligible
// only under explicit privacy/offline policy permissions.
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
 * Module-private brand minted ONLY by declareLocalPlanner (R2, review
 * blocker 2): the proof that a PlannerPort was declared LOCAL at the trusted
 * composition boundary. `localPlannerAdapter` refuses any planner without
 * this brand, so the publicly callable factory can no longer bind an
 * arbitrary (remote-backed) planner to LOCAL transport.
 */
const LOCAL_PLANNER_PROVENANCE_BRAND = Symbol('shun.local-planner-provenance');

/**
 * A PlannerPort whose LOCAL provenance was declared at the trusted
 * composition boundary (R2, review blocker 2). The composition/integration
 * layer is the only actor entitled to assert that a planner executes
 * in-process — the same trust boundary that wires the registry port and the
 * policy-fact evaluator. Declaring a remote-backed planner local here is a
 * wiring-level lie outside the resolver's enforcement model, exactly like
 * forging any other injected port.
 */
export interface LocalProvenancePlannerPort extends PlannerPort {
  readonly [LOCAL_PLANNER_PROVENANCE_BRAND]: true;
}

/**
 * Declare, at the trusted composition boundary, that a PlannerPort executes
 * locally (in-process, no network round trip). This is the single trust
 * anchor for LOCAL transport: without it `localPlannerAdapter` refuses to
 * mint, so a remote-backed planner cannot be smuggled through the LOCAL path
 * under local-only/offline policy.
 */
export function declareLocalPlanner(planner: PlannerPort): LocalProvenancePlannerPort {
  return new Proxy(planner, {
    get(target, property, receiver) {
      if (property === LOCAL_PLANNER_PROVENANCE_BRAND) {
        return true as const;
      }
      return Reflect.get(target, property, receiver);
    },
  }) as LocalProvenancePlannerPort;
}

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

/**
 * Bind a PlannerPort to LOCAL transport provenance at the trust boundary.
 * R2 (review blocker 2): only a planner whose local provenance was declared
 * via {@link declareLocalPlanner} can be bound — minting throws for any
 * other planner, so a remote-backed planner can no longer be wrapped into a
 * LOCAL adapter by a caller.
 */
export function localPlannerAdapter(planner: PlannerPort): TrustedPlannerAdapter {
  if (
    (planner as unknown as Partial<Record<symbol, unknown>>)[LOCAL_PLANNER_PROVENANCE_BRAND] !==
    true
  ) {
    throw new TypeError(
      'localPlannerAdapter requires a planner whose local provenance was declared at the trusted composition boundary via declareLocalPlanner — an arbitrary PlannerPort (possibly remote-backed) cannot be bound to LOCAL transport',
    );
  }
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
 * (P1-01) bound by the trusted adapter factory (P2, R1) — pass `adapter`
 * minted via localPlannerAdapter/remotePlannerAdapter. R2 (review blocker 2):
 * the caller-supplied `{ planner, transport }` pair form is REMOVED — a
 * caller-labeled LOCAL transport let a remote-backed planner run under
 * local-only/offline policy, and the label is an assertion, not provenance.
 * Untyped callers that still pass a planner/transport pair fail closed at
 * runtime and are never invoked.
 */
export type InterpretGoalViaPlannerInput =
  | {
      request: GoalRequest;
      registry: ShunRegistry;
      /** Planner + transport bound together by the trusted adapter factory. */
      adapter: TrustedPlannerAdapter;
      objectExists?: (ref: string) => boolean;
    }
  | {
      request: GoalRequest;
      registry: ShunRegistry;
      /** No planner configured — typed PLANNER_UNAVAILABLE, deterministic paths remain usable. */
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

  // Resolve the planner + transport provenance (P2, R1; R2 blocker 2): ONLY
  // the adapter path reaches a PlannerPort. A caller-supplied planner/transport
  // pair is never accepted — the transport label is an assertion, not
  // provenance, and a remote-backed planner labeled 'LOCAL' previously ran
  // under local-only/offline policy. Fail closed with zero invocations.
  if (!('adapter' in input)) {
    if ('planner' in input || 'transport' in input) {
      return {
        status: 'PLANNER_UNAVAILABLE',
        reason:
          'caller-supplied planner/transport inputs are not accepted: transport provenance must be bound by the trusted adapter factory (localPlannerAdapter / remotePlannerAdapter) at the composition boundary; a caller label is not provenance and the planner is never invoked',
      };
    }
    return {
      status: 'PLANNER_UNAVAILABLE',
      reason: 'no PlannerPort configured; deterministic and structured paths remain usable',
    };
  }

  const adapter = input.adapter;
  // P1-01 fail-closed provenance check, ahead of any policy evaluation or
  // adapter invocation: a forged adapter (not minted by the factory) is never
  // invoked.
  if (adapter[TRUSTED_PLANNER_ADAPTER_BRAND] !== true) {
    return {
      status: 'PLANNER_UNAVAILABLE',
      reason:
        'planner adapter transport provenance is not minted by the trusted adapter factory (localPlannerAdapter / remotePlannerAdapter) — a forged adapter is never invoked',
    };
  }
  const planner: PlannerPort | undefined = adapter.planner;
  const transport: PlannerTransport | undefined = adapter.transport;
  // R2 (review blocker 2), defense in depth: a LOCAL adapter must carry a
  // planner whose local provenance was declared at the composition boundary.
  // The factory already refuses to mint such an adapter; this seam-side check
  // keeps the invariant independently of the factory.
  if (
    transport === 'LOCAL' &&
    (planner as unknown as Partial<Record<symbol, unknown>>)[LOCAL_PLANNER_PROVENANCE_BRAND] !==
      true
  ) {
    return {
      status: 'PLANNER_UNAVAILABLE',
      reason:
        'LOCAL transport is bound to a planner without declared local provenance (declareLocalPlanner at the trusted composition boundary) — a possibly remote-backed planner is never invoked under a LOCAL label',
    };
  }

  // R3 security disposition: this package has no non-user-mintable host
  // principal that can attest a PlannerPort's actual egress behavior.
  // In particular, declareLocalPlanner is public and can wrap a remote
  // implementation. Module-private symbols only authenticate the factory,
  // NOT the transport. Until the host supplies enforceable no-network
  // composition, all LOCAL execution fails closed (including open policies,
  // so an offline request cannot be routed remotely through this seam).
  // Deterministic/structured normalization remains available, as does the
  // explicit REMOTE adapter when disclosure and offline policy allow it.
  if (transport === 'LOCAL') {
    return {
      status: 'PLANNER_UNAVAILABLE',
      reason:
        'LOCAL PlannerPort origin cannot be independently attested by this runtime; caller-declared local provenance is not proof of no network egress — refusing execution until an enforceable trusted host is provided',
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
  } catch {
    return {
      status: 'PROPOSAL_REJECTED',
      reason: 'PLANNER_EXECUTION_REFUSED',
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
      reason: 'PLANNER_TASK_SCOPE_MISMATCH',
    };
  }

  // The planner may not invent objects beyond the request's referenced set.
  const requestedObjects = new Set(request.objects.map((object) => `${object.kind}:${object.ref}`));
  for (const object of proposal.goalContract.objects) {
    if (!requestedObjects.has(`${object.kind}:${object.ref}`)) {
      return {
        status: 'PROPOSAL_REJECTED',
        reason: 'PLANNER_OBJECT_SCOPE_MISMATCH',
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
